"""Remove CFG blocks proven unreachable from each decompiled prototype entry.

The typed capture contains decoy blocks as well as executable instructions.
This pass follows only recovered static PC edges. Dynamic/partially decoded
branches remain conservative: both their known target and fallthrough are kept,
and an unknown target disables block pruning for that prototype. Prototype
pruning follows typed ``ProtoRef`` operands and stops on dynamic closure targets.
"""
from __future__ import annotations

from dataclasses import replace
import re
from typing import Mapping

from . import luraph_decompiler, luraph_lift
from . import luraph_public_v147 as public
from .luraph_full import Program, ProtoRef


_INSTALLED = False
_ORIGINAL_RENDER = None


def _code_only(source: str) -> str:
    """Mask comments and strings while preserving token offsets."""
    pieces = []
    cursor = 0
    for token in public._tokens(source):
        pieces.append(" " * (token.start - cursor))
        if token.kind == "string":
            pieces.append(" " * (token.end - token.start))
        else:
            pieces.append(source[token.start:token.end])
        cursor = token.end
    pieces.append(" " * (len(source) - cursor))
    return "".join(pieces)


def has_residual_pc_write(source: str, branch) -> bool:
    """Return whether a PC mutation is not represented by ``branch``."""
    text = re.sub(r"\bu\b", "pc", _code_only(source))
    compound = list(re.finditer(
        r"(?<![A-Za-z0-9_.])\(?\s*pc\s*\)?\s*"
        r"(?:\+=|-=|\*=|/=|%=|\^=|\.\.=)",
        text,
    ))
    assignments = []
    lhs_pattern = re.compile(
        r"(?<![A-Za-z0-9_.])(?P<lhs>\(?\s*[A-Za-z_]\w*\s*\)?"
        r"(?:\s*,\s*\(?\s*[A-Za-z_]\w*\s*\)?\s*)*)=(?!=)"
    )
    for match in lhs_pattern.finditer(text):
        names = re.findall(r"[A-Za-z_]\w*", match.group("lhs"))
        if "pc" in names:
            assignments.append(match)
    writes = compound + assignments
    if not writes:
        return False
    canonical = list(re.finditer(
        r"(?<![A-Za-z0-9_.,])\(?\s*pc\s*\)?\s*=\s*\(?\s*"
        r"[EpoH_B]\s*\[\s*pc\s*\]\s*\)?",
        text,
    ))
    return branch is None or len(writes) != 1 or len(canonical) != 1


def reachable_block_starts(proto, semantics):
    blocks = luraph_decompiler.build_blocks(proto, semantics)
    if not blocks:
        return set()
    by_start = {block.start: block for block in blocks}
    reachable = set()
    pending = [blocks[0].start]
    while pending:
        start = pending.pop()
        if start in reachable or start not in by_start:
            continue
        reachable.add(start)
        block = by_start[start]
        for instruction in block.instructions:
            instruction_source = semantics[instruction.opcode]
            instruction_branch = luraph_decompiler.decode_branch(
                instruction_source, instruction
            )
            if has_residual_pc_write(instruction_source, instruction_branch):
                return set(by_start)
        last = block.instructions[-1]
        source = semantics[last.opcode]
        branch = luraph_decompiler.decode_branch(source, last)
        returned = luraph_decompiler.return_expression(source, last)
        if returned is not None:
            continue
        if branch is None:
            if block.fallthrough is not None:
                pending.append(block.fallthrough)
            continue
        if branch.target is None:
            # Generated fallback executes this branch body verbatim. With no
            # typed target, it may select any captured block in the prototype;
            # retaining all blocks is the only sound approximation.
            return set(by_start)
        if branch.target is not None:
            pending.append(branch.target)
        if not branch.unconditional and block.fallthrough is not None:
            pending.append(block.fallthrough)
    return reachable


def _resolved_if_count(program: Program, source: str, instruction) -> int:
    """Return conditionals covered by one explicit structural proof."""
    from . import luraph_lift_calls, luraph_lift_close_upvalues
    from . import luraph_lift_closures, luraph_lift_forloops

    branch = luraph_decompiler.decode_branch(source, instruction)
    proofs = [
        1 if branch is not None and branch.condition is not None else 0,
        luraph_lift_calls.resolved_if_count(source),
        luraph_lift_forloops.resolved_if_count(source),
        luraph_lift_closures.resolved_if_count(source, instruction, program),
        luraph_lift_close_upvalues.resolved_if_count(source, instruction),
    ]
    # These whole-instruction classifiers are mutually exclusive. Taking the
    # strongest proof avoids double-counting if a future cosmetic normalizer
    # makes two classifiers recognize the same semantic text.
    return max(proofs)


def conditional_metrics(program: Program, semantics) -> dict:
    """Audit raw, proven and residual reachable conditionals fail-closed."""
    unknown_ifs = getattr(semantics, "unknown_ifs", None)
    if not isinstance(unknown_ifs, Mapping):
        return {
            "reachable_dispatcher_conditionals": -1,
            "resolved_dispatcher_conditionals": -1,
            "unresolved_dispatcher_conditionals": -1,
        }
    raw_total = 0
    resolved_total = 0
    for proto in program.protos.values():
        for instruction in proto.instructions:
            raw = unknown_ifs.get(instruction.opcode)
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
                return {
                    "reachable_dispatcher_conditionals": -1,
                    "resolved_dispatcher_conditionals": -1,
                    "unresolved_dispatcher_conditionals": -1,
                }
            resolved = _resolved_if_count(
                program, semantics[instruction.opcode], instruction
            )
            raw_total += raw
            resolved_total += min(raw, resolved)
    return {
        "reachable_dispatcher_conditionals": raw_total,
        "resolved_dispatcher_conditionals": resolved_total,
        "unresolved_dispatcher_conditionals": raw_total - resolved_total,
    }


def unresolved_conditionals(program: Program, semantics) -> int:
    """Compatibility helper returning the independently audited residual."""
    return conditional_metrics(program, semantics)[
        "unresolved_dispatcher_conditionals"
    ]


def _prototype_refs(instruction):
    return {
        value.id
        for value in (
            instruction.e, instruction.p, instruction.o, instruction.h,
            instruction.underscore, instruction.b,
        )
        if isinstance(value, ProtoRef)
    }


def live_prototype_ids(program: Program, semantics):
    """Return proven root-reachable prototypes, or all on a dynamic edge."""
    if not program.protos:
        return set()
    root = 0 if 0 in program.protos else min(program.protos)
    live = {root}
    pending = [root]
    while pending:
        pid = pending.pop()
        proto = program.protos[pid]
        for instruction in proto.instructions:
            refs = _prototype_refs(instruction)
            source = semantics[instruction.opcode]

            # The normal closure family proves its child operand structurally.
            # A missing ProtoRef at such a reachable construction site means
            # the target set is dynamic, so cross-prototype pruning stops.
            from .luraph_lift_closures import infer_closure_shape
            shape = infer_closure_shape(source)
            if shape is not None:
                child = luraph_lift.field_value(instruction, shape.child_field)
                if not isinstance(child, ProtoRef):
                    return set(program.protos)

            # Alternate closure tables index prototypes dynamically. They are
            # uncommon and intentionally remain fail-closed.
            if re.search(r"\bG\s*\[", source) or "__make_closure" in source:
                return set(program.protos)

            for child in refs:
                if child in program.protos and child not in live:
                    live.add(child)
                    pending.append(child)
    return live


def prune_program(program: Program, semantics):
    block_pruned = {}
    removed = 0
    for pid, proto in program.protos.items():
        blocks = luraph_decompiler.build_blocks(proto, semantics)
        reachable = reachable_block_starts(proto, semantics)
        instructions = [
            instruction
            for block in blocks if block.start in reachable
            for instruction in block.instructions
        ]
        removed += len(proto.instructions) - len(instructions)
        block_pruned[pid] = replace(
            proto,
            instruction_count=len(instructions),
            instructions=instructions,
        )
    staged = Program(protos=block_pruned, declared_count=program.declared_count)
    live = live_prototype_ids(staged, semantics)
    protos = {pid: proto for pid, proto in block_pruned.items() if pid in live}
    removed += sum(
        len(proto.instructions)
        for pid, proto in block_pruned.items() if pid not in live
    )
    return Program(protos=protos, declared_count=len(protos)), removed


def render_program(program, semantics):
    if _ORIGINAL_RENDER is None:
        raise luraph_decompiler.DecompileError(
            "reachability renderer is unavailable"
        )
    pruned, removed = prune_program(program, semantics)
    source, metrics = _ORIGINAL_RENDER(pruned, semantics)
    metrics = dict(metrics)
    metrics["captured_instructions"] = program.instruction_count
    metrics["reachable_instructions"] = pruned.instruction_count
    metrics["unreachable_instructions_removed"] = removed
    metrics["captured_prototypes"] = len(program.protos)
    metrics["reachable_prototypes"] = len(pruned.protos)
    metrics["unreachable_prototypes_removed"] = len(program.protos) - len(pruned.protos)
    metrics.update(conditional_metrics(pruned, semantics))
    # Preserve the established top-level metric as the capture total. The
    # clean ratio remains scoped to emitted reachable instructions.
    metrics["instructions"] = program.instruction_count
    metrics["prototypes"] = len(program.protos)
    return source, metrics


def install() -> None:
    global _INSTALLED, _ORIGINAL_RENDER
    if _INSTALLED:
        return
    _ORIGINAL_RENDER = luraph_decompiler.render_program
    luraph_decompiler.render_program = render_program
    _INSTALLED = True
