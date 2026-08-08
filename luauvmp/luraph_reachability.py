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

from . import luraph_decompiler, luraph_lift
from .luraph_full import Program, ProtoRef


_INSTALLED = False
_ORIGINAL_RENDER = None


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
