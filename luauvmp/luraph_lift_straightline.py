"""Emit exact straight-line dispatcher micro-operations as executable Luau.

Some Luraph v14.7 opcodes are not standalone source-level instructions: they
only update persistent dispatcher scratch locals that a later opcode consumes.
Quoting those operations as semantic fallbacks loses the state edge and forces
large families of otherwise-known instructions to remain unresolved.

This pass is deliberately narrow.  It accepts only semantic bodies composed of
assignments/indexing/arithmetic over the decompiler's declared scratch locals
and register operands.  Control flow, calls, helpers, environment/upvalue
state, varargs, locals, and any unknown identifier fail closed.  The exact
sample-local semantic body is emitted; no operation is guessed or discarded.
"""
from __future__ import annotations

import re

from . import luraph_decompiler


_INSTALLED = False
_ORIGINAL_DECOMPILE = None

# Every name here is either a decompiler-declared persistent VM scratch local or
# a canonical operand/register name that is substituted before source emission.
_SCRATCH = {
    "M", "V", "h", "r", "o", "L", "z", "Y", "W", "n", "T", "S",
    "N", "g", "K", "C", "Z", "e", "m", "O", "U", "F", "J", "d",
    "b", "H", "X", "y", "t", "a", "i", "R", "c", "u",
}
_OPERANDS = {"E", "p", "o", "H", "_"}
_SAFE_GLOBALS = {
    "bit32", "string",
    "rshift", "lrotate", "bor", "countrz", "bxor", "band", "bnot",
    "lshift", "countlz", "rrotate", "unpack",
}
_FORBIDDEN_NAMES = {"A", "B", "I", "P", "q", "j", "game", "workspace", "require"}
_FORBIDDEN_KEYWORDS = re.compile(
    r"\b(?:if|then|else|elseif|for|while|repeat|until|function|return|break|continue|local|do|end)\b"
)
_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")


def is_proven_straightline(source: str) -> bool:
    """Whether ``source`` is an exact side-effect-bounded scratch micro-op."""
    if not source.strip() or _FORBIDDEN_KEYWORDS.search(source):
        return False
    if re.search(r"\b(?:A|B|I|P|q|j)\s*\[", source):
        return False
    # Reject all calls, including parenthesized callees such as ``(M)()``.
    if re.search(r"[A-Za-z_]\w*\s*\(", source) or re.search(r"\)\s*\(", source):
        return False
    # A direct PC write is control flow and belongs to the CFG lifter.
    stripped_operands = re.sub(r"[EpoH_B]\s*\[\s*u\s*\]", "@operand", source)
    if re.search(r"\bu\s*(?:=|\+=|-=|\*=|/=|//=|%=|\^=)", stripped_operands):
        return False

    allowed = _SCRATCH | _OPERANDS | _SAFE_GLOBALS | {"true", "false", "nil"}
    for match in _IDENTIFIER.finditer(source):
        name = match.group(0)
        if name in _FORBIDDEN_NAMES:
            return False
        if name not in allowed:
            return False
    return True


def _normalize_emitted(raw: str) -> str:
    """Remove only cosmetic parentheses that can make Luau lvalues awkward."""
    text = raw
    for _ in range(3):
        updated = re.sub(r"\(([A-Za-z_]\w*)\)\s*\[", r"\1[", text)
        updated = re.sub(r"\(([A-Za-z_]\w*)\)", r"\1", updated)
        if updated == text:
            break
        text = updated
    return text


def _span(marker, pc_line, raw_lines):
    lines = [marker]
    if pc_line is not None:
        lines.append(pc_line)
    lines.extend(raw_lines)
    return "\n".join(lines)


def decompile_proto(proto, semantics, prepared):
    source, metrics = _ORIGINAL_DECOMPILE(proto, semantics, prepared)
    replacements = 0
    for block in luraph_decompiler.build_blocks(proto, semantics):
        for pos, ins in enumerate(block.instructions):
            semantic = semantics[ins.opcode]
            if not is_proven_straightline(semantic):
                continue
            # Do not interfere with instructions already lifted structurally by
            # an earlier layer in the composed backend.
            marker = "            -- pc=%d opcode=%d" % (ins.pc, ins.opcode)
            next_pc = (block.instructions[pos + 1].pc
                       if pos + 1 < len(block.instructions) else block.fallthrough)
            raw_lines = luraph_decompiler._indent(luraph_decompiler._raw(ins, prepared))
            old = _span(
                marker,
                ("            pc = %d" % next_pc) if next_pc is not None else None,
                raw_lines,
            )
            if source.count(old) == 0:
                continue
            if source.count(old) != 1:
                raise luraph_decompiler.DecompileError(
                    "straight-line fallback span is ambiguous for proto %d pc %d"
                    % (proto.id, ins.pc)
                )
            emitted = _normalize_emitted(luraph_decompiler._raw(ins, prepared))
            new_lines = [marker]
            if next_pc is not None:
                new_lines.append("            pc = %d" % next_pc)
            new_lines.extend(luraph_decompiler._indent(emitted))
            source = source.replace(old, "\n".join(new_lines), 1)
            replacements += 1

    if not replacements:
        return source, metrics
    metrics = dict(metrics)
    metrics["fallback_instructions"] -= replacements
    metrics["clean_instructions"] += replacements
    metrics["straightline_instructions"] = (
        metrics.get("straightline_instructions", 0) + replacements
    )
    return source, metrics


def install() -> None:
    global _INSTALLED, _ORIGINAL_DECOMPILE
    if _INSTALLED:
        return
    _ORIGINAL_DECOMPILE = luraph_decompiler.decompile_proto
    luraph_decompiler.decompile_proto = decompile_proto
    _INSTALLED = True
