"""Lift exact public-v14.7 numeric-for state machines.

Luraph keeps numeric-for execution state in dispatcher scratch locals and a
linked stack.  The three relevant virtual operations are split into:

* FORPREP: save the enclosing loop state, load init/limit/step, and jump;
* FORRESTORE: restore the enclosing state after an inner loop; and
* FORLOOP: increment, test the signed bound, publish the visible loop value,
  and jump back when the loop continues.

The scratch variable names are randomized.  Recognition therefore uses exact
backreferences across every def/use in the operation.  Rewriting is also
fail-closed against the exact fallback span emitted by the decompiler.
"""
from __future__ import annotations

import re

from . import luraph_decompiler, luraph_lift


_INSTALLED = False
_ORIGINAL_DECOMPILE = None
_ID = r"[A-Za-z_]\w*"
_FIELD = r"[EpoH_B]"


def _text(source: str) -> str:
    return luraph_lift.compact(source).rstrip(";")


def classify(source: str):
    """Return ``(kind, fields)`` for a fully proven numeric-for operation."""
    text = _text(source)

    match = re.fullmatch(
        r"(?P<state>" + _ID + r")=\(\{\[5\]=(?P<index>" + _ID
        + r"),\[2\]=(?P=state),\[1\]=(?P<step>" + _ID
        + r"),\[4\]=(?P<limit>" + _ID + r")\}\);"
        r"(?P<base>" + _ID + r")=@(?P<base_field>" + _FIELD + r");"
        r"(?P=step)=\(R\[(?P=base)\+2(?:\.0)?\]\+0(?:\.0)?\);"
        r"(?P=limit)=R\[(?P=base)\+1(?:\.0)?\]\+0(?:\.0)?;"
        r"(?P=index)=R\[(?P=base)\]-(?P=step);"
        r"pc=@(?P<target_field>" + _FIELD + r")",
        text,
    )
    if match:
        return "prep", match.groupdict()

    match = re.fullmatch(
        r"(?P<index>" + _ID + r")=\((?P<state>" + _ID + r")\[5(?:\.0)?\]\);"
        r"(?P<limit>" + _ID + r")=\((?P=state)\[4(?:\.0)?\]\);"
        r"(?P<step>" + _ID + r")=\((?P=state)\[1(?:\.0)?\]\);"
        r"(?P=state)=\((?P=state)\[2(?:\.0)?\]\)",
        text,
    )
    if match:
        return "restore", match.groupdict()

    match = re.fullmatch(
        r"(?P<flag>" + _ID + r")=false;"
        r"(?P<index>" + _ID + r")\+=(?P<step>" + _ID + r");"
        r"ifnot\((?P=step)<=0(?:\.0)?\)then"
        r"(?P=flag)=\((?P=index)<=(?P<limit>" + _ID + r")\);"
        r"else(?P=flag)=\((?P=index)>=(?P=limit)\);end"
        r"ifnot\((?P=flag)\)thenelse"
        r"R\[@(?P<base_field>" + _FIELD + r")\+3(?:\.0)?\]="
        r"(?:\((?P=index)\)|(?P=index));"
        r"pc=@(?P<target_field>" + _FIELD + r");end",
        text,
    )
    if match:
        return "loop", match.groupdict()
    return None


def resolved_if_count(source: str) -> int:
    """Number of conditionals fully discharged by this semantic recognizer."""
    hit = classify(source)
    return 2 if hit is not None and hit[0] == "loop" else 0


def _value(ins, field: str) -> str:
    return luraph_lift.value_expr(luraph_lift.field_value(ins, field))


def _span(marker, pc_line, raw_lines):
    lines = [marker]
    if pc_line is not None:
        lines.append(pc_line)
    lines.extend(raw_lines)
    return "\n".join(lines)


def _replacement(kind, fields, ins, next_pc):
    marker = "            -- pc=%d opcode=%d" % (ins.pc, ins.opcode)
    lines = [marker]
    if kind == "prep":
        base = _value(ins, fields["base_field"])
        target = _value(ins, fields["target_field"])
        lines.extend([
            "            __for_state = { __for_index, __for_limit, __for_step, __for_state }",
            "            __for_step = R[%s + 2] + 0" % base,
            "            __for_limit = R[%s + 1] + 0" % base,
            "            __for_index = R[%s] - __for_step" % base,
            "            pc = %s" % target,
            "            continue",
        ])
        return "\n".join(lines)

    if kind == "restore":
        if next_pc is not None:
            lines.append("            pc = %d" % next_pc)
        lines.extend([
            "            __for_index = __for_state[1]",
            "            __for_limit = __for_state[2]",
            "            __for_step = __for_state[3]",
            "            __for_state = __for_state[4]",
        ])
        return "\n".join(lines)

    if kind == "loop":
        base = _value(ins, fields["base_field"])
        target = _value(ins, fields["target_field"])
        lines.extend([
            "            __for_index += __for_step",
            "            local __for_continue",
            "            if not (__for_step <= 0) then",
            "                __for_continue = (__for_index <= __for_limit)",
            "            else",
            "                __for_continue = (__for_index >= __for_limit)",
            "            end",
            "            if __for_continue then",
            "                R[%s + 3] = __for_index" % base,
            "                pc = %s" % target,
            "            else",
            ("                pc = %d" % next_pc) if next_pc is not None else "                return",
            "            end",
            "            continue",
        ])
        return "\n".join(lines)
    raise AssertionError(kind)


def decompile_proto(proto, semantics, prepared):
    source, metrics = _ORIGINAL_DECOMPILE(proto, semantics, prepared)
    replacements = 0
    kinds = {"prep": 0, "restore": 0, "loop": 0}

    for block in luraph_decompiler.build_blocks(proto, semantics):
        for pos, ins in enumerate(block.instructions):
            hit = classify(semantics[ins.opcode])
            if hit is None:
                continue
            kind, fields = hit
            next_pc = (block.instructions[pos + 1].pc
                       if pos + 1 < len(block.instructions) else block.fallthrough)
            marker = "            -- pc=%d opcode=%d" % (ins.pc, ins.opcode)
            raw = luraph_decompiler._indent(luraph_decompiler._raw(ins, prepared))
            old = _span(
                marker,
                ("            pc = %d" % next_pc) if next_pc is not None else None,
                raw,
            )
            if source.count(old) != 1:
                raise luraph_decompiler.DecompileError(
                    "numeric-for fallback span changed for proto %d pc %d"
                    % (proto.id, ins.pc)
                )
            source = source.replace(
                old, _replacement(kind, fields, ins, next_pc), 1
            )
            replacements += 1
            kinds[kind] += 1

    if not replacements:
        return source, metrics
    declaration = "    local Z = -1\n"
    if source.count(declaration) != 1:
        raise luraph_decompiler.DecompileError(
            "numeric-for declaration anchor changed for proto %d" % proto.id
        )
    source = source.replace(
        declaration,
        declaration + "    local __for_index, __for_limit, __for_step, __for_state\n",
        1,
    )
    metrics = dict(metrics)
    metrics["fallback_instructions"] -= replacements
    metrics["clean_instructions"] += replacements
    metrics["numeric_for_instructions"] = metrics.get("numeric_for_instructions", 0) + replacements
    metrics["numeric_for_prep"] = metrics.get("numeric_for_prep", 0) + kinds["prep"]
    metrics["numeric_for_restore"] = metrics.get("numeric_for_restore", 0) + kinds["restore"]
    metrics["numeric_for_loop"] = metrics.get("numeric_for_loop", 0) + kinds["loop"]
    return source, metrics


def install() -> None:
    global _INSTALLED, _ORIGINAL_DECOMPILE
    if _INSTALLED:
        return
    _ORIGINAL_DECOMPILE = luraph_decompiler.decompile_proto
    luraph_decompiler.decompile_proto = decompile_proto
    _INSTALLED = True
