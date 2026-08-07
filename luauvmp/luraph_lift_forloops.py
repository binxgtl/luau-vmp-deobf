"""Lift exact public-v14.7 numeric-for state machines.

Luraph keeps numeric-for execution state in dispatcher scratch locals and a
linked table.  Slot numbers and scratch names vary by build, so this pass proves
roles from the complete def-use shape instead of assuming one state layout.
"""
from __future__ import annotations

import re

from . import luraph_decompiler, luraph_lift


_INSTALLED = False
_ORIGINAL_DECOMPILE = None
_ID = r"[A-Za-z_]\w*"
_FIELD = r"[EpoH_B]"
_NUMBER = r"\d+(?:\.0)?"


def _text(source: str) -> str:
    text = luraph_lift.compact(source).rstrip(";")
    # These parentheses are purely grouping around scratch atoms/comparisons.
    # Do not touch calls, arithmetic expressions, constructors, or indexing.
    for _ in range(3):
        updated = re.sub(r"\(([A-Za-z_]\w*\[" + _NUMBER + r"\])\)", r"\1", text)
        updated = re.sub(r"\(([A-Za-z_]\w*)\)", r"\1", updated)
        updated = re.sub(
            r"\(([A-Za-z_]\w*)(<=|>=)([A-Za-z_]\w*)\)", r"\1\2\3", updated
        )
        if updated == text:
            break
        text = updated

    # Be robust when this classifier is called without the dead-prefix compact
    # wrapper installed.  Only discard one leading scalar local when its name is
    # provably absent from the remaining semantic body.
    prefix = re.match(
        r"^local(?P<name>" + _ID + r")=(?:-?\d+(?:\.\d+)?|nil|true|false);",
        text,
    )
    if prefix is not None:
        remainder = text[prefix.end():]
        name = prefix.group("name")
        if re.search(r"\b" + re.escape(name) + r"\b", remainder) is None:
            text = remainder
    return text


def _balanced(expr: str) -> str:
    return r"(?:\(" + expr + r"\)|" + expr + r")"


def _state_entries(table_text: str):
    if not (table_text.startswith("{") and table_text.endswith("}")):
        return None
    entries = []
    for part in table_text[1:-1].split(","):
        match = re.fullmatch(r"\[(" + _NUMBER + r")\]=(" + _ID + r")", part)
        if match is None:
            return None
        entries.append((int(float(match.group(1))), match.group(2)))
    if len(entries) != 4 or len({key for key, _value in entries}) != 4:
        return None
    return entries


def _classify_prep(text: str):
    match = re.fullmatch(
        r"(?P<state>" + _ID + r")=(?:\((?P<table_p>\{[^{}]+\})\)|(?P<table_u>\{[^{}]+\}));"
        r"(?P<base>" + _ID + r")=@(?P<base_field>" + _FIELD + r");"
        r"(?P<step>" + _ID + r")="
        + _balanced(r"R\[(?P=base)\+2(?:\.0)?\]\+0(?:\.0)?") + r";"
        r"(?P<limit>" + _ID + r")="
        + _balanced(r"R\[(?P=base)\+1(?:\.0)?\]\+0(?:\.0)?") + r";"
        r"(?P<index>" + _ID + r")="
        + _balanced(r"R\[(?P=base)\]-(?P=step)") + r";"
        r"pc=@(?P<target_field>" + _FIELD + r")",
        text,
    )
    if match is None:
        return None
    fields = match.groupdict()
    entries = _state_entries(fields["table_p"] or fields["table_u"])
    if entries is None:
        return None
    roles = [fields["state"], fields["index"], fields["limit"], fields["step"]]
    if len(set(roles)) != 4:
        return None
    if sorted(value for _key, value in entries) != sorted(roles):
        return None
    fields["state_slots"] = {value: key for key, value in entries}
    return "prep", fields


def _classify_restore(text: str):
    match = re.fullmatch(
        r"(?P<index>" + _ID + r")=(?P<state>" + _ID + r")\[(?P<index_slot>" + _NUMBER + r")\];"
        r"(?P<limit>" + _ID + r")=(?P=state)\[(?P<limit_slot>" + _NUMBER + r")\];"
        r"(?P<step>" + _ID + r")=(?P=state)\[(?P<step_slot>" + _NUMBER + r")\];"
        r"(?P=state)=(?P=state)\[(?P<state_slot>" + _NUMBER + r")\]",
        text,
    )
    if match is None:
        return None
    fields = match.groupdict()
    if len({fields["index"], fields["limit"], fields["step"], fields["state"]}) != 4:
        return None
    slots = {
        int(float(fields["index_slot"])), int(float(fields["limit_slot"])),
        int(float(fields["step_slot"])), int(float(fields["state_slot"])),
    }
    if len(slots) != 4:
        return None
    return "restore", fields


def _classify_loop(text: str):
    prefix = (
        r"(?P<flag>" + _ID + r")=false;"
        r"(?P<index>" + _ID + r")\+=(?P<step>" + _ID + r");"
    )
    suffix = (
        r"ifnot(?P=flag)thenelse"
        r"R\[@(?P<base_field>" + _FIELD + r")\+3(?:\.0)?\]=(?P=index);"
        r"pc=@(?P<target_field>" + _FIELD + r");end"
    )
    # Equivalent signed-step spellings used by different randomized builds.
    patterns = (
        prefix
        + r"ifnot\((?P=step)<=0(?:\.0)?\)then"
          r"(?P=flag)=(?P=index)<=(?P<limit>" + _ID + r");"
          r"else(?P=flag)=(?P=index)>=(?P=limit);end"
        + suffix,
        prefix
        + r"if(?P=step)<=0(?:\.0)?then"
          r"(?P=flag)=(?P=index)>=(?P<limit>" + _ID + r");"
          r"else(?P=flag)=(?P=index)<=(?P=limit);end"
        + suffix,
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, text)
        if match is None:
            continue
        fields = match.groupdict()
        if len({fields["flag"], fields["index"], fields["step"], fields["limit"]}) != 4:
            return None
        return "loop", fields
    return None


def classify(source: str):
    """Return ``(kind, fields)`` for a fully proven numeric-for operation."""
    text = _text(source)
    return _classify_prep(text) or _classify_restore(text) or _classify_loop(text)


def resolved_if_count(source: str) -> int:
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
            source = source.replace(old, _replacement(kind, fields, ins, next_pc), 1)
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
