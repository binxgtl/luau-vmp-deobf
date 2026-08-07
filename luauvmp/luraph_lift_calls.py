"""Lift proven call/vararg operations that share the VM's persistent top state.

Public Luraph v14.7 dispatchers randomize scratch names, but their call
operations retain exact def-use shapes.  This pass recognizes those shapes with
backreferences and emits ordinary Luau using one synthetic ``__top`` value.
Unsupported or partially matching call bodies remain explicit fallbacks.
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
    text = _text(source)

    match = re.fullmatch(
        r"(?P<top>" + _ID + r")=@(?P<func_field>" + _FIELD + r");"
        r"R\[(?P=top)\]\(\);(?P=top)-=1",
        text,
    )
    if match:
        return "call0", match.groupdict()

    match = re.fullmatch(
        r"(?P<base>" + _ID + r")=@(?P<base_field>" + _FIELD + r");"
        r"R\[(?P=base)\]\(table\.unpack\(R,(?P=base)\+1,(?P<top>" + _ID + r")\)\);"
        r"(?P=top)=(?P=base)-1",
        text,
    )
    if match:
        return "call_open", match.groupdict()

    match = re.fullmatch(
        r"(?P<base>" + _ID + r")=@(?P<base_field>" + _FIELD + r");"
        r"R\[(?P=base)\]=R\[(?P=base)\]\(table\.unpack\(R,(?P=base)\+1,(?P<top>" + _ID + r")\)\);"
        r"(?P=top)=(?P=base)",
        text,
    )
    if match:
        return "call_one", match.groupdict()

    match = re.fullmatch(
        r"for(?P<index>" + _ID + r")=1,@(?P<count_field>" + _FIELD + r")do"
        r"R\[(?P=index)\]=(?P<varargs>" + _ID + r")\[(?P=index)\];?end",
        text,
    )
    if match:
        return "vararg_copy", match.groupdict()

    # Generic CALL: argument count and requested result count are operands.  A
    # helper packs all returned values as (count, table).  The exact downstream
    # count/table use proves that role, so generated Luau can use table.pack
    # without relying on the randomized helper slot number.
    match = re.fullmatch(
        r"(?P<base>" + _ID + r")=@(?P<base_field>" + _FIELD + r");"
        r"(?P<argc>" + _ID + r")=@(?P<argc_field>" + _FIELD + r");"
        r"(?P<retc>" + _ID + r")=@(?P<retc_field>" + _FIELD + r");"
        r"if(?P=argc)==0thenelse(?P<top>" + _ID + r")=(?P=base)\+(?P=argc)-1;end"
        r"(?P<count>" + _ID + r"),(?P<results>" + _ID + r")=nil;"
        r"if(?P=argc)~=1then"
        r"(?P=count),(?P=results)=A\[(?P<pack_slot>\d+)\]\(R\[(?P=base)\]\(table\.unpack\(R,(?P=base)\+1,(?P=top)\)\)\);"
        r"else(?P=count),(?P=results)=A\[(?P=pack_slot)\]\(R\[(?P=base)\]\(\)\);end"
        r"if(?P=retc)~=1then"
        r"if(?P=retc)==0then(?P=count)=(?P=count)\+(?P=base)-1;(?P=top)=(?P=count);"
        r"else(?P=count)=(?P=base)\+(?P=retc)-2;(?P=top)=(?P=count)\+1;end"
        r"(?P<cursor>" + _ID + r")=0;"
        r"for(?P<loop>" + _ID + r")=(?P=base),(?P=count)do"
        r"(?P=cursor)\+=1;R\[(?P=loop)\]=(?P=results)\[(?P=cursor)\];?end"
        r"else(?P=top)=(?P=base)-1;end",
        text,
    )
    if match:
        return "call_generic", match.groupdict()
    return None


def resolved_if_count(source: str) -> int:
    hit = classify(source)
    return 4 if hit is not None and hit[0] == "call_generic" else 0


def _value(ins, field: str) -> str:
    return luraph_lift.value_expr(luraph_lift.field_value(ins, field))


def _replacement(kind: str, fields, ins, next_pc):
    marker = "            -- pc=%d opcode=%d" % (ins.pc, ins.opcode)
    lines = [marker]
    if next_pc is not None:
        lines.append("            pc = %d" % next_pc)

    if kind == "call0":
        func = _value(ins, fields["func_field"])
        lines.extend([
            "            __top = %s" % func,
            "            R[__top]()",
            "            __top -= 1",
        ])
    elif kind == "call_open":
        base = _value(ins, fields["base_field"])
        lines.extend([
            "            R[%s](table.unpack(R, %s + 1, __top))" % (base, base),
            "            __top = %s - 1" % base,
        ])
    elif kind == "call_one":
        base = _value(ins, fields["base_field"])
        lines.extend([
            "            R[%s] = R[%s](table.unpack(R, %s + 1, __top))" % (base, base, base),
            "            __top = %s" % base,
        ])
    elif kind == "vararg_copy":
        count = _value(ins, fields["count_field"])
        lines.extend([
            "            for __argi = 1, %s do" % count,
            "                R[__argi] = argv[__argi]",
            "            end",
        ])
    elif kind == "call_generic":
        base = _value(ins, fields["base_field"])
        argc = _value(ins, fields["argc_field"])
        retc = _value(ins, fields["retc_field"])
        lines.extend([
            "            local __call_base = %s" % base,
            "            local __call_argc = %s" % argc,
            "            local __call_retc = %s" % retc,
            "            if __call_argc ~= 0 then",
            "                __top = __call_base + __call_argc - 1",
            "            end",
            "            local __call_results",
            "            if __call_argc ~= 1 then",
            "                __call_results = table.pack(R[__call_base](table.unpack(R, __call_base + 1, __top)))",
            "            else",
            "                __call_results = table.pack(R[__call_base]())",
            "            end",
            "            if __call_retc ~= 1 then",
            "                local __call_last",
            "                if __call_retc == 0 then",
            "                    __call_last = __call_results.n + __call_base - 1",
            "                    __top = __call_last",
            "                else",
            "                    __call_last = __call_base + __call_retc - 2",
            "                    __top = __call_last + 1",
            "                end",
            "                local __result_index = 0",
            "                for __reg = __call_base, __call_last do",
            "                    __result_index += 1",
            "                    R[__reg] = __call_results[__result_index]",
            "                end",
            "            else",
            "                __top = __call_base - 1",
            "            end",
        ])
    else:
        raise AssertionError(kind)
    return "\n".join(lines)


def _span(marker, pc_line, raw_lines):
    lines = [marker]
    if pc_line is not None:
        lines.append(pc_line)
    lines.extend(raw_lines)
    return "\n".join(lines)


def decompile_proto(proto, semantics, prepared):
    source, metrics = _ORIGINAL_DECOMPILE(proto, semantics, prepared)
    replacements = 0
    kinds = {}
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
                    "call-state fallback span changed for proto %d pc %d" %
                    (proto.id, ins.pc)
                )
            source = source.replace(old, _replacement(kind, fields, ins, next_pc), 1)
            replacements += 1
            kinds[kind] = kinds.get(kind, 0) + 1

    if not replacements:
        return source, metrics
    anchor = "    local Z = -1\n"
    declaration = "    local __top = 1\n"
    if declaration not in source:
        if source.count(anchor) != 1:
            raise luraph_decompiler.DecompileError(
                "call-state declaration anchor changed for proto %d" % proto.id
            )
        source = source.replace(anchor, anchor + declaration, 1)
    metrics = dict(metrics)
    metrics["fallback_instructions"] -= replacements
    metrics["clean_instructions"] += replacements
    metrics["call_state_instructions"] = metrics.get("call_state_instructions", 0) + replacements
    for kind, count in kinds.items():
        metrics["call_state_" + kind] = metrics.get("call_state_" + kind, 0) + count
    return source, metrics


def install() -> None:
    global _INSTALLED, _ORIGINAL_DECOMPILE
    if _INSTALLED:
        return
    _ORIGINAL_DECOMPILE = luraph_decompiler.decompile_proto
    luraph_decompiler.decompile_proto = decompile_proto
    _INSTALLED = True
