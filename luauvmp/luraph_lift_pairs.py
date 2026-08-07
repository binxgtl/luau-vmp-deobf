"""Lift exact adjacent public-v14.7 virtual-instruction pairs.

Some builds split one logical VM operation across two opcode slots: the first
copies captured start/end operands into randomized dispatcher scratch locals,
and the immediately following opcode consumes those same locals to clear the
register range. A single-instruction lifter cannot prove that def-use chain.

Pairs are considered only inside one basic block, which proves the second
instruction is not an independent branch target. The wrapper then replaces only
the exact fallback spans reconstructed by the backend's own ``_raw`` helper. If
the rendered source differs from that expected shape, the transformation fails
closed instead of editing approximate text.
"""
from __future__ import annotations

import re

from . import luraph_decompiler, luraph_lift

_INSTALLED = False
_ORIGINAL_DECOMPILE = None
_FIELD = "[EpoH_B]"
_ID = r"[A-Za-z_]\w*"


def clean_pair(source_a, ins_a, source_b, ins_b):
    first = luraph_lift.compact(source_a).rstrip(";")
    second = luraph_lift.compact(source_b).rstrip(";")

    init = re.fullmatch(
        r"(?P<lo>" + _ID + r")=@(?P<start>" + _FIELD + r");"
        r"(?P<hi>" + _ID + r")=@(?P<stop>" + _FIELD + r")",
        first,
    )
    if init is None:
        return None

    lo = re.escape(init.group("lo"))
    hi = re.escape(init.group("hi"))
    clear = re.fullmatch(
        r"for(?P<idx>" + _ID + r")=" + lo + r"," + hi
        + r"(?:,1(?:\.0)?)?do"
        r"(?P<table>" + _ID + r")=R;"
        r"(?P<key>" + _ID + r")=(?P=idx);"
        r"(?P=idx)=nil;"
        r"(?P=table)\[(?P=key)\]=(?P=idx);?end",
        second,
    )
    if clear is None:
        return None

    start = luraph_lift.value_expr(
        luraph_lift.field_value(ins_a, init.group("start"))
    )
    stop = luraph_lift.value_expr(
        luraph_lift.field_value(ins_a, init.group("stop"))
    )
    return "for __i = %s, %s do R[__i] = nil end" % (start, stop)


def _span(marker, pc_line, raw_lines):
    lines = [marker]
    if pc_line is not None:
        lines.append(pc_line)
    lines.extend(raw_lines)
    return "\n".join(lines)


def _candidate_pairs(proto, semantics):
    for block in luraph_decompiler.build_blocks(proto, semantics):
        pos = 0
        while pos + 1 < len(block.instructions):
            first, second = block.instructions[pos], block.instructions[pos + 1]
            source_a, source_b = semantics[first.opcode], semantics[second.opcode]
            if (luraph_lift.decode_branch(source_a, first) is not None
                    or luraph_lift.return_expression(source_a, first) is not None
                    or luraph_lift.decode_branch(source_b, second) is not None
                    or luraph_lift.return_expression(source_b, second) is not None):
                pos += 1
                continue
            if (luraph_lift.clean_statement(source_a, first) is not None
                    or luraph_lift.clean_statement(source_b, second) is not None):
                pos += 1
                continue
            lifted = clean_pair(source_a, first, source_b, second)
            if lifted is not None:
                next_after_second = (
                    block.instructions[pos + 2].pc
                    if pos + 2 < len(block.instructions)
                    else block.fallthrough
                )
                yield first, second, next_after_second, lifted
                pos += 2
            else:
                pos += 1


def decompile_proto(proto, semantics, prepared):
    source, metrics = _ORIGINAL_DECOMPILE(proto, semantics, prepared)
    replacements = 0
    for first, second, next_pc, lifted in _candidate_pairs(proto, semantics):
        marker_a = "            -- pc=%d opcode=%d" % (first.pc, first.opcode)
        marker_b = "            -- pc=%d opcode=%d" % (second.pc, second.opcode)
        raw_a = luraph_decompiler._indent(luraph_decompiler._raw(first, prepared))
        raw_b = luraph_decompiler._indent(luraph_decompiler._raw(second, prepared))

        old_a = _span(marker_a, "            pc = %d" % second.pc, raw_a)
        new_a = marker_a
        old_b = _span(
            marker_b,
            ("            pc = %d" % next_pc) if next_pc is not None else None,
            raw_b,
        )
        new_b = _span(
            marker_b,
            ("            pc = %d" % next_pc) if next_pc is not None else None,
            luraph_decompiler._indent(lifted),
        )

        if source.count(old_a) != 1 or source.count(old_b) != 1:
            raise luraph_decompiler.DecompileError(
                "adjacent pair fallback span changed for proto %d pcs %d/%d"
                % (proto.id, first.pc, second.pc)
            )
        source = source.replace(old_a, new_a, 1).replace(old_b, new_b, 1)
        replacements += 1

    if not replacements:
        return source, metrics
    metrics = dict(metrics)
    metrics["fallback_instructions"] -= replacements * 2
    metrics["clean_instructions"] += replacements * 2
    metrics["paired_instructions"] = metrics.get("paired_instructions", 0) + replacements * 2
    return source, metrics


def install() -> None:
    global _INSTALLED, _ORIGINAL_DECOMPILE
    if _INSTALLED:
        return
    _ORIGINAL_DECOMPILE = luraph_decompiler.decompile_proto
    luraph_decompiler.decompile_proto = decompile_proto
    luraph_lift.clean_pair = clean_pair
    _INSTALLED = True
