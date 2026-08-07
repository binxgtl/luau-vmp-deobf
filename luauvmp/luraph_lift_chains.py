"""Lift proven straight-line dispatcher scratch chains.

Some public Luraph v14.7 builds split one logical register operation across
several virtual opcode slots.  Individual slots only copy values through the
interpreter's persistent scratch locals (for example ``M``, ``h``, ``n`` and
``W``), so a single-instruction lifter cannot safely classify them.

This pass recognizes only exact def-use chains contained in one basic block.
Every scratch read must be defined by the same matched chain and the final
statement must reduce to an ordinary register/upvalue operation.  Branch
boundaries, returns, already-clean instructions, and approximate matches are
left untouched.
"""
from __future__ import annotations

import re

from . import luraph_decompiler, luraph_lift


_INSTALLED = False
_ORIGINAL_DECOMPILE = None
_FIELD = "[EpoH_B]"
_ID = r"[A-Za-z_]\w*"


def _compact(source: str) -> str:
    text = luraph_lift.compact(source).rstrip(";")
    # ``luraph_lift.compact`` deliberately unwraps only canonical operand atoms.
    # Scratch locals are safe to unwrap for these exact straight-line shapes.
    for _ in range(3):
        text = re.sub(r"\(([A-Za-z_]\w*)\)", r"\1", text)
    return text


def _value(ins, field: str) -> str:
    return luraph_lift.value_expr(luraph_lift.field_value(ins, field))


def _reg(ins, field: str) -> str:
    return luraph_lift.reg_expr(luraph_lift.field_value(ins, field))


def _indexed(space: str, ins, field: str) -> str:
    value = _value(ins, field)
    return "%s[%s]" % (space, value)


def _direct_set(items):
    (source_a, ins_a), (source_b, _ins_b) = items
    first = _compact(source_a)
    second = _compact(source_b)
    match = re.fullmatch(
        r"(?P<table>" + _ID + r")=R;"
        r"(?P<index>" + _ID + r")=@(?P<dst>" + _FIELD + r");"
        r"(?P<value>" + _ID + r")=@(?P<src>" + _FIELD + r")",
        first,
    )
    if match is None:
        return None
    if second != "%s[%s]=%s" % (
        match.group("table"), match.group("index"), match.group("value")
    ):
        return None
    return "%s = %s" % (_reg(ins_a, match.group("dst")),
                         _value(ins_a, match.group("src")))


def _nested_set(items):
    (source_a, ins_a), (source_b, ins_b), (source_c, _ins_c) = items
    first, second, third = map(_compact, (source_a, source_b, source_c))
    match = re.fullmatch(
        r"(?P<table>" + _ID + r")=R;"
        r"(?P<index>" + _ID + r")=@(?P<base>" + _FIELD + r");"
        r"(?P=table)=(?P=table)\[(?P=index)\]",
        first,
    )
    if match is None:
        return None
    follow = re.fullmatch(
        re.escape(match.group("index")) + r"=@(?P<key>" + _FIELD + r");"
        r"(?P<value>" + _ID + r")=@(?P<src>" + _FIELD + r")",
        second,
    )
    if follow is None:
        return None
    if third != "%s[%s]=%s" % (
        match.group("table"), match.group("index"), follow.group("value")
    ):
        return None
    return "%s[%s] = %s" % (
        _reg(ins_a, match.group("base")),
        _value(ins_b, follow.group("key")),
        _value(ins_b, follow.group("src")),
    )


def _move_chain(items):
    (source_a, _ins_a), (source_b, ins_b), (source_c, _ins_c), (source_d, _ins_d) = items
    first, second, third, fourth = map(
        _compact, (source_a, source_b, source_c, source_d)
    )
    root = re.fullmatch(r"(?P<table>" + _ID + r")=R", first)
    if root is None:
        return None
    setup = re.fullmatch(
        r"(?P<index>" + _ID + r")=@(?P<dst>" + _FIELD + r");"
        r"(?P<value>" + _ID + r")=R;"
        r"(?P<key>" + _ID + r")=@(?P<src>" + _FIELD + r")",
        second,
    )
    if setup is None:
        return None
    if third != "%s=%s[%s]" % (
        setup.group("value"), setup.group("value"), setup.group("key")
    ):
        return None
    if fourth != "%s[%s]=%s" % (
        root.group("table"), setup.group("index"), setup.group("value")
    ):
        return None
    return "%s = %s" % (_reg(ins_b, setup.group("dst")),
                         _reg(ins_b, setup.group("src")))


def _double_index_chain(items):
    (source_a, ins_a), (source_b, ins_b), (source_c, ins_c), (source_d, _ins_d) = items
    first, second, third, fourth = map(
        _compact, (source_a, source_b, source_c, source_d)
    )
    setup = re.fullmatch(
        r"(?P<table>" + _ID + r")=R;"
        r"(?P<index>" + _ID + r")=@(?P<dst>" + _FIELD + r")",
        first,
    )
    if setup is None:
        return None
    load = re.fullmatch(
        r"(?P<value>" + _ID + r")=(?P<space>R|I);"
        r"(?P<key>" + _ID + r")=@(?P<base>" + _FIELD + r")",
        second,
    )
    if load is None:
        return None
    deref = re.fullmatch(
        re.escape(load.group("value")) + r"=" + re.escape(load.group("value"))
        + r"\[" + re.escape(load.group("key")) + r"\];"
        + re.escape(load.group("key")) + r"=@(?P<key2>" + _FIELD + r");"
        + re.escape(load.group("value")) + r"=" + re.escape(load.group("value"))
        + r"\[" + re.escape(load.group("key")) + r"\]",
        third,
    )
    if deref is None:
        return None
    if fourth != "%s[%s]=%s" % (
        setup.group("table"), setup.group("index"), load.group("value")
    ):
        return None
    base = _indexed(load.group("space"), ins_b, load.group("base"))
    return "%s = %s[%s]" % (
        _reg(ins_a, setup.group("dst")), base, _value(ins_c, deref.group("key2"))
    )


def _single_index_chain(items):
    (source_a, ins_a), (source_b, ins_b), (source_c, _ins_c) = items
    first, second, third = map(_compact, (source_a, source_b, source_c))
    setup = re.fullmatch(
        r"(?P<table>" + _ID + r")=R;"
        r"(?P<index>" + _ID + r")=@(?P<dst>" + _FIELD + r")",
        first,
    )
    if setup is None:
        return None
    load = re.fullmatch(
        r"(?P<value>" + _ID + r")=(?P<space>R|I);"
        r"(?P<key>" + _ID + r")=@(?P<src>" + _FIELD + r");"
        r"(?P=value)=(?P=value)\[(?P=key)\]",
        second,
    )
    if load is None:
        return None
    if third != "%s[%s]=%s" % (
        setup.group("table"), setup.group("index"), load.group("value")
    ):
        return None
    return "%s = %s" % (
        _reg(ins_a, setup.group("dst")),
        _indexed(load.group("space"), ins_b, load.group("src")),
    )


def clean_chain(items):
    """Return one proven high-level statement for an exact scratch chain."""
    if len(items) == 4:
        return _move_chain(items) or _double_index_chain(items)
    if len(items) == 3:
        return _nested_set(items) or _single_index_chain(items)
    if len(items) == 2:
        return _direct_set(items)
    return None


def _candidate_chains(proto, semantics):
    for block in luraph_decompiler.build_blocks(proto, semantics):
        pos = 0
        while pos < len(block.instructions):
            matched = None
            for width in (4, 3, 2):
                if pos + width > len(block.instructions):
                    continue
                window = block.instructions[pos:pos + width]
                items = []
                valid = True
                for ins in window:
                    source = semantics[ins.opcode]
                    if (luraph_lift.decode_branch(source, ins) is not None
                            or luraph_lift.return_expression(source, ins) is not None
                            or luraph_lift.clean_statement(source, ins) is not None):
                        valid = False
                        break
                    items.append((source, ins))
                if not valid:
                    continue
                lifted = clean_chain(items)
                if lifted is not None:
                    matched = (window, lifted)
                    break
            if matched is None:
                pos += 1
                continue
            window, lifted = matched
            next_after = (
                block.instructions[pos + len(window)].pc
                if pos + len(window) < len(block.instructions)
                else block.fallthrough
            )
            yield window, next_after, lifted
            pos += len(window)


def _span(marker, pc_line, raw_lines):
    lines = [marker]
    if pc_line is not None:
        lines.append(pc_line)
    lines.extend(raw_lines)
    return "\n".join(lines)


def decompile_proto(proto, semantics, prepared):
    source, metrics = _ORIGINAL_DECOMPILE(proto, semantics, prepared)
    replacements = 0
    chained = 0
    for window, next_after, lifted in _candidate_chains(proto, semantics):
        old_spans = []
        for index, ins in enumerate(window):
            next_pc = (window[index + 1].pc
                       if index + 1 < len(window) else next_after)
            marker = "            -- pc=%d opcode=%d" % (ins.pc, ins.opcode)
            raw = luraph_decompiler._indent(luraph_decompiler._raw(ins, prepared))
            old_spans.append(_span(
                marker,
                ("            pc = %d" % next_pc) if next_pc is not None else None,
                raw,
            ))

        for old in old_spans:
            if source.count(old) != 1:
                raise luraph_decompiler.DecompileError(
                    "scratch-chain fallback span changed for proto %d pcs %s"
                    % (proto.id, "/".join(str(ins.pc) for ins in window))
                )

        for index, (ins, old) in enumerate(zip(window, old_spans)):
            marker = "            -- pc=%d opcode=%d" % (ins.pc, ins.opcode)
            if index + 1 < len(window):
                new = marker
            else:
                new = _span(
                    marker,
                    ("            pc = %d" % next_after)
                    if next_after is not None else None,
                    luraph_decompiler._indent(lifted),
                )
            source = source.replace(old, new, 1)
        replacements += 1
        chained += len(window)

    if not replacements:
        return source, metrics
    metrics = dict(metrics)
    metrics["fallback_instructions"] -= chained
    metrics["clean_instructions"] += chained
    metrics["chained_instructions"] = metrics.get("chained_instructions", 0) + chained
    metrics["scratch_chains"] = metrics.get("scratch_chains", 0) + replacements
    return source, metrics


def install() -> None:
    global _INSTALLED, _ORIGINAL_DECOMPILE
    if _INSTALLED:
        return
    _ORIGINAL_DECOMPILE = luraph_decompiler.decompile_proto
    luraph_decompiler.decompile_proto = decompile_proto
    luraph_lift.clean_chain = clean_chain
    _INSTALLED = True
