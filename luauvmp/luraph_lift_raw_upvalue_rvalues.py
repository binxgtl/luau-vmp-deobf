"""Lift grouped raw-upvalue rvalue spellings used by public v14.7.

The core sequence lifter handles the same raw-cell dereference without an outer
pair of grouping parentheses.  Randomized public builds also emit the entire
rvalue as ``(cell[2][cell[1]][R[index]])``.  Accept only that exact proven
backreference shape; arbitrary grouped expressions remain fallbacks.
"""
from __future__ import annotations

import re

from . import luraph_lift


_INSTALLED = False
_ORIGINAL_CLEAN = None
_FIELD = r"[EpoH_B]"
_ID = r"[A-Za-z_]\w*"


def _value(ins, field: str) -> str:
    return luraph_lift.value_expr(luraph_lift.field_value(ins, field))


def _reg(ins, field: str) -> str:
    return luraph_lift.reg_expr(luraph_lift.field_value(ins, field))


def clean_statement(source, ins):
    existing = _ORIGINAL_CLEAN(source, ins)
    if existing is not None:
        return existing
    text = luraph_lift.compact(source).rstrip(";")

    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=I\[@(?P<key>" + _FIELD + r")\];"
        r"R\[@(?P<dst>" + _FIELD + r")\]=\((?P=tmp)\[2(?:\.0)?\]"
        r"\[(?P=tmp)\[1(?:\.0)?\]\]\[R\[@(?P<index>" + _FIELD + r")\]\]\)",
        text,
    )
    if match:
        key = _value(ins, match.group("key"))
        return "%s = I[%s][2][I[%s][1]][%s]" % (
            _reg(ins, match.group("dst")), key, key,
            _reg(ins, match.group("index")),
        )
    return None


def install() -> None:
    global _INSTALLED, _ORIGINAL_CLEAN
    if _INSTALLED:
        return
    _ORIGINAL_CLEAN = luraph_lift.clean_statement
    luraph_lift.clean_statement = clean_statement
    _INSTALLED = True
