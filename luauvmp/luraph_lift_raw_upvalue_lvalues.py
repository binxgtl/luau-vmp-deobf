"""Lift the two parenthesized raw-upvalue lvalue spellings used by v14.7.

``luraph_lift_sequences`` handles the equivalent unparenthesized raw-cell
operations.  Luau permits grouping around the table expression on the left hand
side, and randomized public dispatchers use both spellings.  Keep the extension
separate and exact instead of normalizing arbitrary lvalues globally.
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

    # tmp = I[key]; (tmp[2][tmp[1]])[R[index]] = R[src]
    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=I\[@(?P<key>" + _FIELD + r")\];"
        r"\((?P=tmp)\[2(?:\.0)?\]\[(?P=tmp)\[1(?:\.0)?\]\]\)"
        r"\[R\[@(?P<index>" + _FIELD + r")\]\]=R\[@(?P<src>"
        + _FIELD + r")\]",
        text,
    )
    if match:
        key = _value(ins, match.group("key"))
        return "I[%s][2][I[%s][1]][%s] = %s" % (
            key, key, _reg(ins, match.group("index")),
            _reg(ins, match.group("src")),
        )

    # tmp = I[key]; (tmp[2])[tmp[1]] = R[src]
    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=I\[@(?P<key>" + _FIELD + r")\];"
        r"\((?P=tmp)\[2(?:\.0)?\]\)\[(?P=tmp)\[1(?:\.0)?\]\]"
        r"=R\[@(?P<src>" + _FIELD + r")\]",
        text,
    )
    if match:
        key = _value(ins, match.group("key"))
        return "I[%s][2][I[%s][1]] = %s" % (
            key, key, _reg(ins, match.group("src")),
        )
    return None


def install() -> None:
    global _INSTALLED, _ORIGINAL_CLEAN
    if _INSTALLED:
        return
    _ORIGINAL_CLEAN = luraph_lift.clean_statement
    luraph_lift.clean_statement = clean_statement
    _INSTALLED = True
