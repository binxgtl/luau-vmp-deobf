"""Lift exact multi-statement public-v14.7 instruction sequences.

These patterns describe one virtual instruction but use randomized temporary
locals inside the Luraph dispatcher. Backreferences prove each temporary's
complete def-use chain before the sequence is collapsed to direct register code.
No partial sequence is accepted.
"""
from __future__ import annotations

import re

from . import luraph_lift

_INSTALLED = False
_ORIGINAL_CLEAN = None
_FIELD = "[EpoH_B]"
_ID = r"[A-Za-z_]\w*"
_SAFE_HELPER = re.compile(
    r"(?:bit32\.(?:band|bnot|bor|bxor|countlz|countrz|lrotate|lshift|rrotate|rshift)"
    r"|math\.(?:ceil|floor|modf|pi)"
    r"|string\.(?:byte|len|packsize|unpack))"
)


def _value(ins, field: str) -> str:
    return luraph_lift.value_expr(luraph_lift.field_value(ins, field))


def _reg(ins, field: str) -> str:
    return luraph_lift.reg_expr(luraph_lift.field_value(ins, field))


def _integral_slot(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _helper_entries(text: str):
    """Parse only the exact literal produced by nested-helper recovery."""
    entries = {}
    if not text:
        return entries
    for item in text.split(","):
        match = re.fullmatch(
            r"\[(?P<slot>\d+)\]=(?P<name>" + _SAFE_HELPER.pattern + r")",
            item,
        )
        if match is None:
            return None
        slot = int(match.group("slot"))
        if slot in entries:
            return None
        entries[slot] = match.group("name")
    return entries


def clean_statement(source, ins):
    existing = _ORIGINAL_CLEAN(source, ins)
    if existing is not None:
        return existing
    text = luraph_lift.compact(source).rstrip(";")

    # A randomized helper table has already been converted to an explicit pure
    # Luau literal by luraph_nested_helper_literals. Select its exact entry using
    # the captured operand for this instruction. Unknown/missing slots fail
    # closed instead of falling back to a guessed helper.
    match = re.fullmatch(
        r"R\[@(?P<dst>" + _FIELD + r")\]=\(\{(?P<entries>[^{}]+)\}\)"
        r"\[@(?P<src>" + _FIELD + r")\]",
        text,
    )
    if match:
        entries = _helper_entries(match.group("entries"))
        slot = _integral_slot(luraph_lift.field_value(ins, match.group("src")))
        if entries is not None and slot in entries:
            return "%s = %s" % (_reg(ins, match.group("dst")), entries[slot])

    # base = operand; object = R[source]
    # R[base + 1] = object; R[base] = object[key]
    match = re.fullmatch(
        r"(?P<base>" + _ID + r")=@(?P<base_field>" + _FIELD + r");"
        r"(?P<object>" + _ID + r")=R\[@(?P<object_field>" + _FIELD + r")\];"
        r"R\[(?P=base)\+1(?:\.0)?\]=(?P=object);"
        r"R\[(?P=base)\]=\(?(?P=object)\[@(?P<key_field>" + _FIELD + r")\]\)?",
        text,
    )
    if match:
        base = _value(ins, match.group("base_field"))
        obj = _reg(ins, match.group("object_field"))
        key = _value(ins, match.group("key_field"))
        return "R[%s + 1] = %s; R[%s] = %s[%s]" % (
            base, obj, base, obj, key,
        )

    # Direct two-level environment/upvalue indexing.
    match = re.fullmatch(
        r"R\[@(?P<dst>" + _FIELD + r")\]=I\[@(?P<a>" + _FIELD
        + r")\]\[@(?P<b>" + _FIELD + r")\]",
        text,
    )
    if match:
        return "%s = I[%s][%s]" % (
            _reg(ins, match.group("dst")),
            _value(ins, match.group("a")),
            _value(ins, match.group("b")),
        )

    # tmp = I[key]; R[dst] = tmp[2][tmp[1]]
    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=I\[@(?P<key>" + _FIELD + r")\];"
        r"R\[@(?P<dst>" + _FIELD + r")\]=(?P=tmp)\[2(?:\.0)?\]"
        r"\[(?P=tmp)\[1(?:\.0)?\]\]",
        text,
    )
    if match:
        key = _value(ins, match.group("key"))
        return "%s = I[%s][2][I[%s][1]]" % (
            _reg(ins, match.group("dst")), key, key,
        )

    return None


def install() -> None:
    global _INSTALLED, _ORIGINAL_CLEAN
    if _INSTALLED:
        return
    _ORIGINAL_CLEAN = luraph_lift.clean_statement
    luraph_lift.clean_statement = clean_statement
    _INSTALLED = True
