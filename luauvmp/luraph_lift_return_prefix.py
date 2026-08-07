"""Lift pure operand-to-scratch prefixes before terminal returns.

Some public v14.7 superinstructions stage one or two operand values in persistent
scratch locals and immediately return them.  The base return lifter correctly
extracts the terminal expression but intentionally rejects a non-empty prefix.
This pass accepts only a complete sequence of simple ``scratch = field[pc]``
assignments, then evaluates the original return inside a tail-called IIFE so Lua
multi-return behavior is preserved exactly.
"""
from __future__ import annotations

from typing import List, Optional, Tuple
import re

from . import luraph_decompiler, luraph_lift
from .luraph_full import Instruction


_INSTALLED = False
_ORIGINAL_RETURN = None
_ORIGINAL_RAW = None
_ID = r"[A-Za-z_]\w*"
_FIELD = r"[EpoH_B]"
_ALLOWED = {
    "M", "V", "h", "r", "z", "Y", "W", "n", "T", "S", "N", "g",
    "K", "C", "Z", "e", "m", "O", "U", "F", "J", "d", "b", "y",
    "t", "a", "i", "w", "l", "Q", "G", "P",
    "__s_A", "__s_I", "__s_E", "__s_p", "__s_o", "__s_H", "__s__",
    "__s_B", "__s_L", "__s_X", "__s_c", "__s_u", "__s_R",
}


def _prefix(source: str, ins: Instruction) -> Optional[List[str]]:
    match = re.search(r"\breturn(?:\s+[^;]*)?;\s*$", source, re.S)
    if match is None:
        return None
    prefix = source[:match.start()].strip()
    if not prefix:
        return None
    statements = [part.strip() for part in prefix.split(";") if part.strip()]
    if not statements or len(statements) > 4:
        return None
    output: List[str] = []
    for statement in statements:
        item = re.fullmatch(
            r"(?:local\s+)?(?P<name>" + _ID + r")\s*=\s*\(?\s*"
            r"(?P<field>" + _FIELD + r")\s*\[\s*u\s*\]\s*\)?",
            statement,
            re.S,
        )
        if item is None or item.group("name") not in _ALLOWED:
            return None
        value = luraph_lift.value_expr(
            luraph_lift.field_value(ins, item.group("field"))
        )
        output.append("%s = %s" % (item.group("name"), value))
    return output


def return_expression(source, ins):
    original = _ORIGINAL_RETURN(source, ins)
    if original is None:
        return None
    prefix = _prefix(source, ins)
    if prefix is None:
        return original
    lines = ["(function()"]
    lines.extend("    " + line for line in prefix)
    lines.append("    return%s" % ((" " + original) if original else ""))
    lines.append("end)()")
    return "\n".join(lines)


def raw_instruction(ins, prepared):
    try:
        source = prepared[ins.opcode][1]
    except (KeyError, TypeError):
        return _ORIGINAL_RAW(ins, prepared)
    if _ORIGINAL_RETURN(source, ins) is not None and _prefix(source, ins) is not None:
        return "return;"
    return _ORIGINAL_RAW(ins, prepared)


def install() -> None:
    global _INSTALLED, _ORIGINAL_RETURN, _ORIGINAL_RAW
    if _INSTALLED:
        return
    _ORIGINAL_RETURN = luraph_lift.return_expression
    _ORIGINAL_RAW = luraph_decompiler._raw
    luraph_lift.return_expression = return_expression
    luraph_decompiler._raw = raw_instruction
    _INSTALLED = True
