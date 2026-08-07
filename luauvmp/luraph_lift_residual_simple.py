"""Lift two exact residual public-v14.7 micro-operations.

These forms remain after helper identity recovery because one ``bit32.bxor``
operand is an immediate typed-IR field rather than a register, and the register
clear opcode preserves two persistent scratch assignments inside its numeric
loop.  Both shapes are complete and side-effect bounded; everything else stays
fail-closed.
"""
from __future__ import annotations

import re

from . import luraph_lift


_INSTALLED = False
_ORIGINAL_CLEAN = None
_FIELD = r"[EpoH_B]"
_ID = r"[A-Za-z_]\w*"
_ALLOWED_SCRATCH = {
    "M", "V", "h", "r", "z", "Y", "W", "n", "T", "S", "N", "g",
    "K", "C", "Z", "e", "m", "O", "U", "F", "J", "d", "b", "y",
    "t", "a", "i", "w", "l", "Q", "G", "P",
    "__s_A", "__s_I", "__s_E", "__s_p", "__s_o", "__s_H", "__s__",
    "__s_B", "__s_L", "__s_X", "__s_c", "__s_u", "__s_R",
}


def _value(ins, field: str) -> str:
    return luraph_lift.value_expr(luraph_lift.field_value(ins, field))


def _reg(ins, field: str) -> str:
    return luraph_lift.reg_expr(luraph_lift.field_value(ins, field))


def clean_statement(source, ins):
    existing = _ORIGINAL_CLEAN(source, ins)
    if existing is not None:
        return existing
    text = luraph_lift.compact(source).rstrip(";")

    # R[dst] = bit32.bxor(R[left], immediate_operand)
    match = re.fullmatch(
        r"R\[@(?P<dst>" + _FIELD + r")\]=bit32\.bxor\("
        r"R\[@(?P<left>" + _FIELD + r")\],@(?P<right>" + _FIELD + r")\)",
        text,
    )
    if match:
        return "%s = bit32.bxor(%s, %s)" % (
            _reg(ins, match.group("dst")),
            _reg(ins, match.group("left")),
            _value(ins, match.group("right")),
        )

    # for loop = start,end do table=R; key=loop; loop=nil; table[key]=loop end
    # The loop variable is lexical, so assigning nil to it is equivalent to the
    # final table write of nil.  Preserve the two persistent scratch assignments
    # (table/key) on every iteration because later VM superinstructions may read
    # their final values.
    match = re.fullmatch(
        r"for(?P<loop>" + _ID + r")=(?P<start>" + _ID + r"),(?P<end>" + _ID
        + r")do(?P<table>" + _ID + r")=R;(?P<key>" + _ID + r")=(?P=loop);"
        r"(?P=loop)=nil;(?P=table)\[(?P=key)\]=(?P=loop);end",
        text,
    )
    if match:
        names = [match.group(name) for name in ("start", "end", "table", "key")]
        if any(name not in _ALLOWED_SCRATCH for name in names):
            return None
        start, end = match.group("start"), match.group("end")
        table, key = match.group("table"), match.group("key")
        return "\n".join([
            "for __clear_i = %s, %s do" % (start, end),
            "    %s = R" % table,
            "    %s = __clear_i" % key,
            "    %s[%s] = nil" % (table, key),
            "end",
        ])
    return None


def install() -> None:
    global _INSTALLED, _ORIGINAL_CLEAN
    if _INSTALLED:
        return
    _ORIGINAL_CLEAN = luraph_lift.clean_statement
    luraph_lift.clean_statement = clean_statement
    _INSTALLED = True
