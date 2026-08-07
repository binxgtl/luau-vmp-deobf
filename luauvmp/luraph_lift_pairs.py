"""Lift exact adjacent public-v14.7 virtual-instruction pairs.

Some builds split one logical VM operation across two opcode slots: the first
copies the captured start/end operands into randomized dispatcher scratch locals,
and the immediately following opcode consumes those same locals to clear the
register range.  A single-instruction lifter cannot prove that def-use chain.

The decompiler calls this hook only for two instructions inside the same basic
block, so the second instruction cannot be an independent branch target.  This
module additionally requires exact backreferences across both recovered semantic
bodies; any extra statement or mismatched scratch local fails closed.
"""
from __future__ import annotations

import re

from . import luraph_lift

_INSTALLED = False
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


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    # Accessed dynamically by luraph_decompiler so this late-installed hook does
    # not suffer from the module-level function snapshot issue fixed elsewhere.
    luraph_lift.clean_pair = clean_pair
    _INSTALLED = True
