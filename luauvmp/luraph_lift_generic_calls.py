"""Lift call/clear opcode shapes whose scratch-local names are randomized.

The reference lifter already recognizes these exact VM operations when Luraph
names its scratch locals ``m`` and ``Z``. Public v14.7 randomizes those local
names per build (for example ``e/t``, ``x/r`` or ``M/T``), which should not turn
the same instruction shape into semantic fallback.

Every pattern below uses regex backreferences so the same scratch register must
flow through the complete sequence. No unknown statement is skipped.
"""
from __future__ import annotations

import re

from . import luraph_lift

_INSTALLED = False
_ORIGINAL_CLEAN = None
_FIELD_RE = "[EpoH_B]"
_ID = r"[A-Za-z_]\w*"


def _field_reg(ins, field: str) -> str:
    return luraph_lift.reg_expr(luraph_lift.field_value(ins, field))


def _field_value(ins, field: str) -> str:
    return luraph_lift.value_expr(luraph_lift.field_value(ins, field))


def clean_statement(source, ins):
    existing = _ORIGINAL_CLEAN(source, ins)
    if existing is not None:
        return existing

    text = luraph_lift.compact(source).rstrip(";")

    # dst = dst(dst + 1), then interpreter top = dst
    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=@(?P<field>" + _FIELD_RE + r");"
        r"R\[(?P=tmp)\]=R\[(?P=tmp)\]\(R\[(?P=tmp)\+1(?:\.0)?\]\);"
        r"(?P<top>" + _ID + r")=\(?(?P=tmp)\)?",
        text,
    )
    if match:
        base = _field_value(ins, match.group("field"))
        return "R[%s] = R[%s](R[%s + 1])" % (base, base, base)

    # dst = dst(dst + 1, dst + 2), then interpreter top = dst
    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=@(?P<field>" + _FIELD_RE + r");"
        r"R\[(?P=tmp)\]=R\[(?P=tmp)\]\(R\[(?P=tmp)\+1(?:\.0)?\],R\[(?P=tmp)\+2(?:\.0)?\]\);"
        r"(?P<top>" + _ID + r")=\(?(?P=tmp)\)?",
        text,
    )
    if match:
        base = _field_value(ins, match.group("field"))
        return "R[%s] = R[%s](R[%s + 1], R[%s + 2])" % (
            base, base, base, base,
        )

    # dst(dst + 1), then interpreter top = dst - 1
    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=@(?P<field>" + _FIELD_RE + r");"
        r"R\[(?P=tmp)\]\(R\[(?P=tmp)\+1(?:\.0)?\]\);"
        r"(?P<top>" + _ID + r")=\(?(?P=tmp)-1(?:\.0)?\)?",
        text,
    )
    if match:
        base = _field_value(ins, match.group("field"))
        return "R[%s](R[%s + 1])" % (base, base)

    # dst(dst + 1, dst + 2), then interpreter top = dst - 1
    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=@(?P<field>" + _FIELD_RE + r");"
        r"R\[(?P=tmp)\]\(R\[(?P=tmp)\+1(?:\.0)?\],R\[(?P=tmp)\+2(?:\.0)?\]\);"
        r"(?P<top>" + _ID + r")=\(?(?P=tmp)-1(?:\.0)?\)?",
        text,
    )
    if match:
        base = _field_value(ins, match.group("field"))
        return "R[%s](R[%s + 1], R[%s + 2])" % (base, base, base)

    # dst = dst() with a randomized scratch/top local.
    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=@(?P<field>" + _FIELD_RE + r");"
        r"R\[(?P=tmp)\]=R\[(?P=tmp)\]\(\)",
        text,
    )
    if match:
        base = luraph_lift.field_value(ins, match.group("field"))
        return "%s = %s()" % (
            luraph_lift.reg_expr(base), luraph_lift.reg_expr(base),
        )

    # Register clearing loop. The loop variable is local to the emitted Luau,
    # while both bounds come from the current virtual instruction operands.
    match = re.fullmatch(
        r"for(?P<tmp>" + _ID + r")=@(?P<start>" + _FIELD_RE + r"),"
        r"@(?P<stop>" + _FIELD_RE + r")(?:,1(?:\.0)?)?do"
        r"R\[(?P=tmp)\]=nil;?end",
        text,
    )
    if match:
        start = _field_value(ins, match.group("start"))
        stop = _field_value(ins, match.group("stop"))
        return "for __i = %s, %s do R[__i] = nil end" % (start, stop)

    return None


def install() -> None:
    global _INSTALLED, _ORIGINAL_CLEAN
    if _INSTALLED:
        return
    _ORIGINAL_CLEAN = luraph_lift.clean_statement
    luraph_lift.clean_statement = clean_statement
    _INSTALLED = True
