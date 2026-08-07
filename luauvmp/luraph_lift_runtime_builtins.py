"""Lift exact call shapes after runtime helper identity literalization."""
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

    # table.create(count) is pure allocation and its only VM-visible effect is
    # the destination register assignment represented here.
    match = re.fullmatch(
        r"R\[@(?P<dst>" + _FIELD + r")\]=table\.create\(@(?P<count>"
        + _FIELD + r")\)",
        text,
    )
    if match:
        return "%s = table.create(%s)" % (
            _reg(ins, match.group("dst")), _value(ins, match.group("count")),
        )

    # SETLIST-style transfer. Preserve every persistent scratch assignment in
    # the recovered semantic instead of collapsing it to a higher-level guess.
    match = re.fullmatch(
        r"(?P<start>" + _ID + r")=@(?P<start_field>" + _FIELD + r");"
        r"(?P<dest>" + _ID + r")=@(?P<dest_field>" + _FIELD + r");"
        r"(?P<table>" + _ID + r")=R\[(?P=start)\];"
        r"table\.move\(R,(?P=start)\+1(?:\.0)?,(?P<top>" + _ID
        + r"),(?P=dest)\+1(?:\.0)?,(?P=table)\)",
        text,
    )
    if match:
        start = match.group("start")
        dest = match.group("dest")
        table = match.group("table")
        top = match.group("top")
        return "\n".join([
            "%s = %s" % (start, _value(ins, match.group("start_field"))),
            "%s = %s" % (dest, _value(ins, match.group("dest_field"))),
            "%s = R[%s]" % (table, start),
            "table.move(R, %s + 1, %s, %s + 1, %s)" % (
                start, top, dest, table,
            ),
        ])
    return None


def install() -> None:
    global _INSTALLED, _ORIGINAL_CLEAN
    if _INSTALLED:
        return
    _ORIGINAL_CLEAN = luraph_lift.clean_statement
    luraph_lift.clean_statement = clean_statement
    _INSTALLED = True
