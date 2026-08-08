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


def _atom_pattern(prefix: str) -> str:
    return (
        r"(?:R\[@(?P<" + prefix + r"_reg>" + _FIELD + r")\]"
        r"|@(?P<" + prefix + r"_value>" + _FIELD + r"))"
    )


def _matched_atom(match, prefix: str, ins) -> str:
    reg_field = match.group(prefix + "_reg")
    if reg_field is not None:
        return _reg(ins, reg_field)
    return _value(ins, match.group(prefix + "_value"))


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


def _range_call(text, *, assign: bool):
    """Parse an exact call using a recovered table.unpack register range."""
    target = (
        r"R\[(?P=base)\]=R\[(?P=base)\]" if assign
        else r"R\[(?P=base)\]"
    )
    return re.fullmatch(
        r"(?P<base>" + _ID + r")=@(?P<base_field>" + _FIELD + r");"
        r"(?P<last>" + _ID + r")=\(?(?P=base)\+@(?P<count_field>"
        + _FIELD + r")-1(?:\.0)?\)?;"
        + target
        + r"\(table\.unpack\(R,(?P=base)\+1(?:\.0)?,(?P=last)\)\);"
        r"(?P<top>" + _ID + r")=\(?(?P=base)(?P<minus>-1(?:\.0)?)?\)?",
        text,
    )


def clean_statement(source, ins):
    existing = _ORIGINAL_CLEAN(source, ins)
    if existing is not None:
        return existing
    text = luraph_lift.compact(source).rstrip(";")

    # base = operand; last = base + count - 1; then call through the register
    # range recovered from the randomized VM unpack helper. The trailing top
    # assignment is interpreter bookkeeping; assignment/non-assignment forms
    # require the exact top value used by their known v14.7 operation.
    match = _range_call(text, assign=True)
    if match and match.group("minus") is None:
        base = _value(ins, match.group("base_field"))
        count = _value(ins, match.group("count_field"))
        return (
            "R[%s] = R[%s](table.unpack(R, %s + 1, %s + %s - 1))"
            % (base, base, base, base, count)
        )

    match = _range_call(text, assign=False)
    if match and match.group("minus") is not None:
        base = _value(ins, match.group("base_field"))
        count = _value(ins, match.group("count_field"))
        return (
            "R[%s](table.unpack(R, %s + 1, %s + %s - 1))"
            % (base, base, base, count)
        )

    match = re.fullmatch(
        r"R\[@(?P<dst>" + _FIELD + r")\]=(?P<helper>bit32\."
        r"(?:band|bor|bxor|lrotate|lshift|rrotate|rshift))\("
        + _atom_pattern("left") + r"," + _atom_pattern("right") + r"\)",
        text,
    )
    if match:
        return "%s = %s(%s, %s)" % (
            _reg(ins, match.group("dst")), match.group("helper"),
            _matched_atom(match, "left", ins),
            _matched_atom(match, "right", ins),
        )

    match = re.fullmatch(
        r"R\[@(?P<dst>" + _FIELD + r")\]=table\.create\(@(?P<count>"
        + _FIELD + r")\)",
        text,
    )
    if match:
        return "%s = table.create(%s)" % (
            _reg(ins, match.group("dst")), _value(ins, match.group("count")),
        )

    # Recovery interns each proven nested helper literal once. Preserve exact
    # dynamic writes and reads so later slots observe earlier VM mutations.
    helper_text = text
    for _ in range(3):
        updated = re.sub(
            r"\((__VMHELPER_\d+\[@" + _FIELD + r"\])\)", r"\1",
            helper_text,
        )
        if updated == helper_text:
            break
        helper_text = updated
    match = re.fullmatch(
        r"(?P<table>__VMHELPER_\d+)\[@(?P<slot>" + _FIELD + r")\]="
        r"R\[@(?P<src>" + _FIELD + r")\]",
        helper_text,
    )
    if match:
        return "%s[%s] = %s" % (
            match.group("table"), _value(ins, match.group("slot")),
            _reg(ins, match.group("src")),
        )
    match = re.fullmatch(
        r"R\[@(?P<dst>" + _FIELD + r")\]=\(?"
        r"(?P<table>__VMHELPER_\d+)\[@(?P<slot>" + _FIELD + r")\]\)?",
        helper_text,
    )
    if match:
        return "%s = %s[%s]" % (
            _reg(ins, match.group("dst")), match.group("table"),
            _value(ins, match.group("slot")),
        )

    # Public helper slots proven as table.move retain the standard five-argument
    # signature. Require the complete scratch def-use chain before collapsing it.
    match = re.fullmatch(
        r"(?P<base>" + _ID + r")=@(?P<base_field>" + _FIELD + r");"
        r"(?P<src>" + _ID + r")=@(?P<src_field>" + _FIELD + r");"
        r"(?P<table>" + _ID + r")=R\[(?P=base)\];"
        r"table\.move\(R,(?P=base)\+1,(?P<top>" + _ID + r"),"
        r"(?P=src)\+1,(?P=table)\)",
        text,
    )
    if match:
        base = _value(ins, match.group("base_field"))
        src = _value(ins, match.group("src_field"))
        return "table.move(R, %s + 1, %s, %s + 1, R[%s])" % (
            base, match.group("top"), src, base,
        )

    match = re.fullmatch(
        r"(?P<base>" + _ID + r")=@(?P<base_field>" + _FIELD + r");"
        r"(?P<src>" + _ID + r")=@(?P<src_field>" + _FIELD + r");"
        r"(?P<table>" + _ID + r")=R\[(?P=base)\];"
        r"table\.move\(R,(?P=base)\+1,(?P=base)\+@(?P<count_field>"
        + _FIELD + r"),(?P=src)\+1,(?P=table)\)",
        text,
    )
    if match:
        base = _value(ins, match.group("base_field"))
        src = _value(ins, match.group("src_field"))
        count = _value(ins, match.group("count_field"))
        return "table.move(R, %s + 1, %s + %s, %s + 1, R[%s])" % (
            base, base, count, src, base,
        )

    match = re.fullmatch(
        r"(?P<move>" + _ID + r")=\(?table\.move\)?;(?P<dst>" + _ID + r")=R;"
        r"(?P<start>" + _ID + r")=(?P<base>" + _ID + r");"
        r"(?P<one>" + _ID + r")=1;(?P=start)\+=(?P=one);"
        r"(?P<finish>" + _ID + r")=(?P<top>" + _ID + r");"
        r"(?P<source>" + _ID + r")=(?P<src>" + _ID + r");"
        r"(?P<src_one>" + _ID + r")=1;(?P=source)\+=(?P=src_one);"
        r"(?P<table>" + _ID + r")=(?P<value>" + _ID + r");"
        r"(?P=move)\((?P=dst),(?P=start),(?P=finish),(?P=source),(?P=table)\)",
        text,
    )
    if match:
        return "table.move(R, %s + 1, %s, %s + 1, %s)" % (
            match.group("base"), match.group("top"),
            match.group("src"), match.group("value"),
        )

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
    # The public closure/close passes preserve this exact raw-cell representation:
    # an open cell indexes its live register table, while a closed cell points
    # key 2 back at itself and key 1 at the stored-value key.  Therefore these
    # patterns can be emitted structurally without guessing an abstract cell API.
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

    # tmp = I[key]; R[dst] = tmp[2][tmp[1]][R[index]]
    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=I\[@(?P<key>" + _FIELD + r")\];"
        r"R\[@(?P<dst>" + _FIELD + r")\]=(?P=tmp)\[2(?:\.0)?\]"
        r"\[(?P=tmp)\[1(?:\.0)?\]\]\[R\[@(?P<index>" + _FIELD + r")\]\]",
        text,
    )
    if match:
        key = _value(ins, match.group("key"))
        index = _reg(ins, match.group("index"))
        return "%s = I[%s][2][I[%s][1]][%s]" % (
            _reg(ins, match.group("dst")), key, key, index,
        )

    # tmp = I[key]; tmp[2][tmp[1]][R[index]] = R[src]
    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=I\[@(?P<key>" + _FIELD + r")\];"
        r"(?P=tmp)\[2(?:\.0)?\]\[(?P=tmp)\[1(?:\.0)?\]\]"
        r"\[R\[@(?P<index>" + _FIELD + r")\]\]=R\[@(?P<src>" + _FIELD + r")\]",
        text,
    )
    if match:
        key = _value(ins, match.group("key"))
        index = _reg(ins, match.group("index"))
        return "I[%s][2][I[%s][1]][%s] = %s" % (
            key, key, index, _reg(ins, match.group("src")),
        )

    # tmp = I[key]; tmp[2][tmp[1]] = R[src]
    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=I\[@(?P<key>" + _FIELD + r")\];"
        r"(?P=tmp)\[2(?:\.0)?\]\[(?P=tmp)\[1(?:\.0)?\]\]"
        r"=R\[@(?P<src>" + _FIELD + r")\]",
        text,
    )
    if match:
        key = _value(ins, match.group("key"))
        return "I[%s][2][I[%s][1]] = %s" % (
            key, key, _reg(ins, match.group("src")),
        )

    # The same raw cells appear with whole-rvalue/lvalue grouping and with
    # constant operand atoms instead of register atoms in randomized layouts.
    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=I\[@(?P<key>" + _FIELD + r")\];"
        r"R\[@(?P<dst>" + _FIELD + r")\]=\(?(?P=tmp)\[2(?:\.0)?\]"
        r"\[(?P=tmp)\[1(?:\.0)?\]\]\)?",
        text,
    )
    if match:
        key = _value(ins, match.group("key"))
        return "%s = I[%s][2][I[%s][1]]" % (
            _reg(ins, match.group("dst")), key, key,
        )

    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=I\[@(?P<key>" + _FIELD + r")\];"
        r"R\[@(?P<dst>" + _FIELD + r")\]=\(?(?P=tmp)\[2(?:\.0)?\]"
        r"\[(?P=tmp)\[1(?:\.0)?\]\]\[" + _atom_pattern("index") + r"\]\)?",
        text,
    )
    if match:
        key = _value(ins, match.group("key"))
        return "%s = I[%s][2][I[%s][1]][%s]" % (
            _reg(ins, match.group("dst")), key, key,
            _matched_atom(match, "index", ins),
        )

    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=I\[@(?P<key>" + _FIELD + r")\];"
        r"\(?(?P=tmp)\[2(?:\.0)?\]\[(?P=tmp)\[1(?:\.0)?\]\]\)?"
        r"\[" + _atom_pattern("index") + r"\]=" + _atom_pattern("src"),
        text,
    )
    if match:
        key = _value(ins, match.group("key"))
        return "I[%s][2][I[%s][1]][%s] = %s" % (
            key, key, _matched_atom(match, "index", ins),
            _matched_atom(match, "src", ins),
        )

    match = re.fullmatch(
        r"(?P<tmp>" + _ID + r")=I\[@(?P<key>" + _FIELD + r")\];"
        r"\(?(?P=tmp)\[2(?:\.0)?\]\)?\[(?P=tmp)\[1(?:\.0)?\]\]="
        + _atom_pattern("src"),
        text,
    )
    if match:
        key = _value(ins, match.group("key"))
        return "I[%s][2][I[%s][1]] = %s" % (
            key, key, _matched_atom(match, "src", ins),
        )

    # Direct captured-value table indexing. This is intentionally distinct from
    # raw-cell dereferencing above: the recovered semantic itself indexes I[key]
    # directly, so preserve that operation exactly.
    match = re.fullmatch(
        r"R\[@(?P<dst>" + _FIELD + r")\]=I\[@(?P<key>" + _FIELD
        + r")\]\[R\[@(?P<index>" + _FIELD + r")\]\]",
        text,
    )
    if match:
        return "%s = I[%s][%s]" % (
            _reg(ins, match.group("dst")),
            _value(ins, match.group("key")),
            _reg(ins, match.group("index")),
        )

    match = re.fullmatch(
        r"I\[@(?P<key>" + _FIELD + r")\]\[R\[@(?P<index>" + _FIELD
        + r")\]\]=R\[@(?P<src>" + _FIELD + r")\]",
        text,
    )
    if match:
        return "I[%s][%s] = %s" % (
            _value(ins, match.group("key")),
            _reg(ins, match.group("index")),
            _reg(ins, match.group("src")),
        )

    match = re.fullmatch(
        r"I\[@(?P<key>" + _FIELD + r")\]\[" + _atom_pattern("index")
        + r"\]=" + _atom_pattern("src"),
        text,
    )
    if match:
        return "I[%s][%s] = %s" % (
            _value(ins, match.group("key")),
            _matched_atom(match, "index", ins),
            _matched_atom(match, "src", ins),
        )

    # Exact persistent-scratch staging of the captured vector.  These operations
    # have no calls/control flow and the backend declares every named scratch
    # local.  Preserve the state edge instead of quoting it as fallback data.
    match = re.fullmatch(
        r"(?P<table>" + _ID + r")=I;(?P<key>" + _ID + r")=@(?P<field>"
        + _FIELD + r")",
        text,
    )
    if match:
        return "%s = I; %s = %s" % (
            match.group("table"), match.group("key"),
            _value(ins, match.group("field")),
        )

    match = re.fullmatch(
        r"(?P<table>" + _ID + r")=I;(?P<key>" + _ID + r")=@(?P<field>"
        + _FIELD + r");(?P=table)=(?P=table)\[(?P=key)\]",
        text,
    )
    if match:
        table, key = match.group("table"), match.group("key")
        return "%s = I; %s = %s; %s = %s[%s]" % (
            table, key, _value(ins, match.group("field")), table, table, key,
        )

    match = re.fullmatch(
        r"(?P<a>" + _ID + r")=@(?P<afield>" + _FIELD + r");"
        r"(?P<table>" + _ID + r")=I;"
        r"(?P<b>" + _ID + r")=@(?P<bfield>" + _FIELD + r")",
        text,
    )
    if match:
        return "%s = %s; %s = I; %s = %s" % (
            match.group("a"), _value(ins, match.group("afield")),
            match.group("table"), match.group("b"),
            _value(ins, match.group("bfield")),
        )

    return None


def install() -> None:
    global _INSTALLED, _ORIGINAL_CLEAN
    if _INSTALLED:
        return
    _ORIGINAL_CLEAN = luraph_lift.clean_statement
    luraph_lift.clean_statement = clean_statement
    _INSTALLED = True
