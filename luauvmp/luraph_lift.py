"""Structural lifting of sample-local Luraph dispatcher semantics."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import re

from .luraph_full import Instruction, ProtoRef, Value, render_value


@dataclass(frozen=True)
class Branch:
    target: Optional[int]
    condition: Optional[str]
    unconditional: bool


_FIELDS = ("E", "p", "o", "H", "_", "B")
_FIELD_RE = "[EpoH_B]"


def field_value(ins: Instruction, name: str) -> Value:
    return {
        "E": ins.e, "p": ins.p, "o": ins.o,
        "H": ins.h, "_": ins.underscore, "B": ins.b,
    }[name]


def compact(source: str) -> str:
    text = re.sub(r"\blocal\s+W\s*=\s*57(?:\.0)?\s*;", "", source)
    for field in _FIELDS:
        text = text.replace(field + "[u]", "@" + field)
    text = re.sub(r"\bc\b", "R", text)
    text = re.sub(r"\bu\b", "pc", text)
    text = re.sub(r"\s+", "", text)
    atom = r"(R\[[^\[\]()]+\]|I\[[^\[\]()]+\]|P\[[^\[\]()]+\]|A\[[^\[\]()]+\]|@[EpoH_B_]|nil|true|false|-?\d+(?:\.\d+)?)"
    for _ in range(4):
        text = re.sub(r"(?<![A-Za-z0-9_\]])\(" + atom + r"\)", r"\1", text)
    return text.replace("(R)", "R").replace("(I)", "I").replace("(P)", "P")


def value_expr(value: Value) -> str:
    if isinstance(value, ProtoRef):
        return "PROTO[%d]" % value.id
    return render_value(value)


def reg_expr(value: Value) -> str:
    return "R[%s]" % value_expr(value)


def atom_expr(token: str, ins: Instruction) -> Optional[str]:
    token = token.strip()
    m = re.fullmatch(r"@(" + _FIELD_RE + r")", token)
    if m:
        return value_expr(field_value(ins, m.group(1)))
    m = re.fullmatch(r"R\[@(" + _FIELD_RE + r")\]", token)
    if m:
        return reg_expr(field_value(ins, m.group(1)))
    m = re.fullmatch(r"I\[@(" + _FIELD_RE + r")\]", token)
    if m:
        return "I[%s]" % value_expr(field_value(ins, m.group(1)))
    if token in ("nil", "true", "false", "{}"):
        return token
    if re.fullmatch(r"-?\d+(?:\.\d+)?", token):
        return token
    return None


def _clean_assignment(source: str, ins: Instruction) -> Optional[str]:
    text = compact(source).rstrip(";")
    m = re.fullmatch(r"I\[@(" + _FIELD_RE + r")\]=R\[@(" + _FIELD_RE + r")\]", text)
    if m:
        return "I[%s] = %s" % (
            value_expr(field_value(ins, m.group(1))),
            reg_expr(field_value(ins, m.group(2))),
        )

    m = re.fullmatch(r"R\[@(" + _FIELD_RE + r")\]\[(.+)\]=(.+)", text)
    if m:
        base = reg_expr(field_value(ins, m.group(1)))
        key, val = atom_expr(m.group(2), ins), atom_expr(m.group(3), ins)
        if key is not None and val is not None:
            return "%s[%s] = %s" % (base, key, val)

    m = re.fullmatch(r"R\[@(" + _FIELD_RE + r")\]=(.+)", text)
    if not m:
        return None
    dst, rhs = reg_expr(field_value(ins, m.group(1))), m.group(2)
    atom = atom_expr(rhs, ins)
    if atom is not None:
        return "%s = %s" % (dst, atom)

    m = re.fullmatch(r"I\[@(" + _FIELD_RE + r")\]", rhs)
    if m:
        return "%s = I[%s]" % (dst, value_expr(field_value(ins, m.group(1))))
    m = re.fullmatch(r"R\[@(" + _FIELD_RE + r")\]\[(.+)\]", rhs)
    if m:
        key = atom_expr(m.group(2), ins)
        if key is not None:
            return "%s = %s[%s]" % (
                dst, reg_expr(field_value(ins, m.group(1))), key,
            )
    m = re.fullmatch(r"#(R\[@" + _FIELD_RE + r"\])", rhs)
    if m:
        return "%s = #%s" % (dst, atom_expr(m.group(1), ins))
    m = re.fullmatch(r"not(R\[@" + _FIELD_RE + r"\])", rhs)
    if m:
        return "%s = not %s" % (dst, atom_expr(m.group(1), ins))
    m = re.fullmatch(r"-(R\[@" + _FIELD_RE + r"\])", rhs)
    if m:
        return "%s = -%s" % (dst, atom_expr(m.group(1), ins))
    m = re.fullmatch(r"VMCONST\[@(" + _FIELD_RE + r")\]", rhs)
    if m:
        return "%s = VMCONST[%s]" % (dst, value_expr(field_value(ins, m.group(1))))
    m = re.fullmatch(
        r"bit32\.bxor\((R\[@" + _FIELD_RE + r"\]),(R\[@" + _FIELD_RE + r"\])\)", rhs,
    )
    if m:
        return "%s = bit32.bxor(%s, %s)" % (
            dst, atom_expr(m.group(1), ins), atom_expr(m.group(2), ins),
        )

    for op in ("~=", "==", "<=", ">=", "..", "+", "-", "*", "/", "%", "^", "<", ">"):
        if op not in rhs:
            continue
        left, right = rhs.split(op, 1)
        lhs, rhs_value = atom_expr(left, ins), atom_expr(right, ins)
        if lhs is not None and rhs_value is not None:
            return "%s = %s %s %s" % (dst, lhs, op, rhs_value)
    return None


def clean_statement(source: str, ins: Instruction) -> Optional[str]:
    text = compact(source)
    if not text:
        return "-- no operation"
    if ("A[50]" in source or "__make_closure" in source) and isinstance(ins.b, ProtoRef):
        return "%s = __closure(%d, P, I)" % (reg_expr(ins.underscore), ins.b.id)

    m = re.fullmatch(
        r"m=@(" + _FIELD_RE + r");R\[m\]\(R\[m\+1(?:\.0)?\],R\[m\+2(?:\.0)?\]\);Z=\(m-1(?:\.0)?\);?",
        text,
    )
    if m:
        base = field_value(ins, m.group(1))
        b = value_expr(base)
        return "R[%s](R[%s + 1], R[%s + 2])" % (b, b, b)
    m = re.fullmatch(
        r"m=@(" + _FIELD_RE + r");R\[m\]=R\[m\]\(R\[m\+1(?:\.0)?\]\);Z=m;?",
        text,
    )
    if m:
        b = value_expr(field_value(ins, m.group(1)))
        return "R[%s] = R[%s](R[%s + 1])" % (b, b, b)
    m = re.fullmatch(r"Z=@(" + _FIELD_RE + r");R\[Z\]=R\[Z\]\(\);?", text)
    if m:
        base = field_value(ins, m.group(1))
        return "%s = %s()" % (reg_expr(base), reg_expr(base))
    m = re.fullmatch(r"R\[@(" + _FIELD_RE + r")\]=\{\};?", text)
    if m:
        return "%s = {}" % reg_expr(field_value(ins, m.group(1)))
    return _clean_assignment(source, ins)


def _condition(text: str, ins: Instruction) -> str:
    text = text.strip()
    while text.startswith("(") and text.endswith(")"):
        text = text[1:-1]
    negate = False
    while text.startswith("not(") and text.endswith(")"):
        negate = not negate
        text = text[4:-1]
    while text.startswith("notnot(") and text.endswith(")"):
        text = text[7:-1]
    for field in _FIELDS:
        text = text.replace("R[@%s]" % field, reg_expr(field_value(ins, field)))
        text = text.replace("@%s" % field, value_expr(field_value(ins, field)))
    text = re.sub(r"\bnot(?=R\[|I\[|P\[|true|false|nil)", "not ", text)
    text = re.sub(r"(?<=[A-Za-z0-9_\]])and(?=[A-Za-z_(])", " and ", text)
    text = re.sub(r"(?<=[A-Za-z0-9_\]])or(?=[A-Za-z_(])", " or ", text)
    text = text.replace("~=", " ~= ").replace("==", " == ")
    text = text.replace("<=", " <= ").replace(">=", " >= ")
    text = re.sub(r"(?<![<>=~])<(?![=])", " < ", text)
    text = re.sub(r"(?<![<>=~])>(?![=])", " > ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return "not (%s)" % text if negate else text


def decode_branch(source: str, ins: Instruction) -> Optional[Branch]:
    text = compact(source)
    assignments = list(re.finditer(r"pc=@(" + _FIELD_RE + r")", text))
    if not assignments:
        return None
    field = assignments[-1].group(1)
    raw = field_value(ins, field)
    target = int(raw) if isinstance(raw, (int, float)) else None
    if re.fullmatch(r"pc=@" + re.escape(field) + r";?", text):
        return Branch(target, None, True)
    if not text.startswith("if") or "then" not in text:
        return Branch(target, None, False)
    header, body = text[2:].split("then", 1)
    then_body, sep, else_body = body.partition("else")
    assignment = "pc=@" + field
    if assignment in then_body:
        predicate = header
    elif sep and assignment in else_body:
        predicate = "not(" + header + ")"
    else:
        return Branch(target, None, False)
    return Branch(target, _condition(predicate, ins), False)


def return_expression(source: str, ins: Instruction) -> Optional[str]:
    match = re.search(r"return([^;]*);?$", compact(source))
    if match is None:
        return None
    expr = match.group(1)
    if not expr:
        return ""
    for field in _FIELDS:
        expr = expr.replace("R[@%s]" % field, reg_expr(field_value(ins, field)))
        expr = expr.replace("@%s" % field, value_expr(field_value(ins, field)))
    return expr.replace("__unpack_range", "table.unpack")
