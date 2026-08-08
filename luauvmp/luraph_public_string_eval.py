r"""Pure Luau string helpers used by public-v14.7 dispatcher arithmetic.

The dispatcher hides control-state constants behind ``string.unpack`` calls and
Luau-specific string escapes.  Python's ``unicode_escape`` disagrees with Luau
on decimal escapes (``\105``), ``\u{...}``, and ``\z`` whitespace elision, so
those constants previously became UNKNOWN and kept entire anti-tamper state
machines in recovered opcode bodies.

Only pure in-memory string operations are implemented here.  No recovered code
or application closure is executed.
"""
from __future__ import annotations

import re

from tools import recover_luraph_dispatch as core
from tools import recover_luraph_dispatch_v147 as public

_INSTALLED = False
_ORIGINAL_LEX = None
_ORIGINAL_APPLY = None

_SIMPLE_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    '"': '"',
    "'": "'",
}


def _decode_luau_quoted(token: str) -> str:
    if len(token) < 2 or token[0] not in ('"', "'") or token[-1] != token[0]:
        return token
    body = token[1:-1]
    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        index += 1
        if index >= len(body):
            out.append("\\")
            break
        esc = body[index]
        simple = _SIMPLE_ESCAPES.get(esc)
        if simple is not None:
            out.append(simple)
            index += 1
            continue
        if esc == "z":
            index += 1
            while index < len(body) and body[index].isspace():
                index += 1
            continue
        if esc == "x" and index + 2 < len(body):
            digits = body[index + 1:index + 3]
            if re.fullmatch(r"[0-9A-Fa-f]{2}", digits):
                out.append(chr(int(digits, 16)))
                index += 3
                continue
        if esc == "u" and index + 1 < len(body) and body[index + 1] == "{":
            close = body.find("}", index + 2)
            if close >= 0:
                digits = body[index + 2:close]
                if digits and re.fullmatch(r"[0-9A-Fa-f]+", digits):
                    value = int(digits, 16)
                    if value <= 0x10FFFF:
                        out.append(chr(value))
                        index = close + 1
                        continue
        if esc.isdigit():
            end = index
            while end < len(body) and end < index + 3 and body[end].isdigit():
                end += 1
            value = int(body[index:end], 10)
            if value <= 255:
                out.append(chr(value))
                index = end
                continue
        if esc == "\n":
            out.append("\n")
            index += 1
            continue
        if esc == "\r":
            if index + 1 < len(body) and body[index + 1] == "\n":
                index += 1
            out.append("\n")
            index += 1
            continue
        out.append(esc)
        index += 1
    return "".join(out)


def _quote_for_existing_parser(value: str) -> str:
    escaped = value.encode("unicode_escape").decode("ascii")
    escaped = escaped.replace('"', '\\"')
    return '"' + escaped + '"'


def lex(source: str):
    tokens = _ORIGINAL_LEX(source)
    for token in tokens:
        if token.kind == "str" and token.v[:1] in ('"', "'"):
            token.v = _quote_for_existing_parser(_decode_luau_quoted(token.v))
    return tokens


def _as_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise TypeError("string helper expected a string")
    try:
        return value.encode("latin1")
    except UnicodeEncodeError:
        return value.encode("utf-8")


def _integer_format(fmt: str):
    if not isinstance(fmt, str):
        return None
    index = 0
    endian = "little"
    if fmt[:1] in ("<", ">", "="):
        if fmt[0] == ">":
            endian = "big"
        index = 1
    match = re.fullmatch(r"([iI])(\d+)", fmt[index:])
    if match is None:
        return None
    size = int(match.group(2), 10)
    if size < 1 or size > 16:
        return None
    signed = match.group(1) == "i"
    return endian, size, signed


def _string_unpack(args):
    if len(args) < 2:
        return core.UNKNOWN
    spec = _integer_format(args[0])
    if spec is None:
        return core.UNKNOWN
    endian, size, signed = spec
    try:
        data = _as_bytes(args[1])
        position = int(args[2]) if len(args) > 2 else 1
    except Exception:
        return core.UNKNOWN
    start = position - 1
    if start < 0 or start + size > len(data):
        return core.UNKNOWN
    return int.from_bytes(data[start:start + size], endian, signed=signed)


def _string_packsize(args):
    if not args:
        return core.UNKNOWN
    spec = _integer_format(args[0])
    return core.UNKNOWN if spec is None else spec[1]


def apply_known_func(function, args):
    name = getattr(function, "name", None)
    if any(value is core.UNKNOWN for value in args):
        return core.UNKNOWN
    if name == "string.unpack":
        return _string_unpack(args)
    if name == "string.packsize":
        return _string_packsize(args)
    return _ORIGINAL_APPLY(function, args)


def install() -> None:
    global _INSTALLED, _ORIGINAL_LEX, _ORIGINAL_APPLY
    if _INSTALLED:
        return
    _ORIGINAL_LEX = public.lex
    _ORIGINAL_APPLY = core.apply_known_func
    public.lex = lex
    core.apply_known_func = apply_known_func
    _INSTALLED = True
