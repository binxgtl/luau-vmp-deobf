"""Decode the typed table syntax used for captured Luraph closure metadata.

Capture serialises arbitrary tables as deterministic ``T{typed=typed,...}``
values.  Closure lifting only needs a much narrower subset: dense numeric outer
indices whose values are tables containing numeric descriptor fields.  This
module parses that subset without evaluating Lua and fails closed on cycles,
non-numeric keys, sparse arrays, duplicate keys, or unexpected value types.
"""
from __future__ import annotations

from typing import Dict, List, Tuple, Union
import re

from .luraph_full import OpaqueTable


Scalar = Union[None, bool, int, float, str]
Parsed = Union[Scalar, Dict[int, "Parsed"]]


class DescriptorError(ValueError):
    """Raised when captured closure metadata is not structurally provable."""


def _split_top(text: str) -> List[str]:
    parts, start, depth = [], 0, 0
    index = 0
    while index < len(text):
        if text.startswith("T{", index):
            depth += 1
            index += 2
            continue
        char = text[index]
        if char == "}":
            if depth <= 0:
                raise DescriptorError("unbalanced typed-table close")
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
        index += 1
    if depth != 0:
        raise DescriptorError("unbalanced typed-table nesting")
    parts.append(text[start:])
    return [part for part in parts if part]


def _decode_scalar(token: str) -> Scalar:
    if token == "N":
        return None
    if token == "B0":
        return False
    if token == "B1":
        return True
    if token.startswith("D"):
        try:
            value = float(token[1:])
        except ValueError as exc:
            raise DescriptorError("invalid numeric typed value") from exc
        if value.is_integer() and abs(value) <= 2**53:
            return int(value)
        return value
    if token.startswith("S"):
        try:
            return bytes.fromhex(token[1:]).decode("utf-8", "surrogateescape")
        except (ValueError, UnicodeError) as exc:
            raise DescriptorError("invalid string typed value") from exc
    raise DescriptorError("unsupported typed value %r" % token[:40])


def parse_typed(token: str) -> Parsed:
    if not token.startswith("T{"):
        return _decode_scalar(token)
    if not token.endswith("}"):
        raise DescriptorError("unterminated typed table")
    inner = token[2:-1]
    if not inner:
        return {}
    table: Dict[int, Parsed] = {}
    for item in _split_top(inner):
        depth = 0
        split = None
        index = 0
        while index < len(item):
            if item.startswith("T{", index):
                depth += 1
                index += 2
                continue
            char = item[index]
            if char == "}":
                depth -= 1
                if depth < 0:
                    raise DescriptorError("unbalanced typed table item")
            elif char == "=" and depth == 0:
                split = index
                break
            index += 1
        if split is None:
            raise DescriptorError("typed table item has no key separator")
        key_token, value_token = item[:split], item[split + 1:]
        key = _decode_scalar(key_token)
        if not isinstance(key, int) or isinstance(key, bool):
            raise DescriptorError("closure descriptor key is not an integer")
        if key in table:
            raise DescriptorError("duplicate closure descriptor key %d" % key)
        table[key] = parse_typed(value_token)
    return table


def _dense(table: Dict[int, Parsed], *, zero_based: bool) -> List[Parsed]:
    if not table:
        return []
    first = 0 if zero_based else 1
    expected = list(range(first, first + len(table)))
    if sorted(table) != expected:
        raise DescriptorError(
            "closure descriptor array is sparse: %s" % sorted(table)
        )
    return [table[index] for index in expected]


def decode_descriptors(value, mode_key: int, register_key: int) -> List[Tuple[int, int]]:
    """Return ordered ``(mode, register)`` descriptors from ``Proto.field3``.

    Luraph builders index the freshly allocated capture vector at ``loop-1``, so
    the descriptor source itself is normally one-based.  A zero-based source is
    accepted only when it is independently dense.
    """
    if value is None:
        return []
    if not isinstance(value, OpaqueTable) or not value.text.startswith("T{"):
        raise DescriptorError("prototype upvalue metadata is not a typed table")
    parsed = parse_typed(value.text)
    if not isinstance(parsed, dict):
        raise DescriptorError("prototype upvalue metadata is not a table")
    try:
        rows = _dense(parsed, zero_based=False)
    except DescriptorError:
        rows = _dense(parsed, zero_based=True)

    output: List[Tuple[int, int]] = []
    for position, row in enumerate(rows):
        if not isinstance(row, dict):
            raise DescriptorError("descriptor %d is not a table" % position)
        if mode_key not in row or register_key not in row:
            raise DescriptorError("descriptor %d lacks proven mode/register fields" % position)
        mode, register = row[mode_key], row[register_key]
        if not isinstance(mode, int) or isinstance(mode, bool) or mode not in (0, 1, 2):
            raise DescriptorError("descriptor %d has invalid capture mode" % position)
        if not isinstance(register, int) or isinstance(register, bool) or register < 0:
            raise DescriptorError("descriptor %d has invalid register index" % position)
        output.append((mode, register))
    return output
