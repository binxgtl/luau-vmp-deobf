"""Delimiter-tolerant facade over the Luraph v14.x static unpacker."""
from __future__ import annotations

import re

from . import luraph as _base

_LONG_BRACKET = re.compile(r"\[(=*)\[(.*?)\]\1\]", re.S)


def extract_payloads(source):
    """Return all Lua long-bracket strings in source order."""
    return [match.group(2) for match in _LONG_BRACKET.finditer(source)]


def _looks_like_luraph_stream(payload):
    """Recognise one encoded stream without relying on loader-local constants.

    Public v14.7 builds aggressively rewrite the surrounding decoder and may
    remove the decimal multipliers used by older detection heuristics. The
    stable format is the four-byte ``LPH?`` header followed by Ascii85 groups,
    where ``z`` is the all-zero shorthand.
    """
    if len(payload) < 9 or not payload.startswith("LPH"):
        return False
    body = payload[4:]
    for char in body:
        code = ord(char)
        if char != "z" and not 33 <= code <= 117:
            return False
    expanded_length = len(body) + body.count("z") * 4
    return expanded_length >= 5 and expanded_length % 5 == 0


def _luraph_payloads(source):
    return [
        payload for payload in extract_payloads(source)
        if _looks_like_luraph_stream(payload)
    ]


def detect(source):
    """Detect v14.x loaders from their two stable encoded streams.

    Do not require names, banners, arithmetic constants, or a particular long
    bracket delimiter: all of those are routinely rewritten by Luraph builds.
    """
    return len(_luraph_payloads(source)) >= 2


def unpack(source):
    """Unpack the two LPH streams while ignoring unrelated long strings."""
    payloads = _luraph_payloads(source)
    if len(payloads) < 2:
        raise ValueError("expected two Luraph payloads, found %d" % len(payloads))
    streams = []
    for payload in payloads[:2]:
        coded = _base.decode_base85(payload, drop=5)
        try:
            streams.append(_base.decompress(coded))
        except (IndexError, ValueError):
            streams.append(False)
    vm, bytecode = streams
    if vm is False or bytecode is False:
        raise ValueError("Luraph stream decompression aborted (corrupt loader?)")
    return vm, bytecode


# Upgrade existing callers (legacy CLI and corpus module) after this facade is imported.
_base.extract_payloads = extract_payloads
_base.detect = detect
_base.unpack = unpack

decode_base85 = _base.decode_base85
decompress = _base.decompress
