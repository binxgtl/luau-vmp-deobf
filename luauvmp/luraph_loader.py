"""Delimiter-tolerant facade over the Luraph v14.x static unpacker."""
from __future__ import annotations

import re

from . import luraph as _base

_LONG_BRACKET = re.compile(r"\[(=*)\[(.*?)\]\1\]", re.S)


def extract_payloads(source):
    """Return all Lua long-bracket strings in source order."""
    return [match.group(2) for match in _LONG_BRACKET.finditer(source)]


def _luraph_payloads(source):
    return [payload for payload in extract_payloads(source)
            if payload.startswith("LPH")]


def detect(source):
    """Detect Luraph loaders even when the two blobs use different delimiters."""
    if "LPH" not in source:
        return False
    if "52200625" not in source and "614125" not in source:
        return False
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
