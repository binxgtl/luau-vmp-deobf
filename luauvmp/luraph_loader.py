"""Delimiter-tolerant facade over the Luraph v14.x static unpacker."""
from __future__ import annotations

import re

from . import luraph as _base

_LONG_BRACKET = re.compile(r"\[(=*)\[(.*?)\]\1\]", re.S)


def extract_payloads(source):
    """Return LPH blobs from any valid Lua long-bracket delimiter."""
    return [match.group(2) for match in _LONG_BRACKET.finditer(source)
            if match.group(2).startswith("LPH")]


def detect(source):
    """Detect Luraph loaders even when the two blobs use different delimiters."""
    if "LPH" not in source:
        return False
    if "52200625" not in source and "614125" not in source:
        return False
    return len(extract_payloads(source)) >= 2


# The original unpack() resolves these names from its module globals. Replacing
# them here upgrades every existing caller, including corpus and legacy commands.
_base.extract_payloads = extract_payloads
_base.detect = detect

unpack = _base.unpack
decode_base85 = _base.decode_base85
decompress = _base.decompress
