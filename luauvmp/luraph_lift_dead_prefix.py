"""Remove provably dead literal-only prefixes before structural lifting.

Public v14.7 dispatchers prepend many opcode bodies with anti-tamper locals such
as ``local Q = 188``.  When the local is never referenced by the remaining
semantic body, keeping that declaration prevents the strict lifter from matching
an otherwise exact VM operation or branch.  Removing it is semantics-preserving.

This pass is intentionally narrow: only *leading* local declarations whose RHS
is a scalar literal are considered, and an identifier must have zero references
in the remainder of the semantic source.  Calls, indexes, tables, expressions,
and non-leading declarations are never removed.
"""
from __future__ import annotations

import re

from . import luraph_lift

_INSTALLED = False
_ORIGINAL_COMPACT = None

_IDENTIFIER = r"[A-Za-z_]\w*"
_NUMBER = r"-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?"
_LITERAL = r"(?:" + _NUMBER + r"|nil|true|false)"
_PREFIX = re.compile(
    r"^\s*local\s+(?P<name>" + _IDENTIFIER + r")\s*=\s*"
    r"(?P<value>\(?\s*" + _LITERAL + r"\s*\)?)\s*;\s*",
    re.S,
)


def strip_dead_literal_prefix(source: str) -> str:
    """Drop only leading literal locals proven unused by the remaining body."""
    text = source
    while True:
        match = _PREFIX.match(text)
        if match is None:
            return text
        name = match.group("name")
        remainder = text[match.end():]
        if re.search(r"\b" + re.escape(name) + r"\b", remainder):
            return text
        text = remainder


def compact(source: str) -> str:
    return _ORIGINAL_COMPACT(strip_dead_literal_prefix(source))


def install() -> None:
    global _INSTALLED, _ORIGINAL_COMPACT
    if _INSTALLED:
        return
    _ORIGINAL_COMPACT = luraph_lift.compact
    luraph_lift.compact = compact
    _INSTALLED = True
