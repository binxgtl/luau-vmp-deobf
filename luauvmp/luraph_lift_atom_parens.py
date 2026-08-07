"""Normalize cosmetic parentheses around scratch atoms for structural lifting.

Luraph randomizes whether a dispatcher spells a scratch value as ``x`` or
``(x)``, and an indexed scratch value as ``x[j]`` or ``(x[j])``. These forms are
Luau-equivalent. The base compact normalizer intentionally handles only canonical
VM objects; this extension adds identifiers and one-level identifier indexes but
never removes parentheses around calls, arithmetic, comparisons, or table
constructors.
"""
from __future__ import annotations

import re

from . import luraph_lift

_INSTALLED = False
_ORIGINAL_COMPACT = None
_SCRATCH_ATOM = r"[A-Za-z_]\w*(?:\[[A-Za-z_]\w*\])?"


def compact(source: str) -> str:
    text = _ORIGINAL_COMPACT(source)
    pattern = re.compile(
        r"(?<![A-Za-z0-9_\]])\((" + _SCRATCH_ATOM + r")\)"
    )
    for _ in range(4):
        updated = pattern.sub(r"\1", text)
        if updated == text:
            break
        text = updated
    return text


def install() -> None:
    global _INSTALLED, _ORIGINAL_COMPACT
    if _INSTALLED:
        return
    _ORIGINAL_COMPACT = luraph_lift.compact
    luraph_lift.compact = compact
    _INSTALLED = True
