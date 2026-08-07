"""Accept integral decimal/exponent literals where Luraph encodes table slots.

Public v14.7 factories freely spell integer table indexes as ``6.0`` or ``6e0``.
Those are exact integer keys in Luau, but the original static field parser only
accepted decimal integer text, hexadecimal, and binary.  Keep the conversion
strict: non-integral finite values are rejected instead of silently truncated.
"""
from __future__ import annotations

from typing import Optional
import math

from . import luraph_semantic_normalize as normalize


def integer(text: str) -> Optional[int]:
    cleaned = text.replace("_", "")
    try:
        lower = cleaned.lower()
        if lower.startswith("0b"):
            return int(cleaned[2:], 2)
        if lower.startswith("0x"):
            return int(cleaned[2:], 16)
        if any(char in cleaned for char in ".eE"):
            value = float(cleaned)
            if not math.isfinite(value) or not value.is_integer():
                return None
            return int(value)
        return int(cleaned, 10)
    except (ValueError, OverflowError):
        return None


_INSTALLED = False


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    normalize._integer = integer
    _INSTALLED = True
