"""Extend the dispatcher constant evaluator with exact signed i8 unpacking.

Public v14.7 anti-tamper arithmetic uses ``string.unpack`` only as a pure way to
materialize signed 64-bit integer constants from eight literal bytes.  The legacy
specializer already models the surrounding bit32 helpers but returned UNKNOWN
for this primitive, breaking constant propagation through otherwise-deterministic
prefixes.

Only ``<i8`` and ``>i8`` with an exact 8-byte literal are accepted.  The Lua
function's secondary next-position result is intentionally omitted because a
function call used as a scalar expression receives only its first result.  Every
other format/arity/type delegates to the original fail-closed evaluator.
"""
from __future__ import annotations

from tools import recover_luraph_dispatch as legacy


_INSTALLED = False
_ORIGINAL = None


def _bytes8(value):
    if isinstance(value, bytes):
        return value if len(value) == 8 else None
    if not isinstance(value, str):
        return None
    try:
        raw = value.encode("latin1")
    except UnicodeEncodeError:
        return None
    return raw if len(raw) == 8 else None


def apply_known_func(fn, args):
    if getattr(fn, "name", None) == "string.unpack":
        if len(args) == 2 and args[0] in ("<i8", ">i8"):
            raw = _bytes8(args[1])
            if raw is not None:
                return int.from_bytes(
                    raw,
                    byteorder="little" if args[0][0] == "<" else "big",
                    signed=True,
                )
        return legacy.UNKNOWN
    return _ORIGINAL(fn, args)


def install() -> None:
    global _INSTALLED, _ORIGINAL
    if _INSTALLED:
        return
    _ORIGINAL = legacy.apply_known_func
    legacy.apply_known_func = apply_known_func
    _INSTALLED = True
