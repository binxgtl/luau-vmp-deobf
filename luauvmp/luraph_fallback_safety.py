"""Emit unsupported Luraph semantics as compile-safe audit markers.

Dispatcher bodies are valid only inside the original VM interpreter context.
Some begin with parenthesised calls such as ``(R[x])(...)`` or contain partial
state-machine fragments; inserting them directly into generated Luau can make
the whole source fail to parse.  Preserve the exact specialised body as a
quoted local value instead of executing it as source.
"""
from __future__ import annotations

from typing import Callable, Mapping, Tuple

from . import luraph_decompiler
from .luraph_full import Instruction, lua_quote


_INSTALLED = False


def install() -> None:
    """Install a syntax-safe replacement for the decompiler fallback emitter."""
    global _INSTALLED
    if _INSTALLED:
        return

    original: Callable[[Instruction, Mapping[int, Tuple[str, str]]], str]
    original = luraph_decompiler._raw

    def safe_raw(ins: Instruction,
                 prepared: Mapping[int, Tuple[str, str]]) -> str:
        semantic = original(ins, prepared)
        return "do local __semantic_fallback = %s end" % lua_quote(semantic)

    safe_raw.__name__ = original.__name__
    safe_raw.__doc__ = (
        "Preserve an unsupported specialised semantic body as compile-safe data."
    )
    luraph_decompiler._raw = safe_raw
    _INSTALLED = True
