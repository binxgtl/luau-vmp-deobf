"""Bind the final composed Luraph lifter into the already-imported decompiler.

``luraph_fallback_safety`` imports :mod:`luraph_decompiler` early so it can wrap
its raw fallback emitter.  That module-level import snapshots ``clean_statement``
before the later public-v14.7 lift passes are installed.  Rebind only the three
pure structural lift helpers after all lift passes are composed; this changes no
sandbox capability and never executes recovered application code.
"""
from __future__ import annotations

from . import luraph_decompiler, luraph_lift

_INSTALLED = False


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    luraph_decompiler.clean_statement = luraph_lift.clean_statement
    luraph_decompiler.decode_branch = luraph_lift.decode_branch
    luraph_decompiler.return_expression = luraph_lift.return_expression
    _INSTALLED = True
