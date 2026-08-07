"""Extend read-only runtime identity telemetry to coroutine helpers.

The generic-for adapter in public v14.7 uses randomized runtime slots for
``coroutine.wrap`` and ``coroutine.yield``.  They are added to the existing
identity-only telemetry before the capture runner is built.  No coroutine helper
is invoked by this module.
"""
from __future__ import annotations

from . import luraph_runtime_identities as identities
from . import luraph_runtime_builtin_semantics as builtins


_INSTALLED = False


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    if identities._INSTALLED:
        raise RuntimeError("coroutine identities must be installed before capture telemetry")
    needle = '    { "math.modf", math.modf },\n}'
    replacement = (
        '    { "math.modf", math.modf },\n'
        '    { "coroutine.wrap", coroutine.wrap },\n'
        '    { "coroutine.yield", coroutine.yield },\n'
        '}'
    )
    if needle not in identities._BUILTIN_LUA:
        raise RuntimeError("runtime builtin identity table marker changed")
    identities._BUILTIN_LUA = identities._BUILTIN_LUA.replace(
        needle, replacement, 1
    )
    builtins._ALLOWED.update({"coroutine.wrap", "coroutine.yield"})
    _INSTALLED = True
