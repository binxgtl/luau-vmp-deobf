"""Preserve source line information for fail-closed Luraph capture errors.

The recovered VM is already executed only inside the closed capture sandbox, and
its final payload constructor remains disabled. Compiling that VM with Luau debug
level 1 keeps line tables so a swallowed probe error followed by an ambiguous
``attempt to call a nil value`` can be traced to the exact recovered-VM source
line without widening capabilities or changing execution semantics.
"""
from __future__ import annotations

from . import luraph_capture

_INSTALLED = False


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    original_builder = luraph_capture.build_lune_runner

    def build_lune_runner(*args, **kwargs):
        runner = original_builder(*args, **kwargs)
        marker = "    debugLevel = 0,\n"
        if marker not in runner:
            raise luraph_capture.CaptureError(
                "safe-capture debug-level marker was not found"
            )
        return runner.replace(marker, "    debugLevel = 1,\n", 1)

    build_lune_runner.__name__ = original_builder.__name__
    luraph_capture.build_lune_runner = build_lune_runner
    _INSTALLED = True
