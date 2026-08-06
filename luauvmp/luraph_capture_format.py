"""Correct delimiter escaping in the generated Lune capture runner.

The runner is itself emitted from a Python raw string and then compiled as
Luau.  TSV delimiters therefore need exactly one backslash in the generated
Luau source (``"\t"`` / ``"\n"``).  The original generator used two, causing
Lune to write the literal characters ``\\t`` and ``\\n`` into capture files.
"""
from __future__ import annotations

from typing import Callable

from . import luraph_capture


_INSTALLED = False


def correct_runner_delimiters(runner: str) -> str:
    """Reduce only the over-escaped capture-format literals by one layer."""
    replacements = (
        (r'"[\\r\\n]"', r'"[\r\n]"'),
        (r'"\\t"', r'"\t"'),
        (r'"\\n"', r'"\n"'),
        (r'"META\\tprotos\\t"', r'"META\tprotos\t"'),
    )
    fixed = runner
    for old, new in replacements:
        fixed = fixed.replace(old, new)
    return fixed


def install() -> None:
    """Install the corrected runner builder once for CLI and library callers."""
    global _INSTALLED
    if _INSTALLED:
        return

    original: Callable[..., str] = luraph_capture.build_lune_runner

    def build_lune_runner(*args, **kwargs) -> str:
        return correct_runner_delimiters(original(*args, **kwargs))

    build_lune_runner.__name__ = original.__name__
    build_lune_runner.__doc__ = original.__doc__
    luraph_capture.build_lune_runner = build_lune_runner
    _INSTALLED = True
