"""Accept cosmetic grouping in otherwise-proven vararg transfer bodies."""
from __future__ import annotations

import re

from . import luraph_vararg_semantics as vararg
from .luraph_vararg_factory_fix import install as _install_factory_fix


_INSTALLED = False
_ID = r"[A-Za-z_]\w*"


def compact(source: str) -> str:
    text = re.sub(r"\s+", "", source)
    # Only scalar atoms, one simple table-index atom, and tiny integer-offset
    # arithmetic emitted by the dispatcher are unwrapped. Calls, indexing chains,
    # comparisons and control flow retain their grouping and must still match the
    # exact classifiers.
    index_atom = _ID + r"\[(?:" + _ID + r"(?:[+\-]" + _ID + r")?|\d+(?:\.0)?)\]"
    atom = (
        r"(?:" + _ID + r"|[EpoH_B]\[u\]|c|-?\d+(?:\.0)?"
        r"|" + _ID + r"[+\-]\d+(?:\.0)?|" + index_atom + r")"
    )
    for _ in range(5):
        updated = re.sub(r"\((" + atom + r")\)", r"\1", text)
        if updated == text:
            break
        text = updated
    return text.rstrip(";")


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    _install_factory_fix()
    vararg._compact = compact
    _INSTALLED = True
