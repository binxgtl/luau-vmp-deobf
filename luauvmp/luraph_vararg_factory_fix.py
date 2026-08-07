"""Match randomized vararg packer slots by numeric value, not spelling."""
from __future__ import annotations

from typing import Optional, Tuple
import re

from . import luraph_semantic_normalize as normalize
from . import luraph_vararg_semantics as vararg


_INSTALLED = False
_ID = r"[A-Za-z_]\w*"
_NUMBER = normalize._NUMBER_TEXT


def infer_factory_varargs(factory_source: str, helper: str,
                          packer_slot: int) -> Optional[Tuple[str, str]]:
    if not helper:
        return None
    pattern = re.compile(
        r"\blocal\s+(?P<count>" + _ID + r")\s*,\s*(?P<table>" + _ID
        + r")\s*=\s*(?:\(\s*" + re.escape(helper) + r"\s*\)|"
        + re.escape(helper) + r")\s*\[\s*(?P<slot>" + _NUMBER
        + r")\s*\]\s*\(\s*\.\.\.\s*\)",
        re.S,
    )
    matches = []
    for match in pattern.finditer(factory_source):
        slot = normalize._integer(match.group("slot"))
        if slot != packer_slot:
            continue
        pair = (match.group("count"), match.group("table"))
        if pair[0] != pair[1]:
            matches.append(pair)
    unique = list(dict.fromkeys(matches))
    return unique[0] if len(unique) == 1 else None


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    vararg.infer_factory_varargs = infer_factory_varargs
    _INSTALLED = True
