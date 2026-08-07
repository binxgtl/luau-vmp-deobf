"""Handle public Luau prototype-array assignment shapes during role inference."""
from __future__ import annotations

import re
from typing import Dict, Optional

from . import luraph_semantic_normalize as normalize

_INSTALLED = False


def _slot_index(text: str) -> Optional[int]:
    """Return an integer prototype slot from any integer-valued Luau number."""
    try:
        value = normalize._number_value(text)
    except (TypeError, ValueError):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _prototype_arrays(source: str, proto_name: str, limit: int) -> Dict[int, str]:
    """Map physical prototype fields to factory locals without evaluating code.

    Public v14.7 uses both ordinary Luau short multi-assignments such as
    ``local a,b,c=x,y`` and integer-valued decimal slot syntax such as
    ``proto[8.0]``.  The latter is semantically the same table key as ``8`` and
    must not be discarded by an integer-only parser.
    """
    result: Dict[int, str] = {}
    declaration = re.compile(r"\blocal\s+(?P<lhs>[^;=]+?)\s*=\s*(?P<rhs>[^;]+);")
    indexed = re.compile(
        r"\(?\s*" + re.escape(proto_name) + r"\s*\[\s*(?P<index>"
        + normalize._NUMBER_TEXT + r")\s*\]\s*\)?$"
    )
    for match in declaration.finditer(source[:limit]):
        lhs = [item.strip() for item in match.group("lhs").split(",")]
        rhs = normalize._split_commas(match.group("rhs"))
        # Extra RHS expressions make positional association ambiguous. Fewer RHS
        # expressions are normal Lua/Luau: unmatched locals simply become nil.
        if len(rhs) > len(lhs):
            continue
        for name, expression in zip(lhs, rhs):
            if normalize._IDENTIFIER.fullmatch(name) is None:
                continue
            cell = indexed.fullmatch(expression)
            if cell is None:
                continue
            index = _slot_index(cell.group("index"))
            if index is not None:
                result[index] = name
    return result


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    normalize._prototype_arrays = _prototype_arrays
    _INSTALLED = True
