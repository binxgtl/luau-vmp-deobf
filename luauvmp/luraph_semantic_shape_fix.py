"""Handle Luau multi-assignments with fewer RHS values during role inference."""
from __future__ import annotations

import re
from typing import Dict

from . import luraph_semantic_normalize as normalize

_INSTALLED = False


def _prototype_arrays(source: str, proto_name: str, limit: int) -> Dict[int, str]:
    """Map prototype field indexes to locals using normal Lua assignment rules.

    ``local a,b,c = x,y`` is valid Luau: ``c`` receives nil.  Public v14.7
    factories use this shape to declare a later closure local alongside the
    physical prototype arrays, so requiring equal list lengths drops every
    otherwise-valid field mapping.
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
        # Extra RHS values may be produced by a multi-return expression and are
        # not safe to associate positionally.  Fewer RHS values are standard
        # Lua/Luau and the unmatched locals simply become nil.
        if len(rhs) > len(lhs):
            continue
        for name, expression in zip(lhs, rhs):
            if normalize._IDENTIFIER.fullmatch(name) is None:
                continue
            cell = indexed.fullmatch(expression)
            if cell is None:
                continue
            index = normalize._integer(cell.group("index"))
            if index is not None:
                result[index] = name
    return result


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    normalize._prototype_arrays = _prototype_arrays
    _INSTALLED = True
