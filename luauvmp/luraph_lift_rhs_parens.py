"""Remove only redundant outer parentheses around a whole assignment RHS."""
from __future__ import annotations

from . import luraph_lift

_INSTALLED = False
_ORIGINAL_COMPACT = None


def _assignment_index(text: str):
    """Return the first top-level assignment '=' in one compact statement."""
    depth = 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            depth -= 1
            continue
        if char != "=" or depth != 0:
            continue
        previous = text[index - 1] if index else ""
        following = text[index + 1] if index + 1 < len(text) else ""
        if previous in "<>=~" or following == "=":
            continue
        return index
    return None


def _encloses_entire_expression(text: str) -> bool:
    if len(text) < 2 or text[0] != "(" or text[-1] != ")":
        return False
    depth = 0
    quote = None
    escaped = False
    for index, char in enumerate(text):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and index != len(text) - 1:
                return False
            if depth < 0:
                return False
    return depth == 0 and quote is None


def strip_assignment_rhs_parens(text: str) -> str:
    """Strip balanced parentheses only when they wrap the entire RHS.

    The function deliberately refuses multi-statement text.  Removing parentheses
    around an entire assignment RHS cannot change operator precedence because no
    outer operator remains, but applying the same rewrite inside compound
    statements/branches would require an AST and is therefore left untouched.
    """
    suffix = ";" if text.endswith(";") else ""
    body = text[:-1] if suffix else text
    if ";" in body:
        return text
    assignment = _assignment_index(body)
    if assignment is None:
        return text
    rhs = body[assignment + 1:]
    changed = False
    while _encloses_entire_expression(rhs):
        rhs = rhs[1:-1]
        changed = True
    if not changed:
        return text
    return body[:assignment + 1] + rhs + suffix


def compact(source: str) -> str:
    return strip_assignment_rhs_parens(_ORIGINAL_COMPACT(source))


def install() -> None:
    global _INSTALLED, _ORIGINAL_COMPACT
    if _INSTALLED:
        return
    _ORIGINAL_COMPACT = luraph_lift.compact
    luraph_lift.compact = compact
    _INSTALLED = True
