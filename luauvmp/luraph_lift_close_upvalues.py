"""Lift raw public-v14.7 open-upvalue close loops.

Closure construction in the public families stores open upvalues in a randomized
numeric cell layout.  The corresponding close opcodes iterate a per-frame cache,
copy the live register into that same cell, flip a numeric selector and remove
the cache entry.  This module recognizes only that complete def/use pattern.

For close+return superinstructions, the close prefix is emitted inside a
 tail-called anonymous function and the original return expression is evaluated
only after the close has completed.  This preserves both evaluation order and
Lua multi-return arity, including a bare ``return``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple
import re

from . import luraph_decompiler, luraph_lift
from . import luraph_public_v147 as public
from .luraph_full import Instruction, substitute_semantics


_INSTALLED = False
_ORIGINAL_CLEAN = None
_ORIGINAL_RETURN = None
_ORIGINAL_RAW = None
_ID = r"[A-Za-z_]\w*"
_FIELD_REF = r"[EpoH_B]\s*\[\s*u\s*\]"


@dataclass(frozen=True)
class CloseShape:
    cache_name: str
    register_name: str
    cell_name: str
    threshold: str
    self_key: int
    value_key: int
    selector_key: int
    selector_value: int
    region_start: int
    region_end: int


def _integer(text: str) -> Optional[int]:
    try:
        value = float(text)
    except ValueError:
        return None
    return int(value) if value.is_integer() else None


def _block_end(source: str, start: int) -> Optional[int]:
    """Return the end offset of one if/for/while/do/repeat block."""
    stack: List[str] = []
    pending_do = 0
    started = False
    for token in public._tokens(source, start):
        if token.kind != "identifier":
            continue
        value = token.value
        if value == "if":
            stack.append("if"); started = True
        elif value in ("while", "for"):
            stack.append(value); pending_do += 1; started = True
        elif value == "repeat":
            stack.append("repeat"); started = True
        elif value == "do":
            if pending_do:
                pending_do -= 1
            else:
                stack.append("do"); started = True
        elif value == "until":
            if not stack or stack[-1] != "repeat":
                return None
            stack.pop()
            if started and not stack:
                return token.end
        elif value == "end":
            if not stack:
                return None
            stack.pop()
            if started and not stack:
                return token.end
    return None


def _if_count(source: str) -> int:
    return sum(
        1 for token in public._tokens(source)
        if token.kind == "identifier" and token.value == "if"
    )


def _simple_surrounding(source: str) -> bool:
    """Accept only scratch assignments around the proven close region."""
    if not source.strip():
        return True
    tokens = list(public._tokens(source))
    if any(
        token.kind == "identifier" and token.value in {
            "if", "then", "else", "elseif", "for", "while", "repeat",
            "until", "do", "end", "function", "return", "break", "continue",
        }
        for token in tokens
    ):
        return False
    # No calls, table constructors, or field writes are allowed outside the
    # close loop. Cosmetic grouping parentheses and arithmetic are fine.
    if "{" in source or "}" in source or re.search(r"\w\s*\(", source):
        return False
    statements = [part.strip() for part in source.split(";") if part.strip()]
    for statement in statements:
        if re.fullmatch(
            r"(?:local\s+)?" + _ID + r"\s*=\s*"
            r"[A-Za-z0-9_@.\[\]\s()+\-*/%^#]+",
            statement,
        ) is None:
            return False
    return True


def _outer_region(source: str, loop_start: int, loop_end: int,
                  cache: str) -> Tuple[int, int, int]:
    """Return region start/end and expected if-count including an outer guard."""
    candidates = []
    patterns = [
        re.compile(r"\bif\s+" + re.escape(cache) + r"\s+then\b", re.S),
        re.compile(
            r"\bif\s+not\s*\(?\s*" + re.escape(cache)
            + r"\s*\)?\s+then\b",
            re.S,
        ),
    ]
    for pattern in patterns:
        for match in pattern.finditer(source, 0, loop_start):
            end = _block_end(source, match.start())
            if end is not None and end >= loop_end:
                candidates.append((match.start(), end))
    if not candidates:
        return loop_start, loop_end, 1
    # Only one guard may own the loop. Nested/overlapping candidates would make
    # the semantic role ambiguous.
    exact = list(dict.fromkeys(candidates))
    if len(exact) != 1:
        return loop_start, loop_end, -1
    return exact[0][0], exact[0][1], 2


def infer_close_shape(source: str) -> Optional[CloseShape]:
    shapes: List[CloseShape] = []
    loop_pattern = re.compile(
        r"\bfor\s+(?P<reg>" + _ID + r")\s*,\s*(?P<cell>" + _ID + r")"
        r"(?:\s*,\s*" + _ID + r")*\s+in\s+(?P<cache>" + _ID + r")\s+do\b",
        re.S,
    )
    for loop in loop_pattern.finditer(source):
        loop_end = _block_end(source, loop.start())
        if loop_end is None:
            continue
        loop_source = source[loop.start():loop_end]
        reg, cell, cache = loop.group("reg", "cell", "cache")

        # The close branch must be exactly a >= threshold test, optionally
        # represented as an empty then branch followed by else.
        threshold_matches = list(re.finditer(
            r"\bif\s+(?:not\s*\(\s*)?" + re.escape(reg)
            + r"\s*>=\s*(?P<threshold>" + _ID + r"|\d+(?:\.0)?)\s*\)?\s+then\b",
            loop_source,
            re.S,
        ))
        if len(threshold_matches) != 1:
            continue
        threshold = threshold_matches[0].group("threshold")

        def keyed(pattern: str):
            return list(re.finditer(pattern, loop_source, re.S))

        self_assign = keyed(
            r"(?:\(\s*" + re.escape(cell) + r"\s*\)|\b" + re.escape(cell)
            + r")\s*\[\s*(?P<key>\d+)\s*\]\s*=\s*\(?\s*"
            + re.escape(cell) + r"\s*\)?\s*;"
        )
        value_assign = keyed(
            r"(?:\(\s*" + re.escape(cell) + r"\s*\)|\b" + re.escape(cell)
            + r")\s*\[\s*(?P<key>\d+)\s*\]\s*=\s*\(?\s*"
            r"(?:\(\s*c\s*\)|c)\s*\[\s*" + re.escape(reg)
            + r"\s*\]\s*\)?\s*;"
        )
        selector_assign = keyed(
            r"(?:\(\s*" + re.escape(cell) + r"\s*\)|\b" + re.escape(cell)
            + r")\s*\[\s*(?P<key>\d+)\s*\]\s*=\s*\(?\s*"
            r"(?P<value>\d+(?:\.0)?)\s*\)?\s*;"
        )
        cache_clear = keyed(
            r"(?:\(\s*" + re.escape(cache) + r"\s*\)|\b" + re.escape(cache)
            + r")\s*\[\s*" + re.escape(reg)
            + r"\s*\]\s*=\s*\(?\s*nil\s*\)?\s*;"
        )
        if not (
            len(self_assign) == len(value_assign) == len(selector_assign)
            == len(cache_clear) == 1
        ):
            continue
        self_key = _integer(self_assign[0].group("key"))
        value_key = _integer(value_assign[0].group("key"))
        selector_key = _integer(selector_assign[0].group("key"))
        selector_value = _integer(selector_assign[0].group("value"))
        if None in (self_key, value_key, selector_key, selector_value):
            continue
        if len({self_key, value_key, selector_key}) != 3:
            continue

        region_start, region_end, expected_ifs = _outer_region(
            source, loop.start(), loop_end, cache
        )
        if expected_ifs < 0:
            continue
        region = source[region_start:region_end]
        if _if_count(region) != expected_ifs:
            continue

        # Everything around the structural region must be simple scratch setup.
        # A trailing terminal return is removed before this check.
        return_match = re.search(r"\breturn(?:\s+[^;]*)?;\s*$", source, re.S)
        prefix_end = return_match.start() if return_match is not None else len(source)
        outside = source[:region_start] + source[region_end:prefix_end]
        if not _simple_surrounding(outside):
            continue

        shapes.append(CloseShape(
            cache_name=cache,
            register_name=reg,
            cell_name=cell,
            threshold=threshold,
            self_key=int(self_key),
            value_key=int(value_key),
            selector_key=int(selector_key),
            selector_value=int(selector_value),
            region_start=region_start,
            region_end=region_end,
        ))
    unique = list(dict.fromkeys(shapes))
    return unique[0] if len(unique) == 1 else None


def _render_close(shape: CloseShape) -> str:
    return "\n".join([
        "if %s ~= nil then" % shape.cache_name,
        "    for __close_reg, __close_cell in %s do" % shape.cache_name,
        "        if __close_reg >= %s then" % shape.threshold,
        "            __close_cell[%d] = __close_cell" % shape.self_key,
        "            __close_cell[%d] = R[__close_reg]" % shape.value_key,
        "            __close_cell[%d] = %d" % (
            shape.selector_key, shape.selector_value
        ),
        "            %s[__close_reg] = nil" % shape.cache_name,
        "        end",
        "    end",
        "end",
    ])


def lift_close_prefix(source: str, ins: Instruction) -> Optional[str]:
    shape = infer_close_shape(source)
    if shape is None:
        return None
    return_match = re.search(r"\breturn(?:\s+[^;]*)?;\s*$", source, re.S)
    prefix_end = return_match.start() if return_match is not None else len(source)
    before = source[:shape.region_start]
    after = source[shape.region_end:prefix_end]
    surrounding = (before + after).strip()
    rendered = []
    if surrounding:
        rendered.append(substitute_semantics(surrounding, ins))
    rendered.append(_render_close(shape))
    return "\n".join(part for part in rendered if part.strip())


def clean_statement(source, ins):
    existing = _ORIGINAL_CLEAN(source, ins)
    if existing is not None:
        return existing
    if _ORIGINAL_RETURN(source, ins) is not None:
        return None
    return lift_close_prefix(source, ins)


def return_expression(source, ins):
    original = _ORIGINAL_RETURN(source, ins)
    if original is None:
        return None
    prefix = lift_close_prefix(source, ins)
    if prefix is None:
        return original
    body = ["(function()"]
    body.extend("    " + line if line else "" for line in prefix.splitlines())
    body.append("    return%s" % ((" " + original) if original else ""))
    body.append("end)()")
    return "\n".join(body)


def raw_instruction(ins, prepared):
    # The decompiler's return path asks _raw only to determine whether a prefix
    # remains after removing the terminal return. Once the exact close prefix is
    # represented by return_expression above, expose only the terminal return so
    # that path counts the instruction as structurally clean.
    try:
        source = prepared[ins.opcode][1]
    except (KeyError, TypeError):
        return _ORIGINAL_RAW(ins, prepared)
    if _ORIGINAL_RETURN(source, ins) is not None and lift_close_prefix(source, ins) is not None:
        return "return;"
    return _ORIGINAL_RAW(ins, prepared)


def install() -> None:
    global _INSTALLED, _ORIGINAL_CLEAN, _ORIGINAL_RETURN, _ORIGINAL_RAW
    if _INSTALLED:
        return
    _ORIGINAL_CLEAN = luraph_lift.clean_statement
    _ORIGINAL_RETURN = luraph_lift.return_expression
    _ORIGINAL_RAW = luraph_decompiler._raw
    luraph_lift.clean_statement = clean_statement
    luraph_lift.return_expression = return_expression
    luraph_decompiler._raw = raw_instruction
    _INSTALLED = True
