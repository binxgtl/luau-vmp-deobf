"""Expose proven current-opcode array reads to the public dispatcher evaluator.

The public factory metadata maps randomized locals to canonical roles. When it
proves three distinct names for the opcode array (``L``), current PC (``u``) and
already-fetched dispatch value (``X``), a later expression ``raw_L[raw_u]`` is
exactly the same value as ``raw_X`` for that dispatcher iteration.

The defining fetch itself must remain intact: rewriting ``local raw_X =
raw_L[raw_u]`` into ``local raw_X = raw_X`` destroys the structural evidence used
to locate the dispatcher. This pass therefore requires exactly one defining
fetch, preserves it byte-for-byte, and rewrites only subsequent executable reads
(including the cosmetic ``(raw_L)[raw_u]`` spelling) in a temporary factory copy.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Tuple
import json
import re
import tempfile

from . import luraph_recover
from . import luraph_public_v147 as public
from . import luraph_semantic_normalize as normalize


_INSTALLED = False
_ORIGINAL_RECOVER = None


def _roles(source: str) -> Optional[Dict[str, str]]:
    metadata = normalize._metadata(source)
    if metadata.get("PUBLIC_V147") != "1":
        return None
    try:
        mapping = json.loads(metadata.get("CANONICAL_VARS", "{}"))
    except json.JSONDecodeError:
        return None
    if not isinstance(mapping, dict):
        return None
    inverse = {}
    for raw, canonical in mapping.items():
        if canonical in {"L", "u", "X"}:
            if canonical in inverse and inverse[canonical] != raw:
                return None
            inverse[canonical] = str(raw)
    if set(inverse) != {"L", "u", "X"} or len(set(inverse.values())) != 3:
        return None
    return inverse


def _code_only(source: str) -> str:
    pieces = []
    cursor = 0
    for token in public._tokens(source):
        pieces.append(" " * (token.start - cursor))
        if token.kind == "string":
            pieces.append(" " * (token.end - token.start))
        else:
            pieces.append(source[token.start:token.end])
        cursor = token.end
    pieces.append(" " * (len(source) - cursor))
    return "".join(pieces)


def _read_pattern(raw_array: str, raw_pc: str) -> str:
    return (
        r"(?:\(\s*" + re.escape(raw_array) + r"\s*\)|(?<![A-Za-z0-9_])"
        + re.escape(raw_array) + r")\s*\[\s*" + re.escape(raw_pc)
        + r"\s*\](?![A-Za-z0-9_])"
    )


def _defining_read_span(code: str, raw_array: str, raw_pc: str,
                        raw_value: str) -> Optional[Tuple[int, int]]:
    pattern = re.compile(
        r"\blocal\s+" + re.escape(raw_value) + r"\s*=\s*\(?\s*"
        r"(?P<read>" + _read_pattern(raw_array, raw_pc) + r")\s*\)?\s*;?"
    )
    matches = list(pattern.finditer(code))
    if len(matches) != 1:
        return None
    return matches[0].span("read")


def rewrite_current_opcode_reads(source: str) -> str:
    roles = _roles(source)
    if roles is None:
        return source
    raw_array, raw_pc, raw_value = roles["L"], roles["u"], roles["X"]
    code = _code_only(source)
    defining = _defining_read_span(code, raw_array, raw_pc, raw_value)
    if defining is None:
        return source
    pattern = re.compile(_read_pattern(raw_array, raw_pc))
    pieces = []
    cursor = 0
    changed = False
    for match in pattern.finditer(code):
        if match.span() == defining:
            continue
        pieces.append(source[cursor:match.start()])
        pieces.append(raw_value)
        cursor = match.end()
        changed = True
    if not changed:
        return source
    pieces.append(source[cursor:])
    return "".join(pieces)


def recover_dispatch(factory, runtime_facts, output, text_output=None):
    factory_path = Path(factory)
    source = factory_path.read_text(encoding="utf-8", errors="surrogateescape")
    rewritten = rewrite_current_opcode_reads(source)
    if rewritten == source:
        return _ORIGINAL_RECOVER(factory, runtime_facts, output, text_output)

    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        errors="surrogateescape",
        prefix=".luraph-known-opcode-",
        suffix=".luau",
        dir=str(factory_path.parent),
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(rewritten)
        return _ORIGINAL_RECOVER(temporary, runtime_facts, output, text_output)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def install() -> None:
    global _INSTALLED, _ORIGINAL_RECOVER
    if _INSTALLED:
        return
    _ORIGINAL_RECOVER = luraph_recover.recover_dispatch
    luraph_recover.recover_dispatch = recover_dispatch
    _INSTALLED = True
