"""Replace sample-local nested VM helper lookups with pure Luau literals.

Public v14.7 stores bit32/string/math helpers in a randomized nested ``A`` table.
The exact slot->builtin map is already recovered into the factory metadata.  By
encoding that map into recovered semantic source, later structural lifting no
longer needs the VM helper table and raw audit fallback remains executable using
only standard pure Luau libraries.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional
import json
import re

from . import luraph_recover
from . import luraph_semantic_normalize as normalize

_INSTALLED = False
_ORIGINAL_RECOVER = None
_FIELD = r"[EpoH_B]"


def _nested_helpers(factory: Path) -> Dict[int, Dict[int, str]]:
    source = factory.read_text(encoding="utf-8", errors="surrogateescape")
    raw = normalize._metadata(source).get("NESTED_HELPERS", "{}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return {
        int(table): {int(slot): str(name) for slot, name in entries.items()}
        for table, entries in data.items()
    }


def _helper_literal(entries: Dict[int, str]) -> str:
    return "{" + ",".join(
        "[%d]=%s" % (slot, name) for slot, name in sorted(entries.items())
    ) + "}"


def rewrite_source(source: str, nested: Dict[int, Dict[int, str]]) -> str:
    text = source
    for table, entries in sorted(nested.items()):
        if not entries:
            continue
        literal = _helper_literal(entries)
        pattern = re.compile(
            r"\bA\s*\[\s*" + str(table) + r"(?:\.0)?\s*\]\s*"
            r"\[\s*(?P<field>" + _FIELD + r")\s*\[\s*u\s*\]\s*\]"
        )
        text = pattern.sub(
            lambda match, value=literal: "(%s)[%s[u]]" % (
                value, match.group("field")
            ),
            text,
        )
    return text


def _rewrite_output(output: Path, text_output: Optional[Path], nested):
    data = json.loads(output.read_text(encoding="utf-8"))
    changed = False
    for value in data.values():
        if not isinstance(value, dict):
            continue
        old = value.get("source", "")
        new = rewrite_source(old, nested)
        if new != old:
            value["source"] = new
            value["nested_helpers_literalized"] = True
            changed = True
    if not changed:
        return data
    output.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if text_output is not None:
        lines = []
        for opcode in sorted(int(key) for key in data):
            item = data[str(opcode)]
            lines.append("=== OPCODE %d | unknown_if=%s ===" % (
                opcode, item.get("unknown_ifs", 0)
            ))
            lines.append(item.get("source", ""))
            lines.append("")
        text_output.write_text("\n".join(lines), encoding="utf-8")
    return data


def recover_dispatch(factory, runtime_facts, output, text_output=None):
    result = _ORIGINAL_RECOVER(factory, runtime_facts, output, text_output)
    nested = _nested_helpers(Path(factory))
    if not nested:
        return result
    return _rewrite_output(
        Path(output), Path(text_output) if text_output is not None else None, nested
    )


def install() -> None:
    global _INSTALLED, _ORIGINAL_RECOVER
    if _INSTALLED:
        return
    _ORIGINAL_RECOVER = luraph_recover.recover_dispatch
    luraph_recover.recover_dispatch = recover_dispatch
    _INSTALLED = True
