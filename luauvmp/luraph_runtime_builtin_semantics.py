"""Replace only proven top-level runtime-helper callees with trusted builtins.

``runtime_A.tsv`` can now contain ``builtin:<name>`` for function objects whose
identity was compared against the runner's explicit trusted builtin list.  This
pass consumes that evidence without invoking any helper.  It rewrites only a
call callee of the form ``A[slot](...)`` or ``(A[slot])(...)``; table mutation,
value extraction, strings/comments and unproven slots are left untouched.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional
import json
import re

from . import luraph_recover
from . import luraph_public_v147 as public


_INSTALLED = False
_ORIGINAL_RECOVER = None
_ALLOWED = {
    "select", "pcall", "xpcall", "type", "typeof", "tostring", "tonumber",
    "rawequal", "rawget", "rawset", "setmetatable", "getmetatable", "next",
    "pairs", "ipairs", "assert", "error",
    "bit32.band", "bit32.bnot", "bit32.bor", "bit32.bxor", "bit32.countlz",
    "bit32.countrz", "bit32.lrotate", "bit32.lshift", "bit32.rrotate",
    "bit32.rshift", "table.concat", "table.create", "table.find",
    "table.freeze", "table.insert", "table.move", "table.pack", "table.remove",
    "table.sort", "table.unpack", "string.byte", "string.char", "string.find",
    "string.format", "string.len", "string.match", "string.pack",
    "string.packsize", "string.rep", "string.reverse", "string.sub",
    "string.unpack", "math.ceil", "math.floor", "math.modf",
}


def builtin_slots(path: Path) -> Dict[int, str]:
    result: Dict[int, str] = {}
    ambiguous = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        cols = line.split("\t")
        if len(cols) != 5 or cols[1] != "function" or not cols[2].startswith("builtin:"):
            continue
        name = cols[2][len("builtin:"):]
        if name not in _ALLOWED:
            continue
        try:
            slot = int(cols[0])
        except ValueError:
            continue
        if slot in ambiguous:
            continue
        previous = result.get(slot)
        if previous is not None and previous != name:
            result.pop(slot, None)
            ambiguous.add(slot)
            continue
        result[slot] = name
    return result


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


def rewrite_builtin_callees(source: str, slots: Dict[int, str]) -> str:
    if not slots:
        return source
    code = _code_only(source)
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])(?P<paren>\(\s*)?A\s*\[\s*(?P<slot>\d+)"
        r"(?:\.0)?\s*\](?(paren)\s*\))\s*(?=\()"
    )
    pieces = []
    cursor = 0
    for match in pattern.finditer(code):
        slot = int(match.group("slot"))
        name = slots.get(slot)
        if name is None:
            continue
        pieces.append(source[cursor:match.start()])
        pieces.append(name)
        cursor = match.end()
    if not pieces:
        return source
    pieces.append(source[cursor:])
    return "".join(pieces)


def _write_text(path: Optional[Path], data: dict) -> None:
    if path is None:
        return
    lines = []
    for opcode in sorted(int(key) for key in data):
        item = data[str(opcode)]
        lines.extend([
            "=== OPCODE %d | unknown_if=%s ===" % (opcode, item.get("unknown_ifs", 0)),
            item.get("source", ""),
            "",
        ])
    path.write_text("\n".join(lines), encoding="utf-8")


def recover_dispatch(factory, runtime_facts, output, text_output=None):
    result = _ORIGINAL_RECOVER(factory, runtime_facts, output, text_output)
    slots = builtin_slots(Path(runtime_facts))
    if not slots:
        return result
    output_path = Path(output)
    data = json.loads(output_path.read_text(encoding="utf-8"))
    changed = False
    for item in data.values():
        if not isinstance(item, dict):
            continue
        old = item.get("source", "")
        new = rewrite_builtin_callees(old, slots)
        if new == old:
            continue
        item["source"] = new
        item["runtime_builtin_callee"] = True
        changed = True
    if not changed:
        return result
    output_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_text(Path(text_output) if text_output is not None else None, data)
    return data


def install() -> None:
    global _INSTALLED, _ORIGINAL_RECOVER
    if _INSTALLED:
        return
    _ORIGINAL_RECOVER = luraph_recover.recover_dispatch
    luraph_recover.recover_dispatch = recover_dispatch
    _INSTALLED = True
