"""Extract embedded Luau source chunks from a finalised Luraph prototype tree.

Some protected programs contain already-authored Luau modules as large string
constants and invoke them through ``loadstring`` at runtime. Returning those
constants verbatim is both more accurate and more readable than structurally
lifting the VM instructions that merely transport the string.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Union
import json
import re

from .luraph_full import Program


_FIELDS = ("e", "p", "o", "h", "underscore", "b")
_SOURCE_WORDS = (
    "local ", "function", " end", "return", "game", "getgenv",
    "loadstring", "hookmetamethod", "getrawmetatable", "task.", "spawn(",
)
_BOOTSTRAP_WORDS = {
    "Luraph", "loadstring", "debug", "getinfo", "getfenv", "setfenv",
    "coroutine", "traceback", "isyieldable", "error in error handling",
}
_KEYWORD_RE = re.compile(r"\b(?:local|function|if|for|while|return|end)\b")
_MINIFIED_SYNTAX = (
    re.compile(r"\blocal\s+[A-Za-z_][A-Za-z0-9_]*\s*="),
    re.compile(r"\bfunction\b(?:\s+[A-Za-z_][A-Za-z0-9_:.]*)?\s*\("),
    re.compile(r"\breturn\b"),
    re.compile(r"\bend\b"),
    re.compile(r"\b[A-Za-z_][A-Za-z0-9_.:]*\s*\("),
)
_MINIFIED_HIGH_SIGNAL = (
    "loadstring", "getgenv", "hookmetamethod", "getrawmetatable",
    "game:getservice", "task.", "spawn(",
)


def iter_string_operands(program: Program):
    """Yield ``(proto, pc, field, value)`` for every direct string operand."""
    for pid in sorted(program.protos):
        proto = program.protos[pid]
        for ins in proto.instructions:
            for field in _FIELDS:
                value = getattr(ins, field)
                if isinstance(value, str):
                    yield pid, ins.pc, field, value


def source_score(value: str) -> int:
    """Return a conservative source-likeness score for a decoded string.

    Multi-line source is scored as before. Minified source is common in
    loadstring payloads, so a long single-line chunk is also accepted when it
    has several independent Luau lexical/syntax signals. Long opaque blobs with
    a few accidental English keywords still fail closed.
    """
    if len(value) < 512:
        return 0
    lower = value.lower()
    keywords = _KEYWORD_RE.findall(lower)
    score = sum(1 for word in _SOURCE_WORDS if word.lower() in lower)
    score += min(4, len(keywords) // 8)

    if value.count("\n") < 3:
        syntax_kinds = sum(1 for pattern in _MINIFIED_SYNTAX if pattern.search(value))
        high_signal = sum(1 for marker in _MINIFIED_HIGH_SIGNAL if marker in lower)
        if score < 3:
            return 0
        if syntax_kinds < 2 and high_signal < 2:
            return 0
        if len(keywords) < 3 and high_signal < 1:
            return 0
        score += min(2, max(0, syntax_kinds - 1))
    return score


def find_embedded_sources(program: Program, minimum_score: int = 3) -> List[dict]:
    """Find unique, source-like string constants, largest first."""
    by_value: Dict[str, dict] = {}
    for pid, pc, field, value in iter_string_operands(program):
        score = source_score(value)
        if score < minimum_score:
            continue
        record = by_value.get(value)
        location = {"proto": pid, "pc": pc, "field": field}
        if record is None:
            by_value[value] = {
                "value": value,
                "bytes": len(value.encode("utf-8", "surrogateescape")),
                "characters": len(value),
                "score": score,
                "locations": [location],
            }
        else:
            record["locations"].append(location)
    return sorted(by_value.values(), key=lambda item: (-item["bytes"], -item["score"]))


def looks_like_luraph_bootstrap(program: Program) -> bool:
    """Detect the small first-stage runtime rather than the final application."""
    strings = {value for _pid, _pc, _field, value in iter_string_operands(program)}
    matches = sum(
        1 for word in _BOOTSTRAP_WORDS if any(word in value for value in strings)
    )
    return matches >= 6 and not find_embedded_sources(program) and len(program.protos) < 600


def _safe_component(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return value.strip("_") or "field"


def write_embedded_sources(
    program: Program,
    out_dir: Union[str, Path],
    dirname: str = "embedded_sources",
) -> dict:
    """Write exact embedded source constants and an index manifest."""
    out = Path(out_dir)
    target = out / dirname
    records = find_embedded_sources(program)
    files: List[str] = []
    public_records: List[dict] = []
    if records:
        target.mkdir(parents=True, exist_ok=True)
    for index, record in enumerate(records, 1):
        first = record["locations"][0]
        filename = "%03d_proto_%04d_pc_%06d_%s_%d.luau" % (
            index,
            first["proto"],
            first["pc"],
            _safe_component(first["field"]),
            record["bytes"],
        )
        path = target / filename
        path.write_text(record["value"], encoding="utf-8", errors="surrogateescape")
        rel = str(path.relative_to(out)).replace("\\", "/")
        files.append(rel)
        public = {key: value for key, value in record.items() if key != "value"}
        public["file"] = rel
        public_records.append(public)

    main_file = None
    if files:
        main = out / "embedded_main.luau"
        main.write_text(records[0]["value"], encoding="utf-8", errors="surrogateescape")
        main_file = "embedded_main.luau"
        files.insert(0, main_file)

    manifest = {
        "format_version": 1,
        "source_chunks": len(records),
        "main": main_file,
        "files": files,
        "chunks": public_records,
    }
    (target if records else out).mkdir(parents=True, exist_ok=True)
    index_path = (target / "index.json") if records else (out / "embedded_sources.json")
    index_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    index_rel = str(index_path.relative_to(out)).replace("\\", "/")
    if index_rel not in manifest["files"]:
        manifest["files"].append(index_rel)
    return manifest
