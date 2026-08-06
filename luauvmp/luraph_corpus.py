"""Safe corpus scanning and VM-family fingerprinting for Luraph loaders.

The scanner performs only the static loader unpack implemented in
:mod:`luauvmp.luraph`.  It never executes the recovered VM source or payload.
It is intended for regression corpora where each protected file may contain a
separately randomised VM build.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Iterable, Iterator, List, Sequence, Union
import json
import re

from . import luraph


_LUA_KEYWORDS = {
    "and", "break", "do", "else", "elseif", "end", "false", "for",
    "function", "goto", "if", "in", "local", "nil", "not", "or",
    "repeat", "return", "then", "true", "until", "while", "continue",
}

_TOKEN_RE = re.compile(
    r"--\[(=*)\[.*?\]\1\]|--[^\r\n]*|"
    r"\[(=*)\[.*?\]\2\]|"
    r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|"
    r"0[xX][0-9A-Fa-f]+|\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|"
    r"[A-Za-z_][A-Za-z0-9_]*|"
    r"\.\.\.|==|~=|<=|>=|//|<<|>>|::|\.\.|[{}()\[\];,:.+\-*/%^#=<>~]",
    re.S,
)


@dataclass(frozen=True)
class CorpusRecord:
    path: str
    status: str
    source_size: int
    vm_size: int = 0
    bytecode_size: int = 0
    vm_sha256: str = ""
    vm_structural_sha256: str = ""
    error: str = ""


def _literal_token(token: str) -> str:
    if token.startswith("[") or token.startswith("'") or token.startswith('"'):
        n = len(token)
        bucket = 0 if n == 0 else min(9, len(str(n)))
        return "<S%d>" % bucket
    if token[0].isdigit():
        return "<N>"
    return token


def normalise_vm_source(source: Union[str, bytes]) -> str:
    """Return an alpha-renamed structural representation of VM source."""
    if isinstance(source, bytes):
        text = source.decode("utf-8", "surrogateescape")
    else:
        text = source
    names = {}
    out: List[str] = []
    for match in _TOKEN_RE.finditer(text):
        token = match.group(0)
        if token.startswith("--"):
            continue
        if token[0].isalpha() or token[0] == "_":
            if token in _LUA_KEYWORDS:
                out.append(token)
            else:
                out.append(names.setdefault(token, "v%d" % len(names)))
        else:
            out.append(_literal_token(token))
    return " ".join(out)


def fingerprint_vm(vm_source: bytes) -> tuple[str, str]:
    raw = sha256(vm_source).hexdigest()
    structural = sha256(normalise_vm_source(vm_source).encode("utf-8", "surrogateescape")).hexdigest()
    return raw, structural


def iter_lua_files(paths: Sequence[Union[str, Path]]) -> Iterator[Path]:
    seen = set()
    for item in paths:
        path = Path(item)
        candidates = path.rglob("*.lua") if path.is_dir() else (path,)
        for candidate in candidates:
            try:
                key = candidate.resolve()
            except OSError:
                key = candidate.absolute()
            if key in seen:
                continue
            seen.add(key)
            yield candidate


def scan_file(path: Union[str, Path]) -> CorpusRecord:
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return CorpusRecord(str(path), "read_error", 0, error=str(exc))
    try:
        source = raw.decode("utf-8", "surrogateescape")
        if not luraph.detect(source):
            return CorpusRecord(str(path), "not_luraph", len(raw))
        vm, bytecode = luraph.unpack(source)
        vm_hash, structural_hash = fingerprint_vm(vm)
        return CorpusRecord(
            path=str(path), status="ok", source_size=len(raw),
            vm_size=len(vm), bytecode_size=len(bytecode),
            vm_sha256=vm_hash, vm_structural_sha256=structural_hash,
        )
    except Exception as exc:
        return CorpusRecord(str(path), "unpack_error", len(raw), error="%s: %s" %
                            (type(exc).__name__, exc))


def scan_corpus(paths: Sequence[Union[str, Path]]) -> List[CorpusRecord]:
    return [scan_file(path) for path in iter_lua_files(paths)]


def build_manifest(records: Iterable[CorpusRecord]) -> dict:
    rows = list(records)
    families = {}
    for row in rows:
        if row.status == "ok":
            families.setdefault(row.vm_structural_sha256, []).append(row.path)
    return {
        "format_version": 1,
        "samples": len(rows),
        "ok": sum(row.status == "ok" for row in rows),
        "failed": sum(row.status not in ("ok", "not_luraph") for row in rows),
        "not_luraph": sum(row.status == "not_luraph" for row in rows),
        "vm_families": len(families),
        "families": {key: sorted(value) for key, value in sorted(families.items())},
        "records": [asdict(row) for row in rows],
    }


def write_manifest(records: Iterable[CorpusRecord], output: Union[str, Path]) -> dict:
    manifest = build_manifest(records)
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest
