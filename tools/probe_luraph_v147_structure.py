"""Print bounded structural excerpts from one public Luraph v14.7 wrapper."""
from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path
import json
import re

from luauvmp import luraph_loader


_SLOT_59_RETURN = re.compile(
    r"return\s+([A-Za-z_]\w*)\s*\[\s*(?:59(?:\.0)?|0[xX]0*3[bB])\s*\]\s*\("
    r"\s*([A-Za-z_]\w*)\s*,\s*\1\s*\[\s*(?:1(?:\.0)?|0[xX]0*1)\s*\]\s*\)",
    re.S,
)
_DISPATCH = re.compile(
    r"while\s+true\s+do\s+local\s+([A-Za-z_]\w*)\s*=\s*\(?(?:[A-Za-z_]\w*)\s*\[",
    re.S,
)
_FUNCTION = re.compile(r"\bfunction\s*\(([^)]*)\)", re.S)


def _excerpt(source: str, start: int, end: int, radius: int = 420) -> str:
    left = max(0, start - radius)
    right = min(len(source), end + radius)
    return source[left:right].replace("\n", "\\n")


def _redact_streams(source: str) -> str:
    matches = list(luraph_loader._LONG_BRACKET.finditer(source))
    for match in reversed(matches):
        payload = match.group(2)
        if payload.startswith("LPH"):
            replacement = "[=[LPH<redacted:%d>]=]" % len(payload)
            source = source[:match.start()] + replacement + source[match.end():]
    return source


def probe(path: Path) -> dict:
    source = path.read_text(encoding="utf-8", errors="surrogateescape")
    compact = _redact_streams(source)
    returns = []
    for match in _SLOT_59_RETURN.finditer(compact):
        returns.append({
            "state": match.group(1),
            "root": match.group(2),
            "start": match.start(),
            "excerpt": _excerpt(compact, match.start(), match.end()),
        })
    dispatches = []
    for match in _DISPATCH.finditer(compact):
        before = list(_FUNCTION.finditer(compact, 0, match.start()))
        nearest = before[-1] if before else None
        dispatches.append({
            "opcode_local": match.group(1),
            "start": match.start(),
            "nearest_function_args": nearest.group(1) if nearest else None,
            "nearest_function_start": nearest.start() if nearest else None,
            "excerpt": _excerpt(compact, match.start(), match.end()),
        })
    decompress = []
    for match in re.finditer(r"DecompressBuffer", compact):
        decompress.append(_excerpt(compact, match.start(), match.end(), 240))
    return {
        "sample": path.name,
        "source_chars": len(source),
        "redacted_chars": len(compact),
        "slot59_return_count": len(returns),
        "slot59_returns": returns[:12],
        "dispatch_count": len(dispatches),
        "dispatches": dispatches[:12],
        "decompress_sites": decompress[:4],
    }


def main() -> int:
    parser = ArgumentParser()
    parser.add_argument("sample", type=Path)
    args = parser.parse_args()
    print("STRUCTURE_PROBE=" + json.dumps(probe(args.sample), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
