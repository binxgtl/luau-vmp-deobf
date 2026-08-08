"""Dispatcher-semantics recovery facade.

The full parser/specialiser is intentionally kept in a standalone script so it
can also run against extracted factories without importing the package.  This
module provides stable validation and I/O helpers used by the CLI/tests.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Mapping, Optional, Union


class SemanticMap(dict):
    """Opcode sources plus recovery-time conditional counts.

    The mapping interface stays compatible with the existing decompiler.  The
    side metadata lets later reachable-instruction proof account for dispatcher
    conditionals without treating a clean/fallback decision as evidence.
    """

    def __init__(self, sources=None, unknown_ifs: Optional[Mapping[int, object]] = None):
        super().__init__(sources or {})
        self.unknown_ifs = dict(unknown_ifs or {})


def load_semantics(path: Union[str, Path]) -> Dict[int, str]:
    with open(path, encoding="utf-8") as source:
        data = json.load(source)
    result = {}
    unknown_ifs = {}
    for k, v in data.items():
        opcode = int(k)
        result[opcode] = v if isinstance(v, str) else v.get("source", "")
        if isinstance(v, dict) and "unknown_ifs" in v:
            unknown_ifs[opcode] = v["unknown_ifs"]
    return SemanticMap(result, unknown_ifs)


def validate_semantics(mapping: Mapping[int, str], required=range(256)) -> None:
    missing = [op for op in required if op not in mapping]
    if missing:
        raise ValueError("missing opcode semantics: %s" % ", ".join(map(str, missing)))
    bad = [op for op, src in mapping.items() if not isinstance(src, str)]
    if bad:
        raise ValueError("non-string opcode semantics: %s" % bad)
