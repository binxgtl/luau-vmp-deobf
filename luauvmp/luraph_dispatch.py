"""Dispatcher-semantics recovery facade.

The full parser/specialiser is intentionally kept in a standalone script so it
can also run against extracted factories without importing the package.  This
module provides stable validation and I/O helpers used by the CLI/tests.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Mapping, Union


def load_semantics(path: Union[str, Path]) -> Dict[int, str]:
    data = json.load(open(path, encoding="utf-8"))
    result = {}
    for k, v in data.items():
        result[int(k)] = v if isinstance(v, str) else v.get("source", "")
    return result


def validate_semantics(mapping: Mapping[int, str], required=range(256)) -> None:
    missing = [op for op in required if op not in mapping]
    if missing:
        raise ValueError("missing opcode semantics: %s" % ", ".join(map(str, missing)))
    bad = [op for op, src in mapping.items() if not isinstance(src, str)]
    if bad:
        raise ValueError("non-string opcode semantics: %s" % bad)
