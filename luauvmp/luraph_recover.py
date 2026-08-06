"""Package facade for the sample-local Luraph dispatcher specializer."""
from __future__ import annotations

from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Tuple
import io
import json

from tools import recover_luraph_dispatch as _impl


def _load_runtime_facts(path: Path):
    """Read capture facts, preserving binary strings encoded as hexadecimal."""
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        index, kind, text, truth, equality_class = line.split("\t")
        classes: Tuple[int, ...] = (
            tuple(map(int, equality_class.split(","))) if equality_class else ()
        )
        value: Any
        if kind == "nil":
            value = None
        elif kind == "boolean":
            value = text == "true"
        elif kind == "number":
            value = float(text)
        elif kind == "string":
            value = (bytes.fromhex(text[4:]).decode("utf-8", "surrogateescape")
                     if text.startswith("hex:") else text)
        else:
            value = ("obj", classes)
        values[int(index)] = _impl.AVal(kind, value, classes, truth == "true")
    return values


def recover_dispatch(factory, runtime_facts, output, text_output=None):
    """Recover all opcode semantics from one sample's extracted dispatcher."""
    _impl.SRC = Path(factory)
    _impl.A_TSV = Path(runtime_facts)
    _impl.OUT_JSON = Path(output)
    _impl.OUT_TXT = (Path(text_output) if text_output is not None
                     else _impl.OUT_JSON.with_suffix(".txt"))
    _impl.load_A = _load_runtime_facts
    with redirect_stdout(io.StringIO()):
        _impl.main()
    return json.loads(_impl.OUT_JSON.read_text(encoding="utf-8"))
