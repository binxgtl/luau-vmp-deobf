"""Package facade for sample-local Luraph dispatcher specialization."""
from __future__ import annotations

from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Tuple
import io
import json

from tools import recover_luraph_dispatch as _legacy
from tools import recover_luraph_dispatch_v147 as _public


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
        values[int(index)] = _legacy.AVal(kind, value, classes, truth == "true")
    return values


def recover_dispatch(factory, runtime_facts, output, text_output=None):
    """Recover all opcode semantics from one sample's extracted dispatcher."""
    factory_path = Path(factory)
    output_path = Path(output)
    text_path = (Path(text_output) if text_output is not None
                 else output_path.with_suffix(".txt"))
    source = factory_path.read_text(encoding="utf-8", errors="surrogateescape")
    values = _load_runtime_facts(Path(runtime_facts))

    if "LUAUVMP_PUBLIC_V147=1" in source:
        return _public.recover(factory_path, values, output_path, text_path)

    _legacy.SRC = factory_path
    _legacy.A_TSV = Path(runtime_facts)
    _legacy.OUT_JSON = output_path
    _legacy.OUT_TXT = text_path
    _legacy.load_A = _load_runtime_facts
    with redirect_stdout(io.StringIO()):
        _legacy.main()
    return json.loads(output_path.read_text(encoding="utf-8"))
