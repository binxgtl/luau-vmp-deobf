"""Canonicalize the dispatcher locals selected from multi-mode public factories."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional
import json

from . import luraph_capture
from . import luraph_semantic_normalize as normalize

_INSTALLED = False
_ORIGINAL_REWRITE = None


def _selected_mapping(data: dict, mapping: Dict[str, str]) -> Dict[str, str]:
    """Extend the factory mapping with the dispatcher actually recovered.

    ``luraph_dispatch_select`` may choose a different interpreter mode than the
    legacy extractor marker.  Every opcode row records that chosen opcode and PC
    local.  They must be identical across the table; otherwise recovery is
    internally inconsistent and we fail closed instead of silently rewriting
    unrelated variables.
    """
    opcode_names = {
        value.get("dispatch_opcode_name")
        for value in data.values()
        if isinstance(value, dict) and value.get("dispatch_opcode_name")
    }
    pc_names = {
        value.get("dispatch_pc_name")
        for value in data.values()
        if isinstance(value, dict) and value.get("dispatch_pc_name")
    }
    if not opcode_names and not pc_names:
        return dict(mapping)
    if len(opcode_names) != 1 or len(pc_names) != 1:
        raise luraph_capture.CaptureError(
            "selected public dispatcher metadata is inconsistent: opcode=%s pc=%s"
            % (sorted(opcode_names), sorted(pc_names))
        )

    result = dict(mapping)
    additions = (
        (next(iter(opcode_names)), "X"),
        (next(iter(pc_names)), "u"),
    )
    for name, canonical in additions:
        existing = result.get(name)
        if existing is not None and existing != canonical:
            raise luraph_capture.CaptureError(
                "selected public dispatcher local %s conflicts with canonical %s"
                % (name, existing)
            )
        result[name] = canonical
    return result


def _rewrite_semantics(output: Path, text_output: Optional[Path],
                       mapping: Dict[str, str]):
    data = json.loads(Path(output).read_text(encoding="utf-8"))
    effective = _selected_mapping(data, mapping)
    return _ORIGINAL_REWRITE(output, text_output, effective)


def install() -> None:
    global _INSTALLED, _ORIGINAL_REWRITE
    if _INSTALLED:
        return
    _ORIGINAL_REWRITE = normalize._rewrite_semantics
    normalize._rewrite_semantics = _rewrite_semantics
    _INSTALLED = True
