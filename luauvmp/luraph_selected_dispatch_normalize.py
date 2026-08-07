"""Canonicalize the dispatcher locals selected from multi-mode public factories."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional
import json
import re

from . import luraph_capture
from . import luraph_semantic_normalize as normalize

_INSTALLED = False
_ORIGINAL_REWRITE = None
_OPERAND_CANONICAL = {"E", "p", "o", "H", "_", "B"}


def _selected_names(data: dict):
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
        return None, None
    if len(opcode_names) != 1 or len(pc_names) != 1:
        raise luraph_capture.CaptureError(
            "selected public dispatcher metadata is inconsistent: opcode=%s pc=%s"
            % (sorted(opcode_names), sorted(pc_names))
        )
    return next(iter(opcode_names)), next(iter(pc_names))


def _selected_register(data: dict, mapping: Dict[str, str], pc_name: str) -> Optional[str]:
    """Infer the register table used by the selected interpreter mode.

    A selected mode can use a different register local from the mode originally
    named in factory metadata.  Count only structural reads of the form
    ``base[operand[pc]]`` across all raw specialized opcode bodies.  Helper,
    environment and operand-array locals are excluded, and a tied maximum is
    rejected instead of guessed.
    """
    operand_names = {
        actual for actual, canonical in mapping.items()
        if canonical in _OPERAND_CANONICAL
    }
    # Identity mappings are normally omitted from CANONICAL_VARS, so include
    # canonical operand names as possible physical locals too.
    operand_names.update(_OPERAND_CANONICAL)
    excluded = set(operand_names) | {pc_name}
    excluded.update(
        actual for actual, canonical in mapping.items()
        if canonical in {"A", "I", "L", "X", "u"}
    )

    counts: Dict[str, int] = {}
    bodies = [
        value.get("source", "")
        for value in data.values()
        if isinstance(value, dict)
    ]
    for operand in sorted(operand_names, key=len, reverse=True):
        pattern = re.compile(
            r"\b(?P<base>[A-Za-z_]\w*)\s*\[\s*"
            + re.escape(operand) + r"\s*\[\s*" + re.escape(pc_name)
            + r"\s*\]\s*\]"
        )
        for body in bodies:
            for match in pattern.finditer(body):
                base = match.group("base")
                if base in excluded:
                    continue
                counts[base] = counts.get(base, 0) + 1
    if not counts:
        return None
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    if len(ordered) > 1 and ordered[0][1] == ordered[1][1]:
        raise luraph_capture.CaptureError(
            "selected public dispatcher register inference is ambiguous: %s"
            % ordered[:4]
        )
    return ordered[0][0]


def _selected_mapping(data: dict, mapping: Dict[str, str]) -> Dict[str, str]:
    """Extend the factory mapping with the dispatcher actually recovered."""
    opcode_name, pc_name = _selected_names(data)
    if opcode_name is None or pc_name is None:
        return dict(mapping)

    result = dict(mapping)
    additions = [(opcode_name, "X"), (pc_name, "u")]
    register = _selected_register(data, result, pc_name)
    if register is not None:
        additions.append((register, "c"))

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
