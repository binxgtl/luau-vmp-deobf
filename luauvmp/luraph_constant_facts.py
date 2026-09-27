"""Replay observed operand values from an external capture, without executing code.

The capture producer is deliberately separate from this module. A fact is only
accepted for the exact source IR and exact original cell it describes. This
keeps dynamic observations auditable and prevents a stale capture from silently
changing the output of a different sample.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

from .luraph_full import OpaqueTable, ProtoRef, Program, decode_typed


_FIELDS = {"E": "e", "p": "p", "o": "o", "H": "h", "_": "underscore", "B": "b"}


class FactError(ValueError):
    """An observation cannot be safely applied to the captured IR."""


def replay_facts(program: Program, ir_path: Path, facts_path: Path) -> dict:
    """Apply a versioned set of observations atomically to an in-memory tree.

    JSON cells use the same typed tokens as full_ir.tsv. The caller must use
    the returned manifest as provenance; no source or capture is run here.
    """
    ir_digest = hashlib.sha256(Path(ir_path).read_bytes()).hexdigest()
    facts_bytes = Path(facts_path).read_bytes()
    data = json.loads(facts_bytes)
    if not isinstance(data, dict) or data.get("format_version") != 1:
        raise FactError("unsupported constant facts format")
    if data.get("ir_sha256") != ir_digest:
        raise FactError("constant facts do not match input IR SHA-256")
    facts = data.get("facts")
    if not isinstance(facts, list):
        raise FactError("facts must be a list")

    locations = {(pid, ins.pc): ins for pid, proto in program.protos.items()
                 for ins in proto.instructions}
    changes = []
    seen = set()
    for row in facts:
        if not isinstance(row, dict):
            raise FactError("fact must be an object")
        pid, pc, field = row.get("proto"), row.get("pc"), row.get("operand")
        if type(pid) is not int or type(pc) is not int or field not in _FIELDS:
            raise FactError("invalid proto, pc, or operand in fact")
        key = (pid, pc, field)
        if key in seen:
            raise FactError("duplicate fact for proto %d pc %d %s" % key)
        seen.add(key)
        ins = locations.get((pid, pc))
        if ins is None:
            raise FactError("unknown proto %d pc %d" % (pid, pc))
        before, after = row.get("before"), row.get("after")
        if not isinstance(before, str) or not isinstance(after, str):
            raise FactError("fact cells must be typed strings")
        try:
            old, new = decode_typed(before), decode_typed(after)
        except (ValueError, UnicodeError) as exc:
            raise FactError("invalid typed cell in fact") from exc
        attr = _FIELDS[field]
        if type(old) is not type(getattr(ins, attr)) or old != getattr(ins, attr):
            raise FactError("original cell mismatch at proto %d pc %d %s" % key)
        if isinstance(new, (OpaqueTable, ProtoRef)):
            raise FactError("observed cell is not a concrete value")
        if old == new and type(old) is type(new):
            raise FactError("fact does not change its operand")
        changes.append((ins, attr, new))

    # Validation completes before any in-memory mutation.
    replacements = {}
    for ins, attr, new in changes:
        identity = id(ins)
        if identity not in replacements:
            replacements[identity] = ins
        replacements[identity] = replace(replacements[identity], **{attr: new})
    for proto in program.protos.values():
        proto.instructions[:] = [replacements.get(id(ins), ins) for ins in proto.instructions]
    return {"format_version": 1, "ir_sha256": ir_digest,
            "facts_sha256": hashlib.sha256(facts_bytes).hexdigest(),
            "applied": len(changes), "replay_executed_payload": False,
            "strict_quality_gate": False, "path_complete": False}
