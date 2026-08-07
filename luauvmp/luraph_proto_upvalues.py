"""Preserve randomized prototype upvalue-descriptor metadata.

The reference v14.7 layout stores a child's capture descriptors in prototype
slot 3, which the original typed IR already serialises as ``Proto.field3``.
Public randomized families move that table (observed slots 4 and 11), while the
dynamic layout adapter intentionally wrote ``N`` for metadata it had not proven.

The closure-constructor opcode itself is authoritative: it loads a prototype
from one instruction array, immediately reads one fixed numeric field, takes the
length of that table, and passes the same prototype to the exact factory helper
slot recorded by the extractor. Public builds may contain several dispatcher
loops/modes, so no single loop's PC variable is assumed here. Ambiguous fields
still fail closed and no closure is invoked.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional
import re

from . import luraph_capture
from . import luraph_semantic_normalize as normalize


_INSTALLED = False
_ORIGINAL_BUILDER = None
_ID = r"[A-Za-z_]\w*"


def infer_upvalue_field(factory_source: str) -> Optional[int]:
    metadata = normalize._metadata(factory_source)
    if metadata.get("PUBLIC_V147") != "1":
        return None
    helper = metadata.get("HELPER_VAR")
    factory_slot = normalize._integer(metadata.get("FACTORY_SLOT", ""))
    if not helper or factory_slot is None:
        return None

    number = normalize._NUMBER_TEXT
    # Do not bind the instruction index to one selected dispatcher PC. The same
    # extracted factory can contain multiple mode-specific dispatchers with
    # different PC locals. The constructor slot + same-prototype def/use chain
    # is the stronger identity.
    pattern = re.compile(
        r"(?P<proto>" + _ID + r")\s*=\s*\(?\s*"
        r"(?P<array>" + _ID + r")\s*\[\s*(?P<index>" + _ID + r")\s*\]"
        r"\s*\)?\s*;\s*"
        r"(?P<descriptors>" + _ID + r")\s*=\s*\(?\s*(?P=proto)"
        r"\s*\[\s*(?P<field>" + number + r")\s*\]\s*\)?\s*;\s*"
        r"(?P<count>" + _ID + r")\s*=\s*\(?\s*#\s*(?P=descriptors)"
        r"\s*\)?\s*;.{0,256}?"
        r"(?P<closure>" + _ID + r")\s*=\s*" + re.escape(helper)
        + r"\s*\[\s*" + str(factory_slot) + r"(?:\.0)?\s*\]\s*"
        r"\(\s*(?P=proto)\s*,",
        re.S,
    )
    fields = []
    for match in pattern.finditer(factory_source):
        field = normalize._integer(match.group("field"))
        if field is not None and field not in fields:
            fields.append(field)
    if not fields:
        return None
    if len(fields) != 1:
        raise luraph_capture.CaptureError(
            "public prototype upvalue-field inference is ambiguous: %s" % fields
        )
    return fields[0]


def _rewrite_runner(runner: str, field: Optional[int]) -> str:
    if field is None:
        return runner
    # Dynamic layouts define this marker.  The reference layout already records
    # proto[3] through the legacy P row and must remain byte-for-byte unchanged.
    declaration = "local PROTO_OPCODE_FIELD = "
    if declaration not in runner:
        return runner
    runner = runner.replace(
        declaration,
        "local PROTO_UPVALUE_FIELD = %d\n%s" % (field, declaration),
        1,
    )

    with_mode = '''            "P", tostring(id), tostring(meta[1]), tostring(meta[2]),
            tostring(meta[3]), tostring(instructionCount), "N",
            "N", typed(rawget(proto, PROTO_MODE_FIELD)), "D0",'''
    new_with_mode = '''            "P", tostring(id), tostring(meta[1]), tostring(meta[2]),
            tostring(meta[3]), tostring(instructionCount), "N",
            typed(rawget(proto, PROTO_UPVALUE_FIELD)), typed(rawget(proto, PROTO_MODE_FIELD)), "D0",'''
    if with_mode in runner:
        return runner.replace(with_mode, new_with_mode, 1)

    without_mode = '''            "P", tostring(id), tostring(meta[1]), tostring(meta[2]),
            tostring(meta[3]), tostring(instructionCount), "N",
            "N", "N", "D0",'''
    new_without_mode = '''            "P", tostring(id), tostring(meta[1]), tostring(meta[2]),
            tostring(meta[3]), tostring(instructionCount), "N",
            typed(rawget(proto, PROTO_UPVALUE_FIELD)), "N", "D0",'''
    if without_mode in runner:
        return runner.replace(without_mode, new_without_mode, 1)

    raise luraph_capture.CaptureError(
        "public prototype upvalue layer could not find dynamic metadata marker"
    )


def build_lune_runner(patched_vm, bytecode, full_ir, runtime_facts):
    if _ORIGINAL_BUILDER is None:
        raise luraph_capture.CaptureError("prototype-upvalue capture layer unavailable")
    runner = _ORIGINAL_BUILDER(patched_vm, bytecode, full_ir, runtime_facts)
    factory = Path(patched_vm).with_name("interpreter.factory.luau")
    if not factory.is_file():
        return runner
    source = factory.read_text(encoding="utf-8", errors="surrogateescape")
    return _rewrite_runner(runner, infer_upvalue_field(source))


def install() -> None:
    global _INSTALLED, _ORIGINAL_BUILDER
    if _INSTALLED:
        return
    _ORIGINAL_BUILDER = luraph_capture.build_lune_runner
    luraph_capture.build_lune_runner = build_lune_runner
    _INSTALLED = True
