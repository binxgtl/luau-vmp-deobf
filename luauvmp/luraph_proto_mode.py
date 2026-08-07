"""Preserve the per-prototype interpreter mode for randomized public v14.7 layouts."""
from __future__ import annotations

from pathlib import Path
from typing import Optional
import re

from . import luraph_capture
from . import luraph_semantic_normalize as normalize

_INSTALLED = False
_ORIGINAL_BUILDER = None


def infer_mode_field(factory_source: str) -> Optional[int]:
    """Return the physical prototype slot assigned to the factory mode argument.

    Public multi-mode factories have the shape ``function(proto, env, mode)``
    followed by one direct assignment ``mode = proto[N]`` before dispatch.  We
    require exactly one integral slot; missing/ambiguous evidence means the
    layout is not rewritten by this layer.
    """
    metadata = normalize._metadata(factory_source)
    if metadata.get("PUBLIC_V147") != "1":
        return None
    arguments = normalize._factory_arguments(factory_source)
    if len(arguments) < 3:
        return None
    proto_name, mode_name = arguments[0], arguments[2]
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])" + re.escape(mode_name)
        + r"\s*=\s*\(?\s*" + re.escape(proto_name)
        + r"\s*\[\s*(?P<slot>" + normalize._NUMBER_TEXT
        + r")\s*\]\s*\)?\s*;"
    )
    slots = []
    for match in pattern.finditer(factory_source):
        slot = normalize._integer(match.group("slot"))
        if slot is not None and slot not in slots:
            slots.append(slot)
    if not slots:
        return None
    if len(slots) != 1:
        raise luraph_capture.CaptureError(
            "public prototype mode-field inference is ambiguous: %s" % slots
        )
    return slots[0]


def _rewrite_runner(runner: str, mode_field: Optional[int]) -> str:
    if mode_field is None:
        return runner
    # This marker exists only after the dynamic prototype-layout layer has
    # deliberately discarded the randomized metadata slots. Reference layouts
    # therefore remain byte-for-byte unchanged.
    declaration = "local PROTO_OPCODE_FIELD = "
    if declaration not in runner:
        return runner
    runner = runner.replace(
        declaration,
        "local PROTO_MODE_FIELD = %d\n%s" % (mode_field, declaration),
        1,
    )
    old_metadata = '''            "P", tostring(id), tostring(meta[1]), tostring(meta[2]),
            tostring(meta[3]), tostring(instructionCount), "N",
            "N", "N", "D0",'''
    new_metadata = '''            "P", tostring(id), tostring(meta[1]), tostring(meta[2]),
            tostring(meta[3]), tostring(instructionCount), "N",
            "N", typed(rawget(proto, PROTO_MODE_FIELD)), "D0",'''
    if old_metadata not in runner:
        raise luraph_capture.CaptureError(
            "public prototype mode layer could not find dynamic metadata marker"
        )
    return runner.replace(old_metadata, new_metadata, 1)


def build_lune_runner(patched_vm, bytecode, full_ir, runtime_facts):
    if _ORIGINAL_BUILDER is None:
        raise luraph_capture.CaptureError("prototype-mode capture layer unavailable")
    runner = _ORIGINAL_BUILDER(patched_vm, bytecode, full_ir, runtime_facts)
    factory = Path(patched_vm).with_name("interpreter.factory.luau")
    if not factory.is_file():
        return runner
    source = factory.read_text(encoding="utf-8", errors="surrogateescape")
    return _rewrite_runner(runner, infer_mode_field(source))


def install() -> None:
    global _INSTALLED, _ORIGINAL_BUILDER
    if _INSTALLED:
        return
    _ORIGINAL_BUILDER = luraph_capture.build_lune_runner
    luraph_capture.build_lune_runner = build_lune_runner
    _INSTALLED = True
