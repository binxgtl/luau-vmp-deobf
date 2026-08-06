"""Generic structural capture for randomized Luraph v14.7 VM sources.

Some public samples use the legacy two-stream container but randomize the
factory slot, while others keep the interpreter in a single-stream wrapper.
This layer first delegates to the verified slot-50/slot-59 instrumenters. Only
when they reject the source does it infer a factory from a matching function
assignment, dispatcher loop, and final constructor for the same numeric slot.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional
import json

from . import luraph_capture
from . import luraph_public_v147 as public


_LEGACY_NESTED = {
    32: {
        5: "math.modf", 6: "math.pi", 7: "bit32.bor", 8: "bit32.bxor",
        9: "string.byte", 10: "bit32.countrz", 11: "bit32.band",
        12: "bit32.rshift", 13: "bit32.countlz", 14: "string.unpack",
        15: "bit32.lrotate", 16: "math.ceil", 17: "string.len",
        18: "string.packsize", 19: "bit32.lshift", 20: "bit32.rrotate",
        21: "math.floor", 22: "bit32.bnot",
    }
}


@dataclass(frozen=True)
class Candidate:
    slot: int
    helper: str
    opcode: str
    function_source: str
    final_match: object
    nested_helpers: Dict[int, Dict[int, str]]


def _select(vm_source: str) -> Optional[Candidate]:
    finals = []
    for match in public._PUBLIC_FINAL_RETURN.finditer(vm_source):
        slot = public._integer(match.group("slot"))
        environment = public._integer(match.group("environment"))
        if slot is not None and environment == 1:
            finals.append((slot, match))
    if not finals:
        return None
    final_by_slot = {}
    for slot, match in finals:
        final_by_slot.setdefault(slot, []).append(match)

    candidates = []
    for match in public._FACTORY_ASSIGN.finditer(vm_source):
        slot = public._integer(match.group("slot"))
        if slot not in final_by_slot:
            continue
        try:
            function_end = public._function_end(vm_source, match.start("function"))
        except luraph_capture.CaptureError:
            continue
        function_source = vm_source[match.start("function"):function_end]
        dispatch = public._DISPATCH_LOCAL.search(function_source)
        if dispatch is None:
            continue
        if len(final_by_slot[slot]) != 1:
            raise luraph_capture.CaptureError(
                "factory slot %d has %d final constructors"
                % (slot, len(final_by_slot[slot]))
            )
        nested = public._nested_helpers(vm_source)
        if not nested:
            nested = {table: dict(slots) for table, slots in _LEGACY_NESTED.items()}
        candidates.append(Candidate(
            slot=slot,
            helper=match.group("helper"),
            opcode=dispatch.group("opcode"),
            function_source=function_source,
            final_match=final_by_slot[slot][0],
            nested_helpers=nested,
        ))

    if not candidates:
        return None
    if len(candidates) != 1:
        details = ", ".join(
            "slot %d (%d chars)" % (item.slot, len(item.function_source))
            for item in candidates
        )
        raise luraph_capture.CaptureError(
            "ambiguous structural Luraph factories: %s" % details
        )
    return candidates[0]


def _render_factory(candidate: Candidate) -> str:
    marker = (
        "-- LUAUVMP_PUBLIC_V147=1\n"
        "-- LUAUVMP_FACTORY_SLOT=%d\n"
        "-- LUAUVMP_HELPER_VAR=%s\n"
        "-- LUAUVMP_DISPATCH_VAR=%s\n"
        "-- LUAUVMP_NESTED_HELPERS=%s\n" % (
            candidate.slot,
            candidate.helper,
            candidate.opcode,
            json.dumps(candidate.nested_helpers, separators=(",", ":"),
                       sort_keys=True),
        )
    )
    return marker + "(" + candidate.function_source + ")"


def extract_interpreter_factory(vm_source: str) -> str:
    original_error = None
    if _ORIGINAL_FACTORY is not None:
        try:
            return _ORIGINAL_FACTORY(vm_source)
        except luraph_capture.CaptureError as exc:
            original_error = exc
    candidate = _select(vm_source)
    if candidate is not None:
        return _render_factory(candidate)
    if original_error is not None:
        raise original_error
    raise luraph_capture.CaptureError("factory extractor is unavailable")


def instrument_vm_source(vm_source: str) -> str:
    original_error = None
    if _ORIGINAL_INSTRUMENT is not None:
        try:
            return _ORIGINAL_INSTRUMENT(vm_source)
        except luraph_capture.CaptureError as exc:
            original_error = exc
    candidate = _select(vm_source)
    if candidate is None:
        if original_error is not None:
            raise original_error
        raise luraph_capture.CaptureError("VM instrumenter is unavailable")
    match = candidate.final_match
    replacement = "return __LUAUVMP_CAPTURE(%s,%s);" % (
        match.group("state"), match.group("root")
    )
    patched = vm_source[:match.start()] + replacement + vm_source[match.end():]
    for remaining in public._PUBLIC_FINAL_RETURN.finditer(patched):
        if public._integer(remaining.group("slot")) == candidate.slot:
            raise luraph_capture.CaptureError(
                "final constructor for inferred slot %d remained after instrumentation"
                % candidate.slot
            )
    return patched


_ORIGINAL_FACTORY = None
_ORIGINAL_INSTRUMENT = None
_INSTALLED = False


def install() -> None:
    global _ORIGINAL_FACTORY, _ORIGINAL_INSTRUMENT, _INSTALLED
    if _INSTALLED:
        return
    _ORIGINAL_FACTORY = luraph_capture.extract_interpreter_factory
    _ORIGINAL_INSTRUMENT = luraph_capture.instrument_vm_source
    luraph_capture.extract_interpreter_factory = extract_interpreter_factory
    luraph_capture.instrument_vm_source = instrument_vm_source
    _INSTALLED = True
