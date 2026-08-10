"""Fail-closed capture for Luraph factories that are immediately invoked.

Some v14.7 wrappers do not expose the constructor through the legacy final
``return state[slot](root, state[env])`` shape. Instead, the randomized helper
slot is assigned a normal dispatcher factory and later used exactly once as:

    result = helpers[slot](root, environment)(...)

The second call would execute the protected root closure. This layer ties that
application site to the same helper table and numeric slot as a structurally
identified dispatcher factory, then replaces the complete application with the
existing capture callback before any root instruction can run.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Dict, Optional

from . import luraph_capture
from . import luraph_generic_capture as generic
from . import luraph_public_v147 as public


_IMMEDIATE_APPLICATION = re.compile(
    r"(?P<result>[A-Za-z_]\w*)\s*=\s*"
    r"(?P<helper>[A-Za-z_]\w*)\s*\[\s*"
    r"(?P<slot>" + public._NUMBER + r")\s*\]\s*"
    r"\(\s*(?P<root>[A-Za-z_]\w*)\s*,\s*"
    r"(?P<environment>[A-Za-z_]\w*)\s*\)\s*\(",
    re.S,
)


@dataclass(frozen=True)
class ApplicationSite:
    start: int
    end: int
    result: str
    helper: str
    root: str
    environment: str
    slot: int


@dataclass(frozen=True)
class Candidate:
    slot: int
    helper: str
    opcode: str
    function_source: str
    application: ApplicationSite
    nested_helpers: Dict[int, Dict[int, str]]


def _application_call_end(source: str, opening_paren: int) -> Optional[int]:
    """Return the offset after one balanced immediate application call."""
    depth = 0
    started = False
    for token in public._tokens(source, opening_paren):
        if token.kind == "string":
            continue
        if token.value == "(":
            depth += 1
            started = True
        elif token.value == ")" and started:
            depth -= 1
            if depth == 0:
                cursor = token.end
                while cursor < len(source) and source[cursor].isspace():
                    cursor += 1
                if cursor < len(source) and source[cursor] == ";":
                    return cursor + 1
                return None
    return None


def _applications(vm_source: str, helper: str, slot: int) -> list[ApplicationSite]:
    sites = []
    for match in _IMMEDIATE_APPLICATION.finditer(vm_source):
        parsed_slot = public._integer(match.group("slot"))
        if parsed_slot != slot or match.group("helper") != helper:
            continue
        opening = match.end() - 1
        end = _application_call_end(vm_source, opening)
        if end is None:
            continue
        sites.append(ApplicationSite(
            start=match.start(),
            end=end,
            result=match.group("result"),
            helper=helper,
            root=match.group("root"),
            environment=match.group("environment"),
            slot=slot,
        ))
    return sites


def _select(vm_source: str) -> Optional[Candidate]:
    candidates = []
    for match in generic._FACTORY_ASSIGN.finditer(vm_source):
        slot = public._integer(match.group("slot"))
        if slot is None:
            continue
        try:
            function_end = public._function_end(vm_source, match.start("function"))
        except luraph_capture.CaptureError:
            continue
        function_source = vm_source[match.start("function"):function_end]
        dispatch = public._DISPATCH_LOCAL.search(function_source)
        if dispatch is None:
            continue

        helper = match.group("helper")
        sites = _applications(vm_source, helper, slot)
        if not sites:
            continue
        if len(sites) != 1:
            raise luraph_capture.CaptureError(
                "dispatcher factory %s[%d] has %d immediate applications"
                % (helper, slot, len(sites))
            )

        nested = public._nested_helpers(vm_source)
        if not nested:
            nested = {
                table: dict(slots)
                for table, slots in generic._LEGACY_NESTED.items()
            }
        candidates.append(Candidate(
            slot=slot,
            helper=helper,
            opcode=dispatch.group("opcode"),
            function_source=function_source,
            application=sites[0],
            nested_helpers=nested,
        ))

    if not candidates:
        return None
    if len(candidates) != 1:
        details = ", ".join(
            "%s[%d]/%s" % (item.helper, item.slot, item.opcode)
            for item in candidates
        )
        raise luraph_capture.CaptureError(
            "ambiguous immediate-application Luraph factories: %s" % details
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
    raise luraph_capture.CaptureError("immediate factory extractor is unavailable")


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
        raise luraph_capture.CaptureError("immediate factory instrumenter is unavailable")

    site = candidate.application
    # Lua evaluates the RHS before assigning result, so this is safe even when
    # result and root are the same randomized local (for example T=... (T,W)).
    replacement = "%s=__LUAUVMP_CAPTURE(%s,%s);" % (
        site.result, site.helper, site.root
    )
    patched = vm_source[:site.start] + replacement + vm_source[site.end:]

    remaining = _applications(patched, candidate.helper, candidate.slot)
    if remaining:
        raise luraph_capture.CaptureError(
            "immediate constructor for %s[%d] remained after instrumentation"
            % (candidate.helper, candidate.slot)
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
