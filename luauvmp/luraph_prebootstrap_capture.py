"""Capture public Luraph v14.7 prototypes before bootstrap closure execution.

The public corpus contains families where replacing only the final application
constructor is too late: the same constructor is invoked elsewhere in the same
state machine to run a bootstrap closure, which can touch Roblox/executor globals
or enter a hot loop.  State-machine execution order is not necessarily source
order, so this layer matches the constructor identity structurally rather than
requiring the bootstrap call to appear textually before the final return.

No Roblox capability is added. If the matching application site is ambiguous,
instrumentation fails closed rather than guessing which closure is safe to
suppress.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Optional

from . import luraph_capture
from . import luraph_generic_capture as generic
from . import luraph_public_v147 as public


_EARLY_PREFIX = re.compile(
    r"(?P<result>[A-Za-z_]\w*)\s*=\s*"
    r"(?P<state>[A-Za-z_]\w*)\s*\[\s*(?P<slot>" + public._NUMBER + r")\s*\]"
    r"\s*\(\s*(?P<root>[A-Za-z_]\w*)\s*,\s*(?P=state)\s*\[\s*"
    r"(?P<environment>" + public._NUMBER + r")\s*\]\s*\)\s*\(",
    re.S,
)


@dataclass(frozen=True)
class EarlySite:
    start: int
    end: int
    result: str
    state: str
    root: str
    slot: int
    environment: int


def _application_call_end(source: str, opening_paren: int) -> Optional[int]:
    """Return the offset after ``;`` for one balanced application call."""
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


def _early_sites(vm_source: str, candidate: generic.Candidate) -> list[EarlySite]:
    final = candidate.final_match
    state = final.group("state")
    root = final.group("root")
    environment = public._integer(final.group("environment"))
    if environment is None:
        return []

    sites = []
    # State-machine branches may place the final-return branch lexically before
    # the branch that actually constructs and invokes the bootstrap closure.
    # Search the complete VM source, then require an exact match on the same
    # state/root/slot/environment tuple as the final constructor.
    for match in _EARLY_PREFIX.finditer(vm_source):
        slot = public._integer(match.group("slot"))
        env = public._integer(match.group("environment"))
        if slot != candidate.slot or env != environment:
            continue
        if match.group("state") != state or match.group("root") != root:
            continue
        opening = match.end() - 1
        end = _application_call_end(vm_source, opening)
        if end is None:
            continue
        sites.append(EarlySite(
            start=match.start(),
            end=end,
            result=match.group("result"),
            state=state,
            root=root,
            slot=slot,
            environment=env,
        ))
    return sites


def _splice(source: str, replacements: list[tuple[int, int, str]]) -> str:
    """Apply non-overlapping source replacements independent of source order."""
    ordered = sorted(replacements, key=lambda item: item[0])
    cursor = 0
    output = []
    for start, end, replacement in ordered:
        if start < cursor or end < start:
            raise luraph_capture.CaptureError(
                "pre-bootstrap instrumentation sites overlapped"
            )
        output.append(source[cursor:start])
        output.append(replacement)
        cursor = end
    output.append(source[cursor:])
    return "".join(output)


def _instrument_prebootstrap(vm_source: str) -> Optional[str]:
    candidate = generic._select(vm_source)
    if candidate is None:
        return None

    sites = _early_sites(vm_source, candidate)
    if not sites:
        return None
    if len(sites) != 1:
        raise luraph_capture.CaptureError(
            "expected one pre-bootstrap constructor invocation for slot %d, found %d"
            % (candidate.slot, len(sites))
        )

    early = sites[0]
    final = candidate.final_match
    early_replacement = "%s=__LUAUVMP_CAPTURE(%s,%s);" % (
        early.result, early.state, early.root
    )

    # Once the application site has captured the prototype tree, the final
    # constructor must not run or call the capture callback a second time.
    # Preserve the exact surrounding return shape by substituting the variable
    # that now holds the callback's deliberately disabled closure.
    if candidate.final_style == "direct":
        final_start, final_end = final.start(), final.end()
        final_replacement = "return %s;" % early.result
    elif candidate.final_style == "wrapped":
        final_start = final.start("constructor")
        final_end = final.end("constructor")
        final_replacement = early.result
    else:
        raise luraph_capture.CaptureError(
            "unsupported pre-bootstrap final constructor style: %s"
            % candidate.final_style
        )

    if not (early.end <= final_start or final_end <= early.start):
        raise luraph_capture.CaptureError(
            "pre-bootstrap and final constructor sites overlapped"
        )

    patched = _splice(vm_source, [
        (early.start, early.end, early_replacement),
        (final_start, final_end, final_replacement),
    ])

    # Fail closed if the exact constructor+call shape survived the mutation.
    for remaining in _EARLY_PREFIX.finditer(patched):
        slot = public._integer(remaining.group("slot"))
        env = public._integer(remaining.group("environment"))
        if (slot == candidate.slot and env == early.environment
                and remaining.group("state") == early.state
                and remaining.group("root") == early.root):
            raise luraph_capture.CaptureError(
                "pre-bootstrap constructor invocation remained after instrumentation"
            )
    return patched


_ORIGINAL_INSTRUMENT = None
_INSTALLED = False


def instrument_vm_source(vm_source: str) -> str:
    patched = _instrument_prebootstrap(vm_source)
    if patched is not None:
        return patched
    if _ORIGINAL_INSTRUMENT is None:
        raise luraph_capture.CaptureError("pre-bootstrap instrumenter is unavailable")
    return _ORIGINAL_INSTRUMENT(vm_source)


def install() -> None:
    global _ORIGINAL_INSTRUMENT, _INSTALLED
    if _INSTALLED:
        return
    _ORIGINAL_INSTRUMENT = luraph_capture.instrument_vm_source
    luraph_capture.instrument_vm_source = instrument_vm_source
    _INSTALLED = True
