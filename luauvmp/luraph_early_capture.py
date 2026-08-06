"""Fail-closed Luraph root-prototype capture instrumentation.

Luraph v14.x may construct *and immediately call* the root closure inside a
parser state-machine helper before the top-level parser returns. Capturing only
the final closure return is therefore too late. This module intercepts the
earlier construction-and-call site and makes the later return pass through the
disabled callback result.
"""
from __future__ import annotations

import re


_PAYLOAD_EXECUTION = re.compile(
    r"(?P<result>[A-Za-z_]\w*)\s*=\s*"
    r"(?P<state>[A-Za-z_]\w*)\[50(?:\.0)?\]\("
    r"(?P<root>[A-Za-z_]\w*),(?P=state)\[1(?:\.0)?\]\)\("
    r"[^;]{1,1000}?\);"
)
_FINAL_CLOSURE_RETURN = re.compile(
    r"return\s+(?P<state>[A-Za-z_]\w*)\[50(?:\.0)?\]\("
    r"(?P<root>[A-Za-z_]\w*),(?P=state)\[1(?:\.0)?\]\);end,"
)


def instrument_vm_source(vm_source: str) -> str:
    """Capture the root prototype before any protected instruction can run."""
    # Import lazily to avoid a package-initialisation cycle.
    from .luraph_capture import CaptureError

    execution_matches = list(_PAYLOAD_EXECUTION.finditer(vm_source))
    final_matches = list(_FINAL_CLOSURE_RETURN.finditer(vm_source))
    if len(execution_matches) != 1:
        raise CaptureError(
            "expected one early payload execution site, found %d"
            % len(execution_matches)
        )
    if len(final_matches) != 1:
        raise CaptureError(
            "expected one final payload-closure construction site, found %d"
            % len(final_matches)
        )

    execution = execution_matches[0]
    final = final_matches[0]
    if execution.start() >= final.start():
        raise CaptureError("payload execution site was not before the final closure return")

    execution_replacement = "%s=__LUAUVMP_CAPTURE(%s,%s);" % (
        execution.group("result"),
        execution.group("state"),
        execution.group("root"),
    )
    final_replacement = "return %s;end," % final.group("root")

    patched = (
        vm_source[:execution.start()]
        + execution_replacement
        + vm_source[execution.end():final.start()]
        + final_replacement
        + vm_source[final.end():]
    )
    if _PAYLOAD_EXECUTION.search(patched):
        raise CaptureError("early payload execution site remained after instrumentation")
    return patched
