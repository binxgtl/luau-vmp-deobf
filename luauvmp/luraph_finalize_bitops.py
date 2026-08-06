"""Native fast paths for finite but extremely hot staged bootstrap helpers.

Some Luraph bootstrap trees contain a pure-Luau 32-bit XOR routine. Executing
that routine through the custom VM costs hundreds of virtual instructions per
byte and can consume tens of millions of guarded steps while making normal
forward progress. Detect the exact sample-local prototype fingerprint and
replace only that closure with ``bit32.bxor``. Unknown trees are unchanged.
"""
from __future__ import annotations

import re

from . import luraph_finalize


_INSTALLED = False
_FACTORY_SITE = re.compile(r";q=\(function\(\.\.\.\)", re.S)
_RUNNER_MARKER = 'status("finalising staged prototype tree in lexical sandbox")\n'
_FASTPATH_SOURCE = r'''status("finalising staged prototype tree in lexical sandbox")
local __xorFastpathReported = false
local function __LUAUVMP_FASTPATH(proto)
    local ops = type(proto) == "table" and proto[4] or nil
    -- Sample-local fingerprint of the no-upvalue 99-instruction XOR helper.
    -- The checks are intentionally strict so unrelated prototypes cannot be
    -- replaced merely because they have a similar length.
    if type(ops) == "table" and #ops == 99
        and ops[12] == 6 and ops[14] == 98 and ops[15] == 186
        and ops[68] == 44 and ops[69] == 44 and ops[85] == 88
        and type(proto[3]) == "table" and next(proto[3]) == nil
    then
        if not __xorFastpathReported then
            print("[finalize] enabled native bit32.bxor bootstrap fast path")
            __xorFastpathReported = true
        end
        return function(a, b)
            return bit32.bxor(a, b)
        end
    end
    return nil
end
'''


def install() -> None:
    """Install the strict sample-local XOR fast path."""
    global _INSTALLED
    if _INSTALLED:
        return

    original_instrument = luraph_finalize.instrument_final_vm_source

    def instrument_final_vm_source(vm_source: str) -> str:
        patched = original_instrument(vm_source)
        replacement = (
            ";local __fast=__LUAUVMP_FASTPATH(W);"
            "if __fast then return __fast end;"
            "q=(function(...)"
        )
        patched, count = _FACTORY_SITE.subn(replacement, patched, count=1)
        if count != 1:
            raise luraph_finalize.FinalizeError(
                "native bitop patch could not locate interpreter factory body"
            )
        return patched

    original_builder = luraph_finalize.build_finalize_runner

    def build_finalize_runner(*args, **kwargs):
        runner = original_builder(*args, **kwargs)
        if runner.count(_RUNNER_MARKER) != 1:
            raise luraph_finalize.FinalizeError(
                "native bitop patch could not locate finaliser runner boundary"
            )
        return runner.replace(_RUNNER_MARKER, _FASTPATH_SOURCE, 1)

    instrument_final_vm_source.__name__ = original_instrument.__name__
    build_finalize_runner.__name__ = original_builder.__name__
    luraph_finalize.instrument_final_vm_source = instrument_final_vm_source
    luraph_finalize.build_finalize_runner = build_finalize_runner
    _INSTALLED = True
