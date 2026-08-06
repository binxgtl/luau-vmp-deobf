"""Native fast paths for exact hot staged-bootstrap helper fingerprints.

The captured Luraph bootstrap spends almost all of its time interpreting three
small pure helpers: arithmetic 32-bit XOR, one-based bit extraction, and a
four-byte word decoder assembled from those primitives.  Replacing only their
exact sample-local prototype shapes keeps unknown trees on the ordinary VM path
while making the finite decoder practical to execute inside the sandbox.
"""
from __future__ import annotations

import re

from . import luraph_finalize


_INSTALLED = False
_FACTORY_SITE = re.compile(r";q=\(function\(\.\.\.\)", re.S)
_RUNNER_MARKER = 'status("finalising staged prototype tree in lexical sandbox")\n'
_FASTPATH_SOURCE = r'''status("finalising staged prototype tree in lexical sandbox")
local __fastpathReports = {}
local function __LUAUVMP_REPORT_FASTPATH(name)
    if not __fastpathReports[name] then
        print("[finalize] enabled native " .. name .. " bootstrap fast path")
        __fastpathReports[name] = true
    end
end
local function __LUAUVMP_FASTPATH(proto, cells)
    local ops = type(proto) == "table" and proto[4] or nil
    local constants = type(proto) == "table" and proto[3] or nil
    if type(ops) ~= "table" then return nil end

    -- Exact no-upvalue 99-instruction arithmetic XOR helper.
    if #ops == 99
        and ops[1] == 186 and ops[12] == 6 and ops[14] == 98
        and ops[15] == 186 and ops[68] == 44 and ops[69] == 44
        and ops[85] == 88 and ops[99] == 186
        and type(constants) == "table" and next(constants) == nil
    then
        __LUAUVMP_REPORT_FASTPATH("bit32.bxor")
        return function(a, b)
            return bit32.bxor(a, b)
        end
    end

    -- Exact no-upvalue 104-instruction helper used as extract(value, first,
    -- last), with one-based inclusive bit positions.  The third argument is
    -- optional and then selects a single bit.
    if #ops == 104
        and ops[1] == 186 and ops[2] == 79 and ops[5] == 41
        and ops[8] == 128 and ops[9] == 135 and ops[10] == 35
        and ops[17] == 6 and ops[18] == 189 and ops[81] == 135
        and ops[84] == 104 and ops[95] == 14 and ops[104] == 186
        and type(constants) == "table" and next(constants) == nil
        and cells == false
    then
        __LUAUVMP_REPORT_FASTPATH("one-based bit extraction")
        return function(value, firstBit, lastBit)
            local finalBit = lastBit or firstBit
            local width = finalBit - firstBit + 1
            return math.floor(value / (2 ^ (firstBit - 1))) % (2 ^ width)
        end
    end

    -- Exact 33-instruction four-byte word helper.  Preserve its captured
    -- string-byte and XOR upvalues instead of assuming their identities.
    if #ops == 33
        and ops[1] == 186 and ops[2] == 153 and ops[3] == 153
        and ops[6] == 43 and ops[10] == 93 and ops[11] == 98
        and ops[14] == 98 and ops[19] == 93 and ops[20] == 98
        and ops[27] == 93 and ops[31] == 93 and ops[33] == 14
        and type(cells) == "table"
        and type(cells[0]) == "function"
        and type(cells[1]) == "string" and #cells[1] == 8
        and type(cells[2]) == "function"
    then
        local byteRange, encoded, xor = cells[0], cells[1], cells[2]
        __LUAUVMP_REPORT_FASTPATH("four-byte word decode")
        return function()
            local b1, b2, b3, b4 = byteRange(encoded, 1, 4)
            return xor(b4, 64) * 16777216
                + xor(b3, 32) * 65536
                + xor(b2, 16) * 256
                + xor(b1, 8)
        end
    end

    return nil
end
'''


def install() -> None:
    """Install strict sample-local native helper fast paths."""
    global _INSTALLED
    if _INSTALLED:
        return

    original_instrument = luraph_finalize.instrument_final_vm_source

    def instrument_final_vm_source(vm_source: str) -> str:
        patched = original_instrument(vm_source)
        replacement = (
            ";local __fast=__LUAUVMP_FASTPATH(W,P);"
            "if __fast then return __fast end;"
            "q=(function(...)"
        )
        patched, count = _FACTORY_SITE.subn(replacement, patched, count=1)
        if count != 1:
            raise luraph_finalize.FinalizeError(
                "native helper patch could not locate interpreter factory body"
            )
        return patched

    original_builder = luraph_finalize.build_finalize_runner

    def build_finalize_runner(*args, **kwargs):
        runner = original_builder(*args, **kwargs)
        if runner.count(_RUNNER_MARKER) != 1:
            raise luraph_finalize.FinalizeError(
                "native helper patch could not locate finaliser runner boundary"
            )
        return runner.replace(_RUNNER_MARKER, _FASTPATH_SOURCE, 1)

    instrument_final_vm_source.__name__ = original_instrument.__name__
    build_finalize_runner.__name__ = original_builder.__name__
    luraph_finalize.instrument_final_vm_source = instrument_final_vm_source
    luraph_finalize.build_finalize_runner = build_finalize_runner
    _INSTALLED = True
