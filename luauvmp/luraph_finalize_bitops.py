"""Native fast paths for exact hot staged-bootstrap helper fingerprints.

The captured Luraph bootstrap spends almost all of its time interpreting a few
small pure helpers: arithmetic 32-bit XOR, one-based bit extraction, four-byte
word decoding, and IEEE-754 double reconstruction. Replacing only their exact
sample-local prototype shapes keeps unknown trees on the ordinary VM path while
making the finite decoder practical to execute inside the sandbox.
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

    -- Exact 104-instruction helper used as extract(value, first, last), with
    -- one-based inclusive bit positions. Its constants include unreachable
    -- anti-tamper material, so the opcode shape and no-cell marker are the
    -- reliable identity here.
    if #ops == 104
        and ops[1] == 186 and ops[2] == 79 and ops[5] == 41
        and ops[8] == 128 and ops[9] == 135 and ops[10] == 35
        and ops[17] == 6 and ops[18] == 189 and ops[81] == 135
        and ops[86] == 104 and ops[95] == 14 and ops[104] == 186
        and cells == false
    then
        __LUAUVMP_REPORT_FASTPATH("one-based bit extraction")
        return function(value, firstBit, lastBit)
            local finalBit = lastBit or firstBit
            local width = finalBit - firstBit + 1
            return math.floor(value / (2 ^ (firstBit - 1))) % (2 ^ width)
        end
    end

    -- Exact 33-instruction four-byte word helper. Upvalue cells are populated
    -- lazily by the VM after closure construction, so read them at call time.
    if #ops == 33
        and ops[1] == 186 and ops[2] == 153 and ops[3] == 153
        and ops[6] == 43 and ops[10] == 93 and ops[11] == 98
        and ops[14] == 98 and ops[19] == 93 and ops[20] == 98
        and ops[27] == 93 and ops[31] == 93 and ops[33] == 14
        and type(cells) == "table"
    then
        __LUAUVMP_REPORT_FASTPATH("four-byte word decode")
        return function()
            local byteRange, encoded, xor = cells[0], cells[1], cells[2]
            local b1, b2, b3, b4 = byteRange(encoded, 1, 4)
            return xor(b4, 64) * 16777216
                + xor(b3, 32) * 65536
                + xor(b2, 16) * 256
                + xor(b1, 8)
        end
    end

    -- Exact 134-instruction IEEE-754 decoder. It reads low/high 32-bit words
    -- through cells[0] and uses the one-based extractor in cells[1]. These
    -- cells are likewise bound lazily and must be dereferenced on invocation.
    if #ops == 134
        and ops[1] == 186 and ops[2] == 186 and ops[3] == 14
        and ops[6] == 128 and ops[7] == 135 and ops[8] == 127
        and ops[10] == 46 and ops[11] == 127 and ops[13] == 53
        and ops[24] == 153 and ops[29] == 174 and ops[30] == 174
        and ops[38] == 14 and ops[40] == 99 and ops[80] == 98
        and ops[84] == 14 and ops[89] == 170 and ops[90] == 98
        and ops[91] == 46 and ops[103] == 153 and ops[105] == 174
        and ops[106] == 93 and ops[119] == 153 and ops[120] == 226
        and ops[121] == 153 and ops[124] == 226 and ops[126] == 153
        and ops[134] == 186 and type(cells) == "table"
    then
        __LUAUVMP_REPORT_FASTPATH("IEEE-754 double decode")
        return function()
            local readWord, extract = cells[0], cells[1]
            local low = readWord()
            local high = readWord()
            local mantissa = extract(high, 1, 20) * 4294967296 + low
            local exponent = extract(high, 21, 31)
            local sign = extract(high, 32) == 0 and 1 or -1
            if exponent == 0 then
                if mantissa == 0 then return sign * 0 end
                return sign * (2 ^ -1022) * (mantissa / 4503599627370496)
            end
            if exponent == 2047 then
                if mantissa == 0 then return sign * math.huge end
                return 0 / 0
            end
            return sign * (2 ^ (exponent - 1023))
                * (1 + mantissa / 4503599627370496)
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
        # Some helper opcode arrays are decoded in place after their closures
        # are constructed. Retry until a match appears, then cache that native
        # closure in an upvalue. External references may retain the wrapper,
        # so assigning q alone would not avoid repeated fingerprint scans.
        replacement = (
            ";local __fast=__LUAUVMP_FASTPATH(W,P);"
            "if __fast then return __fast end;"
            "local __lateFast;"
            "q=(function(...)"
            "if not __lateFast then __lateFast=__LUAUVMP_FASTPATH(W,P) end;"
            "if __lateFast then return __lateFast(...) end;"
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
