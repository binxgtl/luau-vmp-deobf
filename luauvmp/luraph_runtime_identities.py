"""Record trusted builtin identities in runtime-helper facts without invoking them.

Runtime facts historically record only ``function`` plus an equality class.  For
public v14.7 that is enough to specialize anti-tamper comparisons, but not enough
to prove that a randomized helper slot is e.g. ``select`` or ``bit32.bxor``.

This runner-only patch compares captured helper objects by identity with an
explicit list of already-present Luau builtins and writes ``builtin:<name>`` in
the existing text column.  The helper is never called.  The normal runtime-fact
loader intentionally ignores text for function/table objects, so this remains
backward-compatible with dispatcher specialization while later structural passes
can consume the stronger evidence directly from the TSV.
"""
from __future__ import annotations

from . import luraph_capture


_INSTALLED = False


_BUILTIN_LUA = r'''local trustedBuiltinIdentities = {
    { "select", select },
    { "pcall", pcall },
    { "xpcall", xpcall },
    { "type", type },
    { "typeof", typeof },
    { "tostring", tostring },
    { "tonumber", tonumber },
    { "rawequal", rawequal },
    { "rawget", rawget },
    { "rawset", rawset },
    { "setmetatable", setmetatable },
    { "getmetatable", getmetatable },
    { "next", next },
    { "pairs", pairs },
    { "ipairs", ipairs },
    { "assert", assert },
    { "error", error },
    { "bit32.band", bit32.band },
    { "bit32.bnot", bit32.bnot },
    { "bit32.bor", bit32.bor },
    { "bit32.bxor", bit32.bxor },
    { "bit32.countlz", bit32.countlz },
    { "bit32.countrz", bit32.countrz },
    { "bit32.lrotate", bit32.lrotate },
    { "bit32.lshift", bit32.lshift },
    { "bit32.rrotate", bit32.rrotate },
    { "bit32.rshift", bit32.rshift },
    { "table.concat", table.concat },
    { "table.create", table.create },
    { "table.find", table.find },
    { "table.freeze", table.freeze },
    { "table.insert", table.insert },
    { "table.move", table.move },
    { "table.pack", table.pack },
    { "table.remove", table.remove },
    { "table.sort", table.sort },
    { "table.unpack", table.unpack },
    { "string.byte", string.byte },
    { "string.char", string.char },
    { "string.find", string.find },
    { "string.format", string.format },
    { "string.len", string.len },
    { "string.match", string.match },
    { "string.pack", string.pack },
    { "string.packsize", string.packsize },
    { "string.rep", string.rep },
    { "string.reverse", string.reverse },
    { "string.sub", string.sub },
    { "string.unpack", string.unpack },
    { "math.ceil", math.ceil },
    { "math.floor", math.floor },
    { "math.modf", math.modf },
}

local function trustedBuiltinName(value)
    for _, entry in trustedBuiltinIdentities do
        if value == entry[2] then
            return entry[1]
        end
    end
    return nil
end

'''


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    original = luraph_capture.build_lune_runner

    def build_lune_runner(*args, **kwargs):
        runner = original(*args, **kwargs)
        marker = "local function writeRuntimeFacts(runtime)\n"
        if marker not in runner:
            raise luraph_capture.CaptureError(
                "runtime builtin-identity marker was not found"
            )
        runner = runner.replace(marker, _BUILTIN_LUA + marker, 1)

        old = '''            class = tostring(known)\n            text = cleanText(value)'''
        new = '''            class = tostring(known)\n            local builtinName = trustedBuiltinName(value)\n            if builtinName ~= nil then\n                text = "builtin:" .. builtinName\n            else\n                text = cleanText(value)\n            end'''
        if old not in runner:
            raise luraph_capture.CaptureError(
                "runtime helper text serialization marker was not found"
            )
        runner = runner.replace(old, new, 1)
        return runner

    build_lune_runner.__name__ = original.__name__
    luraph_capture.build_lune_runner = build_lune_runner
    _INSTALLED = True
