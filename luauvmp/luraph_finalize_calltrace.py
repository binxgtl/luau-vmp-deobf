"""Branch-only call tracing for hot staged bootstrap closures.

The tracer reports only primitive values, string/table lengths and shallow
numeric state. It never prints protected string contents. Crucially, it injects
at the start of the existing VM closure instead of wrapping that closure;
Luraph's upvalue/environment machinery depends on function identity.
"""
from __future__ import annotations

from . import luraph_finalize


_INSTALLED = False
_MARKER = "-- The VM is compiled as part of this runner, so Lune may use native codegen.\n"
_FUNCTION_ENTRY = "q=(function(...)"
_TRACED_FUNCTION_ENTRY = "q=(function(...)__LUAUVMP_HOT_ENTER(W,P,...);"
_TRACE_HELPERS = r'''-- Diagnostic entry trace for sample-local hot decoder closures.
-- Never print protected string contents; strings are represented by length only.
-- Keep this diagnostic run short even if the workflow ceiling is much higher.
__stepBudget = math.min(__stepBudget, 12000000)
print("[finalize] diagnostic call trace step ceiling=" .. tostring(__stepBudget))
local __hotCallCounts = {}
local function __LUAUVMP_PACK(...)
    return { n = select("#", ...), ... }
end
local function __LUAUVMP_SAFE_VALUE(value, depth)
    local kind = type(value)
    if kind == "nil" then return "nil" end
    if kind == "number" or kind == "boolean" then return tostring(value) end
    if kind == "string" then return "string#" .. tostring(#value) end
    if kind == "function" then return "function" end
    if kind ~= "table" then return kind end
    if depth >= 1 then return "table#" .. tostring(#value) end
    local parts = { "table#" .. tostring(#value) .. "{" }
    local emitted = 0
    for index = 0, 16 do
        local item = value[index]
        if item ~= nil then
            emitted += 1
            parts[#parts + 1] = tostring(index) .. "=" .. __LUAUVMP_SAFE_VALUE(item, depth + 1)
            if emitted >= 10 then break end
        end
    end
    parts[#parts + 1] = "}"
    return table.concat(parts, ",")
end
local function __LUAUVMP_PACK_SUMMARY(values)
    local parts = {}
    for index = 1, math.min(values.n, 12) do
        parts[#parts + 1] = tostring(index) .. "=" .. __LUAUVMP_SAFE_VALUE(values[index], 0)
    end
    if values.n > 12 then parts[#parts + 1] = "...n=" .. tostring(values.n) end
    return table.concat(parts, ";")
end
local function __LUAUVMP_HOT_FINGERPRINT(proto)
    local ops = type(proto) == "table" and proto[4] or nil
    if type(ops) ~= "table" then return nil end
    local count = #ops
    if count == 33 and ops[1] == 186 and ops[2] == 153 and ops[33] == 14 then return "word32" end
    if count == 104 and ops[1] == 186 and ops[2] == 79 and ops[104] == 186 then return "decoder104" end
    if count == 134 and ops[1] == 186 and ops[2] == 186 and ops[134] == 186 then return "decoder134" end
    if count == 232 and ops[1] == 186 and ops[2] == 13 and ops[232] == 186 then return "decoder232" end
    return nil
end
local function __LUAUVMP_HOT_ENTER(proto, cells, ...)
    local fingerprint = __LUAUVMP_HOT_FINGERPRINT(proto)
    if fingerprint == nil then return end
    local protoId = __LUAUVMP_PROTO_ID(proto)
    local key = fingerprint .. "/" .. tostring(protoId)
    local callNumber = (__hotCallCounts[key] or 0) + 1
    __hotCallCounts[key] = callNumber
    if callNumber == 1 then
        print("[finalize] call-trace enabled proto=" .. tostring(protoId)
            .. " kind=" .. fingerprint
            .. " cells=" .. __LUAUVMP_SAFE_VALUE(cells, 0))
    end
    if callNumber <= 8 or callNumber % 25000 == 0 then
        local arguments = __LUAUVMP_PACK(...)
        print("[finalize] enter proto=" .. tostring(protoId)
            .. " kind=" .. fingerprint .. " n=" .. tostring(callNumber)
            .. " args=" .. __LUAUVMP_PACK_SUMMARY(arguments)
            .. " cells=" .. __LUAUVMP_SAFE_VALUE(cells, 0))
    end
end

'''


def install() -> None:
    """Install identity-preserving call-entry tracing after other patches."""
    global _INSTALLED
    if _INSTALLED:
        return

    original = luraph_finalize.build_finalize_runner

    def build_finalize_runner(*args, **kwargs):
        runner = original(*args, **kwargs)
        if _MARKER not in runner:
            raise luraph_finalize.FinalizeError(
                "call tracer could not locate finaliser sandbox boundary"
            )
        runner = runner.replace(_MARKER, _TRACE_HELPERS + _MARKER, 1)
        if runner.count(_FUNCTION_ENTRY) != 1:
            raise luraph_finalize.FinalizeError(
                "call tracer could not uniquely locate VM closure entry"
            )
        return runner.replace(
            _FUNCTION_ENTRY,
            _TRACED_FUNCTION_ENTRY,
            1,
        )

    build_finalize_runner.__name__ = original.__name__
    build_finalize_runner.__doc__ = original.__doc__
    luraph_finalize.build_finalize_runner = build_finalize_runner
    _INSTALLED = True
