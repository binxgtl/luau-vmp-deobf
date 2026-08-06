"""Compatibility-correct staged Luraph finalisation.

Luraph's bootstrap uses ``setfenv`` to build wrapper closures. Version 0.5.0
replaced it with a no-op to keep the lexical sandbox closed; the wrapper never
received its generated environment and the bootstrap entered an anti-tamper
loop. Keep real Luau environment rebinding, but make every ``getfenv`` lookup
return only the closed sandbox environment.
"""
from __future__ import annotations

import re

from . import luraph_finalize


_INSTALLED = False
_GUARDED_FETCH = re.compile(
    r"while\s+true\s+do\s+__LUAUVMP_STEP\(\);\s+"
    r"local\s+X\s*=\s*(?P<fetch>\([^;]+\));"
)
_STEP_BLOCK = re.compile(
    r"local __stepCount = 0\n"
    r"local __stepBudget = (?P<budget>\d+)\n"
    r"local function __LUAUVMP_STEP\(\)\n"
    r"    __stepCount \+= 1\n"
    r"    if __stepCount > __stepBudget then\n"
    r"        error\(\"Luraph bootstrap instruction budget exceeded: \" "
    r"\.\. tostring\(__stepBudget\)\)\n"
    r"    end\n"
    r"end\n"
)
_NEW_STEP = '''local __stepCount = 0
local __stepBudget = %d
local __lastProto, __lastPc, __lastOpcode = nil, nil, nil
local __protoStepCounts = {}
local function __LUAUVMP_PROTO_ID(proto)
    local id = protoIds[proto]
    if id == nil then
        id = registerProto(proto, -3, -3, -3)
    end
    return id
end
local function __LUAUVMP_TOP_PROTOS(limit)
    local rows = {}
    for id, count in __protoStepCounts do
        rows[#rows + 1] = { id, count }
    end
    table.sort(rows, function(a, b)
        if a[2] == b[2] then return a[1] < b[1] end
        return a[2] > b[2]
    end)
    local parts = {}
    local stop = math.min(limit, #rows)
    for index = 1, stop do
        local id, count = rows[index][1], rows[index][2]
        local proto = protoList[id + 1]
        local ops = type(proto) == "table" and proto[4] or nil
        local opCount = type(ops) == "table" and #ops or -1
        local first = type(ops) == "table" and ops[1] or nil
        local middle = type(ops) == "table" and ops[math.max(1, math.floor(opCount / 2))] or nil
        local last = type(ops) == "table" and ops[opCount] or nil
        parts[#parts + 1] = tostring(id) .. ":" .. tostring(count)
            .. "/len=" .. tostring(opCount)
            .. "/sig=" .. tostring(first) .. "," .. tostring(middle) .. "," .. tostring(last)
    end
    return table.concat(parts, ";")
end
local function __LUAUVMP_STEP(proto, pc, opcode)
    __stepCount += 1
    local protoId = __LUAUVMP_PROTO_ID(proto)
    __protoStepCounts[protoId] = (__protoStepCounts[protoId] or 0) + 1
    __lastProto, __lastPc, __lastOpcode = protoId, pc, opcode
    if __stepCount %% 1000000 == 0 then
        print("[finalize] bootstrap steps=" .. tostring(__stepCount)
            .. " proto=" .. tostring(protoId)
            .. " pc=" .. tostring(pc) .. " opcode=" .. tostring(opcode)
            .. " top=" .. __LUAUVMP_TOP_PROTOS(5))
    end
    if __stepCount > __stepBudget then
        error("Luraph bootstrap instruction budget exceeded: " .. tostring(__stepBudget)
            .. " (last proto=" .. tostring(__lastProto)
            .. ", pc=" .. tostring(__lastPc)
            .. ", opcode=" .. tostring(__lastOpcode)
            .. "; top=" .. __LUAUVMP_TOP_PROTOS(10) .. ")")
    end
end
'''
_ENV_MARKER = '''-- The VM is compiled as part of this runner, so Lune may use native codegen.
'''
_ENV_COMPAT = '''-- Preserve real Luau environment rebinding inside a closed environment.
-- The final payload is still intercepted before construction and is never run.
local __realSetfenv = setfenv
local __functionEnvironments = setmetatable({}, { __mode = "k" })
local function __closedGetfenv(target)
    if type(target) == "function" then
        return __functionEnvironments[target] or environment
    end
    return environment
end
local function __closedSetfenv(fn, env)
    local result = __realSetfenv(fn, env)
    __functionEnvironments[fn] = env
    return result
end
environment.getfenv = __closedGetfenv
environment.setfenv = __closedSetfenv

'''


def install() -> None:
    """Install the closed-but-functional environment compatibility layer."""
    global _INSTALLED
    if _INSTALLED:
        return

    original = luraph_finalize.build_finalize_runner

    def build_finalize_runner(*args, **kwargs):
        runner = original(*args, **kwargs)
        runner, fetch_count = _GUARDED_FETCH.subn(
            lambda match: (
                "while true do local X=%s; __LUAUVMP_STEP(W,u,X);" %
                match.group("fetch")
            ),
            runner,
            count=1,
        )
        if fetch_count != 1:
            raise luraph_finalize.FinalizeError(
                "finaliser compatibility patch could not locate dispatcher fetch"
            )
        step_match = _STEP_BLOCK.search(runner)
        if step_match is None:
            raise luraph_finalize.FinalizeError(
                "finaliser compatibility patch could not locate budget guard"
            )
        runner = (runner[:step_match.start()]
                  + (_NEW_STEP % int(step_match.group("budget")))
                  + runner[step_match.end():])
        if _ENV_MARKER not in runner:
            raise luraph_finalize.FinalizeError(
                "finaliser compatibility patch could not locate sandbox boundary"
            )
        runner = runner.replace(_ENV_MARKER, _ENV_COMPAT + _ENV_MARKER, 1)
        old_env = (
            "    local getfenv = function() return environment end\n"
            "    local setfenv = function(fn, _env) return fn end\n"
        )
        new_env = (
            "    local getfenv = __closedGetfenv\n"
            "    local setfenv = __closedSetfenv\n"
        )
        if old_env not in runner:
            raise luraph_finalize.FinalizeError(
                "finaliser compatibility patch could not locate environment shims"
            )
        return runner.replace(old_env, new_env, 1)

    build_finalize_runner.__name__ = original.__name__
    build_finalize_runner.__doc__ = original.__doc__
    luraph_finalize.build_finalize_runner = build_finalize_runner
    _INSTALLED = True
