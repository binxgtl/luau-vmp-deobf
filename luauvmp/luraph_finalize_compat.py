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
local __lastPc, __lastOpcode = nil, nil
local function __LUAUVMP_STEP(pc, opcode)
    __stepCount += 1
    __lastPc, __lastOpcode = pc, opcode
    if __stepCount %% 1000000 == 0 then
        print("[finalize] bootstrap steps=" .. tostring(__stepCount)
            .. " pc=" .. tostring(pc) .. " opcode=" .. tostring(opcode))
    end
    if __stepCount > __stepBudget then
        error("Luraph bootstrap instruction budget exceeded: " .. tostring(__stepBudget)
            .. " (last pc=" .. tostring(__lastPc)
            .. ", opcode=" .. tostring(__lastOpcode) .. ")")
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
                "while true do local X=%s; __LUAUVMP_STEP(u,X);" %
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
