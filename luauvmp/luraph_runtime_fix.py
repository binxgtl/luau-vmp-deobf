"""Correct Luraph runtime-helper capture without widening the strict sandbox."""
from __future__ import annotations

from pathlib import Path

from . import luraph_capture

_INSTALLED = False


def validate_runtime_facts(path: Path) -> None:
    """Reject the empty environment-slot capture seen in versions <= 0.4.1."""
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        cols = line.split("\t")
        if len(cols) >= 2:
            rows.append(cols)
    non_nil = sum(1 for cols in rows if cols[1] != "nil")
    if len(rows) < 32 or non_nil < 8:
        raise luraph_capture.CaptureError(
            "captured runtime helper facts are empty or implausible "
            "(%d/%d non-nil slots)" % (non_nil, len(rows))
        )


def install() -> None:
    """Patch helper serialization and add read-only missing-global telemetry."""
    global _INSTALLED
    if _INSTALLED:
        return

    original_builder = luraph_capture.build_lune_runner

    def build_lune_runner(*args, **kwargs):
        runner = original_builder(*args, **kwargs)
        runner = runner.replace(
            'if type(runtimeState) ~= "table" or type(runtimeState[1]) ~= "table" then',
            'if type(runtimeState) ~= "table" then',
        )
        runner = runner.replace(
            'writeRuntimeFacts(runtimeState[1])',
            'writeRuntimeFacts(runtimeState)',
        )

        # Roblox datatypes are not injected as runner globals by Lune. Load the
        # trusted standard library outside the recovered VM. Only an explicit
        # allow-list of pure value constructors enters the parser environment;
        # the module itself, Instance, auth, filesystem and network APIs remain
        # unreachable from recovered code.
        require_marker = 'local stdio = require("@lune/stdio")\n'
        trusted_import = r'''local stdio = require("@lune/stdio")
local robloxDatatypes = require("@lune/roblox")

-- Path2DControlPoint is present in current Roblox bytecode but is not exported
-- by Lune 0.10.5. Parsing only needs a stable constant value, so preserve every
-- constructor argument as inert typed text instead of emulating engine behavior.
local Path2DControlPointCompat = table.freeze({
    new = function(...)
        local input = table.pack(...)
        local captured = {
            __luauvmp_datatype = "Path2DControlPoint",
            n = input.n,
        }
        for index = 1, input.n do
            local value = input[index]
            captured[index] = table.freeze({
                kind = typeof(value),
                text = tostring(value),
            })
        end
        return table.freeze(captured)
    end,
})

-- Some wrappers cancel a watchdog handle during parser teardown. Expose only a
-- synchronous no-op cancel operation. Scheduling APIs remain absent so captured
-- code cannot create, defer, or resume execution through the runner task API.
local TaskCompat = table.freeze({
    cancel = function(_)
        return nil
    end,
})
'''
        if require_marker not in runner:
            raise luraph_capture.CaptureError(
                "safe-capture trusted import marker was not found"
            )
        runner = runner.replace(require_marker, trusted_import, 1)

        datatype_marker = '    utf8 = utf8,\n}'
        datatype_environment = (
            '    utf8 = utf8,\n'
            '    CFrame = robloxDatatypes.CFrame,\n'
            '    Enum = robloxDatatypes.Enum,\n'
            '    Ray = robloxDatatypes.Ray,\n'
            '    UDim = robloxDatatypes.UDim,\n'
            '    UDim2 = robloxDatatypes.UDim2,\n'
            '    Vector2 = robloxDatatypes.Vector2,\n'
            '    Vector3 = robloxDatatypes.Vector3,\n'
            '    Path2DControlPoint = Path2DControlPointCompat,\n'
            '    task = TaskCompat,\n'
            '}'
        )
        if datatype_marker not in runner:
            raise luraph_capture.CaptureError(
                "safe-capture datatype environment marker was not found"
            )
        runner = runner.replace(datatype_marker, datatype_environment, 1)

        # Never perform async I/O from the environment __index metamethod. Lune
        # standard-library writes can yield, which previously replaced the real
        # missing-global error with "yield across metamethod". Record names in a
        # plain table and report them after the parser call has unwound.
        environment_marker = 'local environment = {'
        environment_prefix = 'local missingSafeGlobals = {}\nlocal environment = {'
        if environment_marker not in runner:
            raise luraph_capture.CaptureError(
                "safe-capture environment declaration was not found"
            )
        runner = runner.replace(environment_marker, environment_prefix, 1)

        marker = 'environment._G = environment\n\nlocal function safeLoadString'
        telemetry = r'''environment._G = environment

-- Constructor-bearing globals are deliberately not provided. Return a probe
-- only for the two observed names so a blocked ``X.new`` access reports X
-- precisely instead of the ambiguous "index nil with new". The probe cannot
-- construct, call, index through, or expose any Roblox capability.
local blockedConstructorProbes = {}
local function blockedConstructorProbe(name)
    local existing = blockedConstructorProbes[name]
    if existing ~= nil then return existing end
    local probe = setmetatable({}, {
        __index = function(_, member)
            error(
                "safe-capture blocked access to missing global "
                    .. name .. "." .. tostring(member),
                0
            )
        end,
        __call = function()
            error("safe-capture blocked call to missing global " .. name, 0)
        end,
        __metatable = "locked",
    })
    blockedConstructorProbes[name] = probe
    return probe
end

setmetatable(environment, {
    __index = function(_, key)
        local name = tostring(key)
        missingSafeGlobals[name] = true
        if name == "Instance" or name == "Random" then
            return blockedConstructorProbe(name)
        end
        return nil
    end,
})

local function safeLoadString'''
        if marker not in runner:
            raise luraph_capture.CaptureError(
                "safe-capture environment marker was not found"
            )
        runner = runner.replace(marker, telemetry, 1)

        call_marker = (
            'chunk(buffer.fromstring(bytecode))\n'
            'status("VM parser returned")'
        )
        guarded_call = r'''local parserOk, parserResult = pcall(chunk, buffer.fromstring(bytecode))
local missingNames = {}
for key in missingSafeGlobals do
    missingNames[#missingNames + 1] = key
end
table.sort(missingNames)
if #missingNames > 0 then
    status("missing safe-capture globals: " .. table.concat(missingNames, ", "))
end
if not parserOk then
    error(parserResult, 0)
end
status("VM parser returned")'''
        if call_marker not in runner:
            raise luraph_capture.CaptureError(
                "safe-capture parser invocation marker was not found"
            )
        runner = runner.replace(call_marker, guarded_call, 1)
        return runner

    original_run = luraph_capture.run_capture

    def run_capture(*args, **kwargs):
        artifacts = original_run(*args, **kwargs)
        validate_runtime_facts(artifacts.runtime_facts)
        return artifacts

    build_lune_runner.__name__ = original_builder.__name__
    run_capture.__name__ = original_run.__name__
    luraph_capture.build_lune_runner = build_lune_runner
    luraph_capture.run_capture = run_capture
    luraph_capture._validate_runtime_facts = validate_runtime_facts
    _INSTALLED = True
