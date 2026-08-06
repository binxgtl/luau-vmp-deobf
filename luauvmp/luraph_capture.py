"""Safe prototype capture for sample-local Luraph VMs.

The recovered interpreter is allowed to parse its custom bytecode, but its
returned payload closure is replaced before it can be created or called.  A
small Lune runner serialises the parsed prototype tree and the VM runtime facts
needed to specialise the dispatcher.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence, Union
import re
import shlex
import shutil
import subprocess


_FACTORY_START = re.compile(
    r"\(function\(([A-Za-z_]\w*),([A-Za-z_]\w*)\)local\s+"
    r"([^;]{0,400}?)=\1\[10(?:\.0)?\]"
)
_FACTORY_DISPATCH = re.compile(r"while\s+true\s+do\s+local\s+X\s*=")
_CAPTURE_RETURN = re.compile(
    r"return\s+([A-Za-z_]\w*)\[50(?:\.0)?\]\("
    r"([A-Za-z_]\w*),\1\[1(?:\.0)?\]\);end,"
)


class CaptureError(RuntimeError):
    """Raised when the safe capture stage cannot be prepared or executed."""


@dataclass(frozen=True)
class CaptureArtifacts:
    full_ir: Path
    runtime_facts: Path
    factory: Path
    patched_vm: Path
    runner: Path


def extract_interpreter_factory(vm_source: str) -> str:
    """Extract the sample-local closure factory containing the dispatcher.

    Luraph v14.x stores the factory in the runtime helper table.  The local
    names are randomised, so the extractor keys on the factory's structural
    reads from proto slots 10/6/8/2/11/9/7/4 and on the dispatcher local ``X``.
    """
    dispatch = _FACTORY_DISPATCH.search(vm_source)
    if dispatch is None:
        raise CaptureError("Luraph dispatcher loop was not found in recovered VM source")

    candidates = [m for m in _FACTORY_START.finditer(vm_source, 0, dispatch.start())]
    if not candidates:
        raise CaptureError("Luraph interpreter factory start was not found")
    start = candidates[-1]

    locals_text = start.group(3)
    names = [part.strip() for part in locals_text.split(",") if part.strip()]
    if not names:
        raise CaptureError("could not identify the factory return local")
    result_name = names[-1]
    end_re = re.compile(r"\breturn\s+" + re.escape(result_name) + r"\s*;\s*end\)")
    end = end_re.search(vm_source, dispatch.start())
    if end is None:
        raise CaptureError("Luraph interpreter factory end was not found")
    return vm_source[start.start():end.end()]


def instrument_vm_source(vm_source: str) -> str:
    """Replace the payload-closure constructor with the capture callback.

    The matched return is inside the VM's top-level ``F`` parser.  It normally
    calls helper slot 50 to build the executable payload closure.  Replacing
    that single call means the bytecode parser runs, while payload instructions
    never do.
    """
    matches = list(_CAPTURE_RETURN.finditer(vm_source))
    if len(matches) != 1:
        raise CaptureError(
            "expected one payload-closure construction site, found %d" % len(matches)
        )
    match = matches[0]
    state_name, root_name = match.group(1), match.group(2)
    replacement = "return __LUAUVMP_CAPTURE(%s,%s);end," % (state_name, root_name)
    return vm_source[:match.start()] + replacement + vm_source[match.end():]


def _lua_quote(value: Union[str, Path]) -> str:
    raw = str(value).replace("\\", "\\\\").replace('"', '\\"')
    raw = raw.replace("\n", "\\n").replace("\r", "\\r")
    return '"%s"' % raw


def build_lune_runner(
    patched_vm: Union[str, Path],
    bytecode: Union[str, Path],
    full_ir: Union[str, Path],
    runtime_facts: Union[str, Path],
) -> str:
    """Return a self-contained Lune script for the safe capture stage."""
    return r'''local fs = require("@lune/fs")
local luau = require("@lune/luau")

local VM_PATH = %s
local BYTECODE_PATH = %s
local IR_PATH = %s
local FACTS_PATH = %s

local function hexString(value)
    local out = table.create(#value)
    for i = 1, #value do
        out[i] = string.format("%%02x", string.byte(value, i))
    end
    return table.concat(out)
end

local protoIds = {}
local protoList = {}
local protoMeta = {}

local function isProto(value)
    return type(value) == "table"
        and type(value[4]) == "table"
        and type(value[10]) == "number"
end

local function registerProto(value, parent, parentField, parentPc)
    local current = protoIds[value]
    if current ~= nil then
        return current
    end
    local id = #protoList
    protoIds[value] = id
    protoList[id + 1] = value
    protoMeta[id + 1] = { parent, parentField, parentPc }
    return id
end

local function numberToken(value)
    if value ~= value then
        return "Dnan"
    elseif value == math.huge then
        return "Dinf"
    elseif value == -math.huge then
        return "D-inf"
    end
    return "D" .. string.format("%%.17g", value)
end

local function tableToken(value, seen, depth)
    if isProto(value) then
        local id = protoIds[value]
        if id == nil then
            id = registerProto(value, -2, -2, -2)
        end
        return "P" .. tostring(id)
    end
    if depth > 5 or seen[value] then
        return "T{Xcycle=Xcycle}"
    end
    seen[value] = true
    local entries = {}
    local count = 0
    for key, item in value do
        count += 1
        if count > 128 then
            entries[#entries + 1] = "Xtruncated=Xtruncated"
            break
        end
        local keyToken
        local itemToken
        local keyType = type(key)
        if keyType == "number" then
            keyToken = numberToken(key)
        elseif keyType == "string" then
            keyToken = "S" .. hexString(key)
        elseif keyType == "boolean" then
            keyToken = key and "B1" or "B0"
        else
            keyToken = "X" .. keyType
        end
        local itemType = type(item)
        if item == nil then
            itemToken = "N"
        elseif itemType == "boolean" then
            itemToken = item and "B1" or "B0"
        elseif itemType == "number" then
            itemToken = numberToken(item)
        elseif itemType == "string" then
            itemToken = "S" .. hexString(item)
        elseif itemType == "table" then
            itemToken = tableToken(item, seen, depth + 1)
        else
            itemToken = "X" .. itemType
        end
        entries[#entries + 1] = keyToken .. "=" .. itemToken
    end
    seen[value] = nil
    table.sort(entries)
    return "T{" .. table.concat(entries, ",") .. "}"
end

local function typed(value)
    if value == nil then
        return "N"
    end
    local kind = type(value)
    if kind == "boolean" then
        return value and "B1" or "B0"
    elseif kind == "number" then
        return numberToken(value)
    elseif kind == "string" then
        return "S" .. hexString(value)
    elseif kind == "table" then
        return tableToken(value, {}, 0)
    end
    return "X" .. kind
end

local function cleanText(value)
    return string.gsub(string.gsub(tostring(value), "[\\r\\n]", " "), "\\t", " ")
end

local function writeRuntimeFacts(runtime)
    local classes = {}
    local nextClass = 1
    local lines = {}
    for i = 1, 64 do
        local value = runtime[i]
        local kind = type(value)
        local text
        local class = ""
        if kind == "nil" then
            text = "nil"
        elseif kind == "string" then
            text = "hex:" .. hexString(value)
        elseif kind == "boolean" or kind == "number" then
            text = cleanText(value)
        else
            local known = classes[value]
            if known == nil then
                known = nextClass
                nextClass += 1
                classes[value] = known
            end
            class = tostring(known)
            text = cleanText(value)
        end
        local truth = value ~= nil and value ~= false
        lines[#lines + 1] = table.concat({
            tostring(i), kind, text, tostring(truth), class,
        }, "\\t")
    end
    fs.writeFile(FACTS_PATH, table.concat(lines, "\\n") .. "\\n")
end

local function capture(runtimeState, root)
    if type(runtimeState) ~= "table" or type(runtimeState[1]) ~= "table" then
        error("capture received an invalid Luraph runtime state")
    end
    if not isProto(root) then
        error("capture received an invalid root prototype")
    end

    writeRuntimeFacts(runtimeState[1])
    registerProto(root, -1, -1, -1)

    local body = {}
    local cursor = 1
    local operandFields = { 2, 6, 7, 8, 9, 11 }
    while cursor <= #protoList do
        local proto = protoList[cursor]
        local id = cursor - 1
        local meta = protoMeta[cursor]
        local opcodes = proto[4]
        local instructionCount = #opcodes

        for pc = 1, instructionCount do
            for _, field in operandFields do
                local array = proto[field]
                local value = type(array) == "table" and array[pc] or nil
                if isProto(value) then
                    registerProto(value, id, field, pc)
                end
            end
        end

        body[#body + 1] = table.concat({
            "P", tostring(id), tostring(meta[1]), tostring(meta[2]),
            tostring(meta[3]), tostring(instructionCount), typed(proto[1]),
            typed(proto[3]), typed(proto[5]), typed(proto[10]),
        }, "\\t")

        for pc = 1, instructionCount do
            local function cell(field)
                local array = proto[field]
                return typed(type(array) == "table" and array[pc] or nil)
            end
            body[#body + 1] = table.concat({
                "I", tostring(id), tostring(pc), cell(2), cell(4),
                cell(6), cell(7), cell(8), cell(9), cell(11),
            }, "\\t")
        end
        cursor += 1
    end

    local lines = { "META\\tprotos\\t" .. tostring(#protoList) }
    table.move(body, 1, #body, 2, lines)
    fs.writeFile(IR_PATH, table.concat(lines, "\\n") .. "\\n")

    return function()
        error("captured Luraph payload closure is intentionally disabled")
    end
end

-- Lune intentionally does not expose Luau's debug library. Luraph checks for
-- debug.info while constructing its VM runtime, before the payload closure is
-- returned. Provide a data-only compatibility surface: enough for bootstrap
-- feature detection, but no stack/upvalue mutation primitives.
local function debugInfo(first, second, third)
    local target = first
    local options = second
    if type(first) == "thread" then
        target = second
        options = third
    end
    options = options or ""
    if type(target) == "number" and target > 2 then return nil end
    local functionValue = type(target) == "function" and target or debugInfo
    local values = {}
    for i = 1, #options do
        local option = string.sub(options, i, i)
        if option == "s" then values[#values + 1] = "[Luraph capture]"
        elseif option == "l" then values[#values + 1] = -1
        elseif option == "n" then values[#values + 1] = ""
        elseif option == "f" then values[#values + 1] = functionValue
        elseif option == "a" then
            values[#values + 1] = 0
            values[#values + 1] = true
        else
            error("unsupported debug.info option during safe capture: " .. option)
        end
    end
    return table.unpack(values, 1, #values)
end

local debugCompat = {
    info = debugInfo,
    getinfo = function(first, second, third)
        local target = first
        if type(first) == "thread" then target = second end
        if type(target) == "number" and target > 2 then return nil end
        return {
            source = "[Luraph capture]", short_src = "[Luraph capture]",
            what = "Lua", currentline = -1, linedefined = -1,
            lastlinedefined = -1, name = nil, namewhat = "", nups = 0,
            nparams = 0, isvararg = true,
            func = type(target) == "function" and target or debugInfo,
        }
    end,
    traceback = function(message) return tostring(message or "") end,
}

local environment = {
    __LUAUVMP_CAPTURE = capture,
    assert = assert,
    error = error,
    getfenv = getfenv,
    getmetatable = getmetatable,
    ipairs = ipairs,
    next = next,
    pairs = pairs,
    pcall = pcall,
    rawequal = rawequal,
    rawget = rawget,
    rawlen = rawlen,
    rawset = rawset,
    select = select,
    setfenv = setfenv,
    setmetatable = setmetatable,
    tonumber = tonumber,
    tostring = tostring,
    type = type,
    typeof = typeof,
    unpack = unpack,
    xpcall = xpcall,
    bit32 = bit32,
    buffer = buffer,
    coroutine = coroutine,
    debug = debugCompat,
    math = math,
    string = string,
    table = table,
    utf8 = utf8,
}
environment._G = environment

-- Preserve loadstring's `(nil, error)` contract while forcing every nested
-- chunk into the same closed environment.
local function safeLoadString(source, chunkName)
    local ok, result = pcall(luau.load, source, {
        debugName = tostring(chunkName or "Luraph safe nested chunk"),
        environment = environment,
        injectGlobals = false,
        codegenEnabled = false,
    })
    if ok then return result end
    return nil, tostring(result)
end
environment.loadstring = safeLoadString
environment.load = safeLoadString

local vmSource = fs.readFile(VM_PATH)
local bytecode = fs.readFile(BYTECODE_PATH)
local chunk = luau.load(vmSource, {
    debugName = "Luraph safe prototype capture",
    environment = environment,
    injectGlobals = false,
    codegenEnabled = false,
})
chunk(buffer.fromstring(bytecode))
''' % (
        _lua_quote(patched_vm),
        _lua_quote(bytecode),
        _lua_quote(full_ir),
        _lua_quote(runtime_facts),
    )


def _normalise_runtime_command(runtime: Union[str, Sequence[str]]) -> list[str]:
    if isinstance(runtime, str):
        command = shlex.split(runtime)
    else:
        command = list(runtime)
    if not command:
        raise CaptureError("empty Luau runtime command")
    if len(command) == 1 and shutil.which(command[0]) is None:
        raise CaptureError(
            "Lune was not found. Install Lune or pass --runtime /path/to/lune"
        )
    return command


def run_capture(
    vm_source: Union[str, Path],
    bytecode: Union[str, Path],
    work_dir: Union[str, Path],
    runtime: Union[str, Sequence[str]] = "lune",
    timeout: int = 300,
) -> CaptureArtifacts:
    """Instrument and execute only the Luraph bytecode-parser stage under Lune."""
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)
    vm_path = Path(vm_source)
    bytecode_path = Path(bytecode)
    text = vm_path.read_text(encoding="utf-8", errors="surrogateescape")

    factory_path = work / "interpreter.factory.luau"
    patched_path = work / "interpreter.capture.luau"
    runner_path = work / "capture_runner.luau"
    ir_path = work / "full_ir.tsv"
    facts_path = work / "runtime_A.tsv"

    factory_path.write_text(
        extract_interpreter_factory(text), encoding="utf-8", errors="surrogateescape"
    )
    patched_path.write_text(
        instrument_vm_source(text), encoding="utf-8", errors="surrogateescape"
    )
    runner_path.write_text(
        build_lune_runner(patched_path, bytecode_path, ir_path, facts_path),
        encoding="utf-8",
    )

    command = _normalise_runtime_command(runtime) + ["run", str(runner_path)]
    try:
        result = subprocess.run(
            command,
            cwd=str(work),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CaptureError("Luraph safe capture timed out after %d seconds" % timeout) from exc
    except OSError as exc:
        raise CaptureError("failed to start Lune: %s" % exc) from exc
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "unknown Lune error").strip()
        raise CaptureError("Luraph safe capture failed: %s" % message)
    if not ir_path.is_file() or not facts_path.is_file():
        raise CaptureError("Lune exited successfully but did not produce capture artifacts")

    return CaptureArtifacts(ir_path, facts_path, factory_path, patched_path, runner_path)
