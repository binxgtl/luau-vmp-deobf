-- Luraph stage 5 - instrumented runtime trace.
--
-- Runs the recovered Luraph VM interpreter (from `luauvmp luraph`) under the
-- Lune Luau runtime with an auto-stubbing Roblox environment, and records
-- every global access / service call / stub interaction.  The trace shows
-- which executor-detection and anti-tamper checks the VM performs before it
-- aborts outside a real Roblox host.
--
-- Usage:
--   lune run tools/luraph_trace.lua <vm.lua> <bytecode.bin> [trace.log]
--
-- On the reference v14.7 sample the VM compiles, touches `table`, `bit32`
-- and `string`, then dies with:
--   attempt to yield across metamethod/C-call boundary
-- which is the anti-tamper / executor check refusing a non-Roblox runtime.
local fs = require("@lune/fs")

local _args = (type(arg) == "table" and arg) or {}
local vm_path = _args[1] or "final.vm.lua"
local bc_path = _args[2] or "final.bytecode.bin"
local out_path = _args[3] or "vm_trace.log"

local acc = {}
local n = 0
local function log(...)
    local parts = {}
    for i = 1, select("#", ...) do parts[i] = tostring(select(i, ...)) end
    table.insert(acc, table.concat(parts, " "))
    n = n + 1
    if n % 25 == 0 then
        fs.writeFile(out_path, table.concat(acc, "\n") .. "\n")
    end
end

local StubMT
local function newStub(name)
    return setmetatable({}, StubMT)
end
StubMT = {
    __index = function(self, k)
        log("IDX:", tostring(k))
        return newStub(tostring(k))
    end,
    __call = function(self, ...)
        local args = {}
        for i = 1, select("#", ...) do args[i] = tostring(select(i, ...)) end
        log("CALL:", table.concat(args, ", "))
        return nil
    end,
    __newindex = function(self, k, v)
        log("SET:", tostring(k), "=", tostring(v))
    end,
    __tostring = function(self) return "stub" end,
    __eq = function() return true end,
}

local _ENV = setmetatable({}, {
    __index = function(t, k)
        local kw = tostring(k)
        log("GLOBAL:", kw)
        if kw == "game" then
            local g = newStub("game")
            rawset(g, "GetService", function(_, name)
                log("GetService:", tostring(name))
                return newStub(name)
            end)
            return g
        elseif kw == "Instance" then
            local i = newStub("Instance")
            rawset(i, "new", function(c)
                log("Instance.new:", tostring(c))
                return newStub(c)
            end)
            return i
        elseif kw == "workspace" or kw == "Players" then
            return newStub(kw)
        elseif kw == "getgenv" then
            return function() return _ENV end
        elseif kw == "loadstring" or kw == "load" then
            return loadstring
        elseif kw == "print" or kw == "warn" then
            return function(...) log("LOG:", ...) end
        elseif kw == "tick" then
            return function() return 0 end
        elseif kw == "os" then return os
        elseif kw == "string" then return string
        elseif kw == "table" then return table
        elseif kw == "math" then return math
        elseif kw == "bit32" then return bit32
        elseif kw == "buffer" then return buffer
        elseif kw == "coroutine" then return coroutine
        elseif kw == "debug" then return debug
        elseif kw == "require" then
            return function() return newStub("require") end
        elseif kw == "task" then
            return setmetatable({
                wait = function() return nil end,
                spawn = function(f) return f end,
                defer = function(f) return f end,
            }, StubMT)
        elseif kw == "getfenv" then return getfenv
        elseif kw == "setfenv" then return setfenv
        elseif kw == "select" then return select
        elseif kw == "pairs" then return pairs
        elseif kw == "ipairs" then return ipairs
        elseif kw == "type" then return type
        elseif kw == "tostring" then return tostring
        elseif kw == "tonumber" then return tonumber
        elseif kw == "error" then return error
        elseif kw == "assert" then return assert
        elseif kw == "unpack" then return unpack
        elseif kw == "pcall" or kw == "xpcall" then
            return kw == "pcall" and pcall or xpcall
        elseif kw == "rawget" or kw == "rawset" or kw == "rawequal" then
            return rawget or rawset or rawequal
        end
        return newStub(kw)
    end,
    __newindex = function(t, k, v)
        log("ENV_SET:", tostring(k))
    end,
})

local vm_src = fs.readFile(vm_path)
local data = fs.readFile(bc_path)
local buf = buffer.fromstring(data)

local chunk, err = loadstring(vm_src, "luraph_vm")
log("[compiled]", tostring(chunk ~= nil), tostring(err))
if not chunk then
    fs.writeFile(out_path, table.concat(acc, "\n"))
    return
end
if setfenv then setfenv(chunk, _ENV) end

local ok = xpcall(function()
    local f = chunk(buf)
    log("[RESULT] type:", tostring(type(f)))
end, function(e)
    log("[ERR]", tostring(e))
    return debug.traceback(e, 2)
end)
log("[PCALL]", tostring(ok))
fs.writeFile(out_path, table.concat(acc, "\n"))
print("trace done:", n, "events ->", out_path)
