"""Resolve public-v14.7 capture roots without widening the parser sandbox.

Some Luraph builds pass a small wrapper table to the pre-bootstrap constructor
instead of the prototype object itself.  The hook is still at the correct
constructor site, but the generic capture callback historically rejected that
wrapper before it could serialise the already parsed tree.

This patch only searches existing in-memory tables.  It does not construct or
invoke the application closure and introduces no host capability.
"""
from __future__ import annotations

from . import luraph_capture

_INSTALLED = False


_RESOLVER = r'''local function describeCaptureShape(label, value)
    if type(value) ~= "table" then
        status(label .. " shape: " .. type(value))
        return
    end
    local fields = {}
    for field = 1, 16 do
        local cell = rawget(value, field)
        local kind = type(cell)
        if kind ~= "table" then
            fields[#fields + 1] = tostring(field) .. ":" .. kind
        else
            local numbers, integers, strings, tables, other = 0, 0, 0, 0, 0
            local minimum, maximum = nil, nil
            local key = nil
            local scanned = 0
            while scanned < 64 do
                local nextKey, item = next(cell, key)
                if nextKey == nil then break end
                key = nextKey
                scanned += 1
                local itemKind = type(item)
                if itemKind == "number" then
                    numbers += 1
                    if item % 1 == 0 then integers += 1 end
                    minimum = minimum == nil and item or math.min(minimum, item)
                    maximum = maximum == nil and item or math.max(maximum, item)
                elseif itemKind == "string" then
                    strings += 1
                elseif itemKind == "table" then
                    tables += 1
                else
                    other += 1
                end
            end
            local range = ""
            if minimum ~= nil then
                range = ",min=" .. tostring(minimum) .. ",max=" .. tostring(maximum)
            end
            fields[#fields + 1] = tostring(field)
                .. ":table(len=" .. tostring(#cell)
                .. ",scan=" .. tostring(scanned)
                .. ",num=" .. tostring(numbers)
                .. ",int=" .. tostring(integers)
                .. ",str=" .. tostring(strings)
                .. ",tab=" .. tostring(tables)
                .. ",other=" .. tostring(other) .. range .. ")"
        end
    end
    status(label .. " shape: " .. table.concat(fields, ";"))
end

local function resolveCaptureRoot(directRoot, runtimeState)
    if isProto(directRoot) then
        return directRoot
    end

    -- Search only a deliberately small, deterministic portion of values that
    -- already exist at the intercepted constructor site. ``next`` enumerates
    -- raw table entries and does not invoke __pairs/__index; this is required
    -- because public wrappers use large/random numeric keys rather than 1..64.
    local seen = {}
    local queue = {}
    local candidates = {}
    local candidateSet = {}

    local function enqueue(value, depth)
        if type(value) ~= "table" or seen[value] then
            return
        end
        if #queue >= 256 then
            return
        end
        seen[value] = true
        queue[#queue + 1] = { value = value, depth = depth }
    end

    enqueue(directRoot, 0)
    enqueue(runtimeState, 0)

    local cursor = 1
    while cursor <= #queue do
        local item = queue[cursor]
        cursor += 1
        local value = item.value
        if isProto(value) then
            if not candidateSet[value] then
                candidateSet[value] = true
                candidates[#candidates + 1] = value
            end
        elseif item.depth < 3 then
            local key = nil
            local scanned = 0
            while scanned < 128 do
                local nextKey, child = next(value, key)
                if nextKey == nil then
                    break
                end
                key = nextKey
                scanned += 1
                if type(child) == "table" then
                    enqueue(child, item.depth + 1)
                end
            end
        end
    end

    if #candidates == 1 then
        status("resolved wrapped capture root from bounded raw-table search")
        return candidates[1]
    end

    -- If the bounded wrapper contains more than one prototype, select a root
    -- only when exactly one candidate is not referenced as a child by another
    -- candidate.  This is structural and independent of obfuscated slot names.
    if #candidates > 1 then
        local referenced = {}
        local operandFields = { 2, 6, 7, 8, 9, 11 }
        for _, proto in candidates do
            local opcodes = rawget(proto, 4)
            local instructionCount = type(opcodes) == "table" and #opcodes or 0
            for _, field in operandFields do
                local array = rawget(proto, field)
                if type(array) == "table" then
                    for pc = 1, instructionCount do
                        local child = rawget(array, pc)
                        if candidateSet[child] then
                            referenced[child] = true
                        end
                    end
                end
            end
        end
        local roots = {}
        for _, proto in candidates do
            if not referenced[proto] then
                roots[#roots + 1] = proto
            end
        end
        if #roots == 1 then
            status("resolved wrapped capture root from prototype ownership")
            return roots[1]
        end
    end

    status(
        "capture root resolution failed: direct=" .. type(directRoot)
            .. ", candidates=" .. tostring(#candidates)
            .. ", scanned_tables=" .. tostring(#queue)
    )
    describeCaptureShape("direct root", directRoot)
    describeCaptureShape("runtime state", runtimeState)
    return nil
end

    root = resolveCaptureRoot(root, runtimeState)
    if not isProto(root) then
        error("capture received an invalid root prototype")
    end'''


def install() -> None:
    """Install a bounded structural root resolver into generated Lune runners."""
    global _INSTALLED
    if _INSTALLED:
        return

    original_builder = luraph_capture.build_lune_runner

    def build_lune_runner(*args, **kwargs):
        runner = original_builder(*args, **kwargs)
        marker = '''    if not isProto(root) then
        error("capture received an invalid root prototype")
    end'''
        if marker not in runner:
            raise luraph_capture.CaptureError(
                "safe-capture root-validation marker was not found"
            )
        runner = runner.replace(marker, _RESOLVER, 1)
        return runner

    build_lune_runner.__name__ = original_builder.__name__
    luraph_capture.build_lune_runner = build_lune_runner
    _INSTALLED = True
