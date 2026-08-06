"""Support the public single-stream Luraph v14.7 wrapper family.

These loaders keep the interpreter in the wrapper, store the virtual bytecode in
one Ascii85 + Zstandard stream, build the closure factory in helper slot 59,
and construct the final application closure only after a bootstrap pass.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterator, Optional
import json
import re

from . import luraph_capture


_NUMBER = r"(?:0[xX][0-9A-Fa-f_]+|0[bB][01_]+|[0-9][0-9_]*)"
_PUBLIC_FINAL_RETURN = re.compile(
    r"return\s+(?P<state>[A-Za-z_]\w*)\s*\[\s*(?P<slot>" + _NUMBER + r")\s*\]"
    r"\s*\(\s*(?P<root>[A-Za-z_]\w*)\s*,\s*(?P=state)\s*\[\s*"
    r"(?P<environment>" + _NUMBER + r")\s*\]\s*\)\s*;",
    re.S,
)
_FACTORY_ASSIGN = re.compile(
    r"(?:\(\s*)?(?P<helper>[A-Za-z_]\w*)(?:\s*\))?\s*\[\s*"
    r"(?P<slot>" + _NUMBER + r")\s*\]\s*=\s*(?P<function>function)\s*\(",
    re.S,
)
_DISPATCH_LOCAL = re.compile(
    r"while\s+true\s+do\s+local\s+(?P<opcode>[A-Za-z_]\w*)\s*=",
    re.S,
)
_DIRECT_ALIAS = re.compile(
    r"(?<![A-Za-z0-9_.])(?P<name>[A-Za-z_]\w*)\s*=\s*"
    r"(?P<module>bit32|string|math)\.(?P<function>[A-Za-z_]\w*)"
)
_MODULE_ALIAS = re.compile(
    r"(?<![A-Za-z0-9_.])(?P<name>[A-Za-z_]\w*)\s*=\s*"
    r"(?P<module>bit32|string|math)(?!\s*\.)"
)
_NESTED_ASSIGN = re.compile(
    r"(?:\(\s*)?(?P<table>[A-Za-z_]\w*)(?:\s*\))?\s*"
    r"\[\s*(?P<table_slot>" + _NUMBER + r")\s*\]\s*"
    r"\[\s*(?P<function_slot>" + _NUMBER + r")\s*\]\s*=\s*"
    r"\(?\s*(?P<object>[A-Za-z_]\w*)\.(?P<alias>[A-Za-z_]\w*)"
    r"(?:\.(?P<function>[A-Za-z_]\w*))?\s*\)?",
    re.S,
)
_SUPPORTED_HELPERS = {
    "bit32.band", "bit32.bnot", "bit32.bor", "bit32.bxor",
    "bit32.countlz", "bit32.countrz", "bit32.lrotate", "bit32.lshift",
    "bit32.rrotate", "bit32.rshift",
    "math.ceil", "math.floor", "math.modf", "math.pi",
    "string.byte", "string.len", "string.packsize", "string.unpack",
}


@dataclass(frozen=True)
class _Token:
    value: str
    start: int
    end: int
    kind: str


def _integer(text: str) -> Optional[int]:
    cleaned = text.replace("_", "")
    try:
        return int(cleaned, 0)
    except ValueError:
        try:
            return int(cleaned, 10)
        except ValueError:
            return None


def _long_bracket_end(source: str, start: int) -> Optional[int]:
    match = re.match(r"\[(=*)\[", source[start:])
    if match is None:
        return None
    close = "]" + match.group(1) + "]"
    position = source.find(close, start + len(match.group(0)))
    return None if position < 0 else position + len(close)


def _tokens(source: str, start: int = 0) -> Iterator[_Token]:
    index = start
    length = len(source)
    number = re.compile(_NUMBER)
    identifier = re.compile(r"[A-Za-z_]\w*")
    while index < length:
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("--", index):
            long_end = _long_bracket_end(source, index + 2)
            if long_end is not None:
                index = long_end
            else:
                newline = source.find("\n", index + 2)
                index = length if newline < 0 else newline + 1
            continue
        if char in ('"', "'"):
            quote = char
            cursor = index + 1
            while cursor < length:
                if source[cursor] == "\\":
                    cursor += 2
                    continue
                if source[cursor] == quote:
                    cursor += 1
                    break
                cursor += 1
            yield _Token(source[index:cursor], index, cursor, "string")
            index = cursor
            continue
        if char == "[":
            long_end = _long_bracket_end(source, index)
            if long_end is not None:
                yield _Token(source[index:long_end], index, long_end, "string")
                index = long_end
                continue
        match = identifier.match(source, index)
        if match is not None:
            yield _Token(match.group(0), index, match.end(), "identifier")
            index = match.end()
            continue
        match = number.match(source, index)
        if match is not None:
            yield _Token(match.group(0), index, match.end(), "number")
            index = match.end()
            continue
        yield _Token(char, index, index + 1, "operator")
        index += 1


def _function_end(source: str, function_start: int) -> int:
    """Return the end offset for one anonymous function expression."""
    stack = []
    pending_do = 0
    for token in _tokens(source, function_start):
        value = token.value
        if token.kind != "identifier":
            continue
        if value == "function":
            stack.append("function")
        elif value == "if":
            stack.append("if")
        elif value in ("while", "for"):
            stack.append(value)
            pending_do += 1
        elif value == "repeat":
            stack.append("repeat")
        elif value == "do":
            if pending_do:
                pending_do -= 1
            else:
                stack.append("do")
        elif value == "until":
            if not stack or stack[-1] != "repeat":
                raise luraph_capture.CaptureError(
                    "unbalanced repeat/until while extracting public factory"
                )
            stack.pop()
        elif value == "end":
            if not stack:
                raise luraph_capture.CaptureError(
                    "unexpected end while extracting public factory"
                )
            stack.pop()
            if not stack:
                return token.end
    raise luraph_capture.CaptureError("public slot-59 factory did not terminate")


def _nested_helpers(vm_source: str) -> Dict[int, Dict[int, str]]:
    """Resolve helper identities assigned into runtime sub-tables.

    The public family copies native bit/string/math functions through randomized
    object-field aliases before placing them in helper tables such as slots 52
    and 0x34. Only a small, pure allow-list is emitted to the specializer.
    """
    direct = {
        match.group("name"): "%s.%s" % (
            match.group("module"), match.group("function")
        )
        for match in _DIRECT_ALIAS.finditer(vm_source)
    }
    modules = {
        match.group("name"): match.group("module")
        for match in _MODULE_ALIAS.finditer(vm_source)
    }
    nested: Dict[int, Dict[int, str]] = {}
    for match in _NESTED_ASSIGN.finditer(vm_source):
        table_slot = _integer(match.group("table_slot"))
        function_slot = _integer(match.group("function_slot"))
        if table_slot is None or function_slot is None:
            continue
        alias = match.group("alias")
        function = match.group("function")
        if function is not None and alias in modules:
            identity = "%s.%s" % (modules[alias], function)
        elif function is None:
            identity = direct.get(alias)
        else:
            identity = None
        if identity not in _SUPPORTED_HELPERS:
            continue
        nested.setdefault(table_slot, {})[function_slot] = identity
    return nested


def _public_factory(vm_source: str) -> Optional[str]:
    candidates = []
    for match in _FACTORY_ASSIGN.finditer(vm_source):
        if _integer(match.group("slot")) == 59:
            candidates.append(match)
    if not candidates:
        return None
    if len(candidates) != 1:
        raise luraph_capture.CaptureError(
            "expected one public slot-59 factory assignment, found %d"
            % len(candidates)
        )
    match = candidates[0]
    function_start = match.start("function")
    function_end = _function_end(vm_source, function_start)
    function_source = vm_source[function_start:function_end]
    dispatch = _DISPATCH_LOCAL.search(function_source)
    if dispatch is None:
        raise luraph_capture.CaptureError(
            "public slot-59 factory did not contain a dispatcher loop"
        )
    helper = match.group("helper")
    opcode = dispatch.group("opcode")
    nested = _nested_helpers(vm_source)
    if not nested:
        raise luraph_capture.CaptureError(
            "public wrapper did not expose any recognized nested helpers"
        )
    marker = (
        "-- LUAUVMP_PUBLIC_V147=1\n"
        "-- LUAUVMP_HELPER_VAR=%s\n"
        "-- LUAUVMP_DISPATCH_VAR=%s\n"
        "-- LUAUVMP_NESTED_HELPERS=%s\n" % (
            helper,
            opcode,
            json.dumps(nested, separators=(",", ":"), sort_keys=True),
        )
    )
    return marker + "(" + function_source + ")"


def extract_interpreter_factory(vm_source: str) -> str:
    public = _public_factory(vm_source)
    if public is not None:
        return public
    if _ORIGINAL_FACTORY is None:
        raise luraph_capture.CaptureError("legacy factory extractor is unavailable")
    return _ORIGINAL_FACTORY(vm_source)


def instrument_vm_source(vm_source: str) -> str:
    candidates = []
    for match in _PUBLIC_FINAL_RETURN.finditer(vm_source):
        if (_integer(match.group("slot")) == 59
                and _integer(match.group("environment")) == 1):
            candidates.append(match)
    if candidates:
        if len(candidates) != 1:
            raise luraph_capture.CaptureError(
                "expected one public final closure constructor, found %d"
                % len(candidates)
            )
        match = candidates[0]
        replacement = "return __LUAUVMP_CAPTURE(%s,%s);" % (
            match.group("state"), match.group("root")
        )
        patched = vm_source[:match.start()] + replacement + vm_source[match.end():]
        if _PUBLIC_FINAL_RETURN.search(patched):
            raise luraph_capture.CaptureError(
                "public final closure constructor remained after instrumentation"
            )
        return patched
    if _ORIGINAL_INSTRUMENT is None:
        raise luraph_capture.CaptureError("legacy VM instrumenter is unavailable")
    return _ORIGINAL_INSTRUMENT(vm_source)


_ORIGINAL_FACTORY = None
_ORIGINAL_INSTRUMENT = None
_INSTALLED = False


def install() -> None:
    global _ORIGINAL_FACTORY, _ORIGINAL_INSTRUMENT, _INSTALLED
    if _INSTALLED:
        return
    _ORIGINAL_FACTORY = luraph_capture.extract_interpreter_factory
    _ORIGINAL_INSTRUMENT = luraph_capture.instrument_vm_source
    luraph_capture.extract_interpreter_factory = extract_interpreter_factory
    luraph_capture.instrument_vm_source = instrument_vm_source
    _INSTALLED = True
