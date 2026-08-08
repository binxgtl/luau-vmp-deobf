"""Canonicalize randomized public Luraph dispatcher locals before lifting.

The typed capture has a stable physical layout (prototype fields 2/4/6/7/8/9/11),
but public v14.7 factories rename every local that references those arrays, the
program counter, register file, helper table, and environment.  Older lifting
code expected the names used by one private fixture, causing valid recovered
semantics to fall back to opaque source even when every used opcode was present.

This layer derives the names from the extracted factory, augments the pure helper
map from the recovered VM, and rewrites *semantic text only* into the canonical
vocabulary consumed by ``luraph_full`` / ``luraph_lift``.  ``raw_source`` is kept
in the JSON artifact for auditing.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, Optional
import json
import re

from . import luraph_capture, luraph_recover


_NUMBER_TEXT = r"(?:0[xX][0-9A-Fa-f_]+|0[bB][01_]+|(?:[0-9][0-9_]*\.[0-9_]*|\.[0-9_]+|[0-9][0-9_]*)(?:[eE][+-]?[0-9_]+)?)"
_NUMBER = re.compile(_NUMBER_TEXT)
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_META = re.compile(r"^--\s*LUAUVMP_(?P<key>[A-Z0-9_]+)=(?P<value>.*)$", re.M)
_SUPPORTED_HELPERS = {
    "bit32.band", "bit32.bnot", "bit32.bor", "bit32.bxor",
    "bit32.countlz", "bit32.countrz", "bit32.lrotate", "bit32.lshift",
    "bit32.rrotate", "bit32.rshift",
    "math.ceil", "math.floor", "math.modf", "math.pi",
    "string.byte", "string.len", "string.packsize", "string.unpack",
    "table.create", "table.move",
}
_CANONICAL_FIELDS = {
    1: "P",
    2: "E",
    4: "L",
    6: "p",
    7: "o",
    8: "H",
    9: "_",
    11: "B",
}


def _integer(text: str) -> Optional[int]:
    cleaned = text.replace("_", "")
    try:
        if cleaned.lower().startswith("0b"):
            return int(cleaned[2:], 2)
        if cleaned.lower().startswith("0x"):
            return int(cleaned[2:], 16)
        return int(cleaned, 10)
    except ValueError:
        return None


def _number_value(text: str):
    cleaned = text.replace("_", "")
    if cleaned.lower().startswith("0b"):
        return int(cleaned[2:], 2)
    if cleaned.lower().startswith("0x"):
        return int(cleaned[2:], 16)
    if any(ch in cleaned for ch in ".eE"):
        return float(cleaned)
    return int(cleaned, 10)


def _normal_number(text: str) -> str:
    try:
        value = _number_value(text)
    except ValueError:
        return text
    if isinstance(value, int):
        return str(value)
    if value.is_integer():
        return str(int(value))
    return repr(value)


def _metadata(source: str) -> Dict[str, str]:
    return {
        match.group("key"): match.group("value").strip()
        for match in _META.finditer(source)
    }


def _split_commas(text: str) -> list[str]:
    """Split a compact Luau expression list without evaluating it."""
    parts, start, depth = [], 0, 0
    quote = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote is not None:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ('\"', "'"):
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
        index += 1
    parts.append(text[start:].strip())
    return parts


def _factory_arguments(source: str) -> list[str]:
    match = re.search(r"\(\s*function\s*\((?P<args>[^)]*)\)", source)
    if match is None:
        raise luraph_capture.CaptureError(
            "public factory arguments were not found for semantic normalization"
        )
    return [item.strip() for item in match.group("args").split(",") if item.strip()]


def _prototype_arrays(source: str, proto_name: str, limit: int) -> Dict[int, str]:
    result: Dict[int, str] = {}
    declaration = re.compile(r"\blocal\s+(?P<lhs>[^;=]+?)\s*=\s*(?P<rhs>[^;]+);")
    indexed = re.compile(
        r"\(?\s*" + re.escape(proto_name) + r"\s*\[\s*(?P<index>"
        + _NUMBER_TEXT + r")\s*\]\s*\)?$"
    )
    for match in declaration.finditer(source[:limit]):
        lhs = [item.strip() for item in match.group("lhs").split(",")]
        rhs = _split_commas(match.group("rhs"))
        if len(lhs) != len(rhs):
            continue
        for name, expression in zip(lhs, rhs):
            if _IDENTIFIER.fullmatch(name) is None:
                continue
            cell = indexed.fullmatch(expression)
            if cell is None:
                continue
            index = _integer(cell.group("index"))
            if index is not None:
                result[index] = name
    return result


def _dispatch_shape(source: str, opcode_name: str):
    pattern = re.compile(
        r"while\s+true\s+do\s+local\s+" + re.escape(opcode_name)
        + r"\s*=\s*\(?\s*(?P<array>[A-Za-z_]\w*)\s*\[\s*"
        + r"(?P<pc>[A-Za-z_]\w*)\s*\]\s*\)?",
        re.S,
    )
    match = pattern.search(source)
    if match is None:
        raise luraph_capture.CaptureError(
            "public dispatcher opcode-array/pc shape was not found"
        )
    return match, match.group("array"), match.group("pc")


def _infer_register(source: str, dispatch_start: int, pc_name: str,
                    operand_names: Iterable[str], excluded: set[str]) -> str:
    body = source[dispatch_start:]
    counts: Dict[str, int] = {}
    for operand in operand_names:
        pattern = re.compile(
            r"\b(?P<base>[A-Za-z_]\w*)\s*\[\s*"
            + re.escape(operand) + r"\s*\[\s*" + re.escape(pc_name)
            + r"\s*\]\s*\]"
        )
        for match in pattern.finditer(body):
            base = match.group("base")
            if base in excluded:
                continue
            counts[base] = counts.get(base, 0) + 1
    if not counts:
        raise luraph_capture.CaptureError(
            "public dispatcher register file could not be inferred"
        )
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    if len(ordered) > 1 and ordered[0][1] == ordered[1][1]:
        raise luraph_capture.CaptureError(
            "public dispatcher register file inference was ambiguous"
        )
    return ordered[0][0]


def infer_canonical_variables(factory_source: str) -> Dict[str, str]:
    metadata = _metadata(factory_source)
    opcode_name = metadata.get("DISPATCH_VAR")
    helper_name = metadata.get("HELPER_VAR")
    if metadata.get("PUBLIC_V147") != "1" or not opcode_name or not helper_name:
        return {}
    arguments = _factory_arguments(factory_source)
    if not arguments:
        raise luraph_capture.CaptureError("public factory has no prototype argument")
    proto_name = arguments[0]
    environment_name = arguments[1] if len(arguments) > 1 else None
    dispatch, opcode_array, pc_name = _dispatch_shape(factory_source, opcode_name)
    arrays = _prototype_arrays(factory_source, proto_name, dispatch.start())
    if arrays.get(4) != opcode_array:
        raise luraph_capture.CaptureError(
            "public dispatcher opcode array does not match prototype field 4"
        )

    mapping: Dict[str, str] = {}
    for index, canonical in _CANONICAL_FIELDS.items():
        actual = arrays.get(index)
        if actual is not None and actual != canonical:
            mapping[actual] = canonical
    mapping[opcode_name] = "X"
    mapping[pc_name] = "u"
    mapping[helper_name] = "A"
    if environment_name is not None and environment_name != "I":
        mapping[environment_name] = "I"

    operands = [arrays[index] for index in (2, 6, 7, 8, 9, 11)
                if index in arrays]
    excluded = set(arrays.values()) | {proto_name, helper_name, opcode_name, pc_name}
    if environment_name is not None:
        excluded.add(environment_name)
    register = _infer_register(
        factory_source, dispatch.start(), pc_name, operands, excluded
    )
    if register != "c":
        mapping[register] = "c"
    return mapping


def canonicalize_source(source: str, mapping: Dict[str, str]) -> str:
    """Rename identifiers and normalize numeric literals without touching strings."""
    output = []
    index = 0
    while index < len(source):
        char = source[index]
        if char in ('\"', "'"):
            quote = char
            cursor = index + 1
            while cursor < len(source):
                if source[cursor] == "\\":
                    cursor += 2
                    continue
                if source[cursor] == quote:
                    cursor += 1
                    break
                cursor += 1
            output.append(source[index:cursor])
            index = cursor
            continue
        identifier = _IDENTIFIER.match(source, index)
        if identifier is not None:
            value = identifier.group(0)
            output.append(mapping.get(value, value))
            index = identifier.end()
            continue
        number = _NUMBER.match(source, index)
        if number is not None:
            output.append(_normal_number(number.group(0)))
            index = number.end()
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _complete_nested_helpers(vm_source: str) -> Dict[int, Dict[int, str]]:
    direct_pattern = re.compile(
        r"(?<![A-Za-z0-9_.])(?P<name>[A-Za-z_]\w*)\s*=\s*"
        r"(?P<module>bit32|string|math)\.(?P<function>[A-Za-z_]\w*)"
    )
    module_pattern = re.compile(
        r"(?<![A-Za-z0-9_.])(?P<name>[A-Za-z_]\w*)\s*=\s*"
        r"(?P<module>bit32|string|math)(?!\s*\.)"
    )
    direct = {
        match.group("name"): "%s.%s" % (
            match.group("module"), match.group("function")
        )
        for match in direct_pattern.finditer(vm_source)
    }
    modules = {
        match.group("name"): match.group("module")
        for match in module_pattern.finditer(vm_source)
    }
    nested_pattern = re.compile(
        r"(?:\(\s*)?(?P<table>[A-Za-z_]\w*)\s*\[\s*"
        r"(?P<table_slot>" + _NUMBER_TEXT + r")\s*\](?:\s*\))?\s*"
        r"\[\s*(?P<function_slot>" + _NUMBER_TEXT + r")\s*\]\s*=\s*"
        r"\(?\s*(?P<object>[A-Za-z_]\w*)\.(?P<alias>[A-Za-z_]\w*)"
        r"(?:\.(?P<function>[A-Za-z_]\w*))?\s*\)?",
        re.S,
    )
    nested: Dict[int, Dict[int, str]] = {}
    for match in nested_pattern.finditer(vm_source):
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


def _complete_direct_helpers(vm_source: str, helper_name: str) -> Dict[int, str]:
    """Recover top-level pure helper slots assigned through VM aliases."""
    direct_pattern = re.compile(
        r"(?<![A-Za-z0-9_.])(?P<name>[A-Za-z_]\w*)\s*=\s*"
        r"(?P<module>bit32|string|math|table)\.(?P<function>[A-Za-z_]\w*)"
    )
    module_pattern = re.compile(
        r"(?<![A-Za-z0-9_.])(?P<name>[A-Za-z_]\w*)\s*=\s*"
        r"(?P<module>bit32|string|math|table)(?!\s*\.)"
    )
    direct = {
        match.group("name"): "%s.%s" % (
            match.group("module"), match.group("function")
        )
        for match in direct_pattern.finditer(vm_source)
    }
    modules = {
        match.group("name"): match.group("module")
        for match in module_pattern.finditer(vm_source)
    }
    assignment = re.compile(
        r"(?:\(\s*)?" + re.escape(helper_name) + r"(?:\s*\))?\s*"
        r"\[\s*(?P<slot>" + _NUMBER_TEXT + r")\s*\]\s*=\s*\(?\s*"
        r"(?:[A-Za-z_]\w*\.)?(?P<alias>[A-Za-z_]\w*)"
        r"(?:\.(?P<function>[A-Za-z_]\w*))?\s*\)?",
        re.S,
    )
    recovered: Dict[int, str] = {}
    ambiguous = set()
    for match in assignment.finditer(vm_source):
        slot = _integer(match.group("slot"))
        if slot is None or not 0 <= slot <= 255:
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
        previous = recovered.get(slot)
        if previous is not None and previous != identity:
            ambiguous.add(slot)
        else:
            recovered[slot] = identity
    for slot in ambiguous:
        recovered.pop(slot, None)
    return recovered


def _replace_marker(source: str, key: str, value: str) -> str:
    pattern = re.compile(r"^--\s*LUAUVMP_" + re.escape(key) + r"=.*$", re.M)
    line = "-- LUAUVMP_%s=%s" % (key, value)
    if pattern.search(source):
        return pattern.sub(line, source, count=1)
    first_newline = source.find("\n")
    if first_newline < 0:
        return line + "\n" + source
    return source[:first_newline + 1] + line + "\n" + source[first_newline + 1:]


def _augment_public_factory(factory_path: Path) -> Dict[str, str]:
    source = factory_path.read_text(encoding="utf-8", errors="surrogateescape")
    if "LUAUVMP_PUBLIC_V147=1" not in source:
        return {}
    sibling_vm = factory_path.with_name("interpreter.vm.luau")
    if sibling_vm.is_file():
        vm_source = sibling_vm.read_text(encoding="utf-8", errors="surrogateescape")
        complete = _complete_nested_helpers(vm_source)
        current = _metadata(source).get("NESTED_HELPERS", "{}")
        try:
            merged_raw = json.loads(current)
        except json.JSONDecodeError:
            merged_raw = {}
        merged: Dict[int, Dict[int, str]] = {
            int(table): {int(slot): str(name) for slot, name in entries.items()}
            for table, entries in merged_raw.items()
        }
        for table, entries in complete.items():
            merged.setdefault(table, {}).update(entries)
        encoded = {
            str(table): {str(slot): name for slot, name in sorted(entries.items())}
            for table, entries in sorted(merged.items())
        }
        source = _replace_marker(
            source, "NESTED_HELPERS",
            json.dumps(encoded, separators=(",", ":"), sort_keys=True),
        )
        helper_name = _metadata(source).get("HELPER_VAR")
        if helper_name:
            direct_helpers = _complete_direct_helpers(vm_source, helper_name)
            source = _replace_marker(
                source, "DIRECT_HELPERS",
                json.dumps(direct_helpers, separators=(",", ":"), sort_keys=True),
            )
    mapping = infer_canonical_variables(source)
    source = _replace_marker(
        source, "CANONICAL_VARS",
        json.dumps(mapping, separators=(",", ":"), sort_keys=True),
    )
    factory_path.write_text(source, encoding="utf-8", errors="surrogateescape")
    return mapping


def _rewrite_semantics(output: Path, text_output: Optional[Path],
                       mapping: Dict[str, str]):
    data = json.loads(output.read_text(encoding="utf-8"))
    for value in data.values():
        if not isinstance(value, dict):
            continue
        raw = value.get("source", "")
        value["raw_source"] = raw
        value["source"] = canonicalize_source(raw, mapping)
        value["canonicalized"] = bool(mapping)
    output.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if text_output is not None:
        lines = []
        for opcode in sorted((int(key) for key in data)):
            item = data[str(opcode)]
            lines.append("=== OPCODE %d | unknown_if=%s ===" % (
                opcode, item.get("unknown_ifs", 0)
            ))
            lines.append(item.get("source", ""))
            lines.append("")
        text_output.write_text("\n".join(lines), encoding="utf-8")
    return data


_ORIGINAL_RECOVER = None
_INSTALLED = False


def recover_dispatch(factory, runtime_facts, output, text_output=None):
    if _ORIGINAL_RECOVER is None:
        raise RuntimeError("semantic normalization layer is unavailable")
    factory_path = Path(factory)
    output_path = Path(output)
    text_path = Path(text_output) if text_output is not None else None
    mapping = _augment_public_factory(factory_path)
    result = _ORIGINAL_RECOVER(factory, runtime_facts, output, text_output)
    if not mapping:
        return result
    return _rewrite_semantics(output_path, text_path, mapping)


def install() -> None:
    global _ORIGINAL_RECOVER, _INSTALLED
    if _INSTALLED:
        return
    _ORIGINAL_RECOVER = luraph_recover.recover_dispatch
    luraph_recover.recover_dispatch = recover_dispatch
    _INSTALLED = True
