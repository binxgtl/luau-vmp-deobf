"""Replace sample-local VM helper lookups with pure Luau operations.

Public v14.7 stores bit32/string/math helpers in a randomized nested ``A`` table
and also randomizes the top-level helper used to unpack a register range. The
nested slot map is already recovered into factory metadata. The range helper is
identified structurally from the recovered VM: it has three parameters, defaults
one parameter to ``1``, defaults another to ``#table``, and dispatches between
fast/recursive unpack paths based on that range length.

Only those proven helper shapes are rewritten; everything else remains untouched
for audit/fallback handling.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Tuple
import json
import re

from . import luraph_capture, luraph_recover
from . import luraph_semantic_normalize as normalize

_INSTALLED = False
_ORIGINAL_RECOVER = None
_FIELD = r"[EpoH_B]"
_NUMBER = normalize._NUMBER_TEXT
_NUMBER_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(" + _NUMBER + r")(?![A-Za-z0-9_])"
)


def _nested_helpers(factory: Path) -> Dict[int, Dict[int, str]]:
    source = factory.read_text(encoding="utf-8", errors="surrogateescape")
    raw = normalize._metadata(source).get("NESTED_HELPERS", "{}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return {
        int(table): {int(slot): str(name) for slot, name in entries.items()}
        for table, entries in data.items()
    }


def _helper_literal(entries: Dict[int, str]) -> str:
    return "{" + ",".join(
        "[%d]=%s" % (slot, name) for slot, name in sorted(entries.items())
    ) + "}"


def _compact_for_shape(text: str) -> str:
    # Normalize numeric tokens while their lexical boundaries still exist, then
    # remove whitespace. Doing this in the opposite order turns ``or 0b1`` into
    # ``or0b1`` and prevents a boundary-safe numeric match.
    normalized = _NUMBER_TOKEN.sub(
        lambda match: normalize._normal_number(match.group(1)), text
    )
    return re.sub(r"\s+", "", normalized)


def infer_range_helpers(vm_source: str) -> Dict[int, Tuple[int, int, int]]:
    """Return ``slot -> (table_arg, start_arg, end_arg)`` for proven unpackers.

    The argument ordering varies between public builds, so it is recovered from
    the body instead of assumed. Ambiguous duplicate slots are rejected.
    """
    assignment = re.compile(
        r"(?P<table>[A-Za-z_]\w*)\s*\[\s*(?P<slot>" + _NUMBER + r")\s*\]"
        r"\s*=\s*\(?\s*function\s*\((?P<args>[^)]*)\)",
        re.S,
    )
    result: Dict[int, Tuple[int, int, int]] = {}
    for match in assignment.finditer(vm_source):
        args = [item.strip() for item in match.group("args").split(",") if item.strip()]
        if len(args) != 3 or any(
            re.fullmatch(r"[A-Za-z_]\w*", arg) is None for arg in args
        ):
            continue
        compact = _compact_for_shape(vm_source[match.end():match.end() + 900])

        start_name = None
        for arg in args:
            if re.search(
                r"\b" + re.escape(arg) + r"=" + re.escape(arg) + r"or1\b",
                compact,
            ):
                start_name = arg
                break
        if start_name is None:
            continue

        end_name = table_name = None
        for end in args:
            for table in args:
                if end == table:
                    continue
                if re.search(
                    r"\b" + re.escape(end) + r"=" + re.escape(end)
                    + r"or#" + re.escape(table) + r"\b",
                    compact,
                ):
                    end_name, table_name = end, table
                    break
            if end_name is not None:
                break
        if end_name is None or table_name is None:
            continue
        if len({start_name, end_name, table_name}) != 3:
            continue

        expr = end_name + "-" + start_name + "+1"
        if expr not in compact and ("(" + expr + ")") not in compact:
            continue
        if "7997" not in compact or compact.count("return") < 1:
            continue

        slot = normalize._integer(match.group("slot"))
        if slot is None:
            continue
        roles = (
            args.index(table_name), args.index(start_name), args.index(end_name)
        )
        if slot in result and result[slot] != roles:
            raise luraph_capture.CaptureError(
                "ambiguous public range-helper argument order for slot %d" % slot
            )
        result[slot] = roles
    return result


def _split_args(text: str) -> Optional[list[str]]:
    parts = []
    start = 0
    stack = []
    quote = None
    index = 0
    pairs = {")": "(", "]": "[", "}": "{"}
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
        if char in ("'", '"'):
            quote = char
        elif char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or stack[-1] != pairs[char]:
                return None
            stack.pop()
        elif char == "," and not stack:
            parts.append(text[start:index].strip())
            start = index + 1
        index += 1
    if quote is not None or stack:
        return None
    parts.append(text[start:].strip())
    return parts


def _rewrite_range_calls(
    source: str, direct: Dict[int, Tuple[int, int, int]]
) -> str:
    text = source
    for slot, roles in sorted(direct.items()):
        prefix = re.compile(
            r"\bA\s*\[\s*" + str(slot) + r"(?:\.0)?\s*\]\s*\("
        )
        cursor = 0
        pieces = []
        changed = False
        while True:
            match = prefix.search(text, cursor)
            if match is None:
                pieces.append(text[cursor:])
                break
            pieces.append(text[cursor:match.start()])
            depth = 1
            quote = None
            index = match.end()
            while index < len(text) and depth:
                char = text[index]
                if quote is not None:
                    if char == "\\":
                        index += 2
                        continue
                    if char == quote:
                        quote = None
                elif char in ("'", '"'):
                    quote = char
                elif char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                index += 1
            if depth != 0:
                pieces.append(text[match.start():])
                break
            args = _split_args(text[match.end():index - 1])
            if args is None or len(args) != 3:
                pieces.append(text[match.start():index])
                cursor = index
                continue
            table_i, start_i, end_i = roles
            pieces.append(
                "table.unpack(%s,%s,%s)"
                % (args[table_i], args[start_i], args[end_i])
            )
            changed = True
            cursor = index
        rewritten = "".join(pieces)
        if changed:
            text = rewritten
    return text


def rewrite_source(
    source: str,
    nested: Dict[int, Dict[int, str]],
    direct: Optional[Dict[int, Tuple[int, int, int]]] = None,
) -> str:
    text = source
    for table, entries in sorted(nested.items()):
        if not entries:
            continue
        literal = _helper_literal(entries)
        pattern = re.compile(
            r"\bA\s*\[\s*" + str(table) + r"(?:\.0)?\s*\]\s*"
            r"\[\s*(?P<field>" + _FIELD + r")\s*\[\s*u\s*\]\s*\]"
        )
        text = pattern.sub(
            lambda match, value=literal: "(%s)[%s[u]]"
            % (value, match.group("field")),
            text,
        )
    if direct:
        text = _rewrite_range_calls(text, direct)
    return text


def _rewrite_output(output: Path, text_output: Optional[Path], nested, direct):
    data = json.loads(output.read_text(encoding="utf-8"))
    changed = False
    for value in data.values():
        if not isinstance(value, dict):
            continue
        old = value.get("source", "")
        new = rewrite_source(old, nested, direct)
        if new != old:
            value["source"] = new
            value["helpers_literalized"] = True
            changed = True
    if not changed:
        return data
    output.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if text_output is not None:
        lines = []
        for opcode in sorted(int(key) for key in data):
            item = data[str(opcode)]
            lines.append(
                "=== OPCODE %d | unknown_if=%s ==="
                % (opcode, item.get("unknown_ifs", 0))
            )
            lines.append(item.get("source", ""))
            lines.append("")
        text_output.write_text("\n".join(lines), encoding="utf-8")
    return data


def recover_dispatch(factory, runtime_facts, output, text_output=None):
    result = _ORIGINAL_RECOVER(factory, runtime_facts, output, text_output)
    factory_path = Path(factory)
    nested = _nested_helpers(factory_path)
    vm_path = factory_path.with_name("interpreter.vm.luau")
    direct = (
        infer_range_helpers(
            vm_path.read_text(encoding="utf-8", errors="surrogateescape")
        )
        if vm_path.is_file()
        else {}
    )
    if not nested and not direct:
        return result
    return _rewrite_output(
        Path(output),
        Path(text_output) if text_output is not None else None,
        nested,
        direct,
    )


def install() -> None:
    global _INSTALLED, _ORIGINAL_RECOVER
    if _INSTALLED:
        return
    _ORIGINAL_RECOVER = luraph_recover.recover_dispatch
    luraph_recover.recover_dispatch = recover_dispatch
    _INSTALLED = True
