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
from . import luraph_public_v147 as public
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


def _normalize_numbers(text: str) -> str:
    """Canonicalize Luau numeric spelling without changing token boundaries."""
    return _NUMBER_TOKEN.sub(
        lambda match: normalize._normal_number(match.group(1)), text
    )


def _compact_for_shape(text: str) -> str:
    # Use compact text only for punctuation-heavy arithmetic fingerprints. Token
    # boundary-sensitive assignments are matched against _normalize_numbers()
    # directly so ``then j=`` can never become the fake identifier ``thenj``.
    return re.sub(r"\s+", "", _normalize_numbers(text))


def _code_only(source: str) -> str:
    """Mask Luau comments and strings while preserving source offsets."""
    pieces = []
    cursor = 0
    for token in public._tokens(source):
        pieces.append(" " * (token.start - cursor))
        if token.kind == "string":
            pieces.append(" " * (token.end - token.start))
        else:
            pieces.append(source[token.start:token.end])
        cursor = token.end
    pieces.append(" " * (len(source) - cursor))
    return "".join(pieces)


def infer_range_helpers(vm_source: str) -> Dict[int, Tuple[int, int, int]]:
    """Return ``slot -> (table_arg, start_arg, end_arg)`` for proven unpackers.

    The argument ordering varies between public builds, so it is recovered from
    the body instead of assumed. Cosmetic parentheses around the helper table or
    an ``arg or 1`` default are accepted, but all semantic evidence is still
    required. Ambiguous duplicate slots are rejected.
    """
    assignment = re.compile(
        r"(?:\(\s*)?(?P<table>[A-Za-z_]\w*)\s*(?:\)\s*)?"
        r"\[\s*(?P<slot>" + _NUMBER + r")\s*\]"
        r"\s*=\s*\(?\s*(?P<function>function)\s*\((?P<args>[^)]*)\)",
        re.S,
    )
    result: Dict[int, Tuple[int, int, int]] = {}
    code_source = _code_only(vm_source)
    for match in assignment.finditer(code_source):
        args = [item.strip() for item in match.group("args").split(",") if item.strip()]
        if len(args) != 3 or any(
            re.fullmatch(r"[A-Za-z_]\w*", arg) is None for arg in args
        ):
            continue
        function_end = public._function_end(
            code_source, match.start("function")
        )
        body = code_source[match.end():function_end]
        normalized = _normalize_numbers(body)
        compact = re.sub(r"\s+", "", normalized)

        start_name = None
        for arg in args:
            if re.search(
                r"\b" + re.escape(arg) + r"\s*=\s*\(?\s*"
                + re.escape(arg) + r"\s+or\s+1\s*\)?",
                normalized,
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
                    r"\b" + re.escape(end) + r"\s*=\s*\(?\s*"
                    + re.escape(end) + r"\s+or\s*#\s*"
                    + re.escape(table) + r"\s*\)?",
                    normalized,
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


def _split_args(text: str, code: Optional[str] = None) -> Optional[list[str]]:
    structure = _code_only(text) if code is None else code
    if len(structure) != len(text):
        return None
    parts = []
    start = 0
    stack = []
    index = 0
    pairs = {")": "(", "]": "[", "}": "{"}
    while index < len(structure):
        char = structure[index]
        if char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or stack[-1] != pairs[char]:
                return None
            stack.pop()
        elif char == "," and not stack:
            parts.append(text[start:index].strip())
            start = index + 1
        index += 1
    if stack:
        return None
    parts.append(text[start:].strip())
    return parts


def _sub_code(text, pattern, replacement):
    """Apply a regex replacement only to executable Luau tokens."""
    code = _code_only(text)
    pieces = []
    cursor = 0
    for match in pattern.finditer(code):
        pieces.append(text[cursor:match.start()])
        pieces.append(replacement(match))
        cursor = match.end()
    pieces.append(text[cursor:])
    return "".join(pieces)


def _rewrite_range_calls(
    source: str, direct: Dict[int, Tuple[int, int, int]]
) -> str:
    text = source
    for slot, roles in sorted(direct.items()):
        prefix = re.compile(
            r"(?<![A-Za-z0-9_])(?:A|\(\s*A\s*\))\s*\[\s*" + str(slot)
            + r"(?:\.0)?\s*\]\s*\("
        )
        cursor = 0
        pieces = []
        changed = False
        code = _code_only(text)
        while True:
            match = prefix.search(code, cursor)
            if match is None:
                pieces.append(text[cursor:])
                break
            pieces.append(text[cursor:match.start()])
            depth = 1
            index = match.end()
            while index < len(code) and depth:
                char = code[index]
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                index += 1
            if depth != 0:
                pieces.append(text[match.start():])
                break
            args = _split_args(
                text[match.end():index - 1],
                code[match.end():index - 1],
            )
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
        text = _sub_code(
            text,
            pattern,
            lambda match, value=literal: "(%s)[%s[u]]"
            % (value, match.group("field")),
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
