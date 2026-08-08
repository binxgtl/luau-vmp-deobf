"""Lift public-v14.7 closure construction from captured descriptor metadata.

The three pinned public families randomize the child-prototype operand, closure
factory slot, capture-descriptor field, descriptor row layout and raw open-cell
layout.  This module derives every one of those roles from the recovered opcode
body and validates the child descriptor table captured in ``Proto.field3``.

No closure is executed while recovering these facts.  Ambiguous shapes, missing
children, sparse descriptors, unexpected capture modes, or an unproven raw cell
layout remain ordinary semantic fallbacks.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple
import re

from . import luraph_decompiler, luraph_lift
from . import luraph_public_v147 as public
from .luraph_full import Instruction, Program, ProtoRef
from .luraph_upvalue_descriptors import DescriptorError, decode_descriptors


_INSTALLED = False
_ORIGINAL_CLEAN = None
_ORIGINAL_RENDER = None
_CURRENT_PROGRAM: Optional[Program] = None
_CURRENT_CELL_LAYOUT: Optional[Tuple[int, int]] = None
_ID = r"[A-Za-z_]\w*"
_FIELD = r"[EpoH_B]"


@dataclass(frozen=True)
class ClosureShape:
    child_field: str
    destination_field: str
    descriptor_field: int
    mode_key: int
    register_key: int
    captures_name: str
    mode_name: str
    cell_name: str
    cache_name: str
    open_table_key: int
    open_index_key: int


def _integer(text: str) -> Optional[int]:
    try:
        value = float(text)
    except ValueError:
        return None
    if not value.is_integer():
        return None
    return int(value)


def _field_assignment(source: str, name: str):
    return re.search(
        r"(?:(?:local)\s+)?" + re.escape(name)
        + r"\s*=\s*\(?\s*(?P<field>" + _FIELD
        + r")\s*\[\s*u\s*\]\s*\)?\s*;",
        source,
        re.S,
    )


def _candidate_shapes(source: str) -> List[ClosureShape]:
    """Return all complete closure shapes proven by one recovered opcode body."""
    results: List[ClosureShape] = []
    factory = re.compile(
        r"\b(?P<fn>" + _ID + r")\s*=\s*"
        r"A\s*\[\s*(?P<slot>\d+)(?:\.0)?\s*\]\s*"
        r"\(\s*(?P<proto>" + _ID + r")\s*,\s*(?P<caps>" + _ID
        + r")\s*\)\s*;",
        re.S,
    )
    for call in factory.finditer(source):
        fn, proto, caps = call.group("fn", "proto", "caps")

        # The recovered environment pass must independently prove the closure
        # environment before this lifter is allowed to replace the VM factory.
        if re.search(
            r"\(?\s*A\s*\[\s*\d+(?:\.0)?\s*\]\s*\)?\s*"
            r"\(\s*" + re.escape(fn) + r"\s*,\s*__ENV\s*\)\s*;",
            source,
            re.S,
        ) is None:
            continue

        child = _field_assignment(source, proto)
        if child is None:
            continue
        child_field = child.group("field")

        descriptor = re.search(
            r"\b(?P<desc>" + _ID + r")\s*=\s*\(?\s*"
            + re.escape(proto)
            + r"\s*\[\s*(?P<field>\d+)(?:\.0)?\s*\]\s*\)?\s*;",
            source,
            re.S,
        )
        if descriptor is None:
            continue
        desc = descriptor.group("desc")
        descriptor_field = _integer(descriptor.group("field"))
        if descriptor_field is None:
            continue

        count_match = re.search(
            r"\b(?P<count>" + _ID + r")\s*=\s*\(?\s*#\s*"
            + re.escape(desc) + r"\s*\)?\s*;",
            source,
            re.S,
        )
        if count_match is None:
            continue
        count = count_match.group("count")
        if re.search(
            r"\b" + re.escape(caps) + r"\s*=\s*" + re.escape(count)
            + r"\s*>\s*0(?:\.0)?\s+and\s*\{\s*\}\s*;",
            source,
            re.S,
        ) is None:
            continue

        destination = re.search(
            r"(?:\(\s*c\s*\)|c)\s*\[\s*(?P<field>" + _FIELD
            + r")\s*\[\s*u\s*\]\s*\]\s*=\s*\(?\s*"
            + re.escape(fn) + r"\s*\)?\s*;",
            source,
            re.S,
        )
        if destination is None:
            continue

        loop = re.search(
            r"\bfor\s+(?P<loop>" + _ID + r")\s*=\s*1\s*,\s*"
            + re.escape(count) + r"\s*(?:,\s*1(?:\.0)?\s*)?do\b",
            source,
            re.S,
        )
        if loop is None:
            continue
        loop_name = loop.group("loop")
        loop_source = source[loop.end():]
        row_match = re.search(
            r"\b(?P<row>" + _ID + r")\s*=\s*\(?\s*"
            + re.escape(desc) + r"\s*\[\s*" + re.escape(loop_name)
            + r"\s*\]\s*\)?\s*;",
            loop_source,
            re.S,
        )
        if row_match is None:
            continue
        row = row_match.group("row")
        body = loop_source[row_match.end():]
        row_fields: List[Tuple[str, int]] = []
        for item in re.finditer(
            r"\b(?P<name>" + _ID + r")\s*=\s*\(?\s*"
            + re.escape(row) + r"\s*\[\s*(?P<key>\d+)(?:\.0)?\s*\]"
            r"\s*\)?\s*;",
            body,
            re.S,
        ):
            key = _integer(item.group("key"))
            if key is not None:
                row_fields.append((item.group("name"), key))

        role_candidates: List[Tuple[str, int, str, int]] = []
        for mode_name, mode_key in row_fields:
            has_zero = re.search(
                r"\bif\s+" + re.escape(mode_name)
                + r"\s*==\s*0(?:\.0)?\s+then\b",
                body,
                re.S,
            ) is not None
            has_one = (
                re.search(
                    r"\belseif\s+" + re.escape(mode_name)
                    + r"\s*==\s*1(?:\.0)?\s+then\b",
                    body,
                    re.S,
                ) is not None
                or re.search(
                    r"\bif\s+" + re.escape(mode_name)
                    + r"\s*==\s*1(?:\.0)?\s+then\b",
                    body,
                    re.S,
                ) is not None
            )
            if not (has_zero and has_one):
                continue
            for register_name, register_key in row_fields:
                if register_name == mode_name:
                    continue
                has_register = re.search(
                    r"(?:\(\s*c\s*\)|c)\s*\[\s*"
                    + re.escape(register_name) + r"\s*\]",
                    body,
                    re.S,
                ) is not None
                has_inherited = re.search(
                    r"\bI\s*\[\s*" + re.escape(register_name) + r"\s*\]",
                    body,
                    re.S,
                ) is not None
                if has_register and has_inherited:
                    role_candidates.append(
                        (mode_name, mode_key, register_name, register_key)
                    )
        if len(role_candidates) != 1:
            continue
        _mode_name, mode_key, register_name, register_key = role_candidates[0]

        cell_candidates: List[Tuple[str, str, int, int]] = []
        for cached in re.finditer(
            r"\b(?P<cell>" + _ID + r")\s*=\s*\(?\s*"
            r"(?P<cache>" + _ID + r")\s*\[\s*"
            + re.escape(register_name) + r"\s*\]\s*\)?\s*;",
            body,
            re.S,
        ):
            cell, cache = cached.group("cell", "cache")
            if re.search(
                r"\b" + re.escape(cache) + r"\s*\[\s*"
                + re.escape(register_name) + r"\s*\]\s*=\s*\(?\s*"
                + re.escape(cell) + r"\s*\)?\s*;",
                body,
                re.S,
            ) is None:
                continue
            literal = re.search(
                r"\b" + re.escape(cell)
                + r"\s*=\s*\(?\s*\{(?P<body>[^{}]+)\}\s*\)?\s*;",
                body,
                re.S,
            )
            if literal is None:
                continue
            table_key = re.search(
                r"\[\s*(?P<key>\d+)\s*\]\s*=\s*c\b",
                literal.group("body"),
            )
            index_key = re.search(
                r"\[\s*(?P<key>\d+)\s*\]\s*=\s*"
                + re.escape(register_name) + r"\b",
                literal.group("body"),
            )
            if table_key is None or index_key is None:
                continue
            table_value = _integer(table_key.group("key"))
            index_value = _integer(index_key.group("key"))
            if (
                table_value is None
                or index_value is None
                or table_value == index_value
            ):
                continue
            cell_candidates.append((cache, cell, table_value, index_value))
        if len(cell_candidates) != 1:
            continue
        cache, cell_name, open_table_key, open_index_key = cell_candidates[0]

        # Every loop arm must write the same zero-based capture slot. Parentheses
        # around the already-proven capture-vector identifier are cosmetic Luau
        # grouping and are accepted, but arbitrary expressions are not.
        capture_base = r"(?:\(\s*" + re.escape(caps) + r"\s*\)|\b" + re.escape(caps) + r")"
        capture_slot = (
            capture_base + r"\s*\[\s*" + re.escape(loop_name)
            + r"\s*-\s*1(?:\.0)?\s*\]"
        )
        if len(re.findall(capture_slot + r"\s*=", body, re.S)) < 3:
            continue

        results.append(
            ClosureShape(
                child_field=child_field,
                destination_field=destination.group("field"),
                descriptor_field=descriptor_field,
                mode_key=mode_key,
                register_key=register_key,
                captures_name=caps,
                mode_name=_mode_name,
                cell_name=cell_name,
                cache_name=cache,
                open_table_key=open_table_key,
                open_index_key=open_index_key,
            )
        )
    # Repeated textual matches for the same proven shape are harmless, but two
    # distinct shapes in one opcode are ambiguous and therefore not liftable.
    unique = list(dict.fromkeys(results))
    return unique


def infer_closure_shape(source: str) -> Optional[ClosureShape]:
    shapes = _candidate_shapes(source)
    return shapes[0] if len(shapes) == 1 else None


def infer_cell_layout(semantics) -> Optional[Tuple[int, int]]:
    layouts = {
        (shape.open_table_key, shape.open_index_key)
        for source in semantics.values()
        for shape in [infer_closure_shape(source)]
        if shape is not None
    }
    return next(iter(layouts)) if len(layouts) == 1 else None


def current_cell_layout() -> Optional[Tuple[int, int]]:
    return _CURRENT_CELL_LAYOUT


def _if_count(source: str) -> int:
    return sum(
        1 for token in public._tokens(source)
        if token.kind == "identifier" and token.value == "if"
    )


def _static_false_regions(source: str):
    """Return exact numeric-constant guard regions proven never executable."""
    from .luraph_lift_close_upvalues import _block_end

    assignment = re.compile(
        r"(?:\blocal\s+)?(?P<name>" + _ID + r")\s*=\s*\(?\s*"
        r"(?P<value>-?\d+(?:\.\d+)?)\s*\)?\s*;"
    )
    constants = {}
    ambiguous = set()
    for match in assignment.finditer(source):
        name = match.group("name")
        value = float(match.group("value"))
        previous = constants.get(name)
        if previous is not None and previous[0] != value:
            ambiguous.add(name)
        elif previous is None:
            constants[name] = (value, match.end())
    for name in ambiguous:
        constants.pop(name, None)

    guard = re.compile(
        r"\bif\s+(?P<name>" + _ID + r")\s*(?P<operator>==|~=)\s*"
        r"(?P<value>-?\d+(?:\.\d+)?)\s+then\b"
    )
    regions = []
    for match in guard.finditer(source):
        fact = constants.get(match.group("name"))
        if fact is None or fact[1] > match.start():
            continue
        value = float(match.group("value"))
        condition = fact[0] == value
        if match.group("operator") == "~=":
            condition = not condition
        if condition:
            continue
        between = source[fact[1]:match.start()]
        if re.search(
            r"\b" + re.escape(match.group("name"))
            + r"\s*(?:\+=|-=|\*=|/=|%=|\^=|(?<![<>=~])=(?!=))",
            between,
        ):
            continue
        end = _block_end(source, match.start())
        if end is not None:
            regions.append((match.start(), end))
    # Nested static guards are already covered by their outer region.
    result = []
    for start, end in sorted(regions):
        if result and start < result[-1][1]:
            continue
        result.append((start, end))
    return result


def _closure_condition_count(source: str, shape: ClosureShape) -> int:
    """Count only closure branches with explicit role or dead-guard proof."""
    regions = _static_false_regions(source)
    dead_count = sum(_if_count(source[start:end]) for start, end in regions)
    chars = list(source)
    for start, end in regions:
        chars[start:end] = " " * (end - start)
    remaining = "".join(chars)

    headers = re.findall(
        r"\b(?:if|elseif)\s+(?P<condition>.*?)\s+then\b",
        remaining,
        re.S,
    )
    categories = []
    atoms = {
        shape.captures_name: "captures",
        shape.cache_name: "cache",
        shape.cell_name: "cell",
    }
    for condition in headers:
        compact = re.sub(r"\s+", "", condition)
        for _ in range(4):
            updated = re.sub(r"^not\((.*)\)$", r"\1", compact)
            updated = re.sub(r"^\((.*)\)$", r"\1", updated)
            updated = re.sub(r"^not(?=[A-Za-z_])", "", updated)
            if updated == compact:
                break
            compact = updated
        if compact in atoms:
            categories.append(atoms[compact])
            continue
        match = re.fullmatch(
            re.escape(shape.mode_name) + r"==(?P<mode>[01])(?:\.0)?",
            compact,
        )
        if match is not None:
            categories.append("mode" + match.group("mode"))
            continue
        return 0

    required = {"captures", "mode0", "mode1", "cell"}
    if not required.issubset(categories):
        return 0
    if any(categories.count(name) != 1 for name in required):
        return 0
    if categories.count("cache") > 1 or len(categories) not in (4, 5):
        return 0
    return dead_count + _if_count(remaining)


def resolved_if_count(source: str, ins: Instruction, program: Program) -> int:
    """Return the independently proven closure-conditional count."""
    shape = infer_closure_shape(source)
    if shape is None or lift_closure(source, ins, program) is None:
        return 0
    return _closure_condition_count(source, shape)


def lift_closure(source: str, ins: Instruction, program: Program) -> Optional[str]:
    shape = infer_closure_shape(source)
    if shape is None:
        return None
    child = luraph_lift.field_value(ins, shape.child_field)
    if not isinstance(child, ProtoRef) or child.id not in program.protos:
        return None
    try:
        descriptors = decode_descriptors(
            program.protos[child.id].field3,
            shape.mode_key,
            shape.register_key,
        )
    except DescriptorError:
        return None

    destination = luraph_lift.reg_expr(
        luraph_lift.field_value(ins, shape.destination_field)
    )
    lines = ["do", "    local __captures = {}"]
    for index, (mode, register) in enumerate(descriptors):
        if mode == 0:
            lines.extend([
                "    if %s == nil then %s = {} end"
                % (shape.cache_name, shape.cache_name),
                "    do",
                "        local __cell = %s[%d]" % (shape.cache_name, register),
                "        if __cell == nil then",
                "            __cell = {[%d] = R, [%d] = %d}"
                % (shape.open_table_key, shape.open_index_key, register),
                "            %s[%d] = __cell" % (shape.cache_name, register),
                "        end",
                "        __captures[%d] = __cell" % index,
                "    end",
            ])
        elif mode == 1:
            lines.append("    __captures[%d] = R[%d]" % (index, register))
        elif mode == 2:
            lines.append("    __captures[%d] = I[%d]" % (index, register))
        else:  # decode_descriptors already rejects this; retain fail-closed logic.
            return None
    lines.extend([
        "    %s = __closure(%d, __captures, __env)" % (destination, child.id),
        "end",
    ])
    return "\n".join(lines)


def clean_statement(source, ins):
    existing = _ORIGINAL_CLEAN(source, ins)
    if existing is not None:
        return existing
    if _CURRENT_PROGRAM is None:
        return None
    return lift_closure(source, ins, _CURRENT_PROGRAM)


def render_program(program, semantics):
    global _CURRENT_PROGRAM, _CURRENT_CELL_LAYOUT
    if _ORIGINAL_RENDER is None:
        raise luraph_decompiler.DecompileError("closure lifter renderer unavailable")
    previous = _CURRENT_PROGRAM
    previous_layout = _CURRENT_CELL_LAYOUT
    _CURRENT_PROGRAM = program
    _CURRENT_CELL_LAYOUT = infer_cell_layout(semantics)
    try:
        return _ORIGINAL_RENDER(program, semantics)
    finally:
        _CURRENT_PROGRAM = previous
        _CURRENT_CELL_LAYOUT = previous_layout


def install() -> None:
    global _INSTALLED, _ORIGINAL_CLEAN, _ORIGINAL_RENDER
    if _INSTALLED:
        return
    _ORIGINAL_CLEAN = luraph_lift.clean_statement
    luraph_lift.clean_statement = clean_statement
    _ORIGINAL_RENDER = luraph_decompiler.render_program
    luraph_decompiler.render_program = render_program
    _INSTALLED = True
