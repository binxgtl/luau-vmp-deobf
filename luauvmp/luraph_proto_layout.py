"""Infer randomized public-v14.7 prototype-table layouts from the factory.

Luraph randomizes not only opcode numbers and local names but also the physical
slots that hold the per-instruction arrays.  Older capture code assumed the
layout used by one private fixture (opcode slot 4, operand slots
2/6/7/8/9/11).  Two public families instead use opcode slots 8 and 1.

The interpreter factory is authoritative: its dispatcher reads one physical
array as ``opcode_array[pc]`` and the six operand arrays are indexed by the same
program counter.  This module derives that layout statically, remaps capture to
the existing canonical typed IR, and applies the same mapping to recovered
semantic text.  No recovered closure is executed by the inference itself.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple
import re

from . import luraph_capture
from . import luraph_semantic_normalize as normalize


_CANONICAL_OPERANDS: Tuple[Tuple[int, str], ...] = (
    (2, "E"), (6, "p"), (7, "o"), (8, "H"), (9, "_"), (11, "B"),
)
_LEGACY_OPERANDS = (2, 6, 7, 8, 9, 11)


@dataclass(frozen=True)
class ProtoLayout:
    opcode_field: int
    operand_fields: Tuple[int, ...]
    canonical_physical: Tuple[Tuple[int, int], ...]
    field_locals: Tuple[Tuple[int, str], ...]
    pc_name: str
    opcode_name: str
    opcode_array: str
    dynamic: bool

    @property
    def canonical_map(self) -> Dict[int, int]:
        return dict(self.canonical_physical)

    @property
    def locals(self) -> Dict[int, str]:
        return dict(self.field_locals)


def infer_layout(factory_source: str) -> Optional[ProtoLayout]:
    metadata = normalize._metadata(factory_source)
    if metadata.get("PUBLIC_V147") != "1":
        return None
    opcode_name = metadata.get("DISPATCH_VAR")
    if not opcode_name:
        raise luraph_capture.CaptureError(
            "public factory has no dispatcher-variable metadata"
        )
    arguments = normalize._factory_arguments(factory_source)
    if not arguments:
        raise luraph_capture.CaptureError("public factory has no prototype argument")
    proto_name = arguments[0]

    dispatch, opcode_array, pc_name = normalize._dispatch_shape(
        factory_source, opcode_name
    )
    fields = normalize._prototype_arrays(factory_source, proto_name, dispatch.start())
    reverse = {name: index for index, name in fields.items()}
    opcode_field = reverse.get(opcode_array)
    if opcode_field is None:
        raise luraph_capture.CaptureError(
            "public opcode array could not be mapped back to a prototype field"
        )

    body = factory_source[dispatch.start():]
    pc_indexed = []
    for field, name in fields.items():
        pattern = re.compile(
            r"\b" + re.escape(name) + r"\s*\[\s*"
            + re.escape(pc_name) + r"\s*\]"
        )
        if pattern.search(body):
            pc_indexed.append(field)

    candidates = sorted(field for field in pc_indexed if field != opcode_field)
    # The private/reference layout also carries an instruction-indexed debug
    # table in physical field 1.  Keep the already verified six operand slots
    # when that exact layout is present, and ignore the extra debug array.
    if opcode_field == 4 and all(field in candidates for field in _LEGACY_OPERANDS):
        operand_fields = _LEGACY_OPERANDS
    else:
        if len(candidates) != 6:
            raise luraph_capture.CaptureError(
                "expected six public operand arrays beside opcode field %d, found %s"
                % (opcode_field, candidates)
            )
        operand_fields = tuple(candidates)

    canonical_physical = tuple(
        (canonical_field, physical_field)
        for (canonical_field, _name), physical_field
        in zip(_CANONICAL_OPERANDS, operand_fields)
    )
    dynamic = not (
        opcode_field == 4 and tuple(operand_fields) == _LEGACY_OPERANDS
    )
    return ProtoLayout(
        opcode_field=opcode_field,
        operand_fields=tuple(operand_fields),
        canonical_physical=canonical_physical,
        field_locals=tuple(sorted(fields.items())),
        pc_name=pc_name,
        opcode_name=opcode_name,
        opcode_array=opcode_array,
        dynamic=dynamic,
    )


def _lua_int_list(values: Tuple[int, ...]) -> str:
    return "{ " + ", ".join(str(value) for value in values) + " }"


def _lua_field_map(layout: ProtoLayout) -> str:
    return "{ " + ", ".join(
        "[%d] = %d" % (canonical, physical)
        for canonical, physical in layout.canonical_physical
    ) + ", [4] = %d }" % layout.opcode_field


def _rewrite_runner(runner: str, layout: ProtoLayout) -> str:
    if not layout.dynamic:
        return runner

    old_is_proto = '''local function isProto(value)
    return type(value) == "table"
        and type(value[4]) == "table"
        and type(value[10]) == "number"
end'''
    checks = "\n".join(
        '        and type(rawget(value, %d)) == "table"' % field
        for field in layout.operand_fields
    )
    new_is_proto = '''local PROTO_OPCODE_FIELD = %d
local PROTO_OPERAND_FIELDS = %s
local CANONICAL_PHYSICAL_FIELDS = %s

local function isProto(value)
    return type(value) == "table"
        and type(rawget(value, PROTO_OPCODE_FIELD)) == "table"
%s
end''' % (
        layout.opcode_field,
        _lua_int_list(layout.operand_fields),
        _lua_field_map(layout),
        checks,
    )
    if old_is_proto not in runner:
        raise luraph_capture.CaptureError(
            "dynamic prototype layout could not find isProto marker"
        )
    runner = runner.replace(old_is_proto, new_is_proto, 1)

    old_operands = '        local operandFields = { 2, 6, 7, 8, 9, 11 }'
    new_operands = '        local operandFields = PROTO_OPERAND_FIELDS'
    if old_operands not in runner:
        raise luraph_capture.CaptureError(
            "dynamic prototype layout could not find child-field marker"
        )
    runner = runner.replace(old_operands, new_operands, 1)

    old_opcodes = '        local opcodes = proto[4]'
    new_opcodes = '        local opcodes = rawget(proto, PROTO_OPCODE_FIELD)'
    if old_opcodes not in runner:
        raise luraph_capture.CaptureError(
            "dynamic prototype layout could not find opcode-field marker"
        )
    runner = runner.replace(old_opcodes, new_opcodes, 1)

    old_metadata = '''            "P", tostring(id), tostring(meta[1]), tostring(meta[2]),
            tostring(meta[3]), tostring(instructionCount), typed(proto[1]),
            typed(proto[3]), typed(proto[5]), typed(proto[10]),'''
    new_metadata = '''            "P", tostring(id), tostring(meta[1]), tostring(meta[2]),
            tostring(meta[3]), tostring(instructionCount), "N",
            "N", "N", "D0",'''
    if old_metadata not in runner:
        raise luraph_capture.CaptureError(
            "dynamic prototype layout could not find proto-metadata marker"
        )
    runner = runner.replace(old_metadata, new_metadata, 1)

    old_cell = '''            local function cell(field)
                local array = proto[field]
                return typed(type(array) == "table" and array[pc] or nil)
            end'''
    new_cell = '''            local function cell(field)
                local physical = CANONICAL_PHYSICAL_FIELDS[field]
                local array = physical and rawget(proto, physical) or nil
                return typed(type(array) == "table" and rawget(array, pc) or nil)
            end'''
    if old_cell not in runner:
        raise luraph_capture.CaptureError(
            "dynamic prototype layout could not find instruction-cell marker"
        )
    runner = runner.replace(old_cell, new_cell, 1)
    return runner


def infer_canonical_variables(factory_source: str) -> Dict[str, str]:
    layout = infer_layout(factory_source)
    if layout is None:
        # Non-public input keeps the existing reference behavior.
        return _ORIGINAL_INFER(factory_source) if _ORIGINAL_INFER else {}

    metadata = normalize._metadata(factory_source)
    helper_name = metadata.get("HELPER_VAR")
    arguments = normalize._factory_arguments(factory_source)
    environment_name = arguments[1] if len(arguments) > 1 else None
    fields = layout.locals

    mapping: Dict[str, str] = {}
    for (canonical_field, canonical_name), physical in zip(
        _CANONICAL_OPERANDS, layout.operand_fields
    ):
        actual = fields.get(physical)
        if actual is None:
            raise luraph_capture.CaptureError(
                "public operand field %d has no factory local" % physical
            )
        if actual != canonical_name:
            mapping[actual] = canonical_name

    if layout.opcode_array != "L":
        mapping[layout.opcode_array] = "L"
    mapping[layout.opcode_name] = "X"
    mapping[layout.pc_name] = "u"
    if helper_name and helper_name != "A":
        mapping[helper_name] = "A"
    if environment_name is not None and environment_name != "I":
        mapping[environment_name] = "I"

    operand_names = [fields[field] for field in layout.operand_fields]
    excluded = set(fields.values()) | {
        layout.opcode_name, layout.pc_name, layout.opcode_array,
    }
    if helper_name:
        excluded.add(helper_name)
    if environment_name is not None:
        excluded.add(environment_name)
    register = normalize._infer_register(
        factory_source,
        normalize._dispatch_shape(factory_source, layout.opcode_name)[0].start(),
        layout.pc_name,
        operand_names,
        excluded,
    )
    if register != "c":
        mapping[register] = "c"
    return mapping


_ORIGINAL_BUILDER = None
_ORIGINAL_INFER = None
_INSTALLED = False


def build_lune_runner(patched_vm, bytecode, full_ir, runtime_facts):
    if _ORIGINAL_BUILDER is None:
        raise luraph_capture.CaptureError("prototype-layout capture layer unavailable")
    runner = _ORIGINAL_BUILDER(patched_vm, bytecode, full_ir, runtime_facts)
    patched_path = Path(patched_vm)
    factory_path = patched_path.with_name("interpreter.factory.luau")
    if not factory_path.is_file():
        return runner
    factory = factory_path.read_text(encoding="utf-8", errors="surrogateescape")
    layout = infer_layout(factory)
    if layout is None:
        return runner
    return _rewrite_runner(runner, layout)


def install() -> None:
    global _ORIGINAL_BUILDER, _ORIGINAL_INFER, _INSTALLED
    if _INSTALLED:
        return
    _ORIGINAL_BUILDER = luraph_capture.build_lune_runner
    _ORIGINAL_INFER = normalize.infer_canonical_variables
    luraph_capture.build_lune_runner = build_lune_runner
    normalize.infer_canonical_variables = infer_canonical_variables
    _INSTALLED = True
