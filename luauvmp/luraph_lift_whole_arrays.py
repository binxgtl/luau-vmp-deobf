"""Lift public-v14.7 opcodes that expose whole prototype operand arrays.

Some Luraph dispatchers contain real operations such as ``R[dst] = H`` where
``H`` is the complete field-8 array for the current prototype, not ``H[pc]``.
Treating that identifier as the current operand cell would be incorrect.  This
layer recognizes only the exact direct-assignment shape, materializes the exact
captured array once per prototype, and keeps that table shared across invocations
of the generated prototype closure just like the interpreter's captured arrays.

No recovered application code is executed by this module.
"""
from __future__ import annotations

from typing import Dict, Iterable, Mapping, Optional, Set
import re

from . import luraph_decompiler, luraph_lift
from .luraph_full import Instruction, Proto, Program, Value, render_value


_INSTALLED = False
_ORIGINAL_CLEAN = None
_ORIGINAL_DECOMPILE_PROTO = None
_ORIGINAL_RENDER_PROGRAM = None

_ARRAY_FIELDS = ("E", "L", "p", "o", "H", "_", "B")
_OPERAND_FIELDS = ("E", "p", "o", "H", "_", "B")
_WHOLE_ASSIGN = re.compile(
    r"^R\[@(?P<dst>[EpoH_B])\]=(?P<src>E|L|p|o|H|_|B)$"
)


def _array_value(ins: Instruction, name: str) -> Value:
    if name == "L":
        return ins.opcode
    return luraph_lift.field_value(ins, name)


def _whole_array_shape(source: str):
    """Return ``(dst_field, array_field)`` for one exact whole-array move."""
    text = luraph_lift.compact(source).rstrip(";")
    match = _WHOLE_ASSIGN.fullmatch(text)
    if match is None:
        return None
    return match.group("dst"), match.group("src")


def clean_statement(source: str, ins: Instruction) -> Optional[str]:
    existing = _ORIGINAL_CLEAN(source, ins)
    if existing is not None:
        return existing
    shape = _whole_array_shape(source)
    if shape is None:
        return None
    dst, src = shape
    return "%s = __ARR_%s" % (
        luraph_lift.reg_expr(luraph_lift.field_value(ins, dst)), src,
    )


def _needed_arrays(proto: Proto, semantics: Mapping[int, str]) -> Set[str]:
    needed: Set[str] = set()
    for opcode in {ins.opcode for ins in proto.instructions}:
        source = semantics.get(opcode)
        if source is None:
            continue
        shape = _whole_array_shape(source)
        if shape is not None:
            needed.add(shape[1])
    return needed


def _inject_array_locals(source: str, proto: Proto, needed: Iterable[str]) -> str:
    fields = sorted(set(needed), key=_ARRAY_FIELDS.index)
    if not fields:
        return source
    marker = "    local argv = table.pack(...)\n"
    if source.count(marker) != 1:
        raise luraph_decompiler.DecompileError(
            "generated prototype prologue changed before whole-array binding"
        )
    bindings = "".join(
        "    local __ARR_%s = __VMARRAYS[%d].%s\n" % (field, proto.id, field)
        for field in fields
    )
    return source.replace(marker, marker + bindings, 1)


def decompile_proto(proto: Proto, semantics, prepared):
    text, metrics = _ORIGINAL_DECOMPILE_PROTO(proto, semantics, prepared)
    needed = _needed_arrays(proto, semantics)
    return _inject_array_locals(text, proto, needed), metrics


def _render_array(proto: Proto, field: str) -> str:
    lines = ["__VMARRAYS[%d].%s = {" % (proto.id, field)]
    for ins in proto.instructions:
        lines.append(
            "    [%d] = %s," % (ins.pc, render_value(_array_value(ins, field)))
        )
    lines.append("}")
    return "\n".join(lines)


def _render_materialized_arrays(program: Program, semantics: Mapping[int, str]) -> str:
    chunks = []
    for pid in sorted(program.protos):
        proto = program.protos[pid]
        needed = sorted(_needed_arrays(proto, semantics), key=_ARRAY_FIELDS.index)
        if not needed:
            continue
        chunks.append("__VMARRAYS[%d] = {}" % pid)
        chunks.extend(_render_array(proto, field) for field in needed)
    return "\n".join(chunks)


def render_program(program: Program, semantics: Mapping[int, str]):
    source, metrics = _ORIGINAL_RENDER_PROGRAM(program, semantics)
    arrays = _render_materialized_arrays(program, semantics)
    if not arrays:
        return source, metrics

    proto_marker = "local PROTO = {}\n"
    return_marker = "return function(...)\n"
    if source.count(proto_marker) != 1 or source.count(return_marker) != 1:
        raise luraph_decompiler.DecompileError(
            "generated program framing changed before whole-array materialization"
        )
    source = source.replace(
        proto_marker, proto_marker + "local __VMARRAYS = {}\n", 1
    )
    source = source.replace(return_marker, arrays + "\n\n" + return_marker, 1)
    metrics = dict(metrics)
    metrics["materialized_operand_arrays"] = sum(
        len(_needed_arrays(proto, semantics)) for proto in program.protos.values()
    )
    return source, metrics


def install() -> None:
    global _INSTALLED, _ORIGINAL_CLEAN, _ORIGINAL_DECOMPILE_PROTO, _ORIGINAL_RENDER_PROGRAM
    if _INSTALLED:
        return
    _ORIGINAL_CLEAN = luraph_lift.clean_statement
    luraph_lift.clean_statement = clean_statement

    _ORIGINAL_DECOMPILE_PROTO = luraph_decompiler.decompile_proto
    luraph_decompiler.decompile_proto = decompile_proto

    _ORIGINAL_RENDER_PROGRAM = luraph_decompiler.render_program
    luraph_decompiler.render_program = render_program
    _INSTALLED = True
