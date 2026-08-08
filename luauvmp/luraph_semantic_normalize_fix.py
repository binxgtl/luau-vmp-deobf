"""Tight compatibility fix for public semantic-role inference.

The dispatcher expression itself is authoritative for prototype field 4.  Some
minified local declarations are intentionally irregular enough that the simple
parallel-assignment scanner may omit that one entry.  Missing evidence is not a
conflict; a declaration that explicitly maps field 4 to a *different* array is.
"""
from __future__ import annotations

from typing import Dict

from . import luraph_capture
from . import luraph_semantic_normalize as normalize


def infer_canonical_variables(factory_source: str) -> Dict[str, str]:
    metadata = normalize._metadata(factory_source)
    opcode_name = metadata.get("DISPATCH_VAR")
    helper_name = metadata.get("HELPER_VAR")
    if metadata.get("PUBLIC_V147") != "1" or not opcode_name or not helper_name:
        return {}

    arguments = normalize._factory_arguments(factory_source)
    if not arguments:
        raise luraph_capture.CaptureError("public factory has no prototype argument")
    proto_name = arguments[0]
    environment_name = arguments[1] if len(arguments) > 1 else None
    dispatch, opcode_array, pc_name = normalize._dispatch_shape(
        factory_source, opcode_name
    )
    arrays = normalize._prototype_arrays(factory_source, proto_name, dispatch.start())
    declared_opcode_array = arrays.get(4)
    if declared_opcode_array is not None and declared_opcode_array != opcode_array:
        raise luraph_capture.CaptureError(
            "public dispatcher opcode array conflicts with prototype field 4"
        )
    arrays[4] = opcode_array

    mapping: Dict[str, str] = {}
    for index, canonical in normalize._CANONICAL_FIELDS.items():
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
    register = normalize._infer_register(
        factory_source, dispatch.start(), pc_name, operands, excluded
    )
    if register != "c":
        mapping[register] = "c"
    return mapping


def install() -> None:
    normalize.infer_canonical_variables = infer_canonical_variables
