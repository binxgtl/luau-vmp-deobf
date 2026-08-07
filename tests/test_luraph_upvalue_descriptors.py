import pytest

from luauvmp.luraph_full import OpaqueTable
from luauvmp.luraph_upvalue_descriptors import (
    DescriptorError,
    decode_descriptors,
    parse_typed,
)


def test_parses_nested_numeric_typed_tables():
    value = parse_typed("T{D1=T{D1=D4,D2=D0},D2=T{D1=D5,D2=D2}}")
    assert value == {1: {1: 4, 2: 0}, 2: {1: 5, 2: 2}}


def test_decodes_dense_one_based_mode_register_pairs():
    value = OpaqueTable(
        "T{D1=T{D1=D4,D2=D0},D2=T{D1=D5,D2=D2},D3=T{D1=D1,D2=D1}}"
    )
    assert decode_descriptors(value, mode_key=2, register_key=1) == [
        (0, 4), (2, 5), (1, 1)
    ]


def test_decodes_randomized_descriptor_keys():
    value = OpaqueTable("T{D1=T{D3=D9,D1=D0},D2=T{D3=D2,D1=D1}}")
    assert decode_descriptors(value, mode_key=1, register_key=3) == [(0, 9), (1, 2)]


def test_accepts_empty_descriptor_table():
    assert decode_descriptors(OpaqueTable("T{}"), 2, 1) == []


def test_rejects_sparse_outer_descriptor_array():
    with pytest.raises(DescriptorError):
        decode_descriptors(
            OpaqueTable("T{D1=T{D1=D4,D2=D0},D3=T{D1=D5,D2=D1}}"),
            2,
            1,
        )


def test_rejects_non_numeric_or_invalid_capture_fields():
    with pytest.raises(DescriptorError):
        decode_descriptors(OpaqueTable("T{D1=T{D1=S61,D2=D0}}"), 2, 1)
    with pytest.raises(DescriptorError):
        decode_descriptors(OpaqueTable("T{D1=T{D1=D4,D2=D7}}"), 2, 1)


def test_rejects_duplicate_numeric_keys():
    with pytest.raises(DescriptorError):
        parse_typed("T{D1=D0,D1=D1}")
