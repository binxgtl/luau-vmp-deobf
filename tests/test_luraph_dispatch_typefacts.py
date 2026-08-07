import json

from tools import recover_luraph_dispatch as core
from tools import recover_luraph_dispatch_v147 as public
from luauvmp import luraph_dispatch_typefacts as typefacts


def test_metadata_marks_canonical_operand_locals_as_tables():
    source = '''
-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_HELPER_VAR=A
-- LUAUVMP_DISPATCH_VAR=X
-- LUAUVMP_NESTED_HELPERS={}
-- LUAUVMP_CANONICAL_VARS={"g":"o","f":"L","K":"p"}
'''
    metadata = typefacts._metadata(source)
    names = set(metadata["prototype_table_names"])
    assert {"g", "f", "K"} <= names
    assert {"E", "p", "o", "H", "_", "B", "L"} <= names


def test_table_vs_number_antitamper_condition_is_folded_false():
    source = 'if g==A[16] then bad=1; else good=2; end'
    parser = core.Parser(public.lex(source))
    nodes = parser.parse_block(set())
    metadata = {
        "helper_name": "A",
        "opcode_name": "X",
        "nested_helpers": {},
        "prototype_table_names": ("g",),
    }
    runtime = {
        16: core.AVal("number", 4294967296.0, (), True),
    }
    result = typefacts.specialize(nodes, 0, runtime, metadata)
    rendered = "\n".join(core.render(result))
    assert "bad" not in rendered
    assert "good" in rendered


def test_table_type_fact_survives_an_unknown_branch():
    source = '''
if mystery then temp=1; end;
if g~=A[16] then good=2; else bad=1; end
'''
    parser = core.Parser(public.lex(source))
    nodes = parser.parse_block(set())
    metadata = {
        "helper_name": "A",
        "opcode_name": "X",
        "nested_helpers": {},
        "prototype_table_names": ("g",),
    }
    runtime = {16: core.AVal("number", 4294967296.0, (), True)}
    result = typefacts.specialize(nodes, 0, runtime, metadata)
    rendered = "\n".join(core.render(result))
    assert "good" in rendered
    assert "bad" not in rendered
