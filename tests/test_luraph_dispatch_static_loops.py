from tools import recover_luraph_dispatch as core
from tools import recover_luraph_dispatch_v147 as public
from luauvmp import luraph_dispatch_typefacts as typefacts


def _metadata():
    return {
        "opcode_name": "X",
        "helper_name": "A",
        "nested_helpers": {},
        "prototype_table_names": (),
    }


def _parse_block(source):
    parser = core.Parser(public.lex(source))
    return parser.parse_block(set())


def test_static_state_loop_is_unrolled_to_selected_path():
    nodes = _parse_block("""
        local state = 1;
        while true do
            if state == 1 then
                state = 2;
                continue;
            else
                result = 9;
                break;
            end
        end
    """)
    specialized = typefacts.specialize(nodes, 7, {}, _metadata())
    rendered = "\n".join(core.render(specialized))
    assert "while" not in rendered
    assert "if state" not in rendered
    assert "continue" not in rendered
    assert "break" not in rendered
    assert "state=2" in rendered
    assert "result=9" in rendered
    assert core.count_unknown_ifs(specialized) == 0


def test_dynamic_loop_condition_fails_closed_and_is_preserved():
    nodes = _parse_block("""
        local state = 1;
        while true do
            if dynamic_value then
                break;
            else
                state = 2;
                break;
            end
        end
    """)
    specialized = typefacts.specialize(nodes, 7, {}, _metadata())
    assert any(isinstance(node, core.While) for node in specialized)
    assert core.count_unknown_ifs(specialized) >= 1


def test_infinite_static_loop_hits_budget_and_is_preserved():
    nodes = _parse_block("while true do local state = 1; end")
    specialized = typefacts.specialize(nodes, 7, {}, _metadata())
    assert any(isinstance(node, core.While) for node in specialized)
