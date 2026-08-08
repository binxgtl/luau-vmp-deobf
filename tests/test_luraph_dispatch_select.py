from luauvmp import luraph_dispatch_select as select
from tools import recover_luraph_dispatch_v147 as public


def test_enumerates_repeat_and_while_dispatchers_on_same_opcode_array():
    source = '''
-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_HELPER_VAR=A
-- LUAUVMP_DISPATCH_VAR=s
-- LUAUVMP_CANONICAL_VARS={"ops":"L","s":"X","pc":"u"}
-- LUAUVMP_NESTED_HELPERS={}
(function(P,I,m)
    local ops=P[8]
    if m==0 then
        while true do local s=ops[pc]; if s==0 then x=1 else x=2 end; pc+=1; end
    else
        repeat local wide=ops[cursor]; if wide<128 then x=3 else x=4 end; cursor+=1 until false
    end
end)
'''
    tokens = public.lex(source)
    candidates = select._candidates(source, tokens, "ops")
    assert [(item.kind, item.opcode_name, item.pc_name) for item in candidates] == [
        ("while", "s", "pc"),
        ("repeat", "wide", "cursor"),
    ]


def test_candidate_choice_prefers_semantic_discrimination_not_source_order():
    small = select.Candidate("while", 10, "small", "ops", "pc", [])
    wide = select.Candidate("repeat", 20, "wide", "ops", "cursor", [])
    small_result = select.SpecializedCandidate(
        small,
        {str(i): {"source": str(i % 10)} for i in range(256)},
        [],
        10,
        0,
    )
    wide_result = select.SpecializedCandidate(
        wide,
        {str(i): {"source": str(i)} for i in range(256)},
        [],
        256,
        3,
    )
    assert select._choose([small_result, wide_result]).candidate is wide


def test_opcode_array_comes_from_canonical_mapping():
    source = '''
-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_DISPATCH_VAR=wrong_small_loop
-- LUAUVMP_CANONICAL_VARS={"f":"L","wrong_small_loop":"X"}
'''
    markers = select._markers(source)
    assert select._opcode_array(source, markers) == "f"
