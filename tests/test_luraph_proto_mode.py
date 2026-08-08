from luauvmp import luraph_proto_mode as mode


def test_infers_mode_field_from_public_factory_third_argument():
    factory = '''
-- LUAUVMP_PUBLIC_V147=1
(function(Q,X,S)
    local C=Q[7];
    S=Q[9];
    local F,g,D,b,L,f,K,o=Q[6.0],Q[3.0],Q[1.0],Q[10.0],Q[11.0],Q[8.0],Q[2.0];
    return nil
end)
'''
    assert mode.infer_mode_field(factory) == 9


def test_infers_other_public_mode_field_without_sample_name_rules():
    factory = '''
-- LUAUVMP_PUBLIC_V147=1
(function(j,L,T)
    local n=j[2];
    T=j[6.0];
    local I,E,N,e,B,b,l,g=j[9.0],j[3.0],j[5.0],j[7.0],j[1.0],j[4.0],j[10.0];
    return nil
end)
'''
    assert mode.infer_mode_field(factory) == 6


def test_reference_factory_without_mode_argument_is_unchanged():
    factory = '''
-- LUAUVMP_PUBLIC_V147=1
(function(P,I)
    local L=P[4]
    return nil
end)
'''
    assert mode.infer_mode_field(factory) is None


def test_dynamic_runner_serializes_mode_into_existing_field5_slot():
    runner = '''local PROTO_OPCODE_FIELD = 8
            "P", tostring(id), tostring(meta[1]), tostring(meta[2]),
            tostring(meta[3]), tostring(instructionCount), "N",
            "N", "N", "D0",
'''
    rewritten = mode._rewrite_runner(runner, 9)
    assert 'local PROTO_MODE_FIELD = 9' in rewritten
    assert 'typed(rawget(proto, PROTO_MODE_FIELD)), "D0"' in rewritten


def test_runner_without_dynamic_layout_marker_is_unchanged():
    runner = 'local function capture() return nil end'
    assert mode._rewrite_runner(runner, 9) == runner
