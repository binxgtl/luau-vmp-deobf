import pytest

from luauvmp import luraph_capture
from luauvmp import luraph_proto_upvalues as upvalues


def factory(helper, opcode, pc, closure_body, slot=50):
    return f'''-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_FACTORY_SLOT={slot}
-- LUAUVMP_HELPER_VAR={helper}
-- LUAUVMP_DISPATCH_VAR={opcode}
(function(d, env)
    while true do
        local {opcode} = opcodes[{pc}]
        if {opcode} == 1 then
            {closure_body}
        end
    end
end)
'''


def test_infers_slot_four_from_legacy_randomized_closure_shape():
    source = factory(
        "M", "w", "y",
        "e=g[y]; N=e[4]; l=(#N); I=l>0 and {}; z=M[50](e,I);",
    )
    assert upvalues.infer_upvalue_field(source) == 4


def test_infers_slot_eleven_from_zstd_randomized_closure_shape():
    source = factory(
        "S", "H", "k",
        "x=(I[k]); v=x[11]; m=(#v); caps=m>0 and {}; q=S[50](x,caps);",
    )
    assert upvalues.infer_upvalue_field(source) == 11


def test_infers_hex_slot_three_from_reference_public_shape():
    source = factory(
        "b", "R", "G",
        "M=i[G]; h=M[0X3]; n=#h; W=n>0 and {}; z=b[59](M,W);",
        slot=59,
    )
    assert upvalues.infer_upvalue_field(source) == 3


def test_inference_does_not_depend_on_the_first_dispatch_pc_name():
    source = factory(
        "M", "w", "outerPc",
        "e=g[innerPc]; N=e[4]; l=#N; I=l>0 and {}; z=M[50](e,I);",
    )
    assert upvalues.infer_upvalue_field(source) == 4


def test_non_public_factory_is_ignored():
    source = '''-- LUAUVMP_FACTORY_SLOT=50
-- LUAUVMP_HELPER_VAR=M
-- LUAUVMP_DISPATCH_VAR=w
while true do local w=opcodes[y]; e=g[y];N=e[4];l=#N;z=M[50](e,{});end'''
    assert upvalues.infer_upvalue_field(source) is None


def test_ambiguous_descriptor_fields_fail_closed():
    source = factory(
        "M", "w", "y",
        "e=g[y];N=e[4];l=#N;z=M[50](e,{}); x=g[y];v=x[11];m=#v;q=M[50](x,{});",
    )
    with pytest.raises(luraph_capture.CaptureError):
        upvalues.infer_upvalue_field(source)


def test_dynamic_runner_writes_field_into_canonical_proto_field3():
    runner = '''local PROTO_MODE_FIELD = 5
local PROTO_OPCODE_FIELD = 8
            "P", tostring(id), tostring(meta[1]), tostring(meta[2]),
            tostring(meta[3]), tostring(instructionCount), "N",
            "N", typed(rawget(proto, PROTO_MODE_FIELD)), "D0",'''
    rewritten = upvalues._rewrite_runner(runner, 11)
    assert "local PROTO_UPVALUE_FIELD = 11" in rewritten
    assert 'typed(rawget(proto, PROTO_UPVALUE_FIELD)), typed(rawget(proto, PROTO_MODE_FIELD))' in rewritten
