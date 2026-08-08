from luauvmp.luraph_full import Instruction
from luauvmp import luraph_lift
from luauvmp import luraph_lift_generic_calls as calls


def ins(**overrides):
    values = dict(proto=0, pc=1, e=11, opcode=0, p=12, o=13,
                  h=14, underscore=15, b=16)
    values.update(overrides)
    return Instruction(**values)


def test_lifts_one_arg_assignment_with_random_scratch_names():
    source = 'e=p[u]; c[e]=c[e](c[e+1]); t=(e);'
    assert calls.clean_statement(source, ins()) == 'R[12] = R[12](R[12 + 1])'


def test_lifts_two_arg_assignment_with_other_random_names():
    source = 'x=E[u]; c[x]=c[x](c[x+1],c[x+2]); r=x;'
    assert calls.clean_statement(source, ins()) == 'R[11] = R[11](R[11 + 1], R[11 + 2])'


def test_lifts_nonassigning_calls_and_zero_arg_call():
    assert calls.clean_statement(
        'M=o[u]; c[M](c[M+1],c[M+2]); T=(M-1);', ins()
    ) == 'R[13](R[13 + 1], R[13 + 2])'
    assert calls.clean_statement(
        'q=H[u]; c[q](c[q+1]); z=q-1;', ins()
    ) == 'R[14](R[14 + 1])'
    assert calls.clean_statement(
        't=_[u]; c[t]=c[t]();', ins()
    ) == 'R[15] = R[15]()'


def test_backreferences_reject_mismatched_scratch_flow():
    assert calls.clean_statement(
        'e=p[u]; c[x]=c[e](c[e+1]); t=e;', ins()
    ) is None


def test_lifts_register_clear_loop_with_or_without_explicit_step():
    assert calls.clean_statement(
        'for x=p[u],H[u],1 do c[x]=nil; end', ins()
    ) == 'for __i = 12, 14 do R[__i] = nil end'
    assert calls.clean_statement(
        'for O=H[u],o[u] do c[O]=nil; end', ins()
    ) == 'for __i = 14, 13 do R[__i] = nil end'


def test_lifts_indirect_clear_alias_chain():
    source = 'e=p[u]; N=H[u]; for x=e,N do l=c; I=x; x=nil; l[I]=x; end'
    assert calls.clean_statement(source, ins(p=4, h=9)) == (
        'for __i = 4, 9 do R[__i] = nil end'
    )


def test_real_parenthesized_clear_shape_reaches_final_composed_lifter():
    source = '''e=p[u];
N=(H[u]);
for x=e,N do
    l=c;
    I=(x);
    x=(nil);
    l[I]=x;
end'''
    assert luraph_lift.clean_statement(source, ins(p=4, h=9)) == (
        'for __i = 4, 9 do R[__i] = nil end'
    )


def test_indirect_clear_rejects_non_nil_store():
    source = 'e=p[u]; N=H[u]; for x=e,N do l=c; I=x; x=nil; l[I]=false; end'
    assert calls.clean_statement(source, ins()) is None


def test_lifts_vararg_copy_into_register_file():
    source = 'e=({...}); for x=1,p[u] do c[x]=e[x]; end'
    assert calls.clean_statement(source, ins(p=6)) == (
        'for __i = 1, 6 do R[__i] = argv[__i] end'
    )


def test_lifts_bare_table_vararg_copy_into_register_file():
    source = 'x={...}; for j=1,E[u] do c[j]=x[j]; end'
    assert calls.clean_statement(source, ins(e=6)) == (
        'for __i = 1, 6 do R[__i] = argv[__i] end'
    )


def test_real_parenthesized_vararg_shape_reaches_final_composed_lifter():
    source = '''e=({...});
for x=1,p[u] do
    (c)[x]=e[x];
end'''
    assert luraph_lift.clean_statement(source, ins(p=6)) == (
        'for __i = 1, 6 do R[__i] = argv[__i] end'
    )


def test_vararg_copy_rejects_different_source_table():
    source = 'e=({...}); for x=1,p[u] do c[x]=other[x]; end'
    assert calls.clean_statement(source, ins()) is None


def test_lifts_persistent_scratch_call_and_transfer():
    assert calls.clean_statement('x(); x=(r);', ins()) == 'x(); x = r'


def test_scratch_call_rejects_unknown_identifier():
    assert calls.clean_statement('outside(); outside=r;', ins()) is None
