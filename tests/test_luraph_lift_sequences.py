from luauvmp import luraph_lift
from luauvmp import luraph_lift_raw_upvalue_rvalues as raw_rvalues
from luauvmp.luraph_full import Instruction


def ins(**overrides):
    values = dict(
        proto=0, pc=1, e=11, opcode=0, p=12, o=13,
        h=14, underscore=15, b=16,
    )
    values.update(overrides)
    return Instruction(**values)


def test_lifts_assignment_call_over_recovered_register_range():
    source = '''
        e=H[u];
        t=(e+B[u]-1);
        (c)[e]=c[e](table.unpack(c,e+1,t));
        t=e;
    '''
    assert luraph_lift.clean_statement(source, ins(h=4, b=3)) == (
        'R[4] = R[4](table.unpack(R, 4 + 1, 4 + 3 - 1))'
    )


def test_lifts_nonassigning_call_over_recovered_register_range():
    source = '''
        e=(p[u]);
        t=e+B[u]-1;
        c[e](table.unpack(c,e+1,t));
        t=e-1;
    '''
    assert luraph_lift.clean_statement(source, ins(p=6, b=2)) == (
        'R[6](table.unpack(R, 6 + 1, 6 + 2 - 1))'
    )


def test_range_call_requires_exact_interpreter_top_update():
    source = 'e=H[u];t=e+B[u]-1;c[e]=c[e](table.unpack(c,e+1,t));t=e-1;'
    assert luraph_lift.clean_statement(source, ins()) is None


def test_lifts_recovered_pure_helper_table_lookup():
    source = (
        'c[p[u]]=({[5]=bit32.countlz,[6]=math.ceil,[11]=bit32.bxor,'
        '[14]=string.byte,[17]=string.len})[B[u]];'
    )
    assert luraph_lift.clean_statement(source, ins(p=4, b=11)) == (
        'R[4] = bit32.bxor'
    )


def test_helper_lookup_fails_closed_for_missing_or_unsafe_entry():
    missing = 'c[p[u]]=({[5]=bit32.countlz})[B[u]];'
    assert luraph_lift.clean_statement(missing, ins(b=11)) is None
    unsafe = 'c[p[u]]=({[11]=game.GetService})[B[u]];'
    assert luraph_lift.clean_statement(unsafe, ins(b=11)) is None


def test_lifts_register_pair_index_sequence():
    source = 'e=p[u]; N=c[B[u]]; c[e+1]=N; c[e]=N[_[u]];'
    assert luraph_lift.clean_statement(source, ins(p=4, b=8, underscore=2)) == (
        'R[4 + 1] = R[8]; R[4] = R[8][2]'
    )


def test_register_pair_sequence_rejects_different_object_temp():
    source = 'e=p[u]; N=c[B[u]]; c[e+1]=N; c[e]=other[_[u]];'
    assert luraph_lift.clean_statement(source, ins()) is None


def test_lifts_direct_nested_environment_index():
    source = 'c[_[u]] = I[H[u]][B[u]];'
    assert luraph_lift.clean_statement(source, ins(underscore=3, h=7, b=9)) == (
        'R[3] = I[7][9]'
    )


def test_lifts_tuple_style_environment_cell_index():
    source = 'M=I[o[u]]; c[_[u]]=M[2][M[1]];'
    assert luraph_lift.clean_statement(source, ins(o=5, underscore=6)) == (
        'R[6] = I[5][2][I[5][1]]'
    )


def test_lifts_raw_cell_indexed_get_and_set():
    get_source = 'M=I[H[u]]; c[_[u]]=M[2][M[1]][c[o[u]]];'
    assert luraph_lift.clean_statement(
        get_source, ins(h=5, underscore=6, o=7)
    ) == 'R[6] = I[5][2][I[5][1]][R[7]]'

    set_source = 'M=I[_[u]]; (M[2][M[1]])[c[o[u]]]=c[H[u]];'
    assert luraph_lift.clean_statement(
        set_source, ins(underscore=5, o=7, h=8)
    ) == 'I[5][2][I[5][1]][R[7]] = R[8]'


def test_lifts_raw_cell_value_set():
    source = 'M=I[H[u]]; (M[2])[M[1]]=(c[_[u]]);'
    assert luraph_lift.clean_statement(
        source, ins(h=5, underscore=6)
    ) == 'I[5][2][I[5][1]] = R[6]'


def test_lifts_grouped_raw_cells_with_constant_operand_atoms():
    assert luraph_lift.clean_statement(
        'x=I[B[u]]; c[o[u]]=(x[2][x[1]]);',
        ins(b=5, o=6),
    ) == 'R[6] = I[5][2][I[5][1]]'
    assert luraph_lift.clean_statement(
        'x=I[E[u]]; (x[2][x[1]])[_[u]]=c[B[u]];',
        ins(e=5, underscore="key", b=6),
    ) == 'I[5][2][I[5][1]]["key"] = R[6]'
    assert luraph_lift.clean_statement(
        'x=I[B[u]]; x[2][x[1]]=_[u];',
        ins(b=5, underscore="value"),
    ) == 'I[5][2][I[5][1]] = "value"'
    assert luraph_lift.clean_statement(
        'I[E[u]][H[u]]=_[u];',
        ins(e=5, h="key", underscore="value"),
    ) == 'I[5]["key"] = "value"'


def test_lifts_raw_cell_layout_proven_by_closure_shape():
    source = 'e=(I[B[u]]); c[H[u]]=e[1][e[3]];'
    assert raw_rvalues.clean_layout_statement(
        source, ins(b=427, h=62), (1, 3)
    ) == 'R[62] = I[427][1][I[427][3]]'
    assert raw_rvalues.clean_layout_statement(
        source, ins(b=427, h=62), (2, 1)
    ) is None


def test_lifts_proven_direct_helpers_and_table_move_shapes():
    assert luraph_lift.clean_statement(
        'c[o[u]]=bit32.bxor(c[E[u]],H[u]);',
        ins(o=1, e=2, h=3),
    ) == 'R[1] = bit32.bxor(R[2], 3)'
    assert luraph_lift.clean_statement(
        'c[E[u]]=table.create(B[u]);',
        ins(e=1, b=4),
    ) == 'R[1] = table.create(4)'
    assert luraph_lift.clean_statement(
        'x=B[u]; v=o[u]; m=c[x]; table.move(c,x+1,r,v+1,m);',
        ins(b=3, o=7),
    ) == 'table.move(R, 3 + 1, r, 7 + 1, R[3])'
    assert luraph_lift.clean_statement(
        'x=E[u]; v=o[u]; m=c[x]; table.move(c,x+1,x+B[u],v+1,m);',
        ins(e=3, o=7, b=5),
    ) == 'table.move(R, 3 + 1, 3 + 5, 7 + 1, R[3])'


def test_lifts_shared_nested_helper_write_and_read():
    assert luraph_lift.clean_statement(
        '__VMHELPER_1[E[u]]=(c[B[u]]);', ins(e=23, b=7)
    ) == '__VMHELPER_1[23] = R[7]'
    assert luraph_lift.clean_statement(
        'c[o[u]]=((__VMHELPER_1[E[u]]));', ins(o=4, e=23)
    ) == 'R[4] = __VMHELPER_1[23]'


def test_lifts_persistent_table_move_scratch_call():
    source = '''
        __s__=table.move; q=c; Z=x; M=1; Z+=M; M=r;
        __s_c=v; s=1; __s_c+=s; s=m;
        __s__(q,Z,M,__s_c,s);
    '''
    assert luraph_lift.clean_statement(source, ins()) == (
        'table.move(R, x + 1, r, v + 1, m)'
    )


def test_lifts_direct_capture_value_indexing():
    get_source = 'c[o[u]]=(I[_[u]][c[H[u]]]);'
    assert luraph_lift.clean_statement(
        get_source, ins(o=4, underscore=5, h=6)
    ) == 'R[4] = I[5][R[6]]'

    set_source = '(I[_[u]])[c[o[u]]]=(c[H[u]]);'
    assert luraph_lift.clean_statement(
        set_source, ins(underscore=5, o=6, h=7)
    ) == 'I[5][R[6]] = R[7]'


def test_lifts_exact_capture_vector_scratch_staging():
    assert luraph_lift.clean_statement(
        'M=I; h=H[u];', ins(h=9)
    ) == 'M = I; h = 9'
    assert luraph_lift.clean_statement(
        'n=(I); W=_[u]; n=n[W];', ins(underscore=4)
    ) == 'n = I; W = 4; n = n[W]'
    assert luraph_lift.clean_statement(
        'h=_[u]; n=I; W=(H[u]);', ins(underscore=4, h=8)
    ) == 'h = 4; n = I; W = 8'
