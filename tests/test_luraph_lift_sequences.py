from luauvmp import luraph_lift
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
