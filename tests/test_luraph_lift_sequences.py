from luauvmp import luraph_lift
from luauvmp.luraph_full import Instruction


def ins(**overrides):
    values = dict(
        proto=0, pc=1, e=11, opcode=0, p=12, o=13,
        h=14, underscore=15, b=16,
    )
    values.update(overrides)
    return Instruction(**values)


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
