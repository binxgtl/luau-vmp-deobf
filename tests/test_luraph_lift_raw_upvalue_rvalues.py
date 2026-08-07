from luauvmp import luraph_lift_raw_upvalue_rvalues as raw
from luauvmp.luraph_full import Instruction


def test_lifts_exact_grouped_raw_cell_index_get():
    ins = Instruction(
        proto=0, pc=1, e=None, opcode=1, p=None, o=7,
        h=5, underscore=6, b=None,
    )
    source = 'M=I[H[u]]; c[_[u]]=(M[2][M[1]][c[o[u]]]);'
    assert raw.clean_statement(source, ins) == (
        'R[6] = I[5][2][I[5][1]][R[7]]'
    )


def test_grouped_raw_cell_get_fails_closed_on_different_temp():
    ins = Instruction(0, 1, None, 1, None, 7, 5, 6, None)
    source = 'M=I[H[u]]; c[_[u]]=(N[2][N[1]][c[o[u]]]);'
    assert raw.clean_statement(source, ins) is None
