from luauvmp.luraph_full import Instruction
from luauvmp.luraph_lift_chains import clean_chain


def ins(pc, *, e=None, p=None, o=None, h=None, underscore=None, b=None):
    return Instruction(
        proto=0,
        pc=pc,
        e=e,
        opcode=0,
        p=p,
        o=o,
        h=h,
        underscore=underscore,
        b=b,
    )


def test_lifts_register_move_split_across_four_micro_ops():
    items = [
        ("M=c;", ins(1)),
        ("h=_[u]; n=c; W=H[u];", ins(2, underscore=4, h=9)),
        ("n=n[W];", ins(3)),
        ("M[h]=(n);", ins(4)),
    ]
    assert clean_chain(items) == "R[4] = R[9]"


def test_lifts_nested_set_split_across_three_micro_ops():
    items = [
        ("M=(c); h=o[u]; M=M[h];", ins(1, o=3)),
        ("h=E[u]; n=(p[u]);", ins(2, e="key", p=17)),
        ("M[h]=(n);", ins(3)),
    ]
    assert clean_chain(items) == 'R[3]["key"] = 17'


def test_lifts_double_index_load_split_across_four_micro_ops():
    items = [
        ("M=c; h=o[u];", ins(1, o=8)),
        ("n=c; W=_[u];", ins(2, underscore=2)),
        ("n=n[W]; W=(p[u]); n=(n[W]);", ins(3, p="name")),
        ("M[h]=(n);", ins(4)),
    ]
    assert clean_chain(items) == 'R[8] = R[2]["name"]'


def test_lifts_direct_constant_set_split_across_two_micro_ops():
    items = [
        ("M=c; h=H[u]; n=(E[u]);", ins(1, h=6, e=False)),
        ("M[h]=(n);", ins(2)),
    ]
    assert clean_chain(items) == "R[6] = false"


def test_lifts_single_index_from_upvalue_space():
    items = [
        ("M=c; h=o[u];", ins(1, o=5)),
        ("n=(I); W=_[u]; n=n[W];", ins(2, underscore=7)),
        ("M[h]=(n);", ins(3)),
    ]
    assert clean_chain(items) == "R[5] = I[7]"


def test_rejects_chain_when_scratch_identity_changes():
    items = [
        ("M=c;", ins(1)),
        ("h=_[u]; n=c; W=H[u];", ins(2, underscore=4, h=9)),
        ("x=x[W];", ins(3)),
        ("M[h]=(n);", ins(4)),
    ]
    assert clean_chain(items) is None
