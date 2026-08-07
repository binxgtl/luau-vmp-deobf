from luauvmp import luraph_lift_residual_simple as simple
from luauvmp.luraph_full import Instruction


def _ins(*, p=None, o=None, h=None, underscore=None):
    return Instruction(
        proto=0, pc=1, e=None, opcode=1, p=p, o=o,
        h=h, underscore=underscore, b=None,
    )


def test_lifts_mixed_register_immediate_bxor():
    result = simple.clean_statement(
        '(c)[o[u]]=(bit32.bxor(c[_[u]],p[u]));',
        _ins(o=3, underscore=4, p=0x55),
    )
    assert result == 'R[3] = bit32.bxor(R[4], 85)'


def test_lifts_clear_range_and_preserves_scratch_assignments():
    source = '''
        for __s_A=M,h do
            n=c;
            W=(__s_A);
            __s_A=nil;
            (n)[W]=(__s_A);
        end
    '''
    result = simple.clean_statement(source, _ins())
    assert result == (
        'for __clear_i = M, h do\n'
        '    n = R\n'
        '    W = __clear_i\n'
        '    n[W] = nil\n'
        'end'
    )


def test_clear_range_rejects_unknown_persistent_state():
    source = 'for __s_A=mystery,h do n=c;W=__s_A;__s_A=nil;n[W]=__s_A;end'
    assert simple.clean_statement(source, _ins()) is None
