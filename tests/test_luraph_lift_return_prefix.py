from luauvmp import luraph_lift_return_prefix as prefix
from luauvmp.luraph_full import Instruction


def _ins(*, h=None, o=None, b=None):
    return Instruction(
        proto=0, pc=1, e=None, opcode=1, p=None, o=o,
        h=h, underscore=None, b=b,
    )


def test_lifts_one_operand_prefix_before_multi_return():
    result = prefix.return_expression(
        'M=B[u]; return true,M,M;', _ins(b=9)
    )
    assert result is not None
    assert result.startswith('(function()')
    assert 'M = 9' in result
    assert 'return true,M,M' in result
    assert result.endswith('end)()')


def test_lifts_two_operand_prefixes_in_original_order():
    result = prefix.return_expression(
        'M=H[u]; T=o[u]; return true,M,T;', _ins(h=4, o=7)
    )
    assert result is not None
    assert result.index('M = 4') < result.index('T = 7')
    assert 'return true,M,T' in result


def test_return_prefix_rejects_calls_and_nonoperand_assignments():
    assert prefix._prefix('M=A[2](); return M;', _ins()) is None
    assert prefix._prefix('M=workspace; return M;', _ins()) is None
