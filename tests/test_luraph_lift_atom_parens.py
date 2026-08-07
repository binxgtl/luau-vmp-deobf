from luauvmp import luraph_lift
from luauvmp.luraph_full import Instruction


def ins(**overrides):
    values = dict(
        proto=0, pc=1, e=11, opcode=0, p=12, o=13,
        h=14, underscore=15, b=16,
    )
    values.update(overrides)
    return Instruction(**values)


def test_compact_removes_parentheses_around_scratch_atoms_only():
    assert luraph_lift.compact('N=(H[u]); I=(x); R0=(x[j]);') == (
        'N=@H;I=x;R0=x[j];'
    )
    assert '(x+@B-1)' in luraph_lift.compact('t=(x+B[u]-1);')
    assert 'f(x)' in luraph_lift.compact('y=f(x);')


def test_actual_parenthesized_vararg_copy_shape_is_lifted():
    source = '''
        x=({...});
        for j=1,E[u] do
            (c)[j]=(x[j]);
        end
    '''
    assert luraph_lift.clean_statement(source, ins(e=5)) == (
        'for __i = 1, 5 do R[__i] = argv[__i] end'
    )
