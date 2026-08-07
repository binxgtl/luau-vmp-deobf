from luauvmp import luraph_lift_generic_for_state as generic
from luauvmp.luraph_full import Instruction


def _ins(*, o=None, h=None, underscore=None):
    return Instruction(
        proto=0, pc=7, e=None, opcode=130, p=None, o=o,
        h=h, underscore=underscore, b=None,
    )


def test_classifies_only_literalized_coroutine_generic_for_setup():
    source = '''
        f=({[5]=Z,[2]=f,[1]=N,[4]=g});
        T=(o[u]);
        M=coroutine.wrap(function(...)
            coroutine.yield();
            for f,O in ... do
                coroutine.yield(true,f,O);
            end;
        end);
        M(c[T],c[T+1],c[T+2]);
        Z=M;
        u=(_[u]);
    '''
    assert generic.classify_setup(source)
    assert not generic.classify_setup(source.replace("coroutine.wrap", "A[44]"))
    assert not generic.classify_setup(source.replace("coroutine.yield", "A[29]"))


def test_classifies_generic_for_step_and_resolves_its_branch():
    source = '''
        M=_[u];
        h,n,W=Z();
        if h then
            (c)[M+1]=n;
            c[M+2]=(W);
            u=H[u];
        end
    '''
    assert generic.classify_step(source)
    assert generic.resolved_if_count(source) == 1


def test_generic_for_replacements_preserve_targets_and_saved_state():
    setup = generic._setup_replacement(_ins(o=12, underscore=99))
    assert 'f = {[5] = Z, [2] = f, [1] = N, [4] = g}' in setup
    assert 'T = 12' in setup
    assert 'for __iter_a, __iter_b in ... do' in setup
    assert 'pc = 99' in setup

    step = generic._step_replacement(_ins(h=44, underscore=8), 18)
    assert 'M = 8' in step
    assert 'h, n, W = Z()' in step
    assert 'R[M + 1] = n' in step
    assert 'pc = 44' in step
    assert 'pc = 18' in step
