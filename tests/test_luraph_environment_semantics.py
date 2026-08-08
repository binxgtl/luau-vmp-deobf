import textwrap

from luauvmp import luraph_environment_semantics as env
from luauvmp.luraph_full import Instruction


def _instruction():
    return Instruction(
        proto=0,
        pc=1,
        e="print",
        opcode=1,
        p=None,
        o=None,
        h=3,
        underscore=None,
        b=None,
    )


def test_proves_getfenv_slot_and_environment_receiver():
    vm = '''
        return({
            S=getfenv,
            E=function(v,J,d)
                if d then(J)[0x5]=v.S; end
            end,
        })
    '''
    factory = textwrap.dedent('''
        -- LUAUVMP_PUBLIC_V147=1
        -- LUAUVMP_HELPER_VAR=M
        -- LUAUVMP_DISPATCH_VAR=w
        -- LUAUVMP_CANONICAL_VARS={"D":"E","F":"H","M":"A","O":"c","y":"u","w":"X"}
        (function(d,X)
            local G=(M[0b101]());
            while true do local w=x[y]; break; end
        end)
    ''').lstrip()
    semantics = {
        "1": {
            "raw_source": "O[F[y]]=G[D[y]];",
            "source": "c[H[u]]=G[E[u]];",
        }
    }
    assert env._getfenv_helper_slots(vm) == {5}
    assert env.infer_environment_name(factory, vm, semantics) == "G"
    assert env._canonical_environment_name(factory, "G") == "G"


def test_environment_candidate_respects_register_collision_alias():
    factory = textwrap.dedent('''
        -- LUAUVMP_PUBLIC_V147=1
        -- LUAUVMP_HELPER_VAR=S
        -- LUAUVMP_DISPATCH_VAR=H
        -- LUAUVMP_CANONICAL_VARS={"H":"X","I":"_","S":"A","V":"c","s":"u"}
    ''').lstrip()
    assert env._canonical_environment_name(factory, "R") == "__s_R"


def test_lifts_exact_getglobal_and_setglobal_shapes():
    ins = _instruction()
    assert env.clean_environment_statement(
        'c[H[u]]=(__ENV[E[u]]);', ins
    ) == 'R[3] = __env["print"]'
    assert env.clean_environment_statement(
        '__ENV[E[u]]=c[H[u]];', ins
    ) == '__env["print"] = R[3]'


def test_lifts_proven_environment_scratch_chain_without_dropping_state():
    ins = _instruction()
    lifted = env.clean_environment_statement(
        'n=(__ENV); W=(E[u]); n=n[W];', ins
    )
    assert lifted == 'n = __env\nW = "print"\nn = n[W]'


def test_lifts_split_environment_scratch_staging():
    ins = _instruction()
    assert env.clean_environment_statement(
        'x=c; v=E[u]; m=__ENV;', ins
    ) == 'x = R; v = "print"; m = __env'


def test_environment_scratch_chain_rejects_unknown_locals():
    ins = _instruction()
    assert env.clean_environment_statement(
        'mystery=(__ENV); W=(E[u]); mystery=mystery[W];', ins
    ) is None


def test_environment_proof_ignores_text_inside_strings_and_comments():
    vm = '''
        local text = [[ S=getfenv; (J)[5]=v.S ]]
        -- T[6]=v.RealGetEnv
        return({RealGetEnv=getfenv, put=function(v,J) (J)[7]=v.RealGetEnv end})
    '''
    assert env._getfenv_helper_slots(vm) == {7}
