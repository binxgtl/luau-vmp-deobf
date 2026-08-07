from pathlib import Path

from luauvmp import luraph_runtime_builtin_semantics as builtins
from luauvmp import luraph_lift_runtime_builtins as lift
from luauvmp.luraph_full import Instruction


def test_reads_only_allowlisted_builtin_identities(tmp_path: Path):
    facts = tmp_path / "runtime_A.tsv"
    facts.write_text(
        "2\tfunction\tbuiltin:bit32.bxor\ttrue\t2\n"
        "32\tfunction\tbuiltin:table.move\ttrue\t27\n"
        "38\tfunction\tbuiltin:table.create\ttrue\t32\n"
        "44\tfunction\tbuiltin:game.GetService\ttrue\t40\n",
        encoding="utf-8",
    )
    assert builtins.builtin_slots(facts) == {
        2: "bit32.bxor", 32: "table.move", 38: "table.create"
    }


def test_rewrites_only_direct_builtin_callees_not_strings_or_table_values():
    source = (
        'local s="A[2](x,y)"; -- A[32](a,b,c,d,e)\n'
        'x=(A[2](a,b)); y=(A[38])(n); z=A[2]; A[2]=other;'
    )
    rewritten = builtins.rewrite_builtin_callees(
        source, {2: "bit32.bxor", 38: "table.create"}
    )
    assert '"A[2](x,y)"' in rewritten
    assert '-- A[32](a,b,c,d,e)' in rewritten
    assert 'x=(bit32.bxor(a,b))' in rewritten
    assert 'y=table.create(n)' in rewritten
    assert 'z=A[2]' in rewritten
    assert 'A[2]=other' in rewritten


def _ins(**values):
    base = dict(
        proto=0, pc=1, e=None, opcode=1, p=None, o=None,
        h=None, underscore=None, b=None,
    )
    base.update(values)
    return Instruction(**base)


def test_existing_assignment_lifter_accepts_proven_bit32_bxor_callee():
    result = lift.clean_statement(
        'c[o[u]]=(bit32.bxor(c[_[u]],c[H[u]]));',
        _ins(o=3, underscore=4, h=5),
    )
    # The runtime-builtin wrapper delegates first, so the already-existing base
    # structural assignment lifter should own this exact operation.
    assert result == 'R[3] = bit32.bxor(R[4], R[5])'


def test_lifts_table_create_and_preserves_table_move_scratch_state():
    assert lift.clean_statement(
        'c[H[u]]=table.create(_[u]);', _ins(h=3, underscore=9)
    ) == 'R[3] = table.create(9)'

    result = lift.clean_statement(
        'M=_[u]; h=H[u]; n=c[M]; table.move(c,M+1,T,h+1,n);',
        _ins(underscore=4, h=7),
    )
    assert result == (
        'M = 4\n'
        'h = 7\n'
        'n = R[M]\n'
        'table.move(R, M + 1, T, h + 1, n)'
    )
