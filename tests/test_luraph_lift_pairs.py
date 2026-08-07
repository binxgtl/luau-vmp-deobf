from luauvmp import luraph_decompiler, luraph_lift_pairs
from luauvmp.luraph_full import Instruction, Proto, prepare_semantics


SEMANTICS = {
    52: 'x=o[u]; v=E[u];',
    62: 'for j=x,v,1 do m=c; _=j; j=nil; m[_]=j; end',
}


def ins(pc, opcode, **overrides):
    values = dict(
        proto=0, pc=pc, e=4, opcode=opcode, p=0, o=2,
        h=0, underscore=0, b=0,
    )
    values.update(overrides)
    return Instruction(**values)


def proto(instructions):
    return Proto(
        id=0, parent=-1, parent_field=-1, parent_pc=-1,
        instruction_count=len(instructions), field1=None, field3=None,
        field5=None, max_register=8, instructions=list(instructions),
    )


def test_pair_proof_requires_same_scratch_def_use_shape():
    first, second = ins(1, 52), ins(2, 62)
    assert luraph_lift_pairs.clean_pair(
        SEMANTICS[52], first, SEMANTICS[62], second
    ) == 'for __i = 2, 4 do R[__i] = nil end'
    assert luraph_lift_pairs.clean_pair(
        SEMANTICS[52], first,
        'for j=other,v do m=c; _=j; j=nil; m[_]=j; end', second,
    ) is None


def test_decompiler_replaces_two_fallbacks_with_one_proven_pair():
    p = proto([ins(1, 52), ins(2, 62)])
    source, metrics = luraph_decompiler.decompile_proto(
        p, SEMANTICS, prepare_semantics(SEMANTICS)
    )
    assert metrics['fallback_instructions'] == 0
    assert metrics['clean_instructions'] == 2
    assert '-- pc=1 opcode=52' in source
    assert '-- pc=2 opcode=62' in source
    assert 'for __i = 2, 4 do R[__i] = nil end' in source
    assert 'x=2' not in source
    assert 'for j=x,v' not in source
