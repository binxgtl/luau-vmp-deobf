from luauvmp import luraph_reachability as reachability
from luauvmp.luraph_full import Instruction, Program, Proto, ProtoRef


def instruction(pc, opcode, **values):
    fields = dict(
        proto=0, pc=pc, e=None, opcode=opcode, p=None, o=None,
        h=None, underscore=None, b=None,
    )
    fields.update(values)
    return Instruction(**fields)


def program(instructions):
    proto = Proto(
        id=0, parent=-1, parent_field=-1, parent_pc=-1,
        instruction_count=len(instructions), field1=None, field3=None,
        field5=None, max_register=3, instructions=instructions,
    )
    return Program({0: proto}, 1)


def test_prunes_block_bypassed_by_static_jump():
    captured = program([
        instruction(1, 1, e=3),
        instruction(2, 2),
        instruction(3, 3, p=0, o=7),
    ])
    semantics = {
        1: "u=E[u]",
        2: "unknown_helper()",
        3: "c[p[u]]=o[u]",
    }
    pruned, removed = reachability.prune_program(captured, semantics)
    assert [item.pc for item in pruned.protos[0].instructions] == [1, 3]
    assert removed == 1


def test_keeps_target_and_fallthrough_for_dynamic_condition():
    captured = program([
        instruction(1, 1, e=3, p=0),
        instruction(2, 2),
        instruction(3, 3),
    ])
    semantics = {
        1: "if c[p[u]] then u=E[u] end",
        2: "x=1",
        3: "x=2",
    }
    pruned, removed = reachability.prune_program(captured, semantics)
    assert [item.pc for item in pruned.protos[0].instructions] == [1, 2, 3]
    assert removed == 0


def test_unknown_branch_target_disables_block_pruning():
    captured = program([
        instruction(1, 1, e="dynamic"),
        instruction(2, 2),
        instruction(3, 3),
    ])
    semantics = {
        1: "u=E[u]",
        2: "x=1",
        3: "x=2",
    }
    pruned, removed = reachability.prune_program(captured, semantics)
    assert [item.pc for item in pruned.protos[0].instructions] == [1, 2, 3]
    assert removed == 0


def test_prunes_unreferenced_prototypes_but_follows_typed_refs():
    root = program([instruction(1, 3, e=ProtoRef(1), p=0)])
    root.protos[1] = Proto(
        id=1, parent=0, parent_field=1, parent_pc=1,
        instruction_count=1, field1=None, field3=None, field5=None,
        max_register=1, instructions=[instruction(1, 3, p=0)],
    )
    root.protos[2] = Proto(
        id=2, parent=0, parent_field=1, parent_pc=2,
        instruction_count=1, field1=None, field3=None, field5=None,
        max_register=1, instructions=[instruction(1, 3, p=0)],
    )
    root.declared_count = 3
    pruned, removed = reachability.prune_program(
        root, {3: "c[p[u]]=E[u]"}
    )
    assert set(pruned.protos) == {0, 1}
    assert removed == 1


def test_dynamic_closure_table_disables_prototype_pruning():
    root = program([instruction(1, 4, e=1)])
    root.protos[1] = Proto(
        id=1, parent=0, parent_field=1, parent_pc=1,
        instruction_count=1, field1=None, field3=None, field5=None,
        max_register=1, instructions=[instruction(1, 3, p=0)],
    )
    root.declared_count = 2
    pruned, removed = reachability.prune_program(
        root, {3: "c[p[u]]=E[u]", 4: "x=G[E[u]]({})"}
    )
    assert set(pruned.protos) == {0, 1}
    assert removed == 0
