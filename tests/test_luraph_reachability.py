from luauvmp import luraph_decompiler
from luauvmp import luraph_reachability as reachability
from luauvmp.luraph_dispatch import SemanticMap, load_semantics
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


def test_noncanonical_pc_write_disables_block_pruning():
    captured = program([
        instruction(1, 1),
        instruction(2, 2, e=4),
        instruction(3, 3),
        instruction(4, 3),
    ])
    semantics = {
        1: "u=tmp",
        2: "u=E[u]",
        3: "c[p[u]]=E[u]",
    }
    pruned, removed = reachability.prune_program(captured, semantics)
    assert [item.pc for item in pruned.protos[0].instructions] == [1, 2, 3, 4]
    assert removed == 0


def test_pc_write_detection_is_conservative_and_masks_noncode():
    assert reachability.has_residual_pc_write("u+=1", None)
    assert reachability.has_residual_pc_write("x,u=1,tmp", None)
    assert not reachability.has_residual_pc_write(
        'local text="u=tmp"; -- u+=1\nc[p[u]]=E[u]', None
    )


def test_unresolved_condition_metric_is_independent_from_fallback_count():
    captured = program([instruction(1, 3, p=0, e=7)])
    semantics = SemanticMap(
        {3: "c[p[u]]=E[u]"},
        {3: 1},
    )
    _source, metrics = luraph_decompiler.render_program(captured, semantics)
    assert metrics["fallback_instructions"] == 0
    assert metrics["reachable_dispatcher_conditionals"] == 1
    assert metrics["resolved_dispatcher_conditionals"] == 0
    assert metrics["unresolved_dispatcher_conditionals"] == 1
    assert reachability.unresolved_conditionals(
        captured, {3: "c[p[u]]=E[u]"}
    ) == -1


def test_semantics_loader_preserves_conditional_evidence(tmp_path):
    path = tmp_path / "semantics.json"
    path.write_text(
        '{"3":{"source":"c[p[u]]=E[u]","unknown_ifs":1}}',
        encoding="utf-8",
    )
    semantics = load_semantics(path)
    assert semantics == {3: "c[p[u]]=E[u]"}
    assert semantics.unknown_ifs == {3: 1}


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
