from luauvmp import luraph_decompiler
from luauvmp.luraph_full import Instruction, Program, Proto, ProtoRef
from luauvmp import luraph_lift_whole_arrays as whole


def _instruction(pc, *, p=0, h=None, b=None, opcode=94):
    return Instruction(
        proto=0, pc=pc, e=None, opcode=opcode, p=p, o=None,
        h=h, underscore=None, b=b,
    )


def _proto(instructions):
    return Proto(
        id=0, parent=-1, parent_field=-1, parent_pc=-1,
        instruction_count=len(instructions), field1=None, field3=None,
        field5=None, max_register=8, instructions=list(instructions),
    )


def test_whole_array_shape_is_exact_and_does_not_match_current_cell():
    assert whole._whole_array_shape("c[p[u]] = H;") == ("p", "H")
    assert whole._whole_array_shape("c[p[u]] = H[u];") is None
    assert whole._whole_array_shape("local H = {}; c[p[u]] = H;") is None


def test_render_program_materializes_shared_captured_array_and_lifts_move():
    proto = _proto([
        _instruction(1, p=2, h="alpha"),
        _instruction(2, p=3, h=ProtoRef(1)),
    ])
    child = Proto(
        id=1, parent=0, parent_field=8, parent_pc=2,
        instruction_count=0, field1=None, field3=None, field5=None,
        max_register=0, instructions=[],
    )
    program = Program({0: proto, 1: child}, 2)
    source, metrics = luraph_decompiler.render_program(
        program, {94: "c[p[u]] = H;"}
    )

    assert "local __VMARRAYS = {}" in source
    assert "local __ARR_H = __VMARRAYS[0].H" in source
    assert "R[2] = __ARR_H" in source
    assert "R[3] = __ARR_H" in source
    assert "__VMARRAYS[0].H = {" in source
    assert '[1] = "alpha",' in source
    assert "[2] = PROTO[1]," in source
    assert metrics["fallback_instructions"] == 0
    assert metrics["materialized_operand_arrays"] == 1
