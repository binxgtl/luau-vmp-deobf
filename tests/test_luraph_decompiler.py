from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from luauvmp.luraph_decompiler import build_blocks, render_program, write_decompiled
from luauvmp.luraph_full import Instruction, Program, Proto


def sample_program():
    proto = Proto(0, -1, -1, -1, 5, None, None, None, 4, [
        Instruction(0, 1, 'game', 91, None, 0, None, None, None),
        Instruction(0, 2, None, 17, None, 1, 0, None, 4),
        Instruction(0, 3, None, 53, None, 5, 1, None, None),
        Instruction(0, 4, 'dead', 91, None, 2, None, None, None),
        Instruction(0, 5, None, 99, None, None, None, 1, None),
    ])
    semantics = {
        91: 'c[o[u]]=(E[u]);',
        17: 'c[o[u]]=c[H[u]]+B[u];',
        53: 'if c[H[u]] then u=(o[u]); end',
        99: 'return c[_[u]];',
    }
    return Program({0: proto}, 1), semantics


def test_build_cfg_from_sample_local_semantics():
    program, semantics = sample_program()
    blocks = build_blocks(program.protos[0], semantics)
    assert [block.start for block in blocks] == [1, 4, 5]
    assert blocks[0].fallthrough == 4


def test_render_compile_target_lifts_common_operations():
    program, semantics = sample_program()
    source, metrics = render_program(program, semantics)
    assert 'PROTO[0] = function(__captured, __env, ...)' in source
    assert 'local I = __captured or {}' in source
    assert 'local L, H, W, X, V, n, h, q, y, j, t, a, i, k, x, v' in source
    assert '__env = __env or getfenv()' in source
    assert 'local function __upget(cell)' in source
    assert 'local function __close_cell(cell)' in source
    assert 'R[0] = "game"' in source
    assert 'R[1] = R[0] + 4' in source
    assert 'if R[1] then pc = 5 else pc = 4 end' in source
    assert 'return R[1]' in source
    assert metrics['clean_instructions'] == 5
    assert metrics['fallback_instructions'] == 0


def test_unknown_superinstruction_is_preserved_as_compile_safe_data(tmp_path):
    proto = Proto(0, -1, -1, -1, 1, None, None, None, 2, [
        Instruction(0, 1, None, 200, None, 0, None, None, None),
    ])
    metrics = write_decompiled(
        Program({0: proto}, 1),
        {200: 'm=(o[u]); O=A[99](m); c[o[u]]=O;'},
        tmp_path,
    )
    text = (tmp_path / 'program.decompiled.luau').read_text()
    assert 'do local __semantic_fallback = "m=(0); O=A[99](m); R[0]=O;" end' in text
    assert '\n            O=A[99](m);' not in text
    assert metrics['fallback_instructions'] == 1
    assert metrics['clean_instructions'] == 0


def test_parenthesised_call_fallback_is_never_emitted_as_a_statement():
    proto = Proto(0, -1, -1, -1, 1, None, None, None, 2, [
        Instruction(0, 1, None, 201, None, 0, 1, None, None),
    ])
    source, metrics = render_program(
        Program({0: proto}, 1),
        {201: '(c[o[u]])(c[H[u]]);'},
    )
    assert 'do local __semantic_fallback = "(R[0])(R[1]);" end' in source
    assert '\n            (R[0])' not in source
    assert metrics['fallback_instructions'] == 1
