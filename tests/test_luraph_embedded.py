from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from luauvmp.luraph_embedded import (
    find_embedded_sources,
    looks_like_luraph_bootstrap,
    write_embedded_sources,
)
from luauvmp.luraph_full import Instruction, Program, Proto


def make_program(strings):
    instructions = [
        Instruction(0, pc, value, 1, None, pc, None, None, None)
        for pc, value in enumerate(strings, 1)
    ]
    proto = Proto(
        0, -1, -1, -1, len(instructions), None, None, None, 2, instructions,
    )
    return Program({0: proto}, 1)


def test_embedded_source_extraction_writes_exact_largest_chunk(tmp_path):
    source = (
        'local game = game\nlocal function run()\n'
        + '    return game:GetService("Players")\n' * 40
        + 'end\n'
    )
    program = make_program(['noise', source])
    found = find_embedded_sources(program)
    assert len(found) == 1
    manifest = write_embedded_sources(program, tmp_path)
    assert manifest['source_chunks'] == 1
    assert (tmp_path / 'embedded_main.luau').read_text() == source
    assert (tmp_path / manifest['chunks'][0]['file']).read_text() == source


def test_bootstrap_detector_requires_runtime_strings_and_no_source():
    bootstrap = make_program([
        'Luraph', 'loadstring', 'debug', 'getinfo', 'getfenv', 'setfenv',
        'coroutine', 'traceback', 'error in error handling',
    ])
    assert looks_like_luraph_bootstrap(bootstrap)

    source = 'local function payload()\n' + ('return game\n' * 80) + 'end\n'
    assert not looks_like_luraph_bootstrap(make_program(['Luraph', 'debug', source]))
