from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from luauvmp.luraph_full import (
    ProtoRef, decode_typed, parse_full_ir,
    substitute_semantics, Instruction, render_value,
)
from luauvmp.luraph_dispatch import validate_semantics


def test_decode_typed():
    assert decode_typed('N') is None
    assert decode_typed('B1') is True
    assert decode_typed('D17') == 17
    assert decode_typed('S6869') == 'hi'
    assert decode_typed('P12') == ProtoRef(12)


def test_parse_multi_proto():
    text = '''META\tprotos\t2
P\t0\t-1\t-1\t-1\t1\tN\tT{}\tD0\tD4
I\t0\t1\tN\tD186\tN\tD5\tD0\tD0\tN
P\t1\t0\t11\t1\t1\tN\tT{}\tD0\tD2
I\t1\t1\tS78\tD174\tN\tD1\tD0\tD0\tN
'''
    p = parse_full_ir(text.splitlines(True))
    assert p.declared_count == 2
    assert p.instruction_count == 2
    assert p.protos[1].parent == 0
    assert p.protos[1].instructions[0].e == 'x'


def test_operand_substitution():
    ins = Instruction(0, 1, 'Page_Name', 113, 'Tab Webhook', 261, None, None, None)
    src = '(c[o[u]])[p[u]]=(E[u]);'
    got = substitute_semantics(src, ins)
    assert 'R[261]' in got
    assert '"Tab Webhook"' in got
    assert '"Page_Name"' in got
    assert 'o[u]' not in got


def test_validate_complete_map():
    validate_semantics({i: '' for i in range(256)})


def test_binary_string_quote():
    assert render_value('a\x00b') == '"a\\000b"'
