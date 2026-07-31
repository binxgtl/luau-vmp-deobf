"""Tests for Luraph stages 2-4 (devirt / pseudo / flow)."""
from luauvmp import luraph_devirt as ld
from luauvmp import luraph_pseudo as lp
from luauvmp import luraph_flow as lf

PROTO = """1: op=153 F=709 g=nil b=nil D=nil L=0 K=0
2: op=176 F=15 g=nil b=nil D=4 L=1539 K=0
3: op=155 F=14 g=Disconnect b=nil D=136 L=339 K=1804
4: op=40 F=0 g=nil b=nil D=nil L=9 K=26
5: op=122 F=0 g=nil b=nil D=nil L=0 K=26
6: op=50 F=155 g=nil b=nil D=nil L=19 K=5
7: op=2 F=1 g=nil b=nil D=nil L=0 K=26"""

STRINGS = """1: nil (nil)
2: table: 0x55 (table)
4: Disconnect (string)
9: nil (nil)
19: nil (nil)"""


def parse_all():
    ins = ld.parse_proto_dump(PROTO)
    strings = ld.parse_strings(STRINGS)
    dis = '\n'.join(ld.devirtualize(ins, strings))
    return ins, strings, lp.parse_disasm(dis)


def test_parse_proto_dump():
    ins = ld.parse_proto_dump(PROTO)
    assert len(ins) == 7
    assert ins[0]['op'] == 153
    assert ins[1]['D'] == '4'
    assert ins[2]['g'] == 'Disconnect'


def test_parse_strings():
    s = ld.parse_strings(STRINGS)
    assert s == {4: 'Disconnect'}


def test_devirtualize():
    ins = ld.parse_proto_dump(PROTO)
    strings = ld.parse_strings(STRINGS)
    out = ld.devirtualize(ins, strings)
    joined = '\n'.join(out)
    assert 'GETGLOBAL' in joined
    assert 'Disconnect' in joined
    assert 'SETTABLE' in joined
    assert 'LOADVMK' in joined


def test_opcode_table_complete():
    # the dispatcher analysis mapped 46 opcodes; every entry must have a name
    assert len(ld.OPS) >= 40
    for name, pat in ld.OPS.values():
        assert name and pat


def test_parse_disasm_handles_question_mark_ops():
    # ops with '?' suffix (MOVE?, GETGLOBAL?...) must not be dropped
    proto = "1: op=135 F=1 g=nil b=nil D=nil L=2 K=3\n"
    ins = ld.parse_proto_dump(proto)
    strings = ld.parse_strings('')
    dis = '\n'.join(ld.devirtualize(ins, strings))
    parsed = lp.parse_disasm(dis)
    assert len(parsed) == 1
    assert parsed[0]['op'] == 'MOVE?'


def test_pseudo_reconstruct():
    _, _, parsed = parse_all()
    out = lp.reconstruct(parsed, ld.parse_strings(STRINGS))
    assert 'CONFIG' in out
    assert 'Disconnect' in out
    assert '_G.' in out


def test_flow_edges_and_blocks():
    _, _, parsed = parse_all()
    out = lf.reconstruct(parsed, ld.parse_strings(STRINGS))
    assert '::B_5::' in out        # EQ? jump target becomes a block
    assert 'goto B_5' in out
    assert 'goto B_1' in out
    assert 'control-flow edges' in out


def test_flow_cfg_counts():
    # synthetic proto: 1 TEST + 1 EQ? => exactly 2 edges
    proto = """1: op=176 F=15 g=nil b=nil D=4 L=0 K=0
2: op=2 F=10 g=nil b=nil D=nil L=0 K=26
3: op=155 F=14 g=nil b=nil D=1 L=0 K=15
4: op=50 F=1 g=nil b=nil D=nil L=2 K=6
5: op=155 F=14 g=nil b=nil D=2 L=0 K=15
6: op=121 F=3 g=nil b=nil D=nil L=1 K=3
7: op=155 F=14 g=nil b=nil D=3 L=0 K=15
8: op=155 F=14 g=nil b=nil D=4 L=0 K=15
9: op=155 F=14 g=nil b=nil D=5 L=0 K=15
10: op=121 F=3 g=nil b=nil D=nil L=1 K=3"""
    ins = ld.parse_proto_dump(proto)
    strings = ld.parse_strings('1: nil (nil)\n2: nil (nil)')
    dis = '\n'.join(ld.devirtualize(ins, strings))
    parsed = lp.parse_disasm(dis)
    out = lf.reconstruct(parsed, strings)
    assert '| 2 edges |' in out
