"""A recorded runtime observation must never silently rewrite another IR."""
import hashlib
import json

import pytest

from luauvmp.cli import main
from luauvmp.luraph_family import looks_like_v15
from luauvmp.luraph_constant_facts import FactError, replay_facts
from luauvmp.luraph_full import load_full_ir


IR = ("META\tprotos\t1\n"
      "P\t0\t-1\t-1\t-1\t1\tN\tT{}\tD0\tD2\n"
      "I\t0\t1\tS6f6c64\tD1\tD0\tN\tN\tN\tN\n")


def fixture(tmp_path):
    ir = tmp_path / "full_ir.tsv"
    ir.write_text(IR, encoding="utf-8")
    facts = tmp_path / "facts.json"
    data = {"format_version": 1,
            "ir_sha256": hashlib.sha256(ir.read_bytes()).hexdigest(),
            "facts": [{"proto": 0, "pc": 1, "operand": "E",
                       "before": "S6f6c64", "after": "S6e6577"}]}
    facts.write_text(json.dumps(data), encoding="utf-8")
    return ir, facts, data


def test_replay_and_cli_output(tmp_path):
    ir, facts, _ = fixture(tmp_path)
    semantics = tmp_path / "semantics.json"
    semantics.write_text('{"1": "c[p[u]]=E[u]"}', encoding="utf-8")
    out = tmp_path / "output"
    assert main(["luraph-full", str(ir), str(semantics), "-o", str(out),
                 "--constant-facts", str(facts)]) == 0
    assert '"new"' in (out / "program.pseudo.lua").read_text()
    report = json.loads((out / "constant_facts.json").read_text())
    assert report["applied"] == 1
    assert report["ir_sha256"] == hashlib.sha256(ir.read_bytes()).hexdigest()
    assert report["strict_quality_gate"] is False
    assert report["path_complete"] is False


def test_rejects_stale_ir_before_mutation(tmp_path):
    ir, facts, _ = fixture(tmp_path)
    program = load_full_ir(ir)
    ir.write_text(IR + "\n", encoding="utf-8")
    with pytest.raises(FactError, match="SHA-256"):
        replay_facts(program, ir, facts)
    assert program.protos[0].instructions[0].e == "old"


@pytest.mark.parametrize("update, message", [
    ({"before": "S77726f6e67"}, "mismatch"),
    ({"after": "T{}"}, "concrete"),
    ({"pc": 99}, "unknown proto"),
    ({"operand": "opcode"}, "invalid proto"),
])
def test_rejects_bad_facts_without_mutation(tmp_path, update, message):
    ir, facts, data = fixture(tmp_path)
    row = dict(data["facts"][0])
    row.update(operand="p", before="D0", after="D5")
    row.update(update)
    data["facts"].append(row)
    facts.write_text(json.dumps(data), encoding="utf-8")
    program = load_full_ir(ir)
    with pytest.raises(FactError, match=message):
        replay_facts(program, ir, facts)
    assert program.protos[0].instructions[0].e == "old"


def test_v15_is_rejected_before_v14_pipeline_or_output(tmp_path):
    input_path = tmp_path / "wrapped.luau"
    input_path.write_text("-- Luraph Obfuscator v15.0\nreturn 1\n", encoding="utf-8")
    output = tmp_path / "recovered"
    with pytest.raises(SystemExit, match="v15 wrapper detected"):
        main(["luraph-full", str(input_path), "-o", str(output),
              "--no-lua-expert"])
    assert not output.exists()
    assert looks_like_v15(
        'local T={buffer.fromstring, ZS=[==[LPH:abc]==]}; '
        'setmetatable(T, {}):mS()(...)')
    assert not looks_like_v15('local string = "LPH:"; return string')
