from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from luauvmp import luraph_artifacts


IR = """META\tprotos\t1
P\t0\t-1\t-1\t-1\t1\tN\tT{}\tD0\tD2
I\t0\t1\tS6869\tD1\tD0\tD1\tN\tN\tN
"""
SEMANTICS = {"1": {"source": "c[p[u]]=E[u]", "unknown_ifs": 0, "lines": 1}}


def test_precomputed_semantics_pipeline(tmp_path):
    ir = tmp_path / "full_ir.tsv"
    semantics = tmp_path / "semantics.json"
    output = tmp_path / "out"
    ir.write_text(IR)
    semantics.write_text(json.dumps(SEMANTICS))

    result = luraph_artifacts.run_artifact_pipeline(
        ir, output, semantics_path=semantics
    )

    assert result["mode"] == "offline-artifacts"
    assert result["semantics_source"] == "precomputed"
    assert result["payload_executed"] is False
    assert result["vm_executed"] is False
    assert result["prototypes"] == 1
    assert (output / "program.pseudo.lua").exists()
    assert (output / "program.decompiled.luau").exists()
    assert (output / "artifacts" / "final_ir.tsv").read_text() == IR


def test_recovers_semantics_from_factory_and_runtime_facts(tmp_path, monkeypatch):
    ir = tmp_path / "full_ir.tsv"
    factory = tmp_path / "factory.luau"
    facts = tmp_path / "runtime_A.tsv"
    output = tmp_path / "out"
    ir.write_text(IR)
    factory.write_text("return function() end")
    facts.write_text("1\tnil\tnil\tfalse\t\n")

    def fake_recover(_factory, _facts, output_json, output_text):
        Path(output_json).write_text(json.dumps(SEMANTICS))
        Path(output_text).write_text("-- opcode 1\n")
        return SEMANTICS

    monkeypatch.setattr(luraph_artifacts.luraph_recover, "recover_dispatch", fake_recover)
    result = luraph_artifacts.run_artifact_pipeline(
        ir,
        output,
        factory_path=factory,
        runtime_facts_path=facts,
    )

    assert result["semantics_source"] == "recovered"
    assert (output / "artifacts" / "interpreter.factory.luau").exists()
    assert (output / "artifacts" / "runtime_A.tsv").exists()
    assert (output / "artifacts" / "opcode_semantics.txt").exists()


def test_rejects_ambiguous_semantics_sources(tmp_path):
    ir = tmp_path / "full_ir.tsv"
    semantics = tmp_path / "semantics.json"
    factory = tmp_path / "factory.luau"
    facts = tmp_path / "runtime_A.tsv"
    ir.write_text(IR)
    semantics.write_text(json.dumps(SEMANTICS))
    factory.write_text("return function() end")
    facts.write_text("1\tnil\tnil\tfalse\t\n")

    try:
        luraph_artifacts.run_artifact_pipeline(
            ir,
            tmp_path / "out",
            semantics_path=semantics,
            factory_path=factory,
            runtime_facts_path=facts,
        )
    except luraph_artifacts.ArtifactPipelineError as exc:
        assert "not both" in str(exc)
    else:
        raise AssertionError("ambiguous artifact inputs were accepted")
