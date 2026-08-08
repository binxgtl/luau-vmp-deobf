import json
from pathlib import Path

from luauvmp import luraph_lua_expert


def test_wrapper_runs_local_pipeline_first_and_marks_remote_as_advisory(monkeypatch, tmp_path):
    output = tmp_path / "out"
    order = []

    def fake_local(input_path, output_dir, **kwargs):
        order.append("local")
        out = Path(output_dir)
        out.mkdir()
        (out / "artifacts").mkdir()
        (out / "program.decompiled.luau").write_text(
            "return function() end", encoding="utf-8"
        )
        (out / "pipeline.json").write_text(
            json.dumps({"decompiler": {"file": "program.decompiled.luau"}}),
            encoding="utf-8",
        )
        (out / "manifest.json").write_text(
            json.dumps({"files": ["program.decompiled.luau"]}), encoding="utf-8"
        )
        return {"decompiler": {"file": "program.decompiled.luau"}}

    def fake_remote(source_path, output_path, **kwargs):
        order.append("remote")
        Path(output_path).write_text(
            "-- remote\nreturn function() end", encoding="utf-8"
        )
        return {
            "provider": "lua.expert",
            "file": str(output_path),
            "compiled_bytes": 123,
            "response_bytes": 32,
            "third_party_upload": True,
            "quality_gate_source": False,
        }

    monkeypatch.setattr(luraph_lua_expert.luraph_auto, "run_full_loader", fake_local)
    monkeypatch.setattr(
        luraph_lua_expert.lua_expert, "decompile_source_file", fake_remote
    )

    result = luraph_lua_expert.run_full_loader("sample.lua", output, progress=None)
    assert order == ["local", "remote"]
    assert result["lua_expert"]["strict_quality_gate"] is False
    assert result["lua_expert"]["file"] == "program.luaexpert.luau"

    pipeline = json.loads((output / "pipeline.json").read_text(encoding="utf-8"))
    assert pipeline["lua_expert"]["provider"] == "lua.expert"
    assert pipeline["lua_expert"]["strict_quality_gate"] is False
    assert pipeline["lua_expert"]["source"] == "program.decompiled.luau"

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["lua_expert"] == "program.luaexpert.luau"
    assert "program.luaexpert.luau" in manifest["files"]
