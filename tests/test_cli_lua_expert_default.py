from argparse import Namespace

from luauvmp import cli


def _args(**overrides):
    values = {
        "input": "protected.lua",
        "semantics": None,
        "output": "recovered",
        "runtime": "lune",
        "timeout": 300,
        "api_timeout": 30,
        "force": False,
        "keep_failed": False,
        "split_protos": False,
        "no_lua_expert": False,
    }
    values.update(overrides)
    return Namespace(**values)


def test_luraph_full_uses_lua_expert_by_default(monkeypatch):
    calls = []

    def fake_remote(*args, **kwargs):
        calls.append((args, kwargs))
        return {
            "prototypes": 1,
            "instructions": 1,
            "opcode_slots": 1,
            "lua_expert": {"file": "program.luaexpert.luau", "compiled_bytes": 12},
        }

    monkeypatch.setattr(cli.luraph_lua_expert, "run_full_loader", fake_remote)
    monkeypatch.setattr(
        cli.luraph_auto,
        "run_full_loader",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("local-only path used")),
    )

    cli.cmd_luraph_full(_args())
    assert len(calls) == 1
    assert calls[0][1]["api_timeout"] == 30


def test_luraph_full_no_lua_expert_uses_local_pipeline(monkeypatch):
    calls = []

    def fake_local(*args, **kwargs):
        calls.append((args, kwargs))
        return {"prototypes": 1, "instructions": 1, "opcode_slots": 1}

    monkeypatch.setattr(cli.luraph_auto, "run_full_loader", fake_local)
    monkeypatch.setattr(
        cli.luraph_lua_expert,
        "run_full_loader",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("remote path used")),
    )

    cli.cmd_luraph_full(_args(no_lua_expert=True))
    assert len(calls) == 1
