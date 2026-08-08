import base64
import json
import pathlib
import urllib.error

import pytest

from luauvmp import lua_expert


class FakeResponse:
    def __init__(self, body=b"print('ok')", status=200):
        self.body = body
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


def test_decompile_bytecode_posts_expected_json_and_headers():
    seen = {}

    def opener(request, timeout):
        seen["url"] = request.full_url
        seen["body"] = request.data
        seen["timeout"] = timeout
        seen["content_type"] = request.get_header("Content-type")
        seen["accept"] = request.get_header("Accept")
        return FakeResponse(b"-- decompiled\nreturn 1\n")

    result = lua_expert.decompile_bytecode(b"\x01\x02luac", timeout=7, opener=opener)
    assert result == "-- decompiled\nreturn 1\n"
    assert seen["url"] == lua_expert.API_ENDPOINT
    assert seen["timeout"] == 7
    assert seen["content_type"] == "application/json"
    assert seen["accept"] == "text/plain"
    payload = json.loads(seen["body"].decode("utf-8"))
    assert base64.b64decode(payload["script"]) == b"\x01\x02luac"


def test_empty_bytecode_is_rejected_before_network():
    called = False

    def opener(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError

    with pytest.raises(lua_expert.LuaExpertError, match="empty"):
        lua_expert.decompile_bytecode(b"", opener=opener)
    assert not called


def test_response_limit_is_fail_closed():
    with pytest.raises(lua_expert.LuaExpertError, match="exceeded"):
        lua_expert.decompile_bytecode(
            b"x",
            opener=lambda *_args, **_kwargs: FakeResponse(b"12345"),
            max_response_bytes=4,
        )


def test_non_utf8_response_is_rejected():
    with pytest.raises(lua_expert.LuaExpertError, match="non-UTF-8"):
        lua_expert.decompile_bytecode(
            b"x", opener=lambda *_args, **_kwargs: FakeResponse(b"\xff\xfe")
        )


def test_http_error_is_wrapped():
    def opener(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            lua_expert.API_ENDPOINT, 429, "rate limited", {}, None
        )

    with pytest.raises(lua_expert.LuaExpertError, match="HTTP 429"):
        lua_expert.decompile_bytecode(b"x", opener=opener)


def test_compile_runner_is_compile_only(monkeypatch, tmp_path):
    source = tmp_path / "program.luau"
    source.write_text("print('never execute me')", encoding="utf-8")

    monkeypatch.setattr(lua_expert.shutil, "which", lambda _name: "/fake/lune")
    captured = {}

    def run(command, cwd, text, capture_output, timeout, check):
        runner = pathlib.Path(command[-1])
        runner_text = runner.read_text(encoding="utf-8")
        captured["runner"] = runner_text
        import re
        match = re.search(r'fs\.writeFile\("([^\"]+)", bytecode\)', runner_text)
        assert match is not None
        pathlib.Path(match.group(1)).write_bytes(b"compiled-luauc")

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return Result()

    monkeypatch.setattr(lua_expert.subprocess, "run", run)

    result = lua_expert.compile_source_to_bytecode(
        source, runtime="lune", work_dir=tmp_path
    )
    assert result == b"compiled-luauc"
    assert "luau.compile" in captured["runner"]
    assert "loadstring" not in captured["runner"]
    assert "print('never execute me')" not in captured["runner"]
