"""Optional lua.expert decompiler backend for standard Luau compiler bytecode.

This module never sends Luraph virtual bytecode to lua.expert. The service
accepts standard luauc bytecode, so the Luraph integration first compile-checks
our already-devirtualized Luau source locally, compiles that source to luauc
without executing it, and only then uploads the compiled bytes when explicitly
enabled by the caller.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from typing import Callable, Optional, Sequence, Union
import urllib.error
import urllib.request


API_ENDPOINT = "https://api.lua.expert/decompile"
DEFAULT_TIMEOUT = 30
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class LuaExpertError(RuntimeError):
    """Raised when local luauc compilation or lua.expert decompilation fails."""


def _runtime_command(runtime: Union[str, Sequence[str]]) -> list:
    command = shlex.split(runtime) if isinstance(runtime, str) else list(runtime)
    if not command:
        raise LuaExpertError("empty Luau runtime command")
    if len(command) == 1 and shutil.which(command[0]) is None:
        raise LuaExpertError("Lune was not found for lua.expert compile-only post-pass")
    return command


def _luau_string(value: Union[str, Path]) -> str:
    text = str(value)
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r") + '"'


def compile_source_to_bytecode(
    source_path: Union[str, Path],
    *,
    runtime: Union[str, Sequence[str]] = "lune",
    timeout: int = 120,
    work_dir: Optional[Union[str, Path]] = None,
) -> bytes:
    """Compile Luau source to luauc bytes without executing the source."""
    source = Path(source_path).resolve()
    if not source.is_file():
        raise LuaExpertError("source file does not exist: %s" % source)
    parent = Path(work_dir).resolve() if work_dir is not None else source.parent
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="luaexpert-", dir=str(parent)) as tmp_name:
        tmp = Path(tmp_name)
        runner = tmp / "compile_only.luau"
        output = tmp / "compiled.luac"
        runner.write_text(
            'local fs = require("@lune/fs")\n'
            'local luau = require("@lune/luau")\n'
            'local source = fs.readFile(%s)\n'
            'local ok, bytecode = pcall(luau.compile, source, { optimizationLevel = 1, debugLevel = 1 })\n'
            'if not ok then error(bytecode) end\n'
            'fs.writeFile(%s, bytecode)\n' % (_luau_string(source), _luau_string(output)),
            encoding="utf-8",
        )
        try:
            result = subprocess.run(
                _runtime_command(runtime) + ["run", str(runner)],
                cwd=str(tmp),
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise LuaExpertError("Luau compile-only post-pass timed out") from exc
        except OSError as exc:
            raise LuaExpertError("failed to start Lune: %s" % exc) from exc
        if result.returncode != 0:
            detail = "\n".join(x for x in (result.stdout, result.stderr) if x).strip()
            raise LuaExpertError("Luau compile-only post-pass failed: %s" % (detail or "unknown error"))
        if not output.is_file():
            raise LuaExpertError("Lune did not produce luauc bytecode")
        bytecode = output.read_bytes()
        if not bytecode:
            raise LuaExpertError("Lune produced empty luauc bytecode")
        return bytecode


def decompile_bytecode(
    bytecode: bytes,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    opener: Optional[Callable] = None,
    endpoint: str = API_ENDPOINT,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> str:
    """Send standard luauc bytes to lua.expert and return decompiled Luau."""
    if not isinstance(bytecode, (bytes, bytearray, memoryview)):
        raise TypeError("bytecode must be bytes-like")
    raw = bytes(bytecode)
    if not raw:
        raise LuaExpertError("refusing to send empty luauc bytecode")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if max_response_bytes <= 0:
        raise ValueError("max_response_bytes must be positive")

    body = json.dumps(
        {"script": base64.b64encode(raw).decode("ascii")},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "text/plain",
            "User-Agent": "luau-vmp-deobf/lua-expert",
        },
        method="POST",
    )
    open_url = opener or urllib.request.urlopen
    try:
        response = open_url(request, timeout=timeout)
        with response:
            status = getattr(response, "status", 200)
            if not 200 <= int(status) < 300:
                raise LuaExpertError("lua.expert returned HTTP %s" % status)
            payload = response.read(max_response_bytes + 1)
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read(1024).decode("utf-8", errors="replace").strip()
        except Exception:
            detail = ""
        suffix = ": %s" % detail if detail else ""
        raise LuaExpertError("lua.expert returned HTTP %s%s" % (exc.code, suffix)) from exc
    except urllib.error.URLError as exc:
        raise LuaExpertError("lua.expert request failed: %s" % exc.reason) from exc
    except TimeoutError as exc:
        raise LuaExpertError("lua.expert request timed out") from exc

    if len(payload) > max_response_bytes:
        raise LuaExpertError("lua.expert response exceeded %d bytes" % max_response_bytes)
    if not payload:
        raise LuaExpertError("lua.expert returned an empty response")
    try:
        source = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LuaExpertError("lua.expert returned non-UTF-8 data") from exc
    if not source.strip():
        raise LuaExpertError("lua.expert returned blank Luau source")
    return source


def decompile_file(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """Decompile a standard .luac/.luauc file through lua.expert."""
    source = Path(input_path)
    if not source.is_file():
        raise LuaExpertError("luauc file does not exist: %s" % source)
    bytecode = source.read_bytes()
    text = decompile_bytecode(bytecode, timeout=timeout)
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return {
        "provider": "lua.expert",
        "file": str(target),
        "compiled_bytes": len(bytecode),
        "response_bytes": len(text.encode("utf-8")),
        "third_party_upload": True,
    }


def decompile_source_file(
    source_path: Union[str, Path],
    output_path: Union[str, Path],
    *,
    runtime: Union[str, Sequence[str]] = "lune",
    compile_timeout: int = 120,
    request_timeout: int = DEFAULT_TIMEOUT,
    work_dir: Optional[Union[str, Path]] = None,
) -> dict:
    """Compile source locally, then decompile the luauc bytes through lua.expert."""
    bytecode = compile_source_to_bytecode(
        source_path,
        runtime=runtime,
        timeout=compile_timeout,
        work_dir=work_dir,
    )
    text = decompile_bytecode(bytecode, timeout=request_timeout)
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return {
        "provider": "lua.expert",
        "file": str(target),
        "compiled_bytes": len(bytecode),
        "response_bytes": len(text.encode("utf-8")),
        "third_party_upload": True,
        "quality_gate_source": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m luauvmp.lua_expert",
        description="Opt-in lua.expert backend for standard Luau compiler bytecode",
    )
    parser.add_argument("input", help=".luac/.luauc file, or Luau source with --source")
    parser.add_argument("-o", "--output", help="output Luau path")
    parser.add_argument("--source", action="store_true",
                        help="compile the input Luau source locally before uploading luauc bytes")
    parser.add_argument("--runtime", default="lune", help="Lune command used with --source")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="lua.expert HTTP timeout in seconds")
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    output = Path(args.output) if args.output else input_path.with_suffix(".luaexpert.luau")
    if args.source:
        result = decompile_source_file(
            input_path,
            output,
            runtime=args.runtime,
            request_timeout=args.timeout,
        )
    else:
        result = decompile_file(input_path, output, timeout=args.timeout)
    print("wrote %s via %s (%d-byte luauc upload)" % (
        output, result["provider"], result["compiled_bytes"]
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
