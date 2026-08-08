"""Opt-in Luraph pipeline wrapper with a lua.expert readability post-pass.

The strict devirtualization result is produced and quality-checked locally first.
Only the locally compiled luauc form of ``program.decompiled.luau`` is then sent
to lua.expert. The remote result is advisory and never changes the internal
fallback/unresolved-condition quality gate.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence, Union

from . import lua_expert, luraph_auto


def run_full_loader(
    input_path: Union[str, Path],
    output_dir: Union[str, Path],
    *,
    runtime: Union[str, Sequence[str]] = "lune",
    timeout: int = 300,
    api_timeout: int = lua_expert.DEFAULT_TIMEOUT,
    split_protos: bool = False,
    force: bool = False,
    keep_failed: bool = False,
    progress=print,
) -> dict:
    """Run the safe local pipeline, then opt into a lua.expert source post-pass."""
    result = luraph_auto.run_full_loader(
        input_path,
        output_dir,
        runtime=runtime,
        timeout=timeout,
        split_protos=split_protos,
        force=force,
        keep_failed=keep_failed,
        progress=progress,
    )
    output = Path(output_dir)
    decompiler = result.get("decompiler", {})
    relative_source = decompiler.get("file")
    if not relative_source:
        raise lua_expert.LuaExpertError("local Luraph pipeline produced no decompiled source")

    source_path = output / relative_source
    external_path = output / "program.luaexpert.luau"
    if progress is not None:
        progress(
            "[lua.expert] compiling already-devirtualized Luau locally; "
            "the resulting luauc bytes will be uploaded to a third-party service"
        )
    external = lua_expert.decompile_source_file(
        source_path,
        external_path,
        runtime=runtime,
        compile_timeout=timeout,
        request_timeout=api_timeout,
        work_dir=output / "artifacts",
    )
    external = dict(external)
    external["file"] = external_path.name
    external["strict_quality_gate"] = False
    external["source"] = relative_source

    pipeline_path = output / "pipeline.json"
    pipeline = json.loads(pipeline_path.read_text(encoding="utf-8"))
    pipeline["lua_expert"] = external
    pipeline_path.write_text(
        json.dumps(pipeline, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    manifest_path = output / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["lua_expert"] = external_path.name
        files = manifest.setdefault("files", [])
        if external_path.name not in files:
            files.append(external_path.name)
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    result = dict(result)
    result["lua_expert"] = external
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m luauvmp.luraph_lua_expert",
        description=(
            "Safe Luraph full devirtualization followed by an explicit "
            "lua.expert readability post-pass"
        ),
    )
    parser.add_argument("input", help="protected Luraph v14.x loader")
    parser.add_argument("-o", "--output", required=True, help="output directory")
    parser.add_argument("--runtime", default="lune", help="Lune executable/command")
    parser.add_argument("--timeout", type=int, default=300,
                        help="local capture/compile timeout in seconds")
    parser.add_argument("--api-timeout", type=int, default=lua_expert.DEFAULT_TIMEOUT,
                        help="lua.expert HTTP timeout in seconds")
    parser.add_argument("--split-protos", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--keep-failed", action="store_true")
    args = parser.parse_args(argv)

    result = run_full_loader(
        args.input,
        args.output,
        runtime=args.runtime,
        timeout=args.timeout,
        api_timeout=args.api_timeout,
        split_protos=args.split_protos,
        force=args.force,
        keep_failed=args.keep_failed,
        progress=print,
    )
    external = result["lua_expert"]
    print(
        "lua.expert: wrote %s (%d-byte luauc upload); strict local gate unchanged"
        % (external["file"], external["compiled_bytes"])
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
