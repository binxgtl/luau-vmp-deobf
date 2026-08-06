"""Staged-tree-aware one-command Luraph pipeline (format version 3)."""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional, Sequence, Union
import json
import os
import shutil
import tempfile
import time

from . import luraph_loader as luraph
from . import (
    luraph_capture,
    luraph_decompiler,
    luraph_dispatch,
    luraph_embedded,
    luraph_finalize,
    luraph_full,
    luraph_recover,
)


class PipelineError(RuntimeError):
    """Raised when an end-to-end Luraph stage cannot complete safely."""


def _emit(callback: Optional[Callable[[str], None]], message: str) -> None:
    if callback is not None:
        callback(message)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("", "0", "false", "no", "off")


def _error_summary(exc: Exception, limit: int = 500) -> str:
    """Return one bounded line suitable for a public manifest."""
    text = "%s: %s" % (type(exc).__name__, exc)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def run_full_loader(
    input_path: Union[str, Path],
    output_dir: Union[str, Path],
    *,
    runtime: Union[str, Sequence[str]] = "lune",
    timeout: int = 300,
    split_protos: bool = False,
    force: bool = False,
    keep_failed: bool = False,
    finalize_staged: Optional[bool] = None,
    finalize_fallback: Optional[bool] = None,
    instruction_budget: Optional[int] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> dict:
    """Run strict capture, staged finalisation, extraction and decompilation.

    Strict parser capture always runs first. If it is recognised as the small
    Luraph bootstrap runtime, that bootstrap decoder runs in a lexical sandbox
    with an instruction budget. The final application closure is captured
    before construction and is never invoked.

    A staged finaliser can be sample-dependent or deliberately non-terminating.
    By default, a finaliser failure is recorded and the pipeline continues from
    the already validated strict capture. Set ``LUAUVMP_FINALIZE_FALLBACK=0``
    (or pass ``finalize_fallback=False``) to retain fail-fast behaviour.
    """
    if finalize_staged is None:
        finalize_staged = not _env_bool("LUAUVMP_STRICT_CAPTURE", False)
    if finalize_fallback is None:
        finalize_fallback = _env_bool("LUAUVMP_FINALIZE_FALLBACK", True)
    if instruction_budget is None:
        instruction_budget = int(os.environ.get("LUAUVMP_INSTRUCTION_BUDGET", "5000000"))

    source_path = Path(input_path)
    output = Path(output_dir)
    if not source_path.is_file():
        raise PipelineError("input file does not exist: %s" % source_path)
    if output.exists() and not force:
        raise PipelineError("output already exists (use --force): %s" % output)

    source = source_path.read_text(encoding="utf-8", errors="surrogateescape")
    if not luraph.detect(source):
        raise PipelineError("input is not a supported Luraph v14.x loader")

    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=output.name + ".partial-", dir=str(output.parent)))
    started = time.monotonic()
    try:
        artifacts = stage / "artifacts"
        artifacts.mkdir()

        _emit(progress, "[1/7] statically unpacking loader")
        vm_source, bytecode = luraph.unpack(source)
        vm_path = artifacts / "interpreter.vm.luau"
        bytecode_path = artifacts / "bytecode.bin"
        vm_path.write_bytes(vm_source)
        bytecode_path.write_bytes(bytecode)

        _emit(progress, "[2/7] strictly capturing the parsed prototype tree")
        capture = luraph_capture.run_capture(
            vm_path,
            bytecode_path,
            artifacts,
            runtime=runtime,
            timeout=timeout,
            progress=progress,
        )
        bootstrap_program = luraph_full.load_full_ir(capture.full_ir)
        staged = bool(finalize_staged) and luraph_embedded.looks_like_luraph_bootstrap(
            bootstrap_program
        )

        active_ir = capture.full_ir
        active_facts = capture.runtime_facts
        finalised = False
        finalization_error = None
        if staged:
            shutil.copy2(capture.full_ir, artifacts / "bootstrap_ir.tsv")
            shutil.copy2(capture.runtime_facts, artifacts / "bootstrap_runtime_A.tsv")
            _emit(
                progress,
                "[3/7] finalising staged tree in sandbox (final payload disabled)",
            )
            try:
                final = luraph_finalize.run_finalize(
                    vm_path,
                    bytecode_path,
                    artifacts,
                    runtime=runtime,
                    timeout=timeout,
                    instruction_budget=int(instruction_budget),
                    progress=progress,
                )
            except Exception as exc:
                if not finalize_fallback:
                    raise
                finalization_error = _error_summary(exc)
                _emit(
                    progress,
                    "[3/7] staged finalisation failed; using strict capture: %s"
                    % finalization_error,
                )
            else:
                active_ir = final.full_ir
                active_facts = final.runtime_facts
                finalised = True
        else:
            _emit(progress, "[3/7] parsed tree is already the final capture")

        _emit(progress, "[4/7] recovering sample-local dispatcher semantics")
        semantics_path = artifacts / "opcode_semantics.json"
        semantics_text_path = artifacts / "opcode_semantics.txt"
        luraph_recover.recover_dispatch(
            capture.factory,
            active_facts,
            semantics_path,
            semantics_text_path,
        )

        program = luraph_full.load_full_ir(active_ir)
        embedded = luraph_embedded.write_embedded_sources(program, stage)
        if embedded["source_chunks"]:
            _emit(
                progress,
                "[5/7] extracted %d embedded Luau source chunk(s)" %
                embedded["source_chunks"],
            )
        else:
            _emit(progress, "[5/7] no embedded Luau source chunks found")

        _emit(progress, "[6/7] devirtualising the complete prototype tree")
        semantics = luraph_dispatch.load_semantics(semantics_path)
        used = sorted({
            instruction.opcode
            for proto in program.protos.values()
            for instruction in proto.instructions
        })
        luraph_dispatch.validate_semantics(semantics, used)
        manifest = luraph_full.write_program(
            program,
            semantics,
            stage,
            split_protos=split_protos,
        )

        _emit(progress, "[7/7] decompiling and compile-checking Luau source")
        decompiler = luraph_decompiler.write_decompiled(program, semantics, stage)
        luraph_decompiler.compile_check(
            stage / decompiler["file"],
            artifacts,
            runtime=runtime,
            timeout=timeout,
            progress=progress,
        )
        decompiler["compile_checked"] = True
        (stage / "decompiler.json").write_text(
            json.dumps(decompiler, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        manifest["decompiled"] = decompiler["file"]
        manifest["decompiler"] = decompiler
        manifest["embedded_sources"] = embedded
        for generated in (decompiler["file"], "decompiler.json", *embedded["files"]):
            if generated not in manifest["files"]:
                manifest["files"].append(generated)
        (stage / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        elapsed = time.monotonic() - started
        if finalised:
            capture_kind = "finalised-staged"
        elif finalization_error is not None:
            capture_kind = "strict-fallback"
        else:
            capture_kind = "strict-final"
        finalize_runner = artifacts / "finalize_runner.luau"
        pipeline = {
            "format_version": 3,
            "input": str(source_path),
            "runtime": runtime if isinstance(runtime, str) else list(runtime),
            "payload_executed": False,
            "bootstrap_executed": bool(staged),
            "bootstrap_completed": finalised,
            "final_payload_executed": False,
            "capture_kind": capture_kind,
            "finalization_attempted": bool(staged),
            "finalization_error": finalization_error,
            "prototypes": manifest["prototypes"],
            "instructions": manifest["instructions"],
            "opcode_slots": manifest["opcode_slots"],
            "elapsed_seconds": round(elapsed, 3),
            "artifacts": {
                "vm_source": "artifacts/interpreter.vm.luau",
                "bytecode": "artifacts/bytecode.bin",
                "factory": "artifacts/interpreter.factory.luau",
                "full_ir": str(active_ir.relative_to(stage)).replace("\\", "/"),
                "runtime_facts": str(active_facts.relative_to(stage)).replace("\\", "/"),
                "semantics": "artifacts/opcode_semantics.json",
                "capture_runner": "artifacts/capture_runner.luau",
                "finalize_runner": (
                    "artifacts/finalize_runner.luau" if finalize_runner.is_file() else None
                ),
                "compile_runner": "artifacts/compile_decompiled.luau",
            },
            "embedded_sources": embedded,
            "decompiler": decompiler,
            "output": manifest,
        }
        (stage / "pipeline.json").write_text(
            json.dumps(pipeline, indent=2, sort_keys=True), encoding="utf-8"
        )

        if output.exists():
            shutil.rmtree(output)
        os.replace(stage, output)
        return pipeline
    except Exception:
        if keep_failed:
            (stage / "FAILED.txt").write_text(
                "The pipeline did not complete. This directory may contain sensitive "
                "decoded artifacts; review before sharing.\n",
                encoding="utf-8",
            )
        else:
            shutil.rmtree(stage, ignore_errors=True)
        raise


def install() -> None:
    """Install pipeline v3 behind the existing public module and CLI."""
    from . import luraph_auto
    luraph_auto.run_full_loader = run_full_loader
    luraph_auto.PipelineError = PipelineError
