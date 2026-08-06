"""One-command, sample-local Luraph devirtualisation pipeline."""
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
    luraph_capture, luraph_decompiler, luraph_dispatch, luraph_full, luraph_recover,
)


class PipelineError(RuntimeError):
    """Raised when an end-to-end Luraph stage cannot complete safely."""


def _emit(callback: Optional[Callable[[str], None]], message: str) -> None:
    if callback is not None:
        callback(message)


def run_full_loader(
    input_path: Union[str, Path],
    output_dir: Union[str, Path],
    *,
    runtime: Union[str, Sequence[str]] = "lune",
    timeout: int = 300,
    split_protos: bool = False,
    force: bool = False,
    keep_failed: bool = False,
    progress: Optional[Callable[[str], None]] = None,
) -> dict:
    """Run unpack -> safe capture -> dispatcher recovery -> source decompile.

    Protected bytecode is never invoked. The generated Luau is compiled for
    syntax validation through Lune, but the generated program is not executed.
    """
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

        _emit(progress, "[1/5] statically unpacking loader")
        vm_source, bytecode = luraph.unpack(source)
        vm_path = artifacts / "interpreter.vm.luau"
        bytecode_path = artifacts / "bytecode.bin"
        vm_path.write_bytes(vm_source)
        bytecode_path.write_bytes(bytecode)

        _emit(progress, "[2/5] safely capturing prototypes (payload disabled)")
        capture = luraph_capture.run_capture(
            vm_path,
            bytecode_path,
            artifacts,
            runtime=runtime,
            timeout=timeout,
            progress=progress,
        )

        _emit(progress, "[3/5] recovering sample-local dispatcher semantics")
        semantics_path = artifacts / "opcode_semantics.json"
        semantics_text_path = artifacts / "opcode_semantics.txt"
        luraph_recover.recover_dispatch(
            capture.factory,
            capture.runtime_facts,
            semantics_path,
            semantics_text_path,
        )

        _emit(progress, "[4/5] devirtualising the complete prototype tree")
        program = luraph_full.load_full_ir(capture.full_ir)
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

        _emit(progress, "[5/5] decompiling and compile-checking Luau source")
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
        for generated in (decompiler["file"], "decompiler.json"):
            if generated not in manifest["files"]:
                manifest["files"].append(generated)
        (stage / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        elapsed = time.monotonic() - started
        pipeline = {
            "format_version": 2,
            "input": str(source_path),
            "runtime": runtime if isinstance(runtime, str) else list(runtime),
            "payload_executed": False,
            "prototypes": manifest["prototypes"],
            "instructions": manifest["instructions"],
            "opcode_slots": manifest["opcode_slots"],
            "elapsed_seconds": round(elapsed, 3),
            "artifacts": {
                "vm_source": "artifacts/interpreter.vm.luau",
                "bytecode": "artifacts/bytecode.bin",
                "factory": "artifacts/interpreter.factory.luau",
                "full_ir": "artifacts/full_ir.tsv",
                "runtime_facts": "artifacts/runtime_A.tsv",
                "semantics": "artifacts/opcode_semantics.json",
                "capture_runner": "artifacts/capture_runner.luau",
                "compile_runner": "artifacts/compile_decompiled.luau",
            },
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
            failure_note = stage / "FAILED.txt"
            failure_note.write_text(
                "The pipeline did not complete. This directory may contain sensitive "
                "decoded artifacts; review before sharing.\n",
                encoding="utf-8",
            )
        else:
            shutil.rmtree(stage, ignore_errors=True)
        raise
