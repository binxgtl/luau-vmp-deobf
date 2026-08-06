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
from . import luraph_capture, luraph_dispatch, luraph_full, luraph_recover


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
    """Run unpack -> safe capture -> dispatcher recovery -> devirtualisation."""
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

        _emit(progress, "[1/4] statically unpacking loader")
        vm_source, bytecode = luraph.unpack(source)
        vm_path = artifacts / "interpreter.vm.luau"
        bytecode_path = artifacts / "bytecode.bin"
        vm_path.write_bytes(vm_source)
        bytecode_path.write_bytes(bytecode)

        _emit(progress, "[2/4] safely capturing prototypes (payload disabled)")
        capture = luraph_capture.run_capture(
            vm_path,
            bytecode_path,
            artifacts,
            runtime=runtime,
            timeout=timeout,
            progress=progress,
        )

        _emit(progress, "[3/4] recovering sample-local dispatcher semantics")
        semantics_path = artifacts / "opcode_semantics.json"
        semantics_text_path = artifacts / "opcode_semantics.txt"
        luraph_recover.recover_dispatch(
            capture.factory, capture.runtime_facts,
            semantics_path, semantics_text_path,
        )

        _emit(progress, "[4/4] devirtualising the complete prototype tree")
        program = luraph_full.load_full_ir(capture.full_ir)
        semantics = luraph_dispatch.load_semantics(semantics_path)
        used = sorted({instruction.opcode
                       for proto in program.protos.values()
                       for instruction in proto.instructions})
        luraph_dispatch.validate_semantics(semantics, used)
        manifest = luraph_full.write_program(
            program, semantics, stage, split_protos=split_protos,
        )

        elapsed = time.monotonic() - started
        pipeline = {
            "format_version": 1,
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
            },
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
                "decoded artifacts; review before sharing.\n", encoding="utf-8",
            )
        else:
            shutil.rmtree(stage, ignore_errors=True)
        raise
