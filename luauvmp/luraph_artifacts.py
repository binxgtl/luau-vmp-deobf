"""Offline Luraph devirtualisation from previously captured artifacts.

This path never evaluates the recovered VM or protected payload. It consumes a
typed prototype IR plus either a precomputed dispatcher map, or the extracted
interpreter factory and runtime facts required to recover that map statically.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional, Sequence, Union
import argparse
import json
import os
import shutil
import tempfile

from . import luraph_decompiler, luraph_dispatch, luraph_full, luraph_recover


class ArtifactPipelineError(RuntimeError):
    """Raised when an offline artifact pipeline cannot complete."""


def _emit(callback: Optional[Callable[[str], None]], message: str) -> None:
    if callback is not None:
        callback(message)


def _copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(source), str(target))


def run_artifact_pipeline(
    ir_path: Union[str, Path],
    output_dir: Union[str, Path],
    *,
    semantics_path: Optional[Union[str, Path]] = None,
    factory_path: Optional[Union[str, Path]] = None,
    runtime_facts_path: Optional[Union[str, Path]] = None,
    split_protos: bool = False,
    force: bool = False,
    keep_failed: bool = False,
    compile_check: bool = False,
    runtime: Union[str, Sequence[str]] = "lune",
    timeout: int = 120,
    progress: Optional[Callable[[str], None]] = None,
) -> dict:
    """Recover semantics and devirtualise a captured Luraph prototype tree.

    Exactly one semantics source is required:

    * ``semantics_path`` for a map recovered from the same VM; or
    * both ``factory_path`` and ``runtime_facts_path`` to recover it now.

    Generated source is never executed. ``compile_check=True`` only asks Lune
    to compile the structural Luau output.
    """
    ir = Path(ir_path)
    output = Path(output_dir)
    semantics = Path(semantics_path) if semantics_path is not None else None
    factory = Path(factory_path) if factory_path is not None else None
    runtime_facts = (
        Path(runtime_facts_path) if runtime_facts_path is not None else None
    )

    if not ir.is_file():
        raise ArtifactPipelineError("typed IR does not exist: %s" % ir)
    has_recovery_pair = factory is not None or runtime_facts is not None
    if semantics is not None and has_recovery_pair:
        raise ArtifactPipelineError(
            "choose precomputed semantics or factory + runtime facts, not both"
        )
    if semantics is None and (factory is None or runtime_facts is None):
        raise ArtifactPipelineError(
            "provide semantics_path, or both factory_path and runtime_facts_path"
        )
    for label, path in (
        ("semantics", semantics),
        ("interpreter factory", factory),
        ("runtime facts", runtime_facts),
    ):
        if path is not None and not path.is_file():
            raise ArtifactPipelineError("%s does not exist: %s" % (label, path))
    if output.exists() and not force:
        raise ArtifactPipelineError("output already exists (use --force): %s" % output)

    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=output.name + ".partial-", dir=str(output.parent)))
    try:
        artifacts = stage / "artifacts"
        artifacts.mkdir()
        captured_ir = artifacts / "final_ir.tsv"
        _copy(ir, captured_ir)

        recovered_semantics = artifacts / "opcode_semantics.json"
        semantics_text = artifacts / "opcode_semantics.txt"
        if semantics is not None:
            _emit(progress, "[1/3] loading precomputed dispatcher semantics")
            _copy(semantics, recovered_semantics)
            semantics_source = "precomputed"
        else:
            _emit(progress, "[1/3] recovering dispatcher semantics from artifacts")
            captured_factory = artifacts / "interpreter.factory.luau"
            captured_facts = artifacts / "runtime_A.tsv"
            _copy(factory, captured_factory)  # type: ignore[arg-type]
            _copy(runtime_facts, captured_facts)  # type: ignore[arg-type]
            luraph_recover.recover_dispatch(
                captured_factory,
                captured_facts,
                recovered_semantics,
                semantics_text,
            )
            semantics_source = "recovered"

        _emit(progress, "[2/3] devirtualising the complete prototype tree")
        program = luraph_full.load_full_ir(captured_ir)
        semantic_map = luraph_dispatch.load_semantics(recovered_semantics)
        used = sorted({
            instruction.opcode
            for proto in program.protos.values()
            for instruction in proto.instructions
        })
        luraph_dispatch.validate_semantics(semantic_map, used)
        manifest = luraph_full.write_program(
            program,
            semantic_map,
            stage,
            split_protos=split_protos,
        )

        _emit(progress, "[3/3] lifting structural Luau source")
        decompiler = luraph_decompiler.write_decompiled(program, semantic_map, stage)
        if compile_check:
            luraph_decompiler.compile_check(
                stage / decompiler["file"],
                artifacts,
                runtime=runtime,
                timeout=timeout,
                progress=progress,
            )
        decompiler["compile_checked"] = bool(compile_check)
        (stage / "decompiler.json").write_text(
            json.dumps(decompiler, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        manifest["decompiled"] = decompiler["file"]
        manifest["decompiler"] = decompiler
        for generated in (decompiler["file"], "decompiler.json"):
            if generated not in manifest["files"]:
                manifest["files"].append(generated)
        (stage / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        pipeline = {
            "format_version": 1,
            "mode": "offline-artifacts",
            "payload_executed": False,
            "vm_executed": False,
            "semantics_source": semantics_source,
            "compile_checked": bool(compile_check),
            "prototypes": manifest["prototypes"],
            "instructions": manifest["instructions"],
            "opcode_slots": manifest["opcode_slots"],
            "artifacts": {
                "typed_ir": "artifacts/final_ir.tsv",
                "semantics": "artifacts/opcode_semantics.json",
            },
            "output": manifest,
        }
        if semantics_source == "recovered":
            pipeline["artifacts"].update({
                "factory": "artifacts/interpreter.factory.luau",
                "runtime_facts": "artifacts/runtime_A.tsv",
                "semantics_text": "artifacts/opcode_semantics.txt",
            })
        (stage / "pipeline.json").write_text(
            json.dumps(pipeline, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        if output.exists():
            shutil.rmtree(output)
        os.replace(stage, output)
        return pipeline
    except Exception:
        if keep_failed:
            (stage / "FAILED.txt").write_text(
                "Offline artifact devirtualisation did not complete. Review the "
                "captured inputs before sharing this directory.\n",
                encoding="utf-8",
            )
        else:
            shutil.rmtree(stage, ignore_errors=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="luauvmp-artifacts",
        description="Offline Luraph devirtualisation from captured typed IR",
    )
    parser.add_argument("ir", help="captured typed prototype IR TSV")
    parser.add_argument("semantics", nargs="?", help="precomputed semantics JSON")
    parser.add_argument("-o", "--output", required=True, help="output directory")
    parser.add_argument("--factory", help="extracted sample-local interpreter factory")
    parser.add_argument("--runtime-facts", help="captured runtime helper facts TSV")
    parser.add_argument("--split-protos", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--keep-failed", action="store_true")
    parser.add_argument(
        "--compile-check",
        action="store_true",
        help="compile generated Luau with Lune without executing it",
    )
    parser.add_argument("--runtime", default="lune")
    parser.add_argument("--timeout", type=int, default=120)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run_artifact_pipeline(
            args.ir,
            args.output,
            semantics_path=args.semantics,
            factory_path=args.factory,
            runtime_facts_path=args.runtime_facts,
            split_protos=args.split_protos,
            force=args.force,
            keep_failed=args.keep_failed,
            compile_check=args.compile_check,
            runtime=args.runtime,
            timeout=args.timeout,
            progress=print,
        )
    except Exception as exc:
        raise SystemExit("offline artifact devirtualisation failed: %s" % exc)
    print(
        "complete: %d prototypes, %d instructions, %d opcode slots -> %s"
        % (
            result["prototypes"],
            result["instructions"],
            result["opcode_slots"],
            args.output,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
