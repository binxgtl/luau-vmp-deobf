"""Accept parser termination after a complete, independently verified safe capture.

Some wrappers continue executing bootstrap glue after ``__LUAUVMP_CAPTURE`` has
already serialized the full prototype tree. That glue may call the deliberately
disabled closure, touch unavailable Roblox globals, or otherwise fail inside the
closed sandbox. Once the typed IR and supporting artifacts are complete, those
post-capture failures are irrelevant to stage 2 and must not discard a valid
capture.

This layer therefore accepts a non-zero parser termination only after seeing the
``capture complete`` marker and independently validating the typed IR, runtime
facts, factory, instrumented VM, and generated runner. Failures before capture
completion still propagate unchanged.
"""
from __future__ import annotations

from pathlib import Path
import re

from . import luraph_capture
from .luraph_runtime_fix import validate_runtime_facts


# Retained for compatibility with older callers/tests and for the common case
# where the wrapper explicitly invokes the disabled payload closure.
_SENTINEL = "captured Luraph payload closure is intentionally disabled"
_COMPLETE = re.compile(r"\[capture\] capture complete: (?P<count>[0-9]+) prototypes")


def _validate_complete_ir(path: Path, expected_count: int) -> None:
    if expected_count <= 0:
        raise luraph_capture.CaptureError("post-capture termination reported zero prototypes")
    if not path.is_file():
        raise luraph_capture.CaptureError("post-capture termination had no typed IR artifact")

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        raise luraph_capture.CaptureError("post-capture typed IR was empty")
    header = lines[0].split("\t")
    if len(header) != 3 or header[:2] != ["META", "protos"]:
        raise luraph_capture.CaptureError("post-capture typed IR header was invalid")
    try:
        declared = int(header[2])
    except ValueError as exc:
        raise luraph_capture.CaptureError(
            "post-capture typed IR prototype count was invalid"
        ) from exc
    if declared != expected_count:
        raise luraph_capture.CaptureError(
            "post-capture prototype count mismatch: log=%d IR=%d"
            % (expected_count, declared)
        )

    prototypes = sum(1 for line in lines[1:] if line.startswith("P\t"))
    if prototypes != declared:
        raise luraph_capture.CaptureError(
            "post-capture typed IR was incomplete: expected %d prototype rows, found %d"
            % (declared, prototypes)
        )


def _recover_expected_abort(error: Exception, work_dir: Path):
    message = str(error)
    matches = list(_COMPLETE.finditer(message))
    if not matches:
        return None
    expected = int(matches[-1].group("count"))

    ir_path = work_dir / "full_ir.tsv"
    facts_path = work_dir / "runtime_A.tsv"
    factory_path = work_dir / "interpreter.factory.luau"
    patched_path = work_dir / "interpreter.capture.luau"
    runner_path = work_dir / "capture_runner.luau"

    _validate_complete_ir(ir_path, expected)
    if not facts_path.is_file():
        raise luraph_capture.CaptureError(
            "post-capture termination had no runtime helper facts"
        )
    validate_runtime_facts(facts_path)
    for path, label in (
        (factory_path, "interpreter factory"),
        (patched_path, "instrumented VM"),
        (runner_path, "capture runner"),
    ):
        if not path.is_file() or path.stat().st_size == 0:
            raise luraph_capture.CaptureError(
                "post-capture termination had no complete %s artifact" % label
            )

    return luraph_capture.CaptureArtifacts(
        ir_path, facts_path, factory_path, patched_path, runner_path
    )


_ORIGINAL_RUN = None
_INSTALLED = False


def run_capture(*args, **kwargs):
    if _ORIGINAL_RUN is None:
        raise luraph_capture.CaptureError("capture completion layer is unavailable")
    try:
        return _ORIGINAL_RUN(*args, **kwargs)
    except luraph_capture.CaptureError as exc:
        if "work_dir" in kwargs:
            work_dir = Path(kwargs["work_dir"])
        elif len(args) >= 3:
            work_dir = Path(args[2])
        else:
            raise
        artifacts = _recover_expected_abort(exc, work_dir)
        if artifacts is None:
            raise
        progress = kwargs.get("progress")
        if progress is None and len(args) >= 6:
            progress = args[5]
        if progress is not None:
            progress("[capture] accepted verified post-capture termination")
        return artifacts


def install() -> None:
    global _ORIGINAL_RUN, _INSTALLED
    if _INSTALLED:
        return
    _ORIGINAL_RUN = luraph_capture.run_capture
    luraph_capture.run_capture = run_capture
    _INSTALLED = True
