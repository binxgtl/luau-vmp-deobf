"""Correct Luraph runtime-helper capture without widening the strict sandbox."""
from __future__ import annotations

from pathlib import Path

from . import luraph_capture

_INSTALLED = False


def validate_runtime_facts(path: Path) -> None:
    """Reject the empty environment-slot capture seen in versions <= 0.4.1."""
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        cols = line.split("\t")
        if len(cols) >= 2:
            rows.append(cols)
    non_nil = sum(1 for cols in rows if cols[1] != "nil")
    if len(rows) < 32 or non_nil < 8:
        raise luraph_capture.CaptureError(
            "captured runtime helper facts are empty or implausible "
            "(%d/%d non-nil slots)" % (non_nil, len(rows))
        )


def install() -> None:
    """Patch helper serialization and add read-only missing-global telemetry."""
    global _INSTALLED
    if _INSTALLED:
        return

    original_builder = luraph_capture.build_lune_runner

    def build_lune_runner(*args, **kwargs):
        runner = original_builder(*args, **kwargs)
        runner = runner.replace(
            'if type(runtimeState) ~= "table" or type(runtimeState[1]) ~= "table" then',
            'if type(runtimeState) ~= "table" then',
        )
        runner = runner.replace(
            'writeRuntimeFacts(runtimeState[1])',
            'writeRuntimeFacts(runtimeState)',
        )
        marker = 'environment._G = environment\n\nlocal function safeLoadString'
        telemetry = r'''environment._G = environment
setmetatable(environment, {
    __index = function(_, key)
        status("missing safe-capture global: " .. tostring(key))
        return nil
    end,
})

local function safeLoadString'''
        if marker not in runner:
            raise luraph_capture.CaptureError(
                "safe-capture environment marker was not found"
            )
        runner = runner.replace(marker, telemetry, 1)
        return runner

    original_run = luraph_capture.run_capture

    def run_capture(*args, **kwargs):
        artifacts = original_run(*args, **kwargs)
        validate_runtime_facts(artifacts.runtime_facts)
        return artifacts

    build_lune_runner.__name__ = original_builder.__name__
    run_capture.__name__ = original_run.__name__
    luraph_capture.build_lune_runner = build_lune_runner
    luraph_capture.run_capture = run_capture
    luraph_capture._validate_runtime_facts = validate_runtime_facts
    _INSTALLED = True
