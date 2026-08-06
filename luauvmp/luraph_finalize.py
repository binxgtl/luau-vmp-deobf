"""Finalise staged Luraph prototype trees without executing the final payload.

Some Luraph loaders parse a small bootstrap tree first. That tree performs a
pure decode/mutation pass and returns the actual application prototype tree.
The strict capture boundary intentionally stops before the bootstrap runs, so
this module provides a second, explicit stage:

* the bootstrap runs inside a lexical sandbox with an instruction budget;
* the final closure construction is replaced by a capture callback;
* the returned application closure is never constructed or invoked.

The generated runner is a normal Lune script rather than a custom-environment
``luau.load`` chunk. This lets Lune use native code generation for the heavy
bootstrap while dangerous globals remain lexically shadowed.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence, Union
import queue
import re
import shlex
import shutil
import subprocess
import threading
import time

from . import luraph_capture


_FINAL_RETURN = re.compile(
    r"return\s+(?P<state>[A-Za-z_]\w*)\[50(?:\.0)?\]\("
    r"(?P<root>[A-Za-z_]\w*),(?P=state)\[1(?:\.0)?\]\);end,"
)
_DISPATCH_START = re.compile(
    r"while\s+true\s+do\s+local\s+X\s*=\s*\([^;]+\);"
)


class FinalizeError(RuntimeError):
    """Raised when staged-tree finalisation cannot complete safely."""


@dataclass(frozen=True)
class FinalizeArtifacts:
    full_ir: Path
    runtime_facts: Path
    patched_vm: Path
    runner: Path


def instrument_final_vm_source(vm_source: str) -> str:
    """Keep bootstrap execution but capture before the final payload closure."""
    matches = list(_FINAL_RETURN.finditer(vm_source))
    if len(matches) != 1:
        raise FinalizeError(
            "expected one final payload-closure construction site, found %d" % len(matches)
        )
    match = matches[0]
    replacement = "return __LUAUVMP_CAPTURE(%s,%s);end," % (
        match.group("state"), match.group("root")
    )
    patched = vm_source[:match.start()] + replacement + vm_source[match.end():]

    loops = list(_DISPATCH_START.finditer(patched))
    if len(loops) != 1:
        raise FinalizeError("expected one interpreter dispatcher loop, found %d" % len(loops))
    loop = loops[0]
    guarded = loop.group(0).replace("do", "do __LUAUVMP_STEP();", 1)
    return patched[:loop.start()] + guarded + patched[loop.end():]


def _lua_quote(value: Union[str, Path]) -> str:
    return luraph_capture._lua_quote(value)


def build_finalize_runner(
    patched_vm_source: str,
    bytecode: Union[str, Path],
    full_ir: Union[str, Path],
    runtime_facts: Union[str, Path],
    instruction_budget: int = 5_000_000,
) -> str:
    """Build a native-codegen-friendly lexical-sandbox Lune runner."""
    base = luraph_capture.build_lune_runner(
        "unused.vm.luau", bytecode, full_ir, runtime_facts
    )
    marker = 'status("reading recovered VM and bytecode")'
    if marker not in base:
        raise FinalizeError("capture runner template changed: execution marker missing")
    prefix = base.split(marker, 1)[0]

    lexical = r'''
status("finalising staged prototype tree in lexical sandbox")
local __LUAUVMP_CAPTURE = capture
local __stepCount = 0
local __stepBudget = %d
local function __LUAUVMP_STEP()
    __stepCount += 1
    if __stepCount > __stepBudget then
        error("Luraph bootstrap instruction budget exceeded: " .. tostring(__stepBudget))
    end
end

-- The VM is compiled as part of this runner, so Lune may use native codegen.
-- Every capability-bearing or host-specific global is shadowed before the
-- recovered source. getfenv/_G expose only the closed table used by the parser.
local function __runVM(...)
    local _G = environment
    local shared = environment
    local getgenv = function() return environment end
    local getfenv = function() return environment end
    local setfenv = function(fn, _env) return fn end
    local debug = debugCompat
    local loadstring = safeLoadString
    local load = safeLoadString
    local require = nil
    local fs, net, process = nil, nil, nil
    local game, workspace, script, Instance = nil, nil, nil, nil
    local request, http_request, syn = nil, nil, nil
    local writefile, readfile, appendfile, delfile = nil, nil, nil, nil
    local makefolder, listfiles, isfile, isfolder = nil, nil, nil, nil
%s
end

local bytecode = fs.readFile(%s)
__runVM(buffer.fromstring(bytecode))
status("staged prototype finalisation returned")
''' % (int(instruction_budget), patched_vm_source, _lua_quote(bytecode))
    return prefix + lexical


def _normalise_runtime_command(runtime: Union[str, Sequence[str]]) -> list[str]:
    if isinstance(runtime, str):
        command = shlex.split(runtime)
    else:
        command = list(runtime)
    if not command:
        raise FinalizeError("empty Luau runtime command")
    if len(command) == 1 and shutil.which(command[0]) is None:
        raise FinalizeError("Lune was not found for staged prototype finalisation")
    return command


def run_finalize(
    vm_source: Union[str, Path],
    bytecode: Union[str, Path],
    work_dir: Union[str, Path],
    *,
    runtime: Union[str, Sequence[str]] = "lune",
    timeout: int = 300,
    instruction_budget: int = 5_000_000,
    progress: Optional[Callable[[str], None]] = None,
) -> FinalizeArtifacts:
    """Run only a staged bootstrap decoder and capture its returned tree."""
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)
    text = Path(vm_source).read_text(encoding="utf-8", errors="surrogateescape")
    patched = instrument_final_vm_source(text)

    patched_path = work / "interpreter.finalize.luau"
    runner_path = work / "finalize_runner.luau"
    ir_path = work / "final_ir.tsv"
    facts_path = work / "final_runtime_A.tsv"
    patched_path.write_text(patched, encoding="utf-8", errors="surrogateescape")
    runner_path.write_text(
        build_finalize_runner(
            patched, bytecode, ir_path, facts_path,
            instruction_budget=instruction_budget,
        ),
        encoding="utf-8",
        errors="surrogateescape",
    )

    command = _normalise_runtime_command(runtime) + ["run", str(runner_path)]
    try:
        process = subprocess.Popen(
            command, cwd=str(work), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1,
        )
    except OSError as exc:
        raise FinalizeError("failed to start Lune finaliser: %s" % exc) from exc

    output_lines: list[str] = []
    output_queue: "queue.Queue[Optional[str]]" = queue.Queue()

    def read_output() -> None:
        assert process.stdout is not None
        try:
            for line in process.stdout:
                output_queue.put(line.rstrip("\r\n"))
        finally:
            output_queue.put(None)

    reader = threading.Thread(target=read_output, name="luraph-finalize-output", daemon=True)
    reader.start()
    started = time.monotonic()
    next_heartbeat = started + 15.0
    stream_closed = False
    while process.poll() is None or not stream_closed:
        now = time.monotonic()
        if now - started >= timeout and process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            tail = "\n".join(output_lines[-20:]).strip()
            detail = ("\nlast finaliser output:\n" + tail) if tail else ""
            raise FinalizeError(
                "staged prototype finalisation timed out after %d seconds%s" %
                (timeout, detail)
            )
        try:
            item = output_queue.get(timeout=0.25)
        except queue.Empty:
            item = ""
        if item is None:
            stream_closed = True
        elif item:
            output_lines.append(item)
            if progress is not None:
                progress(item)
        if now >= next_heartbeat and process.poll() is None:
            if progress is not None:
                progress("[finalize] still running (%ds elapsed)" % int(now - started))
            next_heartbeat = now + 15.0

    reader.join(timeout=1)
    return_code = process.wait()
    if return_code != 0:
        message = "\n".join(output_lines[-40:]).strip() or "unknown Lune error"
        raise FinalizeError("staged prototype finalisation failed: %s" % message)
    if not ir_path.is_file() or not facts_path.is_file():
        raise FinalizeError("Lune finaliser exited without capture artifacts")
    try:
        luraph_capture._validate_runtime_facts(facts_path)
    except luraph_capture.CaptureError as exc:
        raise FinalizeError(str(exc)) from exc
    return FinalizeArtifacts(ir_path, facts_path, patched_path, runner_path)
