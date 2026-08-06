"""Run the public terrorlua Luraph v14.7 corpus through the safe pipeline.

The runner deliberately invokes the project CLI as a subprocess so it exercises
installed entry points, atomic output handling, dispatcher recovery, structural
lifting, and Lune compile checking exactly as an end user would.
"""
from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path
from typing import Iterable, Optional, Union
import hashlib
import json
import os
import signal
import subprocess
import sys
import time


TextOrBytes = Optional[Union[str, bytes]]


def select_shard(paths: Iterable[Path], index: int, count: int) -> list[Path]:
    ordered = sorted(paths, key=lambda path: path.name)
    return [path for position, path in enumerate(ordered) if position % count == index]


def _text(value: TextOrBytes) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _last_progress(log: str) -> Optional[str]:
    for line in reversed(log.splitlines()):
        stripped = line.strip()
        if stripped.startswith("[") or stripped.startswith("luraph-full failed:"):
            return stripped[:500]
    return None


def _stop_process(process: subprocess.Popen[bytes]) -> bytes:
    """Stop the CLI and every Lune child while preserving buffered output."""
    if process.poll() is None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGINT)
            else:
                process.send_signal(signal.SIGINT)
        except (ProcessLookupError, OSError):
            pass
    try:
        output, _ = process.communicate(timeout=5)
        return output or b""
    except subprocess.TimeoutExpired as exc:
        partial = exc.output or b""
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (ProcessLookupError, OSError):
            pass
        output, _ = process.communicate()
        return output or partial


def run_sample(sample: Path, output_root: Path, timeout: int) -> dict:
    name = sample.stem
    output = output_root / name
    log_path = output_root / (name + ".log")
    started = time.monotonic()
    env = os.environ.copy()
    env.setdefault("LUAUVMP_FINALIZE_FALLBACK", "1")
    env.setdefault("LUAUVMP_INSTRUCTION_BUDGET", "5000000")
    command = [
        "luauvmp", "luraph-full", str(sample),
        "-o", str(output), "--force", "--timeout", str(timeout),
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        start_new_session=(os.name == "posix"),
    )
    timed_out = False
    try:
        output_bytes, _ = process.communicate(timeout=timeout + 30)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        partial = exc.output or b""
        stopped = _stop_process(process)
        # communicate() normally returns the complete buffered stream after a
        # timeout. Keep the larger value to avoid duplicating the prefix.
        output_bytes = stopped if len(stopped) >= len(partial) else partial
    log = _text(output_bytes)
    if timed_out:
        log += "\nCORPUS RUNNER HARD TIMEOUT (%d seconds)\n" % (timeout + 30)
    returncode = 124 if timed_out else int(process.returncode or 0)
    log_path.write_text(log, encoding="utf-8", errors="replace")

    record = {
        "sample": sample.name,
        "sha256": hashlib.sha256(sample.read_bytes()).hexdigest(),
        "bytes": sample.stat().st_size,
        "returncode": returncode,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "log": log_path.name,
        "last_progress": _last_progress(log),
        "timed_out": timed_out,
        "ok": False,
    }
    pipeline_path = output / "pipeline.json"
    if returncode != 0 or not pipeline_path.is_file():
        record["error"] = "pipeline command timed out" if timed_out else "pipeline command failed"
        return record

    pipeline = json.loads(pipeline_path.read_text(encoding="utf-8"))
    decompiled = output / "program.decompiled.luau"
    pseudo = output / "program.pseudo.lua"
    semantics = output / "artifacts" / "opcode_semantics.json"
    required = [decompiled, pseudo, semantics]
    missing = [str(path.relative_to(output)) for path in required if not path.is_file()]
    record.update({
        "capture_kind": pipeline.get("capture_kind"),
        "bootstrap_completed": pipeline.get("bootstrap_completed"),
        "prototypes": pipeline.get("prototypes"),
        "instructions": pipeline.get("instructions"),
        "opcode_slots": pipeline.get("opcode_slots"),
        "compile_checked": pipeline.get("decompiler", {}).get("compile_checked"),
        "missing": missing,
    })
    if missing:
        record["error"] = "missing generated artifacts"
        return record
    if not record["compile_checked"]:
        record["error"] = "structural source was not compile checked"
        return record
    if not isinstance(record["opcode_slots"], int) or record["opcode_slots"] <= 0:
        record["error"] = "dispatcher semantics were not recovered"
        return record
    record["decompiled_bytes"] = decompiled.stat().st_size
    record["pseudo_bytes"] = pseudo.stat().st_size
    record["ok"] = True
    return record


def _print_failure_tail(record: dict, output_root: Path, lines: int = 30) -> None:
    if record.get("ok"):
        return
    log_path = output_root / str(record["log"])
    if not log_path.is_file():
        return
    tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
    print("--- %s failure tail ---" % record["sample"], flush=True)
    for line in tail:
        print(line, flush=True)
    print("--- end failure tail ---", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser()
    parser.add_argument("samples", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument(
        "--max-failures",
        type=int,
        default=0,
        help="stop a shard after this many failures; zero scans the whole shard",
    )
    args = parser.parse_args(argv)

    if args.shard_count < 1 or not 0 <= args.shard_index < args.shard_count:
        parser.error("shard index must be within shard count")
    if args.max_failures < 0:
        parser.error("max failures must not be negative")
    samples = select_shard(args.samples.glob("*.lua"), args.shard_index, args.shard_count)
    if not samples:
        raise SystemExit("no Luraph v14.7 samples selected")
    args.output.mkdir(parents=True, exist_ok=True)

    records = []
    stopped_early = False
    for position, sample in enumerate(samples, 1):
        print("[%d/%d] %s" % (position, len(samples), sample.name), flush=True)
        record = run_sample(sample, args.output, args.timeout)
        records.append(record)
        print(json.dumps(record, sort_keys=True), flush=True)
        _print_failure_tail(record, args.output)
        failures = sum(not bool(item["ok"]) for item in records)
        if args.max_failures and failures >= args.max_failures:
            stopped_early = position < len(samples)
            if stopped_early:
                print(
                    "stopping shard after %d failure(s); %d sample(s) remain"
                    % (failures, len(samples) - position),
                    flush=True,
                )
            break

    summary = {
        "format_version": 3,
        "shard_index": args.shard_index,
        "shard_count": args.shard_count,
        "selected_samples": len(samples),
        "samples": len(records),
        "passed": sum(bool(record["ok"]) for record in records),
        "failed": sum(not bool(record["ok"]) for record in records),
        "timeouts": sum(bool(record.get("timed_out")) for record in records),
        "stopped_early": stopped_early,
        "records": records,
    }
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        key: summary[key]
        for key in ("selected_samples", "samples", "passed", "failed", "timeouts", "stopped_early")
    }, sort_keys=True))
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
