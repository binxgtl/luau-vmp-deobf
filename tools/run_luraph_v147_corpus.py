"""Run the public terrorlua Luraph v14.7 corpus through the safe pipeline.

The runner deliberately invokes the project CLI as a subprocess so it exercises
installed entry points, atomic output handling, dispatcher recovery, structural
lifting, and Lune compile checking exactly as an end user would.
"""
from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path
from typing import Iterable
import hashlib
import json
import os
import subprocess
import sys
import time


def select_shard(paths: Iterable[Path], index: int, count: int) -> list[Path]:
    ordered = sorted(paths, key=lambda path: path.name)
    return [path for position, path in enumerate(ordered) if position % count == index]


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
    try:
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            timeout=timeout + 60,
            check=False,
        )
        log = completed.stdout
        returncode = completed.returncode
    except subprocess.TimeoutExpired as exc:
        log = (exc.stdout or "") + "\nCORPUS RUNNER TIMEOUT\n"
        returncode = 124
    log_path.write_text(log, encoding="utf-8", errors="replace")

    record = {
        "sample": sample.name,
        "sha256": hashlib.sha256(sample.read_bytes()).hexdigest(),
        "bytes": sample.stat().st_size,
        "returncode": returncode,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "log": log_path.name,
        "ok": False,
    }
    pipeline_path = output / "pipeline.json"
    if returncode != 0 or not pipeline_path.is_file():
        record["error"] = "pipeline command failed"
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


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser()
    parser.add_argument("samples", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args(argv)

    if args.shard_count < 1 or not 0 <= args.shard_index < args.shard_count:
        parser.error("shard index must be within shard count")
    samples = select_shard(args.samples.glob("*.lua"), args.shard_index, args.shard_count)
    if not samples:
        raise SystemExit("no Luraph v14.7 samples selected")
    args.output.mkdir(parents=True, exist_ok=True)

    records = []
    for position, sample in enumerate(samples, 1):
        print("[%d/%d] %s" % (position, len(samples), sample.name), flush=True)
        record = run_sample(sample, args.output, args.timeout)
        records.append(record)
        print(json.dumps(record, sort_keys=True), flush=True)

    summary = {
        "format_version": 1,
        "shard_index": args.shard_index,
        "shard_count": args.shard_count,
        "samples": len(records),
        "passed": sum(bool(record["ok"]) for record in records),
        "failed": sum(not bool(record["ok"]) for record in records),
        "records": records,
    }
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({key: summary[key] for key in ("samples", "passed", "failed")},
                     sort_keys=True))
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
