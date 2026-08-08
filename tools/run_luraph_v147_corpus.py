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

from luauvmp import luraph_loader


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


def _payload_probe(payload: str) -> dict:
    body = payload[4:] if len(payload) >= 4 else ""
    ordinals = [ord(char) for char in body]
    invalid = sorted({
        ordinal for char, ordinal in zip(body, ordinals)
        if char != "z" and not 33 <= ordinal <= 117
    })
    return {
        "length": len(payload),
        "prefix_repr": repr(payload[:24]),
        "suffix_repr": repr(payload[-24:]),
        "body_min_ordinal": min(ordinals) if ordinals else None,
        "body_max_ordinal": max(ordinals) if ordinals else None,
        "invalid_ordinals": invalid[:32],
        "invalid_count": sum(
            char != "z" and not 33 <= ordinal <= 117
            for char, ordinal in zip(body, ordinals)
        ),
        "expanded_length": len(body) + body.count("z") * 4,
        "structural_match": luraph_loader._looks_like_luraph_stream(payload),
    }


def _source_probe(sample: Path) -> dict:
    source = sample.read_text(encoding="utf-8", errors="surrogateescape")
    long_brackets = luraph_loader.extract_payloads(source)
    lph_payloads = [payload for payload in long_brackets if payload.startswith("LPH")]
    prefixes = []
    for payload in long_brackets[:12]:
        prefixes.append({
            "length": len(payload),
            "prefix_repr": repr(payload[:24]),
        })
    return {
        "banner_v147": "Luraph Obfuscator v14.7" in source,
        "source_contains_lph": "LPH" in source,
        "long_bracket_count": len(long_brackets),
        "long_bracket_prefixes": prefixes,
        "lph_payload_count": len(lph_payloads),
        "lph_payloads": [_payload_probe(payload) for payload in lph_payloads[:6]],
        "detected": luraph_loader.detect(source),
    }


def _quality_metrics(pipeline: dict, semantics: dict) -> dict:
    """Return the fail-closed fully-devirtualized corpus metrics."""
    decompiler = pipeline.get("decompiler", {})
    if not isinstance(decompiler, dict):
        decompiler = {}
    fallback = decompiler.get("fallback_instructions")
    if isinstance(fallback, bool) or not isinstance(fallback, int):
        fallback = -1
    unknown_ifs = decompiler.get("unresolved_dispatcher_conditionals")
    if isinstance(unknown_ifs, bool) or not isinstance(unknown_ifs, int):
        unknown_ifs = 0
        valid_unknown_ifs = True
        for entry in semantics.values():
            if not isinstance(entry, dict):
                continue
            value = entry.get("unknown_ifs", 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                valid_unknown_ifs = False
                break
            unknown_ifs += value
        if not valid_unknown_ifs:
            unknown_ifs = -1
    return {
        "compile_checked": decompiler.get("compile_checked") is True,
        "fallback_instructions": fallback,
        "unknown_ifs": unknown_ifs,
        "payload_executed": pipeline.get("payload_executed"),
        "final_payload_executed": pipeline.get("final_payload_executed"),
    }


def _quality_error(quality: dict) -> Optional[str]:
    if not quality["compile_checked"]:
        return "structural source was not compile checked"
    if quality["fallback_instructions"] != 0:
        return "semantic fallback instructions remain"
    if quality["unknown_ifs"] != 0:
        return "unresolved dispatcher conditionals remain"
    if quality["payload_executed"] is not False:
        return "payload execution safety flag is missing or true"
    if quality["final_payload_executed"] is not False:
        return "final payload execution safety flag is missing or true"
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
        "--keep-failed",
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
        if "not a supported Luraph v14.x loader" in log:
            record["source_probe"] = _source_probe(sample)
        return record

    try:
        pipeline = json.loads(pipeline_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        record["error"] = "invalid pipeline JSON: %s" % exc
        return record
    if not isinstance(pipeline, dict):
        record["error"] = "pipeline JSON is not an object"
        return record
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
    try:
        semantic_entries = json.loads(semantics.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        record["error"] = "invalid opcode semantics JSON: %s" % exc
        return record
    if not isinstance(semantic_entries, dict):
        record["error"] = "opcode semantics JSON is not an object"
        return record
    if not isinstance(record["opcode_slots"], int) or record["opcode_slots"] <= 0:
        record["error"] = "dispatcher semantics were not recovered"
        return record
    quality = _quality_metrics(pipeline, semantic_entries)
    record.update(quality)
    quality_error = _quality_error(quality)
    if quality_error is not None:
        record["error"] = quality_error
        return record
    record["decompiled_bytes"] = decompiled.stat().st_size
    record["pseudo_bytes"] = pseudo.stat().st_size
    record["ok"] = True
    return record


def _print_failure_tail(record: dict, output_root: Path, lines: int = 30) -> None:
    if record.get("ok"):
        return
    log_path = output_root / str(record["log"])
    if log_path.is_file():
        tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
        print("--- %s failure tail ---" % record["sample"], flush=True)
        for line in tail:
            print(line, flush=True)
        print("--- end failure tail ---", flush=True)
    if "source_probe" in record:
        print("SOURCE_PROBE=" + json.dumps(record["source_probe"], sort_keys=True), flush=True)


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
        "format_version": 4,
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
