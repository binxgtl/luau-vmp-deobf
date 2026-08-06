"""Statically fingerprint the first public v14.7 sample in one corpus shard."""
from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path
import hashlib
import json
import re

from luauvmp import luraph_loader


def select_shard(paths, index, count):
    return [path for position, path in enumerate(sorted(paths, key=lambda p: p.name))
            if position % count == index]


def _decoded_fingerprint(decoded: bytes) -> dict:
    printable = sum(byte in (9, 10, 13) or 32 <= byte < 127 for byte in decoded)
    text = decoded.decode("utf-8", errors="replace")
    redacted = re.sub(
        r"\[(=*)\[LPH.*?\]\1\]",
        lambda match: "[=[LPH<redacted:%d>]=]" % len(match.group(0)),
        text,
        flags=re.S,
    )
    return {
        "decoded_bytes": len(decoded),
        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
        "decoded_prefix_hex": decoded[:96].hex(),
        "decoded_prefix_repr": repr(text[:256]),
        "decoded_printable_ratio": round(printable / max(1, len(decoded)), 6),
        "while_true_local_count": len(re.findall(
            r"while\s+true\s+do\s+local\s+[A-Za-z_]\w*\s*=", text
        )),
        "slot50_function_count": len(re.findall(
            r"\[\s*(?:50|0[xX]0*32|0[bB]11_?0010)\s*\]\s*=\s*function", text
        )),
        "slot59_function_count": len(re.findall(
            r"\[\s*(?:59|0[xX]0*3[bB]|0[bB]11_?1011)\s*\]\s*=\s*function", text
        )),
        "decompress_buffer_count": text.count("DecompressBuffer"),
        "redacted_prefix_repr": repr(redacted[:512]),
    }


def _stream(payload: str, index: int) -> dict:
    coded = luraph_loader.decode_base85(payload, drop=5)
    record = {
        "index": index,
        "payload_chars": len(payload),
        "coded_bytes": len(coded),
        "coded_sha256": hashlib.sha256(coded).hexdigest(),
        "coded_prefix_hex": coded[:64].hex(),
        "zstd_magic": coded.startswith(b"\x28\xb5\x2f\xfd"),
    }
    try:
        legacy = luraph_loader.decompress(coded)
    except Exception as exc:
        record["legacy_error"] = "%s: %s" % (type(exc).__name__, exc)
    else:
        if legacy is False:
            record["legacy_error"] = "decoder returned False"
        else:
            record["legacy"] = _decoded_fingerprint(legacy)
    try:
        zstd = luraph_loader.decompress_zstd(coded)
    except Exception as exc:
        record["zstd_error"] = "%s: %s" % (type(exc).__name__, exc)
    else:
        record["zstd"] = _decoded_fingerprint(zstd)
    return record


def fingerprint(path: Path) -> dict:
    source = path.read_text(encoding="utf-8", errors="surrogateescape")
    payloads = [payload for payload in luraph_loader.extract_payloads(source)
                if payload.startswith("LPH")]
    result = {
        "sample": path.name,
        "source_bytes": path.stat().st_size,
        "payloads": len(payloads),
        "detected": luraph_loader.detect(source),
        "streams": [_stream(payload, index)
                    for index, payload in enumerate(payloads[:4])],
    }
    try:
        vm, bytecode = luraph_loader.unpack(source)
    except Exception as exc:
        result["unpack_error"] = "%s: %s" % (type(exc).__name__, exc)
    else:
        result["selected_vm"] = _decoded_fingerprint(vm)
        result["selected_bytecode"] = {
            "bytes": len(bytecode),
            "sha256": hashlib.sha256(bytecode).hexdigest(),
            "prefix_hex": bytecode[:64].hex(),
        }
    return result


def main() -> int:
    parser = ArgumentParser()
    parser.add_argument("samples", type=Path)
    parser.add_argument("--shard-index", type=int, required=True)
    parser.add_argument("--shard-count", type=int, required=True)
    args = parser.parse_args()
    selected = select_shard(args.samples.glob("*.lua"), args.shard_index, args.shard_count)
    if not selected:
        raise SystemExit("empty shard")
    print("CONTAINER_PROBE=" + json.dumps(fingerprint(selected[0]), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
