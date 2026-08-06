"""Statically fingerprint the first public v14.7 stream in one corpus shard."""
from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path
import hashlib
import json

from luauvmp import luraph_loader


def select_shard(paths, index, count):
    return [path for position, path in enumerate(sorted(paths, key=lambda p: p.name))
            if position % count == index]


def fingerprint(path: Path) -> dict:
    source = path.read_text(encoding="utf-8", errors="surrogateescape")
    payloads = [payload for payload in luraph_loader.extract_payloads(source)
                if payload.startswith("LPH")]
    result = {
        "sample": path.name,
        "source_bytes": path.stat().st_size,
        "payloads": len(payloads),
    }
    if not payloads:
        return result
    payload = payloads[0]
    coded = luraph_loader.decode_base85(payload, drop=5)
    result.update({
        "payload_chars": len(payload),
        "coded_bytes": len(coded),
        "coded_sha256": hashlib.sha256(coded).hexdigest(),
        "coded_prefix_hex": coded[:64].hex(),
    })
    try:
        decoded = luraph_loader.decompress(coded)
    except Exception as exc:
        result["decompress_error"] = "%s: %s" % (type(exc).__name__, exc)
        return result
    if decoded is False:
        result["decompress_error"] = "decoder returned False"
        return result
    printable = sum(byte in (9, 10, 13) or 32 <= byte < 127 for byte in decoded)
    text = decoded.decode("utf-8", errors="replace")
    nested = luraph_loader.extract_payloads(text)
    result.update({
        "decoded_bytes": len(decoded),
        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
        "decoded_prefix_hex": decoded[:128].hex(),
        "decoded_suffix_hex": decoded[-64:].hex(),
        "decoded_prefix_repr": repr(text[:256]),
        "decoded_printable_ratio": round(printable / max(1, len(decoded)), 6),
        "decoded_contains_loadstring": "loadstring" in text,
        "decoded_contains_return": "return" in text,
        "decoded_contains_lph": "LPH" in text,
        "decoded_long_brackets": len(nested),
        "decoded_nested_lph": sum(payload.startswith("LPH") for payload in nested),
    })
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
    print("SINGLE_STREAM_PROBE=" + json.dumps(fingerprint(selected[0]), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
