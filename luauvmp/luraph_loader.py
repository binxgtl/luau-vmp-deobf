"""Static facade for the Luraph v14.x container layouts.

Supported families:

* legacy two-stream Ascii85 + custom range/LZ compression;
* public one-stream Ascii85 + Zstandard bytecode with the VM in the wrapper; and
* public two-stream Ascii85 + Zstandard, where the wrapper declares the exact
  compressed lengths needed to remove the final Ascii85 padding bytes.
"""
from __future__ import annotations

import io
import os
import re
from typing import List, Optional, Sequence, Tuple

import zstandard as zstd

from . import luraph as _base

_LONG_BRACKET = re.compile(r"\[(=*)\[(.*?)\]\1\]", re.S)
_DECOMPRESS_CALL = re.compile(
    r"game\s*:\s*GetService\("
    r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
    r"\)\s*:\s*DecompressBuffer\("
    r"(?:[^()\"']|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|\([^()]*\))*"
    r"\)",
    re.S,
)
_TRIM_ASSIGN = re.compile(
    r"(?P<name>[A-Za-z_]\w*)\s*=\s*string\s*\.\s*sub\s*\(\s*"
    r"(?P=name)\s*,\s*1\s*,\s*(?P<length>[0-9][0-9_]*)\s*\)",
    re.S,
)
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_DEFAULT_ZSTD_LIMIT = 256 * 1024 * 1024


def extract_payloads(source):
    """Return all Lua long-bracket strings in source order."""
    return [match.group(2) for match in _LONG_BRACKET.finditer(source)]


def _looks_like_luraph_stream(payload):
    """Recognise one encoded stream without loader-local names or constants."""
    if len(payload) < 9 or not payload.startswith("LPH"):
        return False
    body = payload[4:]
    for char in body:
        code = ord(char)
        if char != "z" and not 33 <= code <= 117:
            return False
    # Luraph silently ignores a partial trailing Ascii85 group. Our inverse
    # decoder pads that group to four bytes, so Zstandard layouts must later use
    # the exact string.sub lengths embedded in the wrapper.
    return len(body) + body.count("z") * 4 >= 5


def _raw_lph_payloads(source):
    return [payload for payload in extract_payloads(source) if payload.startswith("LPH")]


def _luraph_payloads(source):
    return [payload for payload in _raw_lph_payloads(source)
            if _looks_like_luraph_stream(payload)]


def _is_single_stream_zstd(source, payloads=None):
    streams = _luraph_payloads(source) if payloads is None else payloads
    return len(streams) == 1 and "DecompressBuffer" in source


def detect(source):
    """Detect supported v14.x stream envelopes without executing the wrapper."""
    payloads = _luraph_payloads(source)
    if len(payloads) >= 2 or _is_single_stream_zstd(source, payloads):
        return True
    # Keep old delimiter-only synthetic fixtures working. Real unpacking still
    # requires structurally valid stream envelopes.
    legacy_signature = "52200625" in source and "614125" in source
    return legacy_signature and len(_raw_lph_payloads(source)) >= 2


def decompress_zstd(data, max_output_size=None):
    """Decompress one frame with a hard output bound.

    Streaming avoids trusting the optional frame content-size field. The bound
    is configurable for large research fixtures but defaults to 256 MiB.
    """
    if max_output_size is None:
        max_output_size = int(os.environ.get(
            "LUAUVMP_ZSTD_MAX_OUTPUT", str(_DEFAULT_ZSTD_LIMIT)
        ))
    if max_output_size <= 0:
        raise ValueError("Zstandard output limit must be positive")

    output = bytearray()
    try:
        with zstd.ZstdDecompressor().stream_reader(io.BytesIO(data)) as reader:
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > max_output_size:
                    raise ValueError(
                        "Zstandard output exceeds %d-byte safety limit" % max_output_size
                    )
    except zstd.ZstdError as exc:
        raise ValueError("invalid Luraph Zstandard stream: %s" % exc) from exc
    return bytes(output)


def _declared_trim_lengths(source: str, coded: Sequence[bytes]) -> Optional[List[int]]:
    """Match wrapper ``string.sub(stream, 1, length)`` declarations to streams.

    Ascii85 expands a partial final group to four bytes in the static decoder.
    The public wrapper immediately removes zero to three padding bytes before
    calling EncodingService. A candidate is accepted only when every declared
    length is within that exact padding window and the assignments occur in
    stream order.
    """
    declarations = [
        int(match.group("length").replace("_", ""))
        for match in _TRIM_ASSIGN.finditer(source)
    ]
    if not declarations:
        return None

    matched: List[int] = []
    cursor = 0
    for stream in coded:
        lower = max(0, len(stream) - 3)
        found = None
        while cursor < len(declarations):
            candidate = declarations[cursor]
            cursor += 1
            if lower <= candidate <= len(stream):
                found = candidate
                break
        if found is None:
            return None
        matched.append(found)
    return matched


def _looks_like_vm_source(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(byte in (9, 10, 13) or 32 <= byte < 127 for byte in data)
    if printable / len(data) < 0.80:
        return False
    text = data.decode("utf-8", errors="ignore")
    return "function" in text and ("return" in text or "while" in text)


def _unpack_zstd_streams(source: str, payloads: Sequence[str]) -> Optional[Tuple[bytes, bytes]]:
    """Try the public EncodingService container before the legacy range coder."""
    if "DecompressBuffer" not in source or not payloads:
        return None
    coded = [_base.decode_base85(payload, drop=5) for payload in payloads[:2]]
    trims = _declared_trim_lengths(source, coded)
    if trims is not None:
        coded = [stream[:length] for stream, length in zip(coded, trims)]

    # A false positive must not feed arbitrary data to the Zstandard backend.
    if not all(stream.startswith(_ZSTD_MAGIC) for stream in coded):
        return None

    decoded = [decompress_zstd(stream) for stream in coded]
    if len(decoded) == 1:
        vm_source = externalize_single_stream_vm(source)
        return vm_source.encode("utf-8", errors="surrogateescape"), decoded[0]

    first, second = decoded[0], decoded[1]
    if _looks_like_vm_source(first):
        return first, second
    if _looks_like_vm_source(second):
        return second, first
    raise ValueError(
        "two-stream Zstandard container did not contain recognizable VM source"
    )


def externalize_single_stream_vm(source):
    """Replace Roblox decompression with the bytecode buffer passed as ``...``.

    The capture runner already invokes every recovered VM chunk with the
    external virtual bytecode buffer. A lexical binding keeps that capability
    local to the wrapper and avoids adding a writable global to the sandbox.
    ``Enum`` is stubbed only because the wrapper stores it before the replaced
    decompression site; no Roblox service is exposed.
    """
    patched, count = _DECOMPRESS_CALL.subn("__LUAUVMP_BYTECODE", source, count=1)
    if count != 1:
        raise ValueError(
            "expected one EncodingService DecompressBuffer call, found %d" % count
        )
    prefix = (
        "local __LUAUVMP_BYTECODE = ...;"
        "local Enum = {CompressionAlgorithm = {}};"
    )
    return prefix + patched


def unpack(source):
    """Return ``(interpreter_source, virtual_bytecode)`` without payload execution."""
    payloads = _luraph_payloads(source)

    zstd_streams = _unpack_zstd_streams(source, payloads)
    if zstd_streams is not None:
        return zstd_streams

    if len(payloads) < 2:
        raise ValueError(
            "expected one Zstd or two legacy Luraph streams, found %d"
            % len(payloads)
        )
    streams = []
    for payload in payloads[:2]:
        coded = _base.decode_base85(payload, drop=5)
        try:
            streams.append(_base.decompress(coded))
        except (IndexError, ValueError):
            streams.append(False)
    vm, bytecode = streams
    if vm is False or bytecode is False:
        raise ValueError("Luraph stream decompression aborted (corrupt loader?)")
    return vm, bytecode


# Upgrade existing callers after this facade is imported.
_base.extract_payloads = extract_payloads
_base.detect = detect
_base.unpack = unpack

decode_base85 = _base.decode_base85
decompress = _base.decompress
