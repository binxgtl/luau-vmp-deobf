"""Static facade for the two Luraph v14.x container layouts.

Older builds carry separate range/LZ-compressed interpreter and bytecode
streams. Public v14.7 corpus builds instead keep the interpreter in the Luau
wrapper and carry one Ascii85 + Zstandard bytecode stream.
"""
from __future__ import annotations

import io
import os
import re

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
    # Luraph silently ignores a partial trailing Ascii85 group.
    return len(body) + body.count("z") * 4 >= 5


def _raw_lph_payloads(source):
    return [payload for payload in extract_payloads(source) if payload.startswith("LPH")]


def _luraph_payloads(source):
    return [payload for payload in _raw_lph_payloads(source)
            if _looks_like_luraph_stream(payload)]


def _is_single_stream_zstd(source, payloads=None):
    streams = _luraph_payloads(source) if payloads is None else payloads
    return (
        len(streams) == 1
        and "DecompressBuffer" in source
        and "CompressionAlgorithm" in source
    )


def detect(source):
    """Detect either the legacy two-stream or public single-stream layout."""
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


def externalize_single_stream_vm(source):
    """Replace Roblox EncodingService decompression with a supplied buffer.

    The replacement does not run the wrapper. It only makes the recovered VM
    compilable in the lexical Lune sandbox, where ``__LUAUVMP_BYTECODE`` is a
    buffer populated from the statically decompressed stream.
    """
    patched, count = _DECOMPRESS_CALL.subn("__LUAUVMP_BYTECODE", source, count=1)
    if count != 1:
        raise ValueError(
            "expected one EncodingService DecompressBuffer call, found %d" % count
        )
    return patched


def unpack(source):
    """Return ``(interpreter_source, virtual_bytecode)`` without payload execution."""
    payloads = _luraph_payloads(source)
    if _is_single_stream_zstd(source, payloads):
        coded = _base.decode_base85(payloads[0], drop=5)
        bytecode = decompress_zstd(coded)
        vm_source = externalize_single_stream_vm(source)
        return vm_source.encode("utf-8", errors="surrogateescape"), bytecode

    if len(payloads) < 2:
        raise ValueError("expected one Zstd or two legacy Luraph streams, found %d"
                         % len(payloads))
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
