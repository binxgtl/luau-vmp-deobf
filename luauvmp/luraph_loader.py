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
_STRING_LITERAL = r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
_DOTTED_RECEIVER = r"[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*"
_DECOMPRESS_RECEIVER = (
    r"(?:"
    + _DOTTED_RECEIVER
    + r"(?:\s*:\s*GetService\(" + _STRING_LITERAL + r"\))?"
    + r")"
)
_DECOMPRESS_CALL = re.compile(
    _DECOMPRESS_RECEIVER
    + r"\s*:\s*DecompressBuffer\("
    + r"(?:[^()\"']|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|\([^()]*\))*"
    + r"\)",
    re.S,
)
_TRIM_ASSIGN = re.compile(
    r"(?P<name>[A-Za-z_]\w*)\s*=\s*string\s*\.\s*sub\s*\(\s*"
    r"(?P=name)\s*,\s*1\s*,\s*(?P<length>[0-9][0-9_]*)\s*\)",
    re.S,
)
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_DEFAULT_ZSTD_LIMIT = 256 * 1024 * 1024


def _semantic_long_string(payload: str) -> str:
    """Apply Lua/Luau's one special long-string newline rule.

    When a long-bracket literal starts with a newline immediately after the
    opening delimiter, Lua removes that initial newline from the string value.
    Regex extraction sees the source spelling instead, so failing to mirror the
    language rule makes otherwise valid ``LPH`` streams look like ``\nLPH`` and
    causes false negatives during loader detection.
    """
    if payload.startswith("\r\n"):
        return payload[2:]
    if payload.startswith(("\n", "\r")):
        return payload[1:]
    return payload


def extract_payloads(source):
    """Return all Lua long-bracket string values in source order."""
    return [_semantic_long_string(match.group(2)) for match in _LONG_BRACKET.finditer(source)]


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


def _stream_has_zstd_magic(payload: str) -> bool:
    """Confirm a public Zstd stream from its decoded frame header.

    This deliberately avoids depending on randomized/minified wrapper names.
    The Ascii85 decoder can add up to three bytes only at the *end* of a stream,
    so the four-byte frame magic is stable even when an exact trim declaration
    is required later for decompression.
    """
    try:
        coded = _base.decode_base85(payload, drop=5)
    except (IndexError, TypeError, ValueError):
        return False
    return coded.startswith(_ZSTD_MAGIC)


def _is_single_stream_zstd(source, payloads=None):
    streams = _luraph_payloads(source) if payloads is None else payloads
    if len(streams) != 1:
        return False
    # Older detection required the literal Roblox API method name. Keep that
    # fast structural hint, but also recognize the stream itself so harmless
    # aliasing/minification cannot make a valid v14.7 loader fall through to the
    # unrelated luau-vmp analyser.
    return "DecompressBuffer" in source or _stream_has_zstd_magic(streams[0])


def diagnose(source):
    """Return a static, JSON-serialisable loader classification.

    No stream is decompressed and no recovered code is executed. This is meant
    for CLI diagnostics and issue reports where a user needs to distinguish a
    detection failure from an unsupported wrapper shape.
    """
    long_strings = extract_payloads(source)
    raw = [payload for payload in long_strings if payload.startswith("LPH")]
    streams = [payload for payload in raw if _looks_like_luraph_stream(payload)]
    zstd = [_stream_has_zstd_magic(payload) for payload in streams]
    legacy_signature = "52200625" in source and "614125" in source
    single_zstd = len(streams) == 1 and bool(zstd and zstd[0])
    detected = (
        len(streams) >= 2
        or (len(streams) == 1 and ("DecompressBuffer" in source or single_zstd))
        or (legacy_signature and len(raw) >= 2)
    )

    if len(streams) >= 2 and len(zstd) >= 2 and all(zstd[:2]):
        layout = "two-stream-zstd"
    elif len(streams) >= 2:
        layout = "two-stream-legacy"
    elif single_zstd:
        layout = "single-stream-zstd"
    elif raw:
        layout = "unsupported-lph"
    else:
        layout = "not-luraph"

    externalizable = None
    if layout == "single-stream-zstd":
        externalizable = _DECOMPRESS_CALL.search(source) is not None

    return {
        "detected": detected,
        "layout": layout,
        "long_strings": len(long_strings),
        "raw_lph_streams": len(raw),
        "valid_lph_streams": len(streams),
        "zstd_streams": sum(bool(item) for item in zstd),
        "legacy_signature": legacy_signature,
        "single_stream_externalizable": externalizable,
    }


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


def _zstd_frame_length(data: bytes) -> int:
    """Return the exact byte length of one standard Zstandard frame.

    Luraph's Ascii85 encoder emits complete 4-byte groups, so an unaligned
    compressed frame may gain one to three zero bytes after the real frame.
    Parsing only the outer Zstandard frame/block headers lets us identify that
    boundary without decompressing or trusting payload-local constants.
    """
    if len(data) < 5 or not data.startswith(_ZSTD_MAGIC):
        raise ValueError("Zstandard frame magic was not found")

    cursor = 4
    descriptor = data[cursor]
    cursor += 1
    if descriptor & 0x08:
        raise ValueError("Zstandard frame uses reserved descriptor bit")

    content_size_flag = descriptor >> 6
    single_segment = bool(descriptor & 0x20)
    checksum = bool(descriptor & 0x04)
    dictionary_flag = descriptor & 0x03

    if not single_segment:
        if cursor >= len(data):
            raise ValueError("truncated Zstandard window descriptor")
        cursor += 1

    dictionary_size = (0, 1, 2, 4)[dictionary_flag]
    content_size = (1 if single_segment else 0, 2, 4, 8)[content_size_flag]
    header_tail = dictionary_size + content_size
    if cursor + header_tail > len(data):
        raise ValueError("truncated Zstandard frame header")
    cursor += header_tail

    while True:
        if cursor + 3 > len(data):
            raise ValueError("truncated Zstandard block header")
        header = int.from_bytes(data[cursor:cursor + 3], "little")
        cursor += 3
        last_block = bool(header & 1)
        block_type = (header >> 1) & 0x03
        block_size = header >> 3
        if block_type == 3:
            raise ValueError("reserved Zstandard block type")
        stored_size = 1 if block_type == 1 else block_size
        if cursor + stored_size > len(data):
            raise ValueError("truncated Zstandard block content")
        cursor += stored_size
        if last_block:
            break

    if checksum:
        if cursor + 4 > len(data):
            raise ValueError("truncated Zstandard content checksum")
        cursor += 4
    return cursor


def _trim_zstd_ascii85_padding(data: bytes) -> bytes:
    """Strip only zero padding introduced after one complete Zstd frame."""
    frame_length = _zstd_frame_length(data)
    trailing = data[frame_length:]
    if len(trailing) > 3 or trailing != b"\0" * len(trailing):
        raise ValueError(
            "Luraph Zstandard stream has unexpected trailing data after frame"
        )
    return data[:frame_length]


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
    if not payloads:
        return None
    coded = [_base.decode_base85(payload, drop=5) for payload in payloads[:2]]
    trims = _declared_trim_lengths(source, coded)
    if trims is not None:
        coded = [stream[:length] for stream, length in zip(coded, trims)]

    # A false positive must not feed arbitrary data to the Zstandard backend.
    if not all(stream.startswith(_ZSTD_MAGIC) for stream in coded):
        return None
    coded = [_trim_zstd_ascii85_padding(stream) for stream in coded]

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
    """Replace public decompression with the bytecode buffer passed as ``...``.

    The receiver may be a local/dotted alias such as ``Encoding`` or a dotted
    Roblox service owner such as ``A.R:GetService(...)``. The entire call is
    removed before the recovered wrapper runs, so no Roblox service or receiver
    capability is introduced into the sandbox.
    """
    patched, count = _DECOMPRESS_CALL.subn("__LUAUVMP_BYTECODE", source, count=1)
    if count != 1:
        raise ValueError(
            "single-stream Zstd loader detected, but no supported "
            "DecompressBuffer call could be externalized"
        )
    if _DECOMPRESS_CALL.search(patched):
        raise ValueError(
            "single-stream Zstd loader contained multiple supported "
            "DecompressBuffer calls; refusing ambiguous externalization"
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
_base.diagnose = diagnose

decode_base85 = _base.decode_base85
decompress = _base.decompress
