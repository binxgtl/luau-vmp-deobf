import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
import zstandard as zstd

from luauvmp import luraph, luraph_loader


def _encode_base85(data):
    out = []
    for offset in range(0, len(data), 4):
        group = data[offset:offset + 4]
        if len(group) < 4:
            group = group + b'\0' * (4 - len(group))
        if group == b'\0\0\0\0':
            out.append('z')
            continue
        value = int.from_bytes(group, 'little')
        chars = []
        for mul in (52200625, 614125, 7225, 85, 1):
            chars.append(chr(value // mul + 33))
            value %= mul
        out.append(''.join(chars))
    return 'LPH\x0e' + ''.join(out)


def test_single_stream_zstd_ignores_only_ascii85_frame_padding():
    compressor = zstd.ZstdCompressor(level=1)
    for length in range(1, 4096):
        original = (b'zephyrion-v14.7-bytecode-' * 256)[:length]
        compressed = compressor.compress(original)
        if len(compressed) % 4:
            break
    else:
        raise AssertionError('could not construct unaligned Zstandard fixture')

    payload = _encode_base85(compressed)
    source = (
        '-- This file was protected using Luraph Obfuscator v14.7\n'
        'return({P=[==[%s]==],f=function(k)'
        'return Encoding:DecompressBuffer(k,Enum.CompressionAlgorithm.Zstd)end}):f(...)'
    ) % payload

    coded = luraph.decode_base85(payload, drop=5)
    padding = len(coded) - len(compressed)
    assert padding in (1, 2, 3)
    assert coded[len(compressed):] == b'\0' * padding

    vm, bytecode = luraph.unpack(source)
    assert bytecode == original
    assert vm.startswith(b'local __LUAUVMP_BYTECODE = ...;')


def test_zstd_padding_rejects_nonzero_trailing_data():
    compressed = zstd.ZstdCompressor(level=1).compress(b'payload')
    with pytest.raises(ValueError, match='trailing data'):
        luraph_loader._trim_zstd_ascii85_padding(compressed + b'X')
