import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

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


def _fixture():
    compressor = zstd.ZstdCompressor(level=1)
    for length in range(1, 4096):
        original = (b'getservice-v14.7-bytecode-' * 256)[:length]
        compressed = compressor.compress(original)
        if len(compressed) % 4:
            break
    else:
        raise AssertionError('could not construct unaligned Zstandard fixture')

    payload = _encode_base85(compressed)
    source = (
        '-- This file was protected using Luraph Obfuscator v14.7\n'
        'return({P=[==[%s]==],f=function(A,k)'
        'return A.R:GetService("E\\110\\99odingService"):'
        'DecompressBuffer(k,A.E.Zstd)end}):f(...)'
    ) % payload
    return source, original


def test_dotted_getservice_receiver_is_externalizable():
    source, original = _fixture()
    report = luraph_loader.diagnose(source)
    assert report['layout'] == 'single-stream-zstd'
    assert report['single_stream_externalizable'] is True

    vm, bytecode = luraph.unpack(source)
    assert bytecode == original
    text = vm.decode('utf-8', errors='surrogateescape')
    assert 'GetService' not in text
    assert 'DecompressBuffer' not in text
    assert '__LUAUVMP_BYTECODE' in text
