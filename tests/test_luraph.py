"""Unit tests for the Luraph v14.x unpacker (sample-free)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest  # noqa: E402
import zstandard as zstd  # noqa: E402

from luauvmp import luraph, luraph_loader  # noqa: E402


def _encode_base85(data):
    """Inverse of luraph.decode_base85: bytes -> payload (with 4-byte magic)."""
    out = []
    for i in range(0, len(data), 4):
        group = data[i:i + 4]
        if len(group) < 4:
            group = group + b'\0' * (4 - len(group))
        if group == b'\0\0\0\0':
            out.append('z')          # zero-run marker (== '!!!!!')
            continue
        value = int.from_bytes(group, 'little')
        chars = []
        for mul in (52200625, 614125, 7225, 85, 1):
            chars.append(chr(value // mul + 33))
            value %= mul
        out.append(''.join(chars))
    return 'LPH\x0e' + ''.join(out)   # 4-byte magic, stripped by the loader


def _loader(vm_payload, bc_payload):
    return ('local Q=("LPH");local R=function(P)'
            'local H=0;H=H+52200625;H=H*614125;return H end'
            '[==[%s]==] [==[%s]==]' % (vm_payload, bc_payload))


def _single_stream_fixture():
    compressor = zstd.ZstdCompressor(level=1)
    for length in range(1, 1024):
        original = (b'public-v14.7-bytecode-' * length)[:length]
        compressed = compressor.compress(original)
        if len(compressed) % 4 == 0:
            payload = _encode_base85(compressed)
            source = (
                '-- protected using Luraph v14.7\n'
                'return({P=[=[%s]=],f=function(m,k)'
                'return game:GetService("EncodingService"):DecompressBuffer('
                'k,Enum.CompressionAlgorithm.Zstd)end}):f(...)'
            ) % payload
            return source, original
    raise AssertionError('could not construct aligned Zstandard fixture')


def _unaligned_compressed(prefix, require_padding=True):
    compressor = zstd.ZstdCompressor(level=1)
    for extra in range(1, 4096):
        original = prefix + (b'x' * extra)
        compressed = compressor.compress(original)
        if (len(compressed) % 4 != 0) == require_padding:
            return original, compressed
    raise AssertionError('could not construct requested Zstandard alignment')


def _two_stream_zstd_fixture():
    vm_prefix = (
        b'local D=...;return function() while true do local X=1;'
        b'if X==1 then return D end end end;'
    )
    vm, vm_compressed = _unaligned_compressed(vm_prefix)
    bytecode, bytecode_compressed = _unaligned_compressed(
        b'virtual-bytecode-binary\x00\xff'
    )
    vm_payload = _encode_base85(vm_compressed)
    bytecode_payload = _encode_base85(bytecode_compressed)
    source = (
        '-- protected using Luraph v14.7\n'
        'local C=decode([=[%s]=]);local U=decode([==[%s]==]);'
        'C=string.sub(C,1,%d);U=string.sub(U,1,%d);'
        'local z=Encoding:DecompressBuffer(buffer.fromstring(C),A);'
        'C=Encoding:DecompressBuffer(buffer.fromstring(U),A);'
        'return load(buffer.tostring(z))(buffer.tostring(C));'
    ) % (
        vm_payload, bytecode_payload,
        len(vm_compressed), len(bytecode_compressed),
    )
    return source, vm, bytecode, vm_compressed, bytecode_compressed


def test_detect_luraph_loader():
    src = _loader(_encode_base85(b'vm-source-here'), _encode_base85(b'\x01\x02\x03\x04'))
    assert luraph.detect(src) is True


def test_detect_rewritten_public_v147_loader_without_decimal_constants():
    vm = _encode_base85(b'vm-source-here')
    bytecode = _encode_base85(b'\x01\x02\x03\x04')
    src = '-- protected using Luraph v14.7\nreturn({O=[=[%s]=],B=[==[%s]==]})' % (
        vm, bytecode,
    )
    assert '52200625' not in src
    assert '614125' not in src
    assert luraph.detect(src) is True


def test_detect_and_unpack_public_single_stream_zstd():
    source, original = _single_stream_fixture()
    assert luraph.detect(source) is True
    vm, bytecode = luraph.unpack(source)
    text = vm.decode()
    assert bytecode == original
    assert text.startswith('local __LUAUVMP_BYTECODE = ...;')
    assert 'local Enum = {CompressionAlgorithm = {}};' in text
    assert 'game:GetService' not in text
    assert '__LUAUVMP_BYTECODE' in text


def test_unpack_public_two_stream_zstd_removes_ascii85_padding():
    source, expected_vm, expected_bytecode, compressed_vm, compressed_bytecode = (
        _two_stream_zstd_fixture()
    )
    coded = [
        luraph.decode_base85(payload, drop=5)
        for payload in luraph_loader._luraph_payloads(source)
    ]
    assert len(coded[0]) - len(compressed_vm) in (1, 2, 3)
    assert len(coded[1]) - len(compressed_bytecode) in (1, 2, 3)
    assert coded[0].startswith(b'\x28\xb5\x2f\xfd')
    assert coded[1].startswith(b'\x28\xb5\x2f\xfd')

    vm, bytecode = luraph.unpack(source)
    assert vm == expected_vm
    assert bytecode == expected_bytecode


def test_declared_zstd_lengths_must_match_padding_window():
    source, _vm, _bytecode, _compressed_vm, _compressed_bytecode = (
        _two_stream_zstd_fixture()
    )
    coded = [
        luraph.decode_base85(payload, drop=5)
        for payload in luraph_loader._luraph_payloads(source)
    ]
    assert luraph_loader._declared_trim_lengths(source, coded) == [
        len(_compressed_vm), len(_compressed_bytecode)
    ]
    bad = source.replace(
        'string.sub(C,1,%d)' % len(_compressed_vm),
        'string.sub(C,1,1)',
        1,
    )
    assert luraph_loader._declared_trim_lengths(bad, coded) is None


def test_zstd_output_limit_is_enforced():
    compressed = zstd.ZstdCompressor().compress(b'x' * 1024)
    with pytest.raises(ValueError, match='safety limit'):
        luraph_loader.decompress_zstd(compressed, max_output_size=10)


def test_detect_rejects_plain_lua():
    assert luraph.detect("print('hello world')") is False
    assert luraph.detect("local x = 52200625 + 1") is False


def test_detect_rejects_arbitrary_lph_long_strings():
    src = 'return [=[LPH$not base85 whitespace]=], [==[LPH$also invalid]==]'
    assert luraph.detect(src) is False


def test_detect_requires_two_payloads_without_zstd_wrapper():
    src = 'LPH [==[only-one]==] *52200625 *614125'
    assert luraph.detect(src) is False


def test_decode_base85_roundtrip():
    data = bytes(range(256)) * 2
    payload = _encode_base85(data)
    assert luraph.decode_base85(payload, drop=5) == data


def test_decode_base85_zero_run():
    data = b'\x00' * 16
    payload = _encode_base85(data)
    assert 'z' in payload
    assert luraph.decode_base85(payload, drop=5) == data


def test_extract_payloads_order():
    src = _loader('AAAAA', 'BBBBB')
    assert luraph.extract_payloads(src) == ['AAAAA', 'BBBBB']


def test_unpack_requires_supported_stream_layout():
    with pytest.raises(ValueError):
        luraph.unpack('LPH [==[only-one]==]')


def test_unpack_corrupt_stream_raises():
    src = _loader('LPH\x0e!!!!!', 'LPH\x0e!!!!!')
    with pytest.raises(ValueError):
        luraph.unpack(src)


def test_cli_deobf_rejects_luraph(monkeypatch):
    from luauvmp import cli
    src = _loader(_encode_base85(b'vm'), _encode_base85(b'bc'))
    monkeypatch.setattr(cli, 'read_source', lambda p: src)
    with pytest.raises(SystemExit) as exc:
        cli.cmd_deobf(type('A', (), {'input': 'x.lua', 'output': None})())
    assert 'Luraph' in str(exc.value)


def test_cli_luraph_creates_output_parent(tmp_path, monkeypatch):
    from luauvmp import cli

    monkeypatch.setattr(cli, 'read_source', lambda _path: 'luraph fixture')
    monkeypatch.setattr(cli.luraph, 'detect', lambda _source: True)
    monkeypatch.setattr(cli.luraph, 'unpack', lambda _source: (b'vm', b'bytecode'))
    output = tmp_path / 'nested' / 'stage1'

    cli.cmd_luraph(type('A', (), {'input': 'sample.lua', 'output': str(output)})())

    assert output.with_suffix('.vm.lua').read_bytes() == b'vm'
    assert output.with_suffix('.bytecode.bin').read_bytes() == b'bytecode'
