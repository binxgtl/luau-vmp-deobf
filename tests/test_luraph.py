"""Unit tests for the Luraph v14.x unpacker (sample-free)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest  # noqa: E402

from luauvmp import luraph  # noqa: E402


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


def test_detect_luraph_loader():
    src = _loader(_encode_base85(b'vm-source-here'), _encode_base85(b'\x01\x02\x03\x04'))
    assert luraph.detect(src) is True


def test_detect_rewritten_public_v147_loader_without_decimal_constants():
    vm = _encode_base85(b'vm-source-here')
    bytecode = _encode_base85(b'\x01\x02\x03\x04')
    # Public corpus samples rewrite every surrounding helper and commonly use
    # different long-bracket delimiters. Only the two stream envelopes survive.
    src = '-- protected using Luraph v14.7\nreturn({O=[=[%s]=],B=[==[%s]==]})' % (
        vm, bytecode,
    )
    assert '52200625' not in src
    assert '614125' not in src
    assert luraph.detect(src) is True


def test_detect_rejects_plain_lua():
    assert luraph.detect("print('hello world')") is False
    assert luraph.detect("local x = 52200625 + 1") is False


def test_detect_rejects_arbitrary_lph_long_strings():
    src = 'return [=[LPH$not base85 whitespace]=], [==[LPH$also invalid]==]'
    assert luraph.detect(src) is False


def test_detect_requires_two_payloads():
    src = 'LPH [==[only-one]==] *52200625 *614125'
    assert luraph.detect(src) is False


def test_decode_base85_roundtrip():
    data = bytes(range(256)) * 2
    payload = _encode_base85(data)
    # strip the 4-byte magic, exactly like the loader does
    assert luraph.decode_base85(payload, drop=5) == data


def test_decode_base85_zero_run():
    data = b'\x00' * 16
    payload = _encode_base85(data)
    assert 'z' in payload
    assert luraph.decode_base85(payload, drop=5) == data


def test_extract_payloads_order():
    src = _loader('AAAAA', 'BBBBB')
    assert luraph.extract_payloads(src) == ['AAAAA', 'BBBBB']


def test_unpack_requires_two_streams():
    with pytest.raises(ValueError):
        luraph.unpack('LPH [==[only-one]==]')


def test_unpack_corrupt_stream_raises():
    # valid-looking loader whose range-coder stream is garbage
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
