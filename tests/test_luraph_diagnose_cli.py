from types import SimpleNamespace

from luauvmp import cli


def test_luraph_diagnose_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, 'read_source', lambda _path: 'fixture')
    monkeypatch.setattr(cli.luraph, 'diagnose', lambda _source: {
        'detected': True,
        'layout': 'single-stream-zstd',
        'long_strings': 1,
        'raw_lph_streams': 1,
        'valid_lph_streams': 1,
        'zstd_streams': 1,
        'legacy_signature': False,
        'single_stream_externalizable': True,
    })

    code = cli.cmd_luraph_diagnose(SimpleNamespace(input='sample.lua', json=True))
    output = capsys.readouterr().out
    assert code == 0
    assert '"layout": "single-stream-zstd"' in output
    assert '"single_stream_externalizable": true' in output


def test_luraph_diagnose_returns_nonzero_for_plain_lua(monkeypatch, capsys):
    monkeypatch.setattr(cli, 'read_source', lambda _path: 'print("hello")')
    monkeypatch.setattr(cli.luraph, 'diagnose', lambda _source: {
        'detected': False,
        'layout': 'not-luraph',
        'long_strings': 0,
        'raw_lph_streams': 0,
        'valid_lph_streams': 0,
        'zstd_streams': 0,
        'legacy_signature': False,
        'single_stream_externalizable': None,
    })

    code = cli.cmd_luraph_diagnose(SimpleNamespace(input='plain.lua', json=False))
    output = capsys.readouterr().out
    assert code == 1
    assert 'detected            : no' in output
    assert 'layout              : not-luraph' in output
