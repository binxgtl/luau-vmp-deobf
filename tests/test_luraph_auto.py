from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from luauvmp import luraph_auto
from luauvmp.luraph_capture import CaptureArtifacts


def test_one_command_pipeline_orchestrates_all_stages(tmp_path, monkeypatch):
    protected = tmp_path / 'protected.lua'
    protected.write_text('synthetic loader')
    output = tmp_path / 'out'

    monkeypatch.setattr(luraph_auto.luraph, 'detect', lambda _source: True)
    monkeypatch.setattr(
        luraph_auto.luraph,
        'unpack',
        lambda _source: (b'local D=...;return function() end', b'bytecode'),
    )

    def fake_capture(
        vm_path, bytecode_path, work_dir,
        runtime='lune', timeout=300, progress=None,
    ):
        work = Path(work_dir)
        ir = work / 'full_ir.tsv'
        facts = work / 'runtime_A.tsv'
        factory = work / 'interpreter.factory.luau'
        patched = work / 'interpreter.capture.luau'
        runner = work / 'capture_runner.luau'
        ir.write_text(
            'META\tprotos\t1\n'
            'P\t0\t-1\t-1\t-1\t1\tN\tT{}\tD0\tD2\n'
            'I\t0\t1\tS6869\tD1\tD0\tN\tN\tN\tN\n'
        )
        facts.write_text('1\tnil\tnil\tfalse\t\n')
        factory.write_text('(function(W,P)return W end)')
        patched.write_text('patched')
        runner.write_text('runner')
        if progress is not None:
            progress('[capture] test progress')
        return CaptureArtifacts(ir, facts, factory, patched, runner)

    def fake_recover(factory, facts, output_path, text_output=None):
        Path(output_path).write_text(json.dumps({'1': {'source': 'c[p[u]]=E[u]'}}))
        if text_output:
            Path(text_output).write_text('opcode 1')
        return {'1': {'source': 'c[p[u]]=E[u]'}}

    monkeypatch.setattr(luraph_auto.luraph_capture, 'run_capture', fake_capture)
    monkeypatch.setattr(luraph_auto.luraph_recover, 'recover_dispatch', fake_recover)

    messages = []
    result = luraph_auto.run_full_loader(protected, output, progress=messages.append)
    assert result['payload_executed'] is False
    assert result['prototypes'] == 1
    assert (output / 'program.pseudo.lua').is_file()
    assert (output / 'pipeline.json').is_file()
    assert (output / 'artifacts' / 'full_ir.tsv').is_file()
    assert '"hi"' in (output / 'program.pseudo.lua').read_text()
    assert '[capture] test progress' in messages
