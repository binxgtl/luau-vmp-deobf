from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from luauvmp import luraph_auto
from luauvmp import luraph_pipeline_v3 as pipeline
from luauvmp.luraph_capture import CaptureArtifacts
from luauvmp.luraph_finalize import FinalizeArtifacts


def _rows(strings):
    out = [
        'META\tprotos\t1',
        'P\t0\t-1\t-1\t-1\t%d\tN\tT{}\tD0\tD2' % len(strings),
    ]
    for pc, value in enumerate(strings, 1):
        out.append(
            'I\t0\t%d\tS%s\tD1\tD0\tN\tN\tN\tN'
            % (pc, value.encode().hex())
        )
    return '\n'.join(out) + '\n'


def test_public_pipeline_finalises_bootstrap_and_extracts_exact_source(
    tmp_path, monkeypatch,
):
    protected = tmp_path / 'protected.lua'
    protected.write_text('synthetic loader')
    output = tmp_path / 'out'

    monkeypatch.setattr(pipeline.luraph, 'detect', lambda _source: True)
    monkeypatch.setattr(
        pipeline.luraph,
        'unpack',
        lambda _source: (b'local D=...;return function() end', b'bytecode'),
    )

    bootstrap_strings = [
        'Luraph', 'loadstring', 'debug', 'getinfo', 'getfenv', 'setfenv',
        'coroutine', 'traceback', 'error in error handling',
    ]

    def fake_capture(
        vm_path, bytecode_path, work_dir,
        runtime='lune', timeout=300, progress=None,
    ):
        work = Path(work_dir)
        ir = work / 'full_ir.tsv'
        ir.write_text(_rows(bootstrap_strings))
        facts = work / 'runtime_A.tsv'
        facts.write_text('1\tfunction\tfunction\ttrue\t1\n')
        factory = work / 'interpreter.factory.luau'
        factory.write_text('(function(W,P)return W end)')
        patched = work / 'interpreter.capture.luau'
        patched.write_text('patched')
        runner = work / 'capture_runner.luau'
        runner.write_text('runner')
        return CaptureArtifacts(ir, facts, factory, patched, runner)

    source = (
        'local function payload()\n'
        + '    return game:GetService("Players")\n' * 40
        + 'end\n'
    )

    def fake_finalize(vm_path, bytecode_path, work_dir, **kwargs):
        work = Path(work_dir)
        ir = work / 'final_ir.tsv'
        ir.write_text(_rows([source]))
        facts = work / 'final_runtime_A.tsv'
        facts.write_text('1\tfunction\tfunction\ttrue\t1\n')
        patched = work / 'interpreter.finalize.luau'
        patched.write_text('patched-final')
        runner = work / 'finalize_runner.luau'
        runner.write_text('runner-final')
        return FinalizeArtifacts(ir, facts, patched, runner)

    def fake_recover(factory, facts, output_path, text_output=None):
        Path(output_path).write_text(
            json.dumps({'1': {'source': 'c[p[u]]=E[u]'}})
        )
        if text_output:
            Path(text_output).write_text('opcode 1')

    monkeypatch.setattr(pipeline.luraph_capture, 'run_capture', fake_capture)
    monkeypatch.setattr(pipeline.luraph_finalize, 'run_finalize', fake_finalize)
    monkeypatch.setattr(pipeline.luraph_recover, 'recover_dispatch', fake_recover)
    monkeypatch.setattr(
        pipeline.luraph_decompiler, 'compile_check', lambda *args, **kwargs: None,
    )

    result = luraph_auto.run_full_loader(
        protected, output, progress=lambda _message: None,
    )
    assert result['payload_executed'] is False
    assert result['bootstrap_executed'] is True
    assert result['final_payload_executed'] is False
    assert result['capture_kind'] == 'finalised-staged'
    assert result['embedded_sources']['source_chunks'] == 1
    assert (output / 'embedded_main.luau').read_text() == source
    assert (output / 'artifacts' / 'bootstrap_ir.tsv').is_file()
    assert (output / 'artifacts' / 'final_ir.tsv').is_file()


def test_strict_environment_opt_out_skips_staged_finaliser(tmp_path, monkeypatch):
    monkeypatch.setenv('LUAUVMP_STRICT_CAPTURE', '1')
    assert pipeline._env_bool('LUAUVMP_STRICT_CAPTURE', False) is True
