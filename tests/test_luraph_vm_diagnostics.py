from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from luauvmp.luraph_vm_diagnostics import diagnose_vm_source, main


def _synthetic_vm():
    return (
        'local D=...;return({A=function(s)A[50]=(function(W,P)local '
        'R,p,H,E,B,_,o,L,q=W[10],W[6],W[8],W[2],W[11],W[9],W[7],W[4];'
        'q=(function(...)local u=1;while true do local X=(L[u]);u+=1;end;end);'
        'return q;end);end,zW=function(s,w,x,G,A,W,P)if A==105 then '
        'w=P[50](w,P[1])(s,W,s.r,P[33]);return A,29382,w;end;end,'
        'F=function(s)local w,R={};local W,x;W,x,R=s:zW(R,nil,nil,105,nil,w);'
        'return w[50](R,w[1]);end,}):F();'
    )


def test_diagnose_vm_source_reports_structural_signals_without_source():
    source = _synthetic_vm()
    report = diagnose_vm_source(source)

    assert report['format_version'] == 1
    assert report['privacy'] == 'no-source-snippets'
    assert report['signals']['factory_assignment_count'] >= 1
    assert 50 in report['signals']['factory_slots']
    assert 50 in report['signals']['final_constructor_slots']
    assert 50 in report['signals']['matching_factory_final_slots']
    assert report['signals']['dispatcher_loop_count'] >= 1
    assert report['factory']['extractable'] is True
    assert report['capture']['instrumentable'] is True
    assert report['capture']['capture_callback_delta'] >= 1

    rendered = json.dumps(report)
    assert 'while true do' not in rendered
    assert 'return w[50]' not in rendered
    assert source not in rendered


def test_diagnose_vm_source_describes_unsupported_family_without_guessing():
    report = diagnose_vm_source('return function() end')
    assert report['factory']['extractable'] is False
    assert report['capture']['instrumentable'] is False
    assert report['factory']['error']
    assert report['capture']['error']
    assert report['signals']['matching_factory_final_slots'] == []


def test_vm_diagnose_cli_writes_json_and_returns_success(tmp_path):
    source = tmp_path / 'stage1.vm.lua'
    output = tmp_path / 'diag.json'
    source.write_text(_synthetic_vm(), encoding='utf-8')

    assert main([str(source), '-o', str(output)]) == 0
    report = json.loads(output.read_text(encoding='utf-8'))
    assert report['factory']['extractable'] is True
    assert report['capture']['instrumentable'] is True
