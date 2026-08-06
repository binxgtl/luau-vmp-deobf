from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from luauvmp import luraph_capture
from luauvmp import luraph_loader as luraph
from luauvmp.luraph_capture import (
    build_lune_runner,
    extract_interpreter_factory,
    instrument_vm_source,
)
from luauvmp.luraph_early_capture import (
    instrument_vm_source as early_instrument_vm_source,
)


def synthetic_vm():
    return (
        'local D=...;return({A=function(s)A[50]=(function(W,P)local '
        'R,p,H,E,B,_,o,L,q=W[10],W[6],W[8],W[2],W[11],W[9],W[7],W[4];'
        'q=(function(...)local u=1;while true do local X=(L[u]);u+=1;end;end);'
        'return q;end);end,zW=function(s,w,x,G,A,W,P)if A==105 then '
        'w=P[50](w,P[1])(s,W,s.r,P[33]);return A,29382,w;end;end,'
        'F=function(s)local w,R={};local W,x;W,x,R=s:zW(R,nil,nil,105,nil,w);'
        'return w[50](R,w[1]);end,}):F();'
    )


def test_mixed_long_bracket_payloads_are_detected():
    source = '52200625 614125 local a=[=[LPHfirst]=];local b=[==[LPHsecond]==]'
    assert luraph.detect(source)
    assert luraph.extract_payloads(source) == ['LPHfirst', 'LPHsecond']


def test_factory_extraction_is_structural():
    factory = extract_interpreter_factory(synthetic_vm())
    assert factory.startswith('(function(W,P)')
    assert 'while true do local X=' in factory
    assert factory.endswith('return q;end)')


def test_fail_closed_instrumenter_is_installed_for_public_api():
    assert luraph_capture.instrument_vm_source is early_instrument_vm_source
    assert instrument_vm_source is early_instrument_vm_source


def test_payload_execution_is_intercepted_before_root_runs():
    patched = instrument_vm_source(synthetic_vm())
    assert 'w=__LUAUVMP_CAPTURE(P,w);' in patched
    assert 'P[50](w,P[1])(' not in patched
    assert 'return R;end,' in patched
    assert 'return w[50](R,w[1])' not in patched


def test_lune_runner_has_closed_capture_boundary():
    runner = build_lune_runner('vm.luau', 'bc.bin', 'full.tsv', 'facts.tsv')
    assert 'chunk(buffer.fromstring(bytecode))' in runner
    assert '__LUAUVMP_CAPTURE = capture' in runner
    assert 'captured Luraph payload closure is intentionally disabled' in runner
    assert 'injectGlobals = false' in runner
    assert '@lune/net' not in runner
    assert 'require = require' not in runner
    assert 'process = process' not in runner
    assert '@lune/roblox' not in runner


def test_lune_runner_supplies_bootstrap_compatibility_without_privileges():
    runner = build_lune_runner('vm.luau', 'bc.bin', 'full.tsv', 'facts.tsv')
    assert 'debug = debugCompat' in runner
    assert 'info = debugInfo' in runner
    assert 'environment.loadstring = safeLoadString' in runner
    assert 'pcall(luau.load, source' in runner
    assert 'environment = environment' in runner
    assert 'injectGlobals = false' in runner
    assert 'getupvalue' not in runner
    assert 'setupvalue' not in runner


def test_lune_runner_uses_optimized_compile_and_reports_progress():
    runner = build_lune_runner('vm.luau', 'bc.bin', 'full.tsv', 'facts.tsv')
    assert 'luau.compile(vmSource' in runner
    assert 'optimizationLevel = 2' in runner
    assert 'status("running bytecode parser")' in runner
    assert 'status("capture callback entered")' in runner
    assert 'status("writing typed IR")' in runner
