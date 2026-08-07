from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from luauvmp import luraph_capture
from luauvmp import luraph_loader as luraph
from luauvmp.luraph_capture import (
    build_lune_runner,
    extract_interpreter_factory,
    instrument_vm_source,
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
    assert luraph_capture.instrument_vm_source is instrument_vm_source
    with pytest.raises(luraph_capture.CaptureError):
        instrument_vm_source('return function() end')


def test_payload_execution_is_intercepted_before_root_runs():
    patched = instrument_vm_source(synthetic_vm())
    assert 'w=__LUAUVMP_CAPTURE(P,w);' in patched
    assert 'P[50](w,P[1])(' not in patched
    assert 'return R;end,' in patched
    assert 'return w[50](R,w[1])' not in patched


def test_lune_runner_has_closed_capture_boundary():
    runner = build_lune_runner('vm.luau', 'bc.bin', 'full.tsv', 'facts.tsv')
    assert 'pcall(chunk, buffer.fromstring(bytecode))' in runner
    assert '__LUAUVMP_CAPTURE = capture' in runner
    assert 'captured Luraph payload closure is intentionally disabled' in runner
    assert 'injectGlobals = false' in runner
    assert '@lune/net' not in runner
    assert 'require = require' not in runner
    assert 'process = process' not in runner
    assert 'game = game' not in runner


def test_lune_runner_allowlists_only_pure_datatypes():
    runner = build_lune_runner('vm.luau', 'bc.bin', 'full.tsv', 'facts.tsv')
    assert 'local robloxDatatypes = require("@lune/roblox")' in runner
    for name in ('CFrame', 'Enum', 'Ray', 'UDim', 'UDim2', 'Vector2', 'Vector3'):
        assert f'{name} = robloxDatatypes.{name}' in runner
    assert 'Path2DControlPoint = Path2DControlPointCompat' in runner
    assert '__luauvmp_datatype = "Path2DControlPoint"' in runner
    assert 'kind = typeof(value)' in runner
    assert 'text = tostring(value)' in runner
    assert 'robloxDatatypes = robloxDatatypes' not in runner
    assert 'Instance = robloxDatatypes.Instance' not in runner
    assert 'getAuthCookie' not in runner


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


def test_missing_global_telemetry_never_yields_from_metamethod():
    runner = build_lune_runner('vm.luau', 'bc.bin', 'full.tsv', 'facts.tsv')
    assert 'local missingSafeGlobals = {}' in runner
    assert 'local name = tostring(key)' in runner
    assert 'missingSafeGlobals[name] = true' in runner
    assert 'status("missing safe-capture global: "' not in runner
    assert 'status("missing safe-capture globals: "' in runner
    assert 'local parserOk, parserResult = pcall(chunk, buffer.fromstring(bytecode))' in runner
    assert 'if not parserOk then' in runner


def test_lune_runner_uses_optimized_compile_and_reports_progress():
    runner = build_lune_runner('vm.luau', 'bc.bin', 'full.tsv', 'facts.tsv')
    assert 'luau.compile(vmSource' in runner
    assert 'optimizationLevel = 2' in runner
    assert 'status("running bytecode parser")' in runner
    assert 'status("capture callback entered")' in runner
    assert 'status("writing typed IR")' in runner


def test_lune_runner_emits_real_tsv_escape_sequences():
    runner = build_lune_runner('vm.luau', 'bc.bin', 'full.tsv', 'facts.tsv')
    assert r'}, "\t")' in runner
    assert r'}, "\\t")' not in runner
    assert r'table.concat(lines, "\n")' in runner
    assert r'table.concat(lines, "\\n")' not in runner
    assert r'"META\tprotos\t"' in runner
    assert r'"META\\tprotos\\t"' not in runner
    assert r'"[\r\n]"' in runner
    assert r'"[\\r\\n]"' not in runner
