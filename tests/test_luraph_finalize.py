from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from luauvmp.luraph_finalize import (
    build_finalize_runner,
    instrument_final_vm_source,
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


def test_final_instrumentation_keeps_bootstrap_and_blocks_final_payload():
    patched = instrument_final_vm_source(synthetic_vm())
    assert 'P[50](w,P[1])(' in patched
    assert 'return __LUAUVMP_CAPTURE(w,R);end,' in patched
    assert 'return w[50](R,w[1])' not in patched
    assert '__LUAUVMP_STEP(); local X=' in patched


def test_finalize_runner_uses_functional_closed_environment_and_diagnostics():
    patched = instrument_final_vm_source(synthetic_vm())
    runner = build_finalize_runner(
        patched, 'bc.bin', 'final.tsv', 'facts.tsv', 12345,
    )
    assert 'local function __runVM(...)' in runner
    assert 'local __LUAUVMP_CAPTURE = capture' in runner
    assert 'local __stepBudget = 12345' in runner
    assert '__LUAUVMP_STEP(W,u,X);' in runner
    assert '[finalize] bootstrap steps=' in runner
    assert 'last proto=' in runner
    assert '__LUAUVMP_TOP_PROTOS' in runner
    assert 'local __realSetfenv = setfenv' in runner
    assert 'environment.getfenv = __closedGetfenv' in runner
    assert 'local getfenv = __closedGetfenv' in runner
    assert 'local setfenv = __closedSetfenv' in runner
    assert 'function(fn, _env) return fn end' not in runner
    assert 'local require = nil' in runner
    assert 'local game, workspace, script, Instance = nil' in runner
    assert 'luau.compile(vmSource' not in runner
    assert 'writeRuntimeFacts(runtimeState)' in runner


def test_finalize_runner_replaces_exact_hot_xor_helper_only():
    patched = instrument_final_vm_source(synthetic_vm())
    assert 'local __fast=__LUAUVMP_FASTPATH(W)' in patched
    runner = build_finalize_runner(
        patched, 'bc.bin', 'final.tsv', 'facts.tsv', 12345,
    )
    assert 'enabled native bit32.bxor bootstrap fast path' in runner
    assert '#ops == 99' in runner
    assert 'ops[12] == 6' in runner
    assert 'ops[68] == 44' in runner
    assert 'return bit32.bxor(a, b)' in runner
