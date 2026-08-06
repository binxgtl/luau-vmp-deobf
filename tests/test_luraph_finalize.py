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


def test_finalize_runner_uses_fast_closed_production_environment():
    patched = instrument_final_vm_source(synthetic_vm())
    runner = build_finalize_runner(
        patched, 'bc.bin', 'final.tsv', 'facts.tsv', 12345,
    )
    assert 'local function __runVM(...)' in runner
    assert 'local __LUAUVMP_CAPTURE = capture' in runner
    assert 'local __stepBudget = 12345' in runner
    assert '__LUAUVMP_STEP(W,u,X);' in runner
    assert 'local function __LUAUVMP_STEP(_proto, _pc, _opcode)' in runner
    assert '__LUAUVMP_TOP_PROTOS' not in runner
    assert '[finalize] bootstrap steps=' not in runner
    assert 'local __realSetfenv = setfenv' in runner
    assert 'environment.getfenv = __closedGetfenv' in runner
    assert 'local getfenv = __closedGetfenv' in runner
    assert 'local setfenv = __closedSetfenv' in runner
    assert 'function(fn, _env) return fn end' not in runner
    assert 'local require = nil' in runner
    assert 'local game, workspace, script, Instance = nil' in runner
    assert 'luau.compile(vmSource' not in runner
    assert 'writeRuntimeFacts(runtimeState)' in runner


def test_finalize_runner_enables_full_diagnostics_only_on_request(monkeypatch):
    monkeypatch.setenv('LUAUVMP_FINALIZE_DIAGNOSTICS', '1')
    patched = instrument_final_vm_source(synthetic_vm())
    runner = build_finalize_runner(
        patched, 'bc.bin', 'final.tsv', 'facts.tsv', 12345,
    )
    assert '[finalize] bootstrap steps=' in runner
    assert 'last proto=' in runner
    assert '__LUAUVMP_TOP_PROTOS' in runner
    assert '__protoTransitions' in runner


def test_finalize_runner_replaces_only_exact_hot_helper_shapes():
    patched = instrument_final_vm_source(synthetic_vm())
    assert 'local __fast=__LUAUVMP_FASTPATH(W,P)' in patched
    assert 'local __lateFast' in patched
    assert 'if not __lateFast then __lateFast=__LUAUVMP_FASTPATH(W,P) end' in patched
    assert 'if __lateFast then return __lateFast(...) end' in patched
    runner = build_finalize_runner(
        patched, 'bc.bin', 'final.tsv', 'facts.tsv', 12345,
    )
    assert 'enabled native " .. name .. " bootstrap fast path' in runner
    assert '#ops == 99' in runner
    assert 'ops[12] == 6' in runner
    assert 'ops[68] == 44' in runner
    assert 'return bit32.bxor(a, b)' in runner
    assert '#ops == 104' in runner
    assert 'ops[86] == 104' in runner
    assert 'ops[95] == 14' in runner
    assert 'local finalBit = lastBit or firstBit' in runner
    assert 'math.floor(value / (2 ^ (firstBit - 1)))' in runner
    assert '#ops == 33' in runner
    assert 'local byteRange, encoded, xor = cells[0], cells[1], cells[2]' in runner
    assert 'local b1, b2, b3, b4 = byteRange(encoded, 1, 4)' in runner
    assert '#ops == 134' in runner
    assert 'local readWord, extract = cells[0], cells[1]' in runner
    assert 'local mantissa = extract(high, 1, 20) * 4294967296 + low' in runner
    assert 'local exponent = extract(high, 21, 31)' in runner


def test_finalize_runner_keeps_expensive_calltrace_disabled_by_default():
    patched = instrument_final_vm_source(synthetic_vm())
    runner = build_finalize_runner(
        patched, 'bc.bin', 'final.tsv', 'facts.tsv', 12345,
    )
    assert 'diagnostic call trace step ceiling=' not in runner
    assert '__LUAUVMP_HOT_ENTER' not in runner
    assert '__LUAUVMP_PACK_SUMMARY' not in runner
