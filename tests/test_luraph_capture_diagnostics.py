from luauvmp.luraph_capture import build_lune_runner


def test_safe_capture_preserves_recovered_vm_line_tables():
    runner = build_lune_runner('vm.luau', 'bc.bin', 'full.tsv', 'facts.tsv')
    assert 'debugLevel = 1' in runner
    assert 'debugLevel = 0' not in runner
    assert 'codegenEnabled = false' in runner
    assert 'injectGlobals = false' in runner
