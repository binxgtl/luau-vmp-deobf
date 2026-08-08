from luauvmp import luraph_dispatch_known_opcode as known


def test_rewrites_only_proven_raw_opcode_array_at_current_pc():
    source = '''
-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_CANONICAL_VARS={"G":"u","R":"X","x":"L","b":"A"}
local text = "x[G]";
-- x[G]
local opcode = x[G];
local other = x[Q];
'''
    rewritten = known.rewrite_current_opcode_reads(source)
    assert 'local text = "x[G]"' in rewritten
    assert '-- x[G]' in rewritten
    assert 'local opcode = R;' in rewritten
    assert 'local other = x[Q];' in rewritten


def test_rewrite_fails_closed_without_unique_role_mapping():
    source = '''
-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_CANONICAL_VARS={"G":"u","R":"X","x":"L","y":"L"}
local opcode = x[G];
'''
    assert known.rewrite_current_opcode_reads(source) == source
