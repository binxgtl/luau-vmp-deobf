from luauvmp import luraph_dispatch_known_opcode as known


def test_preserves_defining_fetch_and_rewrites_only_later_current_opcode_reads():
    source = '''
-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_CANONICAL_VARS={"G":"u","R":"X","x":"L","b":"A"}
local text = "x[G]";
-- x[G]
while true do
    local R=(x[G]);
    if R==1 then
        local a=x[G];
        local b=(x)[G];
        local other=x[Q];
    end
end
'''
    rewritten = known.rewrite_current_opcode_reads(source)
    assert 'local text = "x[G]"' in rewritten
    assert '-- x[G]' in rewritten
    assert 'local R=(x[G]);' in rewritten
    assert 'local a=R;' in rewritten
    assert 'local b=R;' in rewritten
    assert 'local other=x[Q];' in rewritten


def test_rewrite_fails_closed_without_exactly_one_defining_fetch():
    no_fetch = '''
-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_CANONICAL_VARS={"G":"u","R":"X","x":"L"}
local a=x[G];
'''
    assert known.rewrite_current_opcode_reads(no_fetch) == no_fetch

    duplicate = '''
-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_CANONICAL_VARS={"G":"u","R":"X","x":"L"}
local R=x[G]; local R=(x)[G]; local a=x[G];
'''
    assert known.rewrite_current_opcode_reads(duplicate) == duplicate


def test_rewrite_fails_closed_without_unique_role_mapping():
    source = '''
-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_CANONICAL_VARS={"G":"u","R":"X","x":"L","y":"L"}
local R=x[G]; local a=x[G];
'''
    assert known.rewrite_current_opcode_reads(source) == source
