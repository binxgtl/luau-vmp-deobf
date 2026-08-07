from luauvmp import luraph_lift_dead_prefix as dead


def test_strips_unused_leading_literal_local():
    source = 'local Q=(188); c[H[u]][E[u]]=(o[u]);'
    assert dead.strip_dead_literal_prefix(source) == 'c[H[u]][E[u]]=(o[u]);'


def test_strips_multiple_unused_literal_locals():
    source = 'local Q=(188); local h=(115); c[H[u]]=B;'
    assert dead.strip_dead_literal_prefix(source) == 'c[H[u]]=B;'


def test_keeps_literal_local_when_referenced_later():
    source = 'local Q=(188); if Q~=188 then u=H[u]; end'
    assert dead.strip_dead_literal_prefix(source) == source


def test_never_strips_call_or_table_expression_prefixes():
    for source in (
        'local Q=A[16]; c[p[u]]=H;',
        'local Q=f(); c[p[u]]=H;',
        'local Q={}; c[p[u]]=H;',
        'Q=188; c[p[u]]=H;',
    ):
        assert dead.strip_dead_literal_prefix(source) == source


def test_compact_exposes_branch_after_dead_prefix():
    assert dead.compact('local Q=(188); u=(H[u]);') == 'pc=@H;'
