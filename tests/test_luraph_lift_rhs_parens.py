from luauvmp import luraph_lift_rhs_parens as parens


def test_strips_only_parentheses_wrapping_entire_assignment_rhs():
    assert parens.strip_assignment_rhs_parens('R[@p]=(R[@B][@_]);') == 'R[@p]=R[@B][@_];'
    assert parens.strip_assignment_rhs_parens('R[@p]=((R[@B]+@_));') == 'R[@p]=R[@B]+@_;'


def test_keeps_parentheses_that_are_not_the_entire_rhs():
    assert parens.strip_assignment_rhs_parens('R[@p]=(R[@B])+@_;') == 'R[@p]=(R[@B])+@_;'
    assert parens.strip_assignment_rhs_parens('R[@p]=f((R[@B]));') == 'R[@p]=f((R[@B]));'


def test_refuses_compound_statements_and_conditions():
    for source in (
        'x=1;R[@p]=(R[@B]);',
        'if x then R[@p]=(R[@B]);end',
        'R[@p]=(R[@B]);R[@E]=1',
    ):
        assert parens.strip_assignment_rhs_parens(source) == source


def test_ignores_comparison_operators():
    assert parens.strip_assignment_rhs_parens('R[@p]==(R[@B])') == 'R[@p]==(R[@B])'
    assert parens.strip_assignment_rhs_parens('R[@p]~=(R[@B])') == 'R[@p]~=(R[@B])'


def test_compact_exposes_nested_read_and_binary_operation():
    assert parens.compact('(c)[p[u]]=(c[B[u]][_[u]]);') == 'R[@p]=R[@B][@_];'
    assert parens.compact('c[p[u]]=(c[B[u]]+_[u]);') == 'R[@p]=R[@B]+@_;'
