from luauvmp import luraph_decompiler, luraph_lift
from luauvmp import luraph_decompiler_balance as balance


def _flat_dispatch(count):
    lines = ['PROTO[0] = function()', '    while true do']
    for index in range(1, count + 1):
        lines.append(
            '        %s pc == %d then' %
            ('if' if index == 1 else 'elseif', index)
        )
        lines.append('            pc = %d' % (index + 1))
    lines.extend([
        '        else',
        '            error("invalid pc")',
        '        end',
        '    end',
        'end',
        '',
    ])
    return '\n'.join(lines)


def test_decompiler_uses_final_composed_lifter():
    assert luraph_decompiler.clean_statement is luraph_lift.clean_statement
    assert luraph_decompiler.decode_branch is luraph_lift.decode_branch
    assert luraph_decompiler.return_expression is luraph_lift.return_expression


def test_small_dispatch_is_left_byte_for_byte_unchanged():
    source = _flat_dispatch(8)
    assert balance.balance_pc_dispatches(source, 8) == source


def test_large_dispatch_is_split_into_bounded_inner_chains():
    source = _flat_dispatch(130)
    result = balance.balance_pc_dispatches(source, 64)
    assert result != source
    assert result.count('        if pc <= ') == 1
    assert result.count('        elseif pc <= ') == 2
    assert '        if pc <= 64 then' in result
    assert '        elseif pc <= 128 then' in result
    assert '        elseif pc <= 130 then' in result
    assert result.count('            if pc == ') == 3
    assert result.count('            elseif pc == ') == 127
    assert '            if pc == 1 then' in result
    assert '            elseif pc == 64 then' in result
    assert '            if pc == 65 then' in result
    assert '            if pc == 129 then' in result
    assert result.count('error("invalid pc")') == 4


def test_non_monotonic_pc_chain_is_not_rewritten():
    source = _flat_dispatch(3).replace('elseif pc == 2', 'elseif pc == 9')
    assert balance.balance_pc_dispatches(source, 2) == source


def test_chunk_size_must_be_bounded_positive_shape():
    try:
        balance.balance_pc_dispatches(_flat_dispatch(3), 1)
    except ValueError as exc:
        assert 'at least 2' in str(exc)
    else:
        raise AssertionError('expected ValueError')
