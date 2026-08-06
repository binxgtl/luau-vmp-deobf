from pathlib import Path
import json

import pytest

from luauvmp import luraph_capture
from luauvmp import luraph_public_v147 as public_capture
from tools import recover_luraph_dispatch as legacy
from tools import recover_luraph_dispatch_v147 as public_dispatch


def _wrapper():
    return '''
local b = {}
local l = {[1] = {}, [52] = {}}
local m = {e = bit32.rshift, l = bit32}
l[52][9] = m.e
l[52][12] = m.l.lshift
(b)[0B1_11011] = function(d, y)
    local x, G = {[1] = 1}, 1
    return function()
        while true do
            local R = x[G]
            if R == 0b1 then
                return y
            else
                G += 1
            end
        end
    end
end
local k = {}
return l[0X003B](k, l[0X1]);
'''


def test_public_factory_extraction_emits_sample_local_metadata():
    factory = public_capture.extract_interpreter_factory(_wrapper())
    assert 'LUAUVMP_PUBLIC_V147=1' in factory
    assert 'LUAUVMP_HELPER_VAR=b' in factory
    assert 'LUAUVMP_DISPATCH_VAR=R' in factory
    marker = next(line for line in factory.splitlines()
                  if line.startswith('-- LUAUVMP_NESTED_HELPERS='))
    nested = json.loads(marker.split('=', 1)[1])
    assert nested['52']['9'] == 'bit32.rshift'
    assert nested['52']['12'] == 'bit32.lshift'
    assert 'function(d, y)' in factory
    assert 'while true do' in factory


def test_public_instrumentation_blocks_only_final_constructor():
    source = _wrapper()
    patched = public_capture.instrument_vm_source(source)
    assert 'return __LUAUVMP_CAPTURE(l,k);' in patched
    assert 'return l[0X003B](k, l[0X1]);' not in patched
    # The slot-59 factory and its dispatcher remain available for capture and
    # semantics recovery; only the application closure construction is blocked.
    assert '(b)[0B1_11011] = function' in patched
    assert 'while true do' in patched


def test_public_instrumentation_fails_closed_on_ambiguous_constructor():
    source = _wrapper() + '\n' + 'return l[59](k,l[1]);'
    with pytest.raises(luraph_capture.CaptureError, match='found 2'):
        public_capture.instrument_vm_source(source)


def _metadata_source():
    return '''-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_HELPER_VAR=b
-- LUAUVMP_DISPATCH_VAR=R
-- LUAUVMP_NESTED_HELPERS={"52":{"9":"bit32.rshift","12":"bit32.lshift"}}
(function(d,y) return function() while true do local R=1; R=R; end end end)
'''


def test_public_lexer_accepts_binary_and_underscored_literals():
    tokens = public_dispatch.lex('R == 0b1_0000 and R < 0X0_20')
    numbers = [token.v for token in tokens if token.kind == 'num']
    assert numbers == ['0b1_0000', '0X0_20']
    assert public_dispatch._number(numbers[0]) == 16
    assert public_dispatch._number(numbers[1]) == 32


def test_public_expression_uses_randomized_opcode_and_nested_helpers():
    metadata = public_dispatch._metadata(_metadata_source())
    values = {
        1: legacy.AVal('table', ('obj', (1,)), (1,), True),
    }
    condition = public_dispatch.lex('R == 0b1_0000')
    assert public_dispatch.eval_cond(condition, 16, values, {}, metadata) is True
    assert public_dispatch.eval_cond(condition, 17, values, {}, metadata) is False

    expression = public_dispatch.lex('b[52][9](0b1000_0000, 1)')
    parser = public_dispatch.ExprParser(
        expression,
        0,
        values,
        {},
        opcode_name='R',
        helper_name='b',
        nested_helpers={52: {9: 'bit32.rshift'}},
    )
    assert parser.parse() == 64
    assert parser.i == len(parser.t)
