"""Sample-free unit tests: run with `python -m pytest` or `python tests/test_units.py`."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from luauvmp import prelude, container            # noqa: E402
from luauvmp.lualex import lua_unescape, lua_escape, tokenize  # noqa: E402
from luauvmp.deflatten import assignments, loop_offsets, deflatten, Linear  # noqa: E402
from luauvmp.analyse import parse_lines, dispatch_ranges  # noqa: E402


def test_fold_arith():
    assert prelude.fold_arith("x=12958+-12788") == "x=170"
    assert prelude.fold_arith("y=(-42+43)") == "y=1"
    # literals must be left alone
    assert prelude.fold_arith("s='1+1'") == "s='1+1'"


def test_escape_roundtrip():
    raw = bytes(range(256))
    assert lua_unescape(lua_escape(raw)[1:-1]) == raw


def test_string_helper_detection():
    src = ("local Da=function(a,b) return a end "
           + " ".join("Da('\\1\\2','\\3')" for _ in range(4)))
    assert prelude.find_string_helper(src) == 'Da'


def test_decrypt_strings():
    # 'A' ^ 'k' = 0x2a ; helper XORs cipher against a repeating key
    src = "local D=function(a,b) return a end D('\\42','k') D('\\42','k') D('\\42','k')"
    out, st = prelude.decrypt_strings(src)
    assert st['count'] == 3
    assert '"A"' in out


def test_resolve_states():
    src = ("Ca,Xb={},function(rb,nb,wc)Ca[wc]=h(rb,35074)-h(nb,46326)return Ca[wc]end;"
           "r_=Ca[-12872]or Xb(120666,466,-12872)")
    out, st = prelude.resolve_states(src)
    assert st['helpers'] == 1 and st['resolved'] == 1
    expected = (120666 ^ 35074) - (466 ^ 46326)
    assert str(expected) in out


def test_if_expression_rewrite():
    out, n = prelude.neutralise_if_expressions("Ka=if A<32768 then A else A-65536;")
    assert n == 1 and out.startswith('Ka=IFEXP(')


def test_lua_sub_semantics():
    s = b'abcdef'
    assert container.lua_sub(s, 2, 4) == b'bcd'
    assert container.lua_sub(s, -2) == b'ef'
    assert container.lua_sub(s, 0, 2) == b'ab'
    assert container.lua_sub(s, 5, 99) == b'ef'
    assert container.lua_sub(s, 4, 2) == b''


def test_lzss_literals():
    # control byte 0xFF -> eight literal bytes
    data = bytes([0xFF]) + b'abcdefgh'
    assert container.lzss_decompress(data) == b'abcdefgh'


def test_lzss_backreference():
    # eight literals, then one back-reference of length 3 at offset 3
    first = bytes([0xFF]) + b'abcdefgh'
    ref = (3 << 5) | (3 - 3)
    second = bytes([0x00, ref >> 8, ref & 0xFF])
    assert container.lzss_decompress(first + second) == b'abcdefgh' + b'efg'


def test_lzss_match_is_truncated_not_repeated():
    """A match running past the window end truncates - Lua string.sub semantics."""
    first = bytes([0xFF]) + b'abcdefgh'
    ref = (3 << 5) | (6 - 3)          # offset 3, length 6, only 4 bytes available
    second = bytes([0x00, ref >> 8, ref & 0xFF])
    assert container.lzss_decompress(first + second) == b'abcdefgh' + b'efgh'


def test_assignments_tuple():
    got = list(assignments('r_,Ub[18049]=44808,ec(I(Dc,24),255)'))
    assert ('Ub[18049]', 'ec(I(Dc,24),255)') in got
    assert ('r_', '44808') in got


def test_parse_lines_nesting():
    nodes = parse_lines(['if a==1 then', '  x=1', 'else', '  if b==2 then', '    y=2',
                         '  end', '  z=3', 'end'])
    assert nodes[0][0] == 'if'
    assert nodes[0][2][0] == ('stmt', '  x=1')
    assert nodes[0][3][0][0] == 'if'


def test_deflatten_and_dispatch():
    src = ("s=1 while s~=9 do if s>=5 then if s>=7 then a=1;s=9 else b=2;s=9 end "
           "else if s>=3 then c=3;s=9 else d=4;s=9 end end end")
    lo = loop_offsets(src)[0]
    lin = Linear(deflatten(src, lo['offset'], lo['state']), lo['state'], lo['entry'])
    assert lin.blocks
    rng = dispatch_ranges(lin, lo['entry'], 's', 0, 8)
    assert rng


def test_tokenizer_luau_ops():
    toks = tokenize("a+=1 continue x..=y")
    vals = [t.val for t in toks]
    assert '+=' in vals and 'continue' in vals and '..=' in vals


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    bad = 0
    for fn in fns:
        try:
            fn()
            print('ok   %s' % fn.__name__)
        except Exception as exc:
            bad += 1
            print('FAIL %s: %s' % (fn.__name__, exc))
    print('%d/%d passed' % (len(fns) - bad, len(fns)))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(_run())
