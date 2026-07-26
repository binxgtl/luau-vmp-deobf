"""Stage 1 - normalise the protector's loader source.

Three transforms, all driven by patterns rather than hard-coded names, because
every build randomises identifiers and constants:

  * fold_arith()      constant-folds the arithmetic noise (`12958+-12788` -> `170`)
  * decrypt_strings() finds the XOR string helper and inlines every call site
  * resolve_states()  finds the lazy jump-table helpers used by the control-flow
                      flattener and replaces `T[k] or F(a,b,c)` with its value
"""
import re

from .lualex import split_strings, lua_unescape, lua_escape

NUM = r"(?:\d+\.?\d*(?:[eE][+-]?\d+)?)"
LIT = r"""(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")"""


# --------------------------------------------------------------------------- arith
def _fmt(v):
    if isinstance(v, float) and abs(v - round(v)) < 1e-9 and abs(v) < 1e15:
        v = int(round(v))
    return repr(v) if isinstance(v, float) else str(v)


def _fold_code(code):
    prev = None
    while prev != code:
        prev = code

        def ev(expr):
            try:
                return eval(expr, {"__builtins__": {}}, {})
            except Exception:
                return None

        def rp(m):
            v = ev(m.group(1))
            if v is None:
                return m.group(0)
            s = _fmt(v)
            return '(' + s + ')' if s.startswith('-') else s

        code = re.sub(r"\(\s*(-?\s*" + NUM + r"(?:\s*[-+*/]\s*-?\s*" + NUM + r")+)\s*\)", rp, code)

        def rn(m):
            v = ev(m.group(0))
            if v is None:
                return m.group(0)
            s = _fmt(v)
            return '(' + s + ')' if s.startswith('-') else s

        code = re.sub(r"(?<![\w.\)\]])(?:-\s*)?" + NUM +
                      r"(?:\s*[-+*/]\s*-?\s*" + NUM + r")+(?![\w.])", rn, code)
        code = re.sub(r"-\s*\(\s*-(" + NUM + r")\s*\)", r"+\1", code)
        code = re.sub(r"\+\s*\(\s*-(" + NUM + r")\s*\)", r"-\1", code)
        code = re.sub(r"([=,({\[])\s*\(\s*(-" + NUM + r")\s*\)", r"\1\2", code)
    return code


def fold_arith(src):
    """Constant-fold every pure-numeric sub-expression outside string literals."""
    return ''.join(_fold_code(t) if k == 'code' else t for k, t in split_strings(src))


# --------------------------------------------------------------------------- strings
def find_string_helper(src):
    """Identify the `f(cipher, key)` XOR helper by its call-site fingerprint."""
    counts = {}
    for m in re.finditer(r"\b([A-Za-z_]\w*)\(\s*(" + LIT + r")\s*,\s*(" + LIT + r")\s*\)", src):
        counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    cands = [(n, c) for n, c in counts.items() if c >= 3 and re.search(
        r"local\s+" + re.escape(n) + r"\s*=\s*(?:\()?function\(", src)]
    if not cands:
        return None
    cands.sort(key=lambda kv: -kv[1])
    return cands[0][0]


def decrypt_strings(src, helper=None):
    """Replace every `helper('cipher','key')` with the plaintext literal."""
    helper = helper or find_string_helper(src)
    if not helper:
        return src, {'helper': None, 'count': 0}
    pat = re.compile(re.escape(helper) + r"\(\s*(" + LIT + r")\s*,\s*(" + LIT + r")\s*\)")
    stats = {'helper': helper, 'count': 0, 'printable': 0}

    def rep(m):
        a = lua_unescape(m.group(1)[1:-1])
        b = lua_unescape(m.group(2)[1:-1])
        if not b:
            return m.group(0)
        out = bytes(a[i] ^ b[i % len(b)] for i in range(len(a)))
        stats['count'] += 1
        if all(32 <= c < 127 for c in out):
            stats['printable'] += 1
        return lua_escape(out)

    return pat.sub(rep, src), stats


# --------------------------------------------------------------------------- states
_DEF = re.compile(
    r"function\((\w+),(\w+),(\w+)\)\s*(\w+)\[(\w+)\]\s*=\s*"
    r"(\w+)\((\w+),(-?\d+)\)\s*([-+])\s*\6\((\w+),(-?\d+)\)\s*return\s+\4\[\5\]\s*end")


def _u32(v):
    return int(v) % (1 << 32)


def find_state_helpers(src):
    """Locate every `T[k] = bxor(x,C1) -+ bxor(y,C2)` memoised jump-table helper."""
    helpers = []
    for m in _DEF.finditer(src):
        p1, p2, p3, tbl, kp, _fn, a1, c1, op, a2, c2 = m.groups()
        # the helper's own local name sits in the assignment just before it
        head = src[max(0, m.start() - 80):m.start()]
        nm = re.search(r"(\w+)\s*,\s*(\w+)\s*=\s*(?:\{\}\s*,\s*)?$", head)
        if nm:
            fname = nm.group(2) if nm.group(1) == tbl else nm.group(1)
        else:
            nm = re.search(r"(\w+)\s*,\s*(\w+)\s*=\s*$", head)
            fname = nm.group(1) if nm else None
        if not fname:
            continue
        helpers.append({
            'table': tbl, 'func': fname, 'params': [p1, p2, p3],
            'keyparam': kp, 'lhs': (a1, int(c1)), 'op': op, 'rhs': (a2, int(c2)),
            'pos': m.start(),
        })
    return helpers


def resolve_states(src, helpers=None):
    """Replace `T[k] or F(a,b,c)` call sites with the constant they evaluate to."""
    helpers = helpers if helpers is not None else find_state_helpers(src)
    total = 0
    for h in helpers:
        pat = re.compile(re.escape(h['table']) + r"\[(-?\d+)\]\s*or\s*" +
                         re.escape(h['func']) + r"\((-?\d+),(-?\d+),(-?\d+)\)")

        def rep(m, h=h):
            nonlocal total
            env = dict(zip(h['params'], (int(m.group(2)), int(m.group(3)), int(m.group(4)))))
            if h['keyparam'] in env and env[h['keyparam']] != int(m.group(1)):
                return m.group(0)
            a = _u32(env[h['lhs'][0]]) ^ _u32(h['lhs'][1])
            b = _u32(env[h['rhs'][0]]) ^ _u32(h['rhs'][1])
            total += 1
            return str(a - b if h['op'] == '-' else a + b)

        src = pat.sub(rep, src)
    return src, {'helpers': len(helpers), 'resolved': total}


# --------------------------------------------------------------------------- if-exprs
_IFEXPR = re.compile(r"=\s*if\s+(?P<c>[^;]+?)\s+then\s+(?P<a>[^;]+?)\s+else\s+(?P<b>[^;]+?)(?=;|\s+end\b|$)")


def neutralise_if_expressions(src):
    """Luau `x = if c then a else b` breaks block parsing - rewrite to a call form."""
    out, n = [], 0
    for kind, text in split_strings(src):
        if kind == 'str':
            out.append(text)
            continue
        while True:
            m = _IFEXPR.search(text)
            if not m:
                break
            n += 1
            text = text[:m.start()] + '=IFEXP(%s,%s,%s)' % (
                m.group('c'), m.group('a'), m.group('b')) + text[m.end():]
        out.append(text)
    return ''.join(out), n


# --------------------------------------------------------------------------- payload
def find_payload(src, minlen=200):
    """Return the longest base64 string literal - the packed bytecode blob."""
    best = None
    for m in re.finditer(r"'([A-Za-z0-9+/=]{%d,})'" % minlen, src):
        if best is None or len(m.group(1)) > len(best):
            best = m.group(1)
    for m in re.finditer(r'"([A-Za-z0-9+/=]{%d,})"' % minlen, src):
        if best is None or len(m.group(1)) > len(best):
            best = m.group(1)
    return best


def normalise(src):
    """Run the whole stage-1 pipeline. Returns (source, report)."""
    report = {}
    src = fold_arith(src)
    src, st = decrypt_strings(src)
    report['strings'] = st
    src, n = neutralise_if_expressions(src)
    report['if_expressions'] = n
    helpers = find_state_helpers(src)
    src, st = resolve_states(src, helpers)
    report['states'] = st
    report['state_helpers'] = helpers
    return src, report
