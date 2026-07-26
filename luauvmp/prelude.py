"""Stage 1 - normalise the protector's loader source.

Three transforms, all driven by patterns rather than hard-coded names, because
every build randomises identifiers and constants:

  * fold_arith()      constant-folds the arithmetic noise (`12958+-12788` -> `170`)
  * decrypt_strings() finds the XOR string helper and inlines every call site
  * resolve_states()  finds the lazy jump-table helpers used by the control-flow
                      flattener and replaces `T[k] or F(a,b,c)` with its value
"""
import re

from .lualex import split_strings, lua_unescape, lua_escape, tokenize, render, Tok

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
    # the helper may be declared inline (`local f = function`) or pre-declared in a
    # block of locals and assigned later (`f = function`), depending on the build
    cands = [(n, c) for n, c in counts.items() if c >= 3 and re.search(
        r"(?:^|[;\s])(?:local\s+)?" + re.escape(n) + r"\s*=\s*\(?function\(", src)]
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
_EXPR_LEAD = {'=', ',', '(', '{', '[', '..', '+', '-', '*', '/', '%', '^', '#',
              '==', '~=', '<', '>', '<=', '>=', 'and', 'or', 'not', 'return'}
_STMT_KW = {'end', 'else', 'elseif', 'until', 'return', 'if', 'while', 'for',
            'local', 'repeat', 'do', 'then', 'break', 'continue', 'function'}


def _assign_start(toks, i):
    """True if a new assignment statement (`a, b[c].d = ...`) begins at token i."""
    n = i
    while True:
        if n >= len(toks) or toks[n].kind != 'name':
            return False
        n += 1
        while n < len(toks) and toks[n].kind == 'op':
            if toks[n].val == '.':
                n += 2
                continue
            if toks[n].val == '[':
                depth = 0
                while n < len(toks):
                    if toks[n].kind == 'op' and toks[n].val in '([{':
                        depth += 1
                    elif toks[n].kind == 'op' and toks[n].val in ')]}':
                        depth -= 1
                        if depth == 0:
                            n += 1
                            break
                    n += 1
                continue
            break
        if n < len(toks) and toks[n].kind == 'op' and toks[n].val == ',':
            n += 1
            continue
        return n < len(toks) and toks[n].kind == 'op' and toks[n].val == '='


def _expr_end(toks, i):
    """Where the trailing branch of an if-expression stops.

    It runs until the enclosing statement ends: an explicit `;`, a block keyword,
    or the start of the next assignment (a name/index chain followed by `=`).
    """
    depth, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if t.kind == 'op' and t.val in '([{':
            depth += 1
        elif t.kind == 'op' and t.val in ')]}':
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0:
            # an if-expression is a single expression, so a top-level comma ends it
            if t.kind == 'op' and t.val in (';', ','):
                return i
            if t.kind == 'kw' and t.val in _STMT_KW:
                return i
            if t.kind == 'name' and _assign_start(toks, i):
                return i
        i += 1
    return n


def neutralise_if_expressions(src):
    """Luau `x = if c then a else b` has no `end`, so it wrecks block parsing.

    Rewrites it to a call form.  Detection is positional: an `if` whose preceding
    token cannot end a statement is an expression, not a statement.
    """
    toks = tokenize(src)
    n, out, i, total = len(toks), [], 0, 0
    while i < n:
        t = toks[i]
        prev = toks[i - 1] if i else None
        is_expr_if = (t.kind == 'kw' and t.val == 'if' and prev is not None and
                      ((prev.kind == 'op' and prev.val in _EXPR_LEAD) or
                       (prev.kind == 'kw' and prev.val in _EXPR_LEAD)))
        if not is_expr_if:
            out.append(t)
            i += 1
            continue
        parts, j, ok = [], i + 1, True
        while True:
            k = j
            while k < n and not (toks[k].kind == 'kw' and toks[k].val == 'then'):
                k += 1
            if k >= n:
                ok = False
                break
            parts.append(toks[j:k])                      # condition
            j = k + 1
            k = j
            depth = 0
            while k < n:
                u = toks[k]
                if u.kind == 'op' and u.val in '([{':
                    depth += 1
                elif u.kind == 'op' and u.val in ')]}':
                    depth -= 1
                elif depth == 0 and u.kind == 'kw' and u.val in ('else', 'elseif'):
                    break
                k += 1
            if k >= n:
                ok = False
                break
            parts.append(toks[j:k])                      # value when true
            if toks[k].val == 'elseif':
                j = k + 1
                continue
            j = k + 1
            e = _expr_end(toks, j)
            parts.append(toks[j:e])                      # value when false
            j = e
            break
        if not ok:
            out.append(t)
            i += 1
            continue
        total += 1
        out.append(Tok('name', 'IFEXP', t.pos))
        out.append(Tok('op', '(', t.pos))
        for x, part in enumerate(parts):
            if x:
                out.append(Tok('op', ',', t.pos))
            out.append(Tok('op', '(', t.pos))
            out.extend(part)
            out.append(Tok('op', ')', t.pos))
        out.append(Tok('op', ')', t.pos))
        i = j
    return render(out), total


# --------------------------------------------------------------------------- payload
B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def _classify_transform(src, name):
    """Work out what a function wrapping the payload actually does."""
    m = re.search(r"(?:^|[;\s])(?:local\s+)?" + re.escape(name) + r"\s*=\s*\(?function\(", src)
    if not m:
        return None
    body = src[m.end():m.end() + 1200]
    if B64_ALPHABET in body:
        return 'base64'
    if '">I2"' in body or "'>I2'" in body:
        return 'lzss'
    return None


def payload_pipeline(src, blob=None):
    """Which decoders the loader applies to the payload, innermost first.

    One build packs `loader(lzss(base64(blob)))`, another `loader(base64(blob))`.
    Reading the call chain is the only way to know which.
    """
    blob = blob or find_payload(src)
    if not blob:
        return []
    i = src.find(blob[:48])
    if i < 0:
        return []
    head = src[:i].rstrip("'\"")          # drop the literal's opening quote
    chain = []
    while True:
        head = head.rstrip()
        # Lua lets a call on a string literal drop its parentheses (`f'...'`),
        # so the wrapping name may or may not be followed by one.
        m = re.search(r"([A-Za-z_]\w*)\s*(\()?\s*$", head)
        if not m:
            break
        kind = _classify_transform(src, m.group(1))
        if not kind:
            break                          # reached the loader itself
        chain.append(kind)
        head = head[:m.start()].rstrip().rstrip('(')
    return chain          # innermost first


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
