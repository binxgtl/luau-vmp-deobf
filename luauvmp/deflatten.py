"""Stage 2 - undo the control-flow flattening.

The protector compiles each of its own functions into

    state = <entry>
    while state ~= <exit> do
        if state >= A then ... elseif state < B then ... end   -- binary search
    end

Every leaf assigns the next state.  We parse the binary-search tree, recover the
value range that reaches each leaf, then walk the resulting state graph from the
entry point and emit a labelled, goto-style linearisation that is readable and
machine-analysable.
"""
import re

from .lualex import tokenize, render, Tok

CMP = {'<', '>', '<=', '>=', '==', '~='}


# --------------------------------------------------------------------------- parse
def _skip_construct(toks, i):
    t = toks[i]
    if t.kind == 'kw' and t.val in ('do', 'while', 'for', 'function', 'repeat', 'if'):
        depth, j, n = 0, i, len(toks)
        while j < n:
            u = toks[j]
            if u.kind == 'kw':
                if u.val in ('do', 'then', 'function', 'repeat'):
                    depth += 1
                elif u.val in ('end', 'until'):
                    depth -= 1
                    if depth == 0:
                        return j + 1
            j += 1
        return n
    return i + 1


def _read_cond(toks, i):
    depth, j, n = 0, i, len(toks)
    while j < n:
        t = toks[j]
        if t.kind == 'op' and t.val in '([{':
            depth += 1
        elif t.kind == 'op' and t.val in ')]}':
            depth -= 1
        elif t.kind == 'kw' and t.val == 'then' and depth == 0:
            return j, toks[i:j]
        j += 1
    return n, toks[i:n]


def _constrain(cons, cond, state):
    lo, hi = cons
    c = [t for t in cond if not (t.kind == 'op' and t.val in '()')]
    if len(c) == 3 and c[0].kind == 'name' and c[0].val == state and \
       c[1].val in CMP and c[2].kind == 'num':
        v, op = int(float(c[2].val)), c[1].val
        if op == '<':
            return (lo, min(hi, v - 1)), (max(lo, v), hi)
        if op == '<=':
            return (lo, min(hi, v)), (max(lo, v + 1), hi)
        if op == '>':
            return (max(lo, v + 1), hi), (lo, min(hi, v))
        if op == '>=':
            return (max(lo, v), hi), (lo, min(hi, v - 1))
        if op == '==':
            return (v, v), (lo, hi)
        if op == '~=':
            return (lo, hi), (v, v)
    return (lo, hi), (lo, hi)


def _flush(stmt, cons, out):
    if stmt:
        out.append((cons[0], cons[1], render(stmt)))
        stmt.clear()


def _parse_block(toks, i, cons, out, state):
    n, stmt = len(toks), []
    while i < n:
        t = toks[i]
        if t.kind == 'kw' and t.val in ('end', 'else', 'elseif', 'until'):
            _flush(stmt, cons, out)
            return i
        if t.kind == 'kw' and t.val == 'if':
            _flush(stmt, cons, out)
            i = _parse_if(toks, i, cons, out, state)
            continue
        j = _skip_construct(toks, i)
        stmt.extend(toks[i:j])
        i = j
    _flush(stmt, cons, out)
    return i


def _parse_if(toks, i, cons, out, state):
    cur = cons
    while True:
        j, cond = _read_cond(toks, i + 1)
        tc, fc = _constrain(cur, cond, state)
        dispatch = tc != cur or fc != cur
        if not dispatch:
            out.append((cur[0], cur[1], 'IF ' + render(cond) + ' THEN'))
        k = _parse_block(toks, j + 1, tc, out, state)
        if toks[k].val == 'elseif':
            if not dispatch:
                out.append((cur[0], cur[1], 'ELSEIF'))
            cur = fc
            i = k
            toks[k] = Tok('kw', 'if', toks[k].pos)
            continue
        if toks[k].val == 'else':
            if not dispatch:
                out.append((cur[0], cur[1], 'ELSE'))
            k2 = _parse_block(toks, k + 1, fc, out, state)
            if not dispatch:
                out.append((cur[0], cur[1], 'ENDIF'))
            return k2 + 1
        if not dispatch:
            out.append((cur[0], cur[1], 'ENDIF'))
        return k + 1


def deflatten(src, offset, state):
    """Parse `while state ~= X do ... end` at `offset`; return interval->code chunks."""
    toks = tokenize(src[offset:])
    if toks[0].val != 'while':
        raise ValueError('expected a while loop at offset %d' % offset)
    j = 0
    while toks[j].val != 'do':
        j += 1
    out = []
    _parse_block(toks, j + 1, (-10 ** 9, 10 ** 9), out, state)
    return out


# --------------------------------------------------------------------------- link
def group(chunks):
    groups, cur = [], None
    for lo, hi, txt in chunks:
        if cur and cur[0] == lo and cur[1] == hi:
            cur[2].append(txt)
        else:
            cur = [lo, hi, [txt]]
            groups.append(cur)
    return groups


def _split_top(s):
    parts, depth, cur = [], 0, ''
    for ch in s:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(cur)
            cur = ''
        else:
            cur += ch
    parts.append(cur)
    return parts


def successors(lines, state):
    """Every integer literal assigned to the state variable inside a block."""
    blob = '\n'.join(lines)
    out = []
    for m in re.finditer(r"([\w\[\]_.,]+)=([^;\n]+)", blob):
        lhs = m.group(1).split(',')
        rhs = _split_top(m.group(2))
        for a, b in zip(lhs, rhs):
            b = re.sub(r"\s*\b(continue|break|end|else|then|do)\b.*$", '', b.strip())
            if a.strip() == state and re.fullmatch(r"-?\d+", b.strip()):
                out.append(int(b.strip()))
    return out


def _render(lines):
    out, ind = [], 0
    for l in lines:
        if l.startswith('IF ') and l.endswith(' THEN'):
            out.append('  ' * ind + 'if ' + l[3:-5] + ' then')
            ind += 1
        elif l in ('ELSE', 'ELSEIF'):
            ind = max(0, ind - 1)
            out.append('  ' * ind + 'else')
            ind += 1
        elif l == 'ENDIF':
            ind = max(0, ind - 1)
            out.append('  ' * ind + 'end')
        else:
            out.append('  ' * ind + l)
    return out


class Linear:
    """A deflattened function: state value -> list of source lines."""

    def __init__(self, chunks, state, entry):
        self.state = state
        self.entry = entry
        self.index = group(chunks)
        self.blocks = {}
        self._walk(entry)

    def _lookup(self, v):
        hits = [g for g in self.index if g[0] <= v <= g[1]]
        if not hits:
            return None
        hits.sort(key=lambda g: g[1] - g[0])
        return hits[0][2]

    def _walk(self, entry):
        stack, seen = [entry], set()
        while stack:
            v = stack.pop()
            if v in seen:
                continue
            seen.add(v)
            lines = self._lookup(v)
            if lines is None:
                continue
            self.blocks[v] = _render(lines)
            for s in successors(lines, self.state):
                if s not in seen:
                    stack.append(s)

    def text(self, v):
        return '\n'.join(self.blocks.get(v, []))

    def dump(self):
        out = []
        for v, lines in self.blocks.items():
            out.append('::L%d::' % v)
            out.extend('  ' + l for l in _render(lines))
            out.append('')
        return '\n'.join(out)


def find_loops(src):
    """Yield (offset, state_var, entry_state, exit_state) for each dispatch loop."""
    for m in re.finditer(r"(\w+)\s*=\s*(-?\d+)\s*while\s+\1\s*~=\s*(-?\d+)\s*do", src):
        yield m.start(m.re.groups - 2 + 1) if False else m.start(), m.group(1), int(m.group(2)), int(m.group(3))


def loop_offsets(src):
    """Locate dispatch loops; returns list of dicts with offset/state/entry/exit."""
    res = []
    for m in re.finditer(r"(\w+)\s*=\s*(-?\d+)\s*while\s+\1\s*~=\s*(-?\d+)\s*do", src):
        res.append({
            'offset': src.index('while', m.start()),
            'state': m.group(1),
            'entry': int(m.group(2)),
            'exit': int(m.group(3)),
        })
    return res


def assignments(text):
    """Yield (lhs, rhs) pairs, expanding Lua tuple assignments."""
    for line in text.split('\n'):
        for m in re.finditer(r"([\w\[\]_.,()\-+ ]+?)=([^;]+)", line):
            head = m.group(1).strip()
            if head.endswith(('=', '<', '>', '~')) or m.group(2).startswith('='):
                continue
            lhs = _split_top(head)
            rhs = _split_top(m.group(2))
            if len(lhs) != len(rhs):
                yield head, m.group(2).strip()
                continue
            for a, b in zip(lhs, rhs):
                yield a.strip(), b.strip()
