"""Stage 6b - decompile the proto tree back to Lua.

Register-expression propagation plus structural recovery:
short-circuit `and`/`or` chains, if/else, while/repeat, numeric and generic for,
method calls, table constructors, multret argument lists, and the protector's
heap-boxed upvalues.
"""
import re

KEYWORDS = {'and', 'or', 'not', 'if', 'then', 'else', 'end', 'do', 'while', 'for',
            'function', 'local', 'return', 'nil', 'true', 'false', 'in', 'repeat',
            'until', 'break'}

COND = {'JUMPIF', 'JUMPIFNOT', 'JUMPIFEQ', 'JUMPIFNOTEQ', 'JUMPIFLE', 'JUMPIFNOTLE',
        'JUMPIFLT', 'JUMPIFNOTLT', 'JUMPXEQKNIL', 'JUMPXEQKB', 'JUMPXEQKS'}
INLINE_CLOSURE_LINES = 8

PURE = {'MOVE', 'LOADNIL', 'LOADN', 'LOADK', 'GETIMPORT', 'GETTABLE', 'GETTABLEKS',
        'GETTABLEN', 'NAMECALL', 'GETUPVAL', 'ADD', 'SUB', 'MULK', 'DIVK', 'MODK',
        'ADDK', 'SUBK', 'ORK', 'ANDK', 'MUL', 'DIV', 'MOD', 'AND', 'OR', 'NOT',
        'MINUS', 'CONCAT', 'LEN', 'NOP', 'DECSTR', 'DECIMPORT',
        'NEWCLOSURE', 'NEWCLOSURE2'}


def S(v):
    if v is None:
        return 'nil'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (int, float)):
        if isinstance(v, float):
            if v != v or v in (float('inf'), float('-inf')):
                return repr(v)
            if v == int(v) and abs(v) < 1e15:
                return str(int(v))
        return repr(v)
    if isinstance(v, bytes):
        try:
            t = v.decode('utf-8')
        except Exception:
            t = v.decode('latin1')
        out = []
        for ch in t:
            if ch == '\\':
                out.append('\\\\')
            elif ch == '"':
                out.append('\\"')
            elif ch == '\n':
                out.append('\\n')
            elif ch == '\r':
                out.append('\\r')
            elif ch == '\t':
                out.append('\\t')
            elif ord(ch) < 32 or ord(ch) == 127:
                out.append('\\%d' % ord(ch))
            else:
                out.append(ch)
        return '"' + ''.join(out) + '"'
    return str(v)


def kname(v):
    if isinstance(v, bytes):
        try:
            t = v.decode('utf-8')
        except Exception:
            return None
        if re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', t) and t not in KEYWORDS:
            return t
    return None


def kplain(v):
    if isinstance(v, bytes):
        try:
            return v.decode('utf-8')
        except Exception:
            return v.decode('latin1')
    return str(v)


def balanced(s):
    d = 0
    for ch in s:
        if ch in '([{':
            d += 1
        elif ch in ')]}':
            d -= 1
            if d < 0:
                return False
    return d == 0


def neg(c):
    c = c.strip()
    if c.startswith('not (') and c.endswith(')') and balanced(c[5:-1]):
        return c[5:-1]
    for a, b in (('==', '~='), ('~=', '=='), ('<=', '>'), ('>', '<='), ('<', '>='), ('>=', '<')):
        m = re.fullmatch(r'(.+?) ' + re.escape(a) + r' (.+)', c)
        if m and balanced(m.group(1)) and balanced(m.group(2)):
            return '%s %s %s' % (m.group(1), b, m.group(2))
    return 'not (%s)' % c


class Proto:
    def __init__(self, p, path='main'):
        self.p = p
        self.path = path
        self.code = p['code']
        self.k = p['k']
        self.numparams = p['numparams']
        self.nups = p['nups']
        self.protos = [Proto(c, path + '.%d' % i) for i, c in enumerate(p['protos'])]


class Dec:
    def __init__(self, pr, spec, upnames=None, boxctr=None, tmpctr=None):
        self.pr = pr
        self.spec = spec
        self.code = pr.code
        self.out = []
        self.reg = {}
        self.tmp = tmpctr if tmpctr is not None else [0]
        self.boxes = boxctr if boxctr is not None else [0]
        self.upnames = upnames or ['up%d' % i for i in range(pr.nups)]
        self.argnames = ['a%d' % (i + 1) for i in range(pr.numparams)]
        for i, n in enumerate(self.argnames):
            self.reg[i] = n
        self.namecall = {}
        self.top = None
        self.loops = {}
        self.loopstack = []
        self._scan_loops()

    # ---------------------------------------------------------------- helpers
    def nm(self, ins):
        return self.spec.name(ins['op']) or 'OP%d' % ins['op']

    def f(self, ins, name, default=0):
        """Read an instruction field by its *reference* name.

        Builds shuffle which slot plays which role, so every access goes through
        the per-opcode translation recovered by the fingerprinter."""
        real = self.spec.fieldmap.get(ins['op'], {}).get(name, name)
        return ins.get(real, default)

    def has(self, ins, name):
        real = self.spec.fieldmap.get(ins['op'], {}).get(name, name)
        return real in ins

    def mask(self, ins, field):
        real = self.spec.fieldmap.get(ins['op'], {}).get(field, field)
        m = self.spec.masks.get(ins['op'], {}).get('xor', {})
        return ins.get(real, 0) ^ m.get(real, 0)

    def ins(self, i):
        return self.code[i - 1] if 1 <= i <= len(self.code) else None

    def nxt(self, i):
        j = i + 1
        while j <= len(self.code) and self.code[j - 1] is None:
            j += 1
        return j

    def r(self, i):
        return self.reg.get(i, 'r%d' % i)

    def rv(self, i):
        v = self.r(i)
        if v.startswith('BOX:'):
            return v[4:].split('#')[0] + ' --[[byref]]'
        return v

    def setr(self, i, e):
        self.reg[i] = e

    def emit(self, ind, txt):
        for line in txt.split('\n'):
            self.out.append('    ' * ind + line if line else '')

    def newtmp(self):
        self.tmp[0] += 1
        return 'v%d' % self.tmp[0]

    def tgt(self, i):
        return i + 1 + self.f(self.ins(i), 'D')

    def _scan_loops(self):
        for i in range(1, len(self.code) + 1):
            ins = self.ins(i)
            if not ins:
                continue
            n = self.nm(ins)
            if n in COND or n == 'JUMP':
                t = self.tgt(i)
                if t <= i and (self.loops.get(t) is None or i > self.loops[t]):
                    self.loops[t] = i

    # ---------------------------------------------------------------- conditions
    def cond1(self, i):
        ins = self.ins(i)
        n = self.nm(ins)
        A, aux = self.f(ins, 'A'), self.f(ins, 'aux')
        if n == 'JUMPIF':
            c = self.r(A)
        elif n == 'JUMPIFNOT':
            c = neg(self.r(A))
        elif n == 'JUMPIFEQ':
            c = '%s == %s' % (self.r(A), self.r(aux))
        elif n == 'JUMPIFNOTEQ':
            c = '%s ~= %s' % (self.r(A), self.r(aux))
        elif n == 'JUMPIFLE':
            c = '%s <= %s' % (self.r(A), self.r(aux))
        elif n == 'JUMPIFLT':
            c = '%s < %s' % (self.r(A), self.r(aux))
        elif n == 'JUMPIFNOTLE':
            c = '%s > %s' % (self.r(A), self.r(aux))
        elif n == 'JUMPIFNOTLT':
            c = '%s >= %s' % (self.r(A), self.r(aux))
        elif n == 'JUMPXEQKNIL':
            c = ('%s ~= nil' if self.f(ins, 'KC') else '%s == nil') % self.r(A)
        elif n in ('JUMPXEQKB', 'JUMPXEQKS'):
            c = ('%s ~= %s' if self.f(ins, 'KC') else '%s == %s') % (
                self.r(A), S(self.f(ins, 'K', None)))
        else:
            c = '<%s?>' % n
        return c, self.tgt(i)

    def _advance_pure(self, j, limit=40):
        n = 0
        while n < limit:
            ins = self.ins(j)
            if not ins:
                j = self.nxt(j)
                continue
            name = self.nm(ins)
            if name in COND or name == 'JUMP':
                return j
            if name == 'CALL':
                base, nres, nargs = (self.mask(ins, 'C'), self.mask(ins, 'A'), self.mask(ins, 'B'))
                if nres != 2:
                    return None
                args = [self.r(base + x) for x in range(1, nargs)] if nargs else ['...']
                if base in self.namecall:
                    obj, meth = self.namecall.pop(base)
                    fn, args = '%s:%s' % (obj, meth), args[1:]
                else:
                    fn = self.r(base)
                self.setr(base, '%s(%s)' % (fn, ', '.join(args)))
                j = self.nxt(j)
                n += 1
                continue
            if name not in PURE:
                return None
            mark = len(self.out)
            j2 = self.simple(j, 0)
            if len(self.out) != mark:
                del self.out[mark:]
                return None
            j = j2
            n += 1
        return None

    def read_chain(self, i):
        chain, j = [], i
        while True:
            ins = self.ins(j)
            if not ins or self.nm(ins) not in COND:
                break
            c, t = self.cond1(j)
            if t <= j:
                break
            nj = j + 2 if ins.get('hasaux') else self.nxt(j)
            chain.append((c, t, j, nj))
            snap = dict(self.reg)
            j2 = self._advance_pure(nj)
            if j2 is None:
                self.reg = snap
                break
            ins2 = self.ins(j2)
            if not ins2 or self.nm(ins2) not in COND:
                self.reg = snap
                break
            c2, t2 = self.cond1(j2)
            if t2 <= j2:
                self.reg = snap
                break
            nja = j2 + 2 if ins2.get('hasaux') else self.nxt(j2)
            targets = {x[1] for x in chain} | {t2}
            if len({x for x in targets if x != nja}) > 1:
                self.reg = snap
                break
            j = j2
        after = chain[-1][3]
        exits = [t for _, t, _, _ in chain if t != after]
        T = exits[0] if exits else after
        if not exits or any(t not in (after, T) for _, t, _, _ in chain):
            c, t, _jj, nj = chain[0]
            return neg(c), nj, t

        def build(idx):
            if idx >= len(chain):
                return None
            c, t, _, _ = chain[idx]
            rest = build(idx + 1)
            if t == after:
                return c if rest is None else '%s or %s' % (c, rest)
            term = neg(c)
            return term if rest is None else '%s and %s' % (term, rest)
        return build(0), after, T

    # ---------------------------------------------------------------- driver
    def run(self):
        self.block(1, len(self.code) + 1, 0)
        return self.out

    def block(self, start, end, ind):
        i = start
        while i < end:
            if self.code[i - 1] is None:
                i += 1
                continue
            i = self.step(i, end, ind)

    def step(self, i, end, ind):
        ins = self.ins(i)
        name = self.nm(ins)
        if i in self.loops and self.loops[i] < end:
            return self.loop(i, ind)
        if name == 'FORNPREP':
            return self.numeric_for(i, ind)
        if name in ('FORGPREP', 'FORGPREP_F'):
            return self.generic_for(i, ind)
        if name in COND:
            return self.if_stmt(i, end, ind)
        if name == 'JUMP':
            t = self.tgt(i)
            if self.loopstack and t == self.loopstack[-1][1]:
                self.emit(ind, 'break')
            elif t > end:
                self.emit(ind, 'break -- jump to %d' % t)
            return self.nxt(i)
        return self.simple(i, ind)

    # ---------------------------------------------------------------- if
    def if_stmt(self, i, end, ind):
        expr, after, T = self.read_chain(i)
        if T <= i:
            self.emit(ind, '-- backward conditional at %d' % i)
            return self.nxt(i)
        thenend = min(T, end)
        last = self.ins(T - 1)
        elseend = None
        if last and self.nm(last) == 'JUMP':
            t2 = self.tgt(T - 1)
            if t2 > T and t2 <= end:
                elseend, thenend = t2, T - 1
        pos_if = len(self.out)
        self.emit(ind, 'if %s then' % expr)
        saved = dict(self.reg)
        mark = len(self.out)
        self.block(after, thenend, ind + 1)
        if len(self.out) == mark and not elseend:
            changed = [(k, v) for k, v in self.reg.items() if saved.get(k) != v]
            if changed:
                decls, assigns = [], []
                for k, v in changed:
                    nm = self.newtmp()
                    decls.append('    ' * ind + 'local %s = %s' % (nm, saved.get(k, 'nil')))
                    assigns.append('    ' * (ind + 1) + '%s = %s' % (nm, v))
                    self.reg[k] = nm
                self.out[pos_if:pos_if] = decls
                self.out.extend(assigns)
        if elseend:
            self.reg = saved
            self.emit(ind, 'else')
            self.block(T, elseend, ind + 1)
            self.emit(ind, 'end')
            return elseend
        self.emit(ind, 'end')
        return max(T, after)

    # ---------------------------------------------------------------- loops
    def loop(self, start, ind):
        tail = self.loops[start]
        after = self.nxt(tail)
        self.loopstack.append((start, after))
        if self.nm(self.ins(tail)) in COND:
            c, _ = self.cond1(tail)
            self.emit(ind, 'repeat')
            self.block(start, tail, ind + 1)
            self.emit(ind, 'until %s' % neg(c))
        else:
            first = self.ins(start)
            if first and self.nm(first) in COND:
                expr, bstart, T = self.read_chain(start)
                if T == after:
                    self.emit(ind, 'while %s do' % expr)
                    self.block(bstart, tail, ind + 1)
                    self.emit(ind, 'end')
                    self.loopstack.pop()
                    return after
            self.emit(ind, 'while true do')
            self.block(start, tail, ind + 1)
            self.emit(ind, 'end')
        self.loopstack.pop()
        return after

    def numeric_for(self, i, ind):
        ins = self.ins(i)
        A, t = self.f(ins, 'A'), self.tgt(i)
        var = 'i%d' % A
        limit, step, init = self.r(A), self.r(A + 1), self.r(A + 2)
        self.reg[A + 2] = var
        tail = '' if step == '1' else ', %s' % step
        self.emit(ind, 'for %s = %s, %s%s do' % (var, init, limit, tail))
        self.loopstack.append((i, t))
        self.block(i + 1, t - 1, ind + 1)
        self.loopstack.pop()
        self.emit(ind, 'end')
        return t

    def generic_for(self, i, ind):
        ins = self.ins(i)
        A, t = self.f(ins, 'A'), self.tgt(i)
        loopins = self.ins(t)
        n = 2
        kk = self.f(loopins, 'K', None) if loopins else None
        if isinstance(kk, (int, float)):
            n = max(1, int(kk))
        names = ['%s%d' % (b, A) for b in ['k', 'v', 'w', 'x'][:n]]
        for j, name in enumerate(names):
            self.reg[A + 3 + j] = name
        it, st = self.r(A), self.r(A + 1)
        head = it if st in ('nil', 'r%d' % (A + 1)) else '%s, %s' % (it, st)
        self.emit(ind, 'for %s in %s do' % (', '.join(names), head))
        self.loopstack.append((i, t + 1))
        self.block(i + 1, t, ind + 1)
        self.loopstack.pop()
        self.emit(ind, 'end')
        return self.nxt(t)

    # ---------------------------------------------------------------- plain ops
    def simple(self, i, ind):
        ins = self.ins(i)
        name = self.nm(ins)
        A, B, C = self.f(ins, 'A'), self.f(ins, 'B'), self.f(ins, 'C')
        aux, K = self.f(ins, 'aux'), self.f(ins, 'K', None)

        if name == 'MOVE':
            self.setr(A, self.r(B))
        elif name == 'LOADNIL':
            self.setr(A, 'nil')
        elif name == 'LOADB':
            self.setr(C, 'true' if A == 1 else 'false')
            if B:
                return i + 1 + B
        elif name == 'LOADN':
            d = self.mask(ins, 'Du')
            self.setr(self.mask(ins, 'A'), str(d - 65536 if d >= 32768 else d))
        elif name == 'LOADK':
            self.setr(A, S(K))
        elif name == 'GETIMPORT':
            n = self.f(ins, 'KN', 1)
            path = kplain(K)
            if n >= 2:
                k1 = self.f(ins, 'K1', None)
                path += '.' + (kname(k1) or '[%s]' % S(k1))
            if n == 3:
                k2 = self.f(ins, 'K2', None)
                path += '.' + (kname(k2) or '[%s]' % S(k2))
            self.setr(A, path)
            return i + 2
        elif name == 'GETTABLE':
            ra, rc = self.r(A), self.r(C)
            if ra.startswith('BOX:') and ra.endswith('#T') and rc == ra[:-2] + '#I':
                self.setr(B, ra[4:-2])
            else:
                self.setr(B, '%s[%s]' % (ra, rc))
        elif name == 'SETTABLE':
            rc, ra = self.r(C), self.r(A)
            if rc.startswith('BOX:') and rc.endswith('#T') and ra == rc[:-2] + '#I':
                self.emit(ind, '%s = %s' % (rc[4:-2], self.r(B)))
            else:
                self.emit(ind, '%s[%s] = %s' % (rc, ra, self.rv(B)))
        elif name == 'GETTABLEKS':
            k = kname(K)
            self.setr(A, '%s.%s' % (self.r(C), k) if k else '%s[%s]' % (self.r(C), S(K)))
            return i + 2
        elif name == 'SETTABLEKS':
            k = kname(K)
            lhs = '%s.%s' % (self.r(A), k) if k else '%s[%s]' % (self.r(A), S(K))
            self.emit(ind, '%s = %s' % (lhs, self.rv(B)))
            return i + 2
        elif name == 'GETTABLEN':
            ra = self.r(A)
            if ra.startswith('BOX:') and B in (0, 1):
                self.setr(C, ra + ('#T' if B == 1 else '#I'))
            else:
                self.setr(C, '%s[%d]' % (ra, B + 1))
        elif name == 'SETTABLEN':
            self.emit(ind, '%s[%d] = %s' % (self.r(C), B + 1, self.rv(A)))
        elif name == 'NAMECALL':
            k = kname(K) or S(K)
            self.namecall[C] = (self.r(B), k)
            self.setr(C, '%s:%s' % (self.r(B), k))
            return i + 2
        elif name == 'CALL':
            return self.call(i, ind)
        elif name == 'RETURN':
            base, cnt = A, B - 1
            if B == 0:
                if self.top:
                    ts, te = self.top
                    self.emit(ind, 'return ' + ', '.join(
                        [self.r(base + j) for j in range(ts - base)] + [te]))
                else:
                    self.emit(ind, 'return %s' % self.r(base))
            elif cnt == 0:
                self.emit(ind, 'return')
            else:
                self.emit(ind, 'return ' + ', '.join(self.r(base + j) for j in range(cnt)))
        elif name == 'ADD':
            self.setr(C, '(%s + %s)' % (self.r(A), self.r(B)))
        elif name == 'SUB':
            self.setr(A, '(%s - %s)' % (self.r(C), self.r(B)))
        elif name == 'MULK':
            self.setr(C, '(%s * %s)' % (self.r(B), S(K)))
        elif name == 'DIVK':
            self.setr(B, '(%s / %s)' % (self.r(A), S(K)))
        elif name == 'MODK':
            self.setr(A, '(%s %% %s)' % (self.r(C), S(K)))
        elif name == 'ADDK':
            self.setr(C, '(%s + %s)' % (self.r(A), S(K)))
        elif name == 'SUBK':
            self.setr(A, '(%s - %s)' % (self.r(C), S(K)))
        elif name == 'MUL':
            self.setr(A, '(%s * %s)' % (self.r(B), self.r(C)))
        elif name == 'DIV':
            self.setr(B, '(%s / %s)' % (self.r(C), self.r(A)))
        elif name == 'MOD':
            self.setr(A, '(%s %% %s)' % (self.r(B), self.r(C)))
        elif name == 'ORK':
            self.setr(B, '(%s or %s)' % (self.r(A), S(K)))
        elif name == 'ANDK':
            self.setr(B, '(%s and %s)' % (self.r(A), S(K)))
        elif name == 'OR':
            self.setr(B, '(%s or %s)' % (self.r(C), self.r(A)))
        elif name == 'AND':
            self.setr(B, '(%s and %s)' % (self.r(C), self.r(A)))
        elif name == 'NOT':
            self.setr(A, 'not %s' % self.r(B))
        elif name == 'MINUS':
            self.setr(A, '-%s' % self.r(B))
        elif name == 'CONCAT':
            self.setr(C, '(' + ' .. '.join(self.r(x) for x in range(A, B + 1)) + ')')
        elif name == 'LEN':
            self.setr(A, '#%s' % self.r(B))
        elif name == 'NEWTABLE':
            nx = self.ins(self.nxt(i + 1))
            if nx and self.nm(nx) == 'SETLIST' and nx.get('C') == A:
                self.setr(A, '{}')
            else:
                t = self.newtmp()
                self.emit(ind, 'local %s = {}' % t)
                self.setr(A, t)
            return i + 2
        elif name == 'SETLIST':
            cnt, tbl = B - 1, self.r(C)
            if cnt > 0:
                items = ', '.join(self.rv(A + j) for j in range(cnt))
            elif self.top:
                ts, te = self.top
                items = ', '.join([self.rv(A + j) for j in range(ts - A)] + [te])
                self.top = None
            else:
                items = None
            if items is None:
                self.emit(ind, '-- setlist %s <- r%d.. (multret)' % (tbl, A))
            elif tbl == '{}' and aux == 1:
                self.setr(C, '{ %s }' % items)
            else:
                self.emit(ind, '-- %s[%d..] = %s' % (tbl, aux, items))
            return i + 2
        elif name == 'GETUPVAL':
            self.setr(A, self.upnames[B] if B < len(self.upnames) else 'up%d' % B)
        elif name == 'SETUPVAL':
            self.emit(ind, '%s = %s' % (
                self.upnames[B] if B < len(self.upnames) else 'up%d' % B, self.r(A)))
        elif name == 'CLOSEUPVALS':
            pass
        elif name in ('NEWCLOSURE', 'NEWCLOSURE2'):
            return self.closure(i, ind)
        elif name == 'GETVARARGS':
            if B == 0:
                self.setr(A, '...')
            else:
                for j in range(B - 1):
                    self.setr(A + j, '(select(%d, ...))' % (j + 1))
        elif name in ('NOP', 'DECSTR', 'DECIMPORT'):
            pass
        else:
            self.emit(ind, '-- unhandled %s at %d' % (name, i))
        return self.nxt(i)

    # ---------------------------------------------------------------- closures
    def closure(self, i, ind):
        ins = self.ins(i)
        if self.nm(ins) == 'NEWCLOSURE':
            pidx, dst = int(self.f(ins, 'K')), self.f(ins, 'A')
        else:
            d = self.mask(ins, 'Du')
            pidx = d - 65536 if d >= 32768 else d
            dst = self.mask(ins, 'A')
        sub = self.pr.protos[pidx]
        caps, j = [], i + 1
        for _ in range(sub.nups):
            ci = self.code[j - 1] or {}
            ctype = ci.get('origA', ci.get('A', 0))
            creg = ci.get('origB', ci.get('B', 0))
            if ctype == 1:
                cur = self.r(creg)
                if not re.fullmatch(r'[A-Za-z_]\w*', cur) or cur in ('true', 'false', 'nil'):
                    nm = self.newtmp()
                    self.emit(ind, 'local %s = %s' % (nm, cur))
                    self.setr(creg, nm)
                    cur = nm
                caps.append(cur)
            elif ctype == 0:
                caps.append(self.r(creg))
            else:
                caps.append(self.upnames[creg] if creg < len(self.upnames) else 'up%d' % creg)
            j += 1
        d = Dec(sub, self.spec, upnames=caps, boxctr=self.boxes, tmpctr=self.tmp)
        body = d.run()
        params = ', '.join(d.argnames) if sub.numparams else '...'
        text = '\n'.join(['function(%s)' % params] + ['    ' + l for l in body] + ['end'])
        # A closure expression is duplicated every time its register is read, which
        # explodes on deeply nested scripts.  Anything sizeable becomes a local.
        if len(body) > INLINE_CLOSURE_LINES:
            nm = self.newtmp()
            self.emit(ind, 'local %s = %s' % (nm, text))
            self.setr(dst, nm)
        else:
            self.setr(dst, text)
        return j

    # ---------------------------------------------------------------- calls
    def call(self, i, ind):
        ins = self.ins(i)
        base, nres, nargs = self.mask(ins, 'C'), self.mask(ins, 'A'), self.mask(ins, 'B')
        if nargs == 0:
            if self.top:
                ts, te = self.top
                args = [self.rv(base + j) for j in range(1, ts - base)] + [te]
            else:
                args = ['...']
        else:
            args = [self.rv(base + j) for j in range(1, nargs)]
        if self.r(base) == 'NEWBOX' and nargs == 1 and nres == 2:
            self.boxes[0] += 1
            nm = 'b%d' % self.boxes[0]
            self.emit(ind, 'local %s' % nm)
            self.setr(base, 'BOX:' + nm)
            return self.nxt(i)
        if base in self.namecall:
            obj, meth = self.namecall.pop(base)
            fn, args = '%s:%s' % (obj, meth), args[1:]
        else:
            fn = self.r(base)
        expr = '%s(%s)' % (fn, ', '.join(args))
        nout = nres - 1
        if nres == 0:
            self.setr(base, expr)
            self.top = (base, expr)
            return self.nxt(i)
        self.top = None
        if nout == 0:
            self.emit(ind, expr)
        elif nout == 1:
            t = self.newtmp()
            self.emit(ind, 'local %s = %s' % (t, expr))
            self.setr(base, t)
        else:
            ts = [self.newtmp() for _ in range(nout)]
            self.emit(ind, 'local %s = %s' % (', '.join(ts), expr))
            for j, t in enumerate(ts):
                self.setr(base + j, t)
        return self.nxt(i)


def decompile(root, spec):
    pr = Proto(root)
    body = Dec(pr, spec, upnames=['NEWBOX']).run()
    text = '\n'.join(body)
    text = re.sub(r'BOX:(b\d+)#[TI]', r'\1 --[[boxref]]', text)
    text = re.sub(r'BOX:(b\d+)', r'\1', text)
    return text + '\n'
