"""Luraph stage 4 - control-flow & expression reconstruction.

Builds on the stage-2 disassembly and the stage-3 symbolic pass:

  * register aliases are chased through MOVE/LOADK/LOADVMK so every use of a
    register renders as the value it actually holds (a string constant, a
    CONFIG lookup or a member chain);
  * arithmetic chains (SUB/ADD/UNM) are folded into readable Lua expressions
    using the CONFIG table recovered in stage 3;
  * the conditional edges recovered from the dispatcher (``TEST`` and ``EQ?``)
    turn the flat instruction list into labelled basic blocks, so the loader's
    real control flow - which deobf helpers run, which config entries are
    built conditionally - becomes visible.

The output is a ``.flow.lua`` pseudo-source with block labels (``::B_xxx::``)
and ``goto`` edges, still annotated with the original instruction indexes.
"""

import re

from .luraph_pseudo import VMK, _STRING_VMK, _BIT_VMK

CONFIG_REG = '14'


class FlowBuilder:
    """Resolve register values and lay out basic blocks."""

    def __init__(self, instrs, strings):
        self.instrs = instrs
        self.strings = strings
        self.by_idx = {i['idx']: i for i in instrs}
        self.regs = {}          # register -> current resolved value
        self.config = {}        # key -> (idx, value)
        self.calls = []
        self.edges = []         # (src_idx, dst_idx, condition_text)
        self.rendered = []      # (idx, text) in execution order

    # -- value resolution ------------------------------------------------
    def const_val(self, tok):
        """Resolve a dump column that may be a string-constant index."""
        if tok == 'nil':
            return 'nil'
        if tok.isdigit() and int(tok) in self.strings:
            return repr(self.strings[int(tok)])
        if tok.startswith('table'):
            return 'PROTO'
        if re.match(r'^-?\d', tok):
            return tok
        return repr(tok)

    def reg_val(self, name):
        """Current readable value of a register (chasing aliases)."""
        if name == 'nil':
            return 'nil'
        if name in self.regs:
            return self.regs[name]
        return 'R%s' % name

    def set_reg(self, name, val):
        if name != 'nil':
            self.regs[name] = val

    # -- instruction handling -------------------------------------------
    def handle(self, ins):
        idx = ins['idx']
        op = ins['op']
        F, g, b, D, L, K = (ins.get(k, 'nil') for k in ('F', 'g', 'b', 'D', 'L', 'K'))

        if op == 'LOADK':
            val = self.const_val(g)
            self.set_reg(L, val)
            return '%5d: R%s = %s' % (idx, L, val)

        if op == 'LOADNIL':
            lo = int(F) if F.isdigit() else 0
            hi = int(K) if K.isdigit() else lo
            for r in range(lo, hi + 1):
                self.set_reg(str(r), 'nil')
            return '%5d: R%s..R%s = nil' % (idx, F, K)

        if op == 'LOADVMK':
            n = int(L)
            if n in _STRING_VMK:
                val = 'string.%s' % VMK[n]
            elif n in _BIT_VMK:
                val = 'bit32.%s' % VMK[n]
            else:
                val = 'VMK[%s]' % L
            self.set_reg(K, val)
            return '%5d: R%s = %s' % (idx, K, val)

        if op == 'MOVE':
            src = self.reg_val(L) if L != '0' else F
            dst = K if K != '0' else F
            self.set_reg(dst, src)
            return '%5d: R%s = %s' % (idx, dst, src)

        if op == 'GETGLOBAL':
            name = self.strings.get(int(D), D) if D.isdigit() else D
            self.set_reg(F, '_G.%s' % name)
            return '%5d: R%s = _G.%s' % (idx, F, name)

        if op == 'GETTABLE':
            base = self.reg_val(F)
            if b != 'nil':
                member = self.strings.get(int(b), b) if b.isdigit() else b
                val = '%s[%s]' % (base, repr(member))
            else:
                val = '%s[R%s]' % (base, L)
            self.set_reg(K, val)
            return '%5d: R%s = %s' % (idx, K, val)

        if op == 'GETUPVAL':
            val = 'UPVAL[%s]' % F
            self.set_reg(K, val)
            return '%5d: R%s = %s' % (idx, K, val)

        if op == 'SETTABLE':
            if F == CONFIG_REG:
                key = D
                val = self.const_val(g) if g != 'nil' else self.reg_val(K)
                self.config[key] = (idx, val)
                return '%5d: CONFIG[%s] = %s' % (idx, key, val)
            key = D if D != 'nil' else self.reg_val(K)
            val = self.const_val(g) if g != 'nil' else self.reg_val(K)
            return '%5d: R%s[%s] = %s' % (idx, F, key, val)

        if op in ('SUB', 'ADD'):
            # SUB: R[F] = R[K] - const[D] ; ADD: R[K] = R[L] + const[b]
            sym = '-' if op == 'SUB' else '+'
            dst = F if op == 'SUB' else K
            lhs = self.reg_val(K) if op == 'SUB' else self.reg_val(L)
            cfield = D if op == 'SUB' else b
            rhs = self.const_val(cfield)
            expr = '(%s %s %s)' % (lhs, sym, rhs)
            self.set_reg(dst, expr)
            return '%5d: R%s = %s' % (idx, dst, expr)

        if op == 'UNM?':
            expr = '(-%s)' % self.reg_val(K)
            self.set_reg(K, expr)
            return '%5d: R%s = %s' % (idx, K, expr)

        if op == 'LEN':
            expr = '#%s' % self.reg_val(L)
            self.set_reg(F, expr)
            return '%5d: R%s = %s' % (idx, F, expr)

        if op in ('CALL1', 'CALL'):
            fn = self.reg_val(K) if op == 'CALL1' else (self.reg_val(L) if L != '0' else self.reg_val(K))
            self.calls.append((idx, fn))
            return '%5d: %s(...)' % (idx, fn)

        if op == 'TEST':
            # if R[K] then jump F
            tgt = int(F)
            cond = self.reg_val(K)
            self.edges.append((idx, tgt, cond))
            return '%5d: if %s then goto B_%d' % (idx, cond, tgt)

        if op == 'EQ?':
            # if R[F]==R[L] then jump K
            tgt = int(K)
            cond = '%s == %s' % (self.reg_val(F), self.reg_val(L))
            self.edges.append((idx, tgt, cond))
            return '%5d: if %s then goto B_%d' % (idx, cond, tgt)

        if op in ('EQ', 'LT', 'LE'):
            # comparison writing a register result
            lhs, rhs = self.reg_val(K), self.reg_val(L)
            sym = {'EQ': '==', 'LT': '<', 'LE': '<='}[op]
            expr = '(%s %s %s)' % (lhs, sym, rhs)
            dst = F if op != 'LT' else K
            self.set_reg(dst, expr)
            return '%5d: R%s = %s' % (idx, dst, expr)

        # everything else - keep a semantic comment
        return '%5d: %s' % (idx, op)

    # -- execution order -------------------------------------------------
    def linear_order(self):
        """Instruction indexes in fallthrough order (dump has gaps)."""
        return [i['idx'] for i in self.instrs]

    def run_pass(self):
        """Execute the symbolic pass over every instruction once."""
        for ins in self.instrs:
            self.rendered.append((ins['idx'], self.handle(ins)))

    # -- block layout ----------------------------------------------------
    def build_blocks(self):
        targets = {t for _, t, _ in self.edges}
        heads = {self.instrs[0]['idx']} | targets
        for src, _, _ in self.edges:
            nxt = self.next_idx(src)
            if nxt is not None:
                heads.add(nxt)
        return heads

    def next_idx(self, idx):
        for ins in self.instrs:
            if ins['idx'] > idx:
                return ins['idx']
        return None

    # -- output ----------------------------------------------------------
    def render(self):
        self.run_pass()
        labels = self.build_blocks()
        out = []
        out.append('-- ============================================================')
        out.append('-- Stage 4: control-flow & expression reconstruction')
        out.append('-- %d instructions | %d config entries | %d edges | %d blocks'
                   % (len(self.instrs), len(self.config), len(self.edges), len(labels)))
        out.append('-- ============================================================')
        out.append('')
        out.append('-- [[ body ]]')
        for idx, text in self.rendered:
            if idx in labels and idx != self.rendered[0][0]:
                out.append('')
                out.append('::B_%d::' % idx)
            out.append(text)
        out.append('')
        out.append('-- [[ recovered calls (%d) ]]' % len(self.calls))
        for idx, fn in self.calls:
            out.append('-- @%d: %s(...)' % (idx, fn))
        out.append('')
        out.append('-- [[ control-flow edges (%d) ]]' % len(self.edges))
        for src, tgt, cond in sorted(self.edges):
            out.append('-- %d --(%s)--> B_%d' % (src, cond, tgt))
        return '\n'.join(out)


def reconstruct(instrs, strings):
    """Full stage-4 pass: return the flow pseudo-source text."""
    return FlowBuilder(instrs, strings).render()
