"""Canonical form for one opcode handler.

Two builds of the same protector emit the *same* handler with different names,
field slots, state numbers, XOR masks, tuple-assignment order, redundant
parentheses and if/else shape.  To compare them we rewrite each handler into a
form where all of that is gone:

  * identifiers            -> t0, t1, ... in order of first appearance
  * instruction fields     -> $0$, $1$, ... in order of first appearance
  * VM locals              -> CODE / PC / REG / UPV / OPC
  * successor states       -> @0, @1, ... in DFS order
  * XOR masks              -> #
  * upvalue box shape      -> BOX(x)
  * random table slots     -> [#]
  * tuple assignments      -> split into individual, sorted assignments
  * control flow           -> each statement tagged with its guard path, then
                              sorted, so `if c then A end B` and
                              `if c then A else B end` collapse together

What is left is the operation's semantics.
"""
import re

from . import deflatten

MARKERS = {'GOTO', 'XOR', 'BOX', 'IFEXP', 'CODE', 'PC', 'REG', 'UPV', 'OPC', 'TOP'}
LUA_WORDS = {'true', 'false', 'nil', 'and', 'or', 'not', 'if', 'then', 'else',
             'end', 'return', 'continue', 'local', 'while', 'for', 'do', 'until',
             'repeat', 'break', 'in', 'function'}

_IFHEAD = re.compile(r"^\s*if\s*(.*?)\s*then\s*$")


def _strip_parens(s):
    s = s.strip()
    while s.startswith('(') and s.endswith(')'):
        depth = 0
        for i, ch in enumerate(s):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0 and i != len(s) - 1:
                    return s
        s = s[1:-1].strip()
    return s


class Normaliser:
    def __init__(self, fields, roles, state):
        self.state = state
        self.roles = roles
        self.slot2name = {v: k for k, v in fields.items()}

    def reset(self):
        self.locals = {}
        self.fieldseq = []
        self.xors = []
        self.states = {}

    def canon(self, v):
        self.states.setdefault(v, len(self.states))
        return self.states[v]

    # ------------------------------------------------------------------ text
    def rewrite(self, txt):
        r, insn = self.roles, self.roles.get('INSN')

        # String literals carry meaning ("number", "function", ...) and must not be
        # mangled by the identifier renamer, so park them first.
        lits = []

        def park(m):
            lits.append(m.group(0))
            return '\x01%d\x01' % (len(lits) - 1)
        txt = re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", park, txt)

        def fld(m):
            nm = self.slot2name.get(int(m.group(1)), 'f%s' % m.group(1))
            if nm not in self.fieldseq:
                self.fieldseq.append(nm)
            return '$%d$' % self.fieldseq.index(nm)
        if insn:
            txt = re.sub(re.escape(insn) + r"\[(\d+)\]", fld, txt)
        for role in ('CODE', 'PC', 'REG', 'UPV', 'OPC'):
            if r.get(role):
                txt = re.sub(r"\b" + re.escape(r[role]) + r"\b", role, txt)

        txt = re.sub(r"(\w+)\[\d+\]\[\1\[\d+\]\]", r"BOX(\1)", txt)

        def xr(m):
            self.xors.append((m.group(1), int(m.group(2))))
            return 'XOR(%s,#)' % m.group(1)
        txt = re.sub(r"\w+\(\s*(\$\d+\$|[A-Za-z_]\w*)\s*,\s*(\d+)\s*\)", xr, txt)
        txt = re.sub(r"\[\d{4,}\]", '[#]', txt)

        # build-random numerics: mutation guards, loop bases, key material
        txt = re.sub(r"(\$\d+\$)\s*==\s*-?\d+", r"\1==#", txt)
        txt = re.sub(r"(?<![\w.$#])\d{2,}(?![\w.$])",
                     lambda m: m.group(0) if int(m.group(0)) <= 63 else '#', txt)
        # the opcode an instruction rewrites itself into is build-specific too
        txt = re.sub(r"CODE\[PC\]\s*=\s*\{[^{}]*\}",
                     lambda m: re.sub(r"\d+", '#', m.group(0)), txt)

        def unpark(m):
            lit = lits[int(m.group(1))]
            # binary key material is build-specific; plain words are semantic
            return '"#"' if '\\' in lit else lit
        txt = re.sub(r"\x01(\d+)\x01", unpark, txt)
        return re.sub(r"\s+", '', txt)

    def rename_locals(self, txt):
        """Applied once over the assembled handler, so numbering is order-free."""
        lits = []

        def park(m):
            lits.append(m.group(0))
            return '\x01%d\x01' % (len(lits) - 1)
        txt = re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", park, txt)

        def loc(m):
            n = m.group(0)
            if n in MARKERS or n in LUA_WORDS:
                return n
            self.locals.setdefault(n, 't%d' % len(self.locals))
            return self.locals[n]
        txt = re.sub(r"\b[A-Za-z_]\w*\b", loc, txt)
        return re.sub(r"\x01(\d+)\x01", lambda m: lits[int(m.group(1))], txt)

    # ------------------------------------------------------------------ stmts
    def statements(self, txt):
        """Split one source line into canonical, order-independent assignments."""
        body = re.sub(r"\bcontinue\b", '', txt).strip()
        pairs = list(deflatten.assignments(body))
        if not pairs:
            return [self.rewrite(body)] if body else []
        rebuilt = []
        for lhs, rhs in pairs:
            if lhs.strip() == self.state and re.fullmatch(r"-?\d+", rhs.strip()):
                rebuilt.append('GOTO@%d' % self.canon(int(rhs.strip())))
                continue
            rebuilt.append('%s=%s' % (self.rewrite(lhs), self.rewrite(rhs)))
        # An assignment list has no defined order once split, so sort it - but sort
        # on a key with identifier *names* blanked out, otherwise two builds order
        # the same statements differently and every later step diverges.
        return sorted(rebuilt, key=shape)


_LITERAL = re.compile("'(?:\\\\.|[^'\\\\])*'|\"(?:\\\\.|[^\"\\\\])*\"")


def shape(txt):
    """Sort key with identifier names blanked out, so ordering is build-free."""
    txt = _LITERAL.sub(chr(34) * 2, txt)
    return re.sub(r"\b[A-Za-z_]\w*\b",
                  lambda m: m.group(0) if m.group(0) in MARKERS or m.group(0) in LUA_WORDS
                  else '_', txt)


def _terminal(lines):
    return bool(lines) and ('continue' in lines[-1] or 'return' in lines[-1])


def block_canonical(lines, norm):
    """Guard-path form of one block: sorted `guard => statement` records."""
    from .analyse import parse_lines
    out = []

    def walk(nodes, guard):
        i = 0
        while i < len(nodes):
            node = nodes[i]
            if node[0] == 'if':
                m = _IFHEAD.match(node[1])
                cond = norm.rewrite(_strip_parens(m.group(1))) if m else '?'
                then_lines = [n[1] for n in node[2] if n[0] == 'stmt']
                walk(node[2], guard + [cond])
                walk(node[3], guard + ['!' + cond])
                if _terminal(then_lines):
                    guard = guard + ['!' + cond]
                i += 1
                continue
            for stmt in norm.statements(node[1]):
                out.append('%s=>%s' % ('&'.join(guard), stmt))
            i += 1

    walk(parse_lines(lines), [])
    return sorted(out, key=shape)


def handler_signature(lin, entry, norm, stop):
    """Canonical text for the sub-graph implementing one opcode."""
    norm.reset()
    order, seen, queue = [], set(), [entry]
    while queue:
        v = queue.pop(0)
        if v in seen or v in stop or v not in lin.blocks:
            continue
        seen.add(v)
        order.append(v)
        for s in deflatten.successors(lin.blocks[v], lin.state):
            if s not in seen and s not in stop:
                queue.append(s)
    for v in order:
        norm.canon(v)
    lines = []
    for v in order:
        lines.append('@%d:' % norm.canon(v))
        lines.extend(block_canonical(lin.blocks[v], norm))
    # locals are numbered last, over the already-sorted text, so two builds that
    # emit the same statements in a different order still agree
    text = norm.rename_locals('\n'.join(lines))
    return text, list(norm.fieldseq), list(norm.xors)
