"""Stage 3 driver - turn a protected loader into a `Spec`.

Everything that the protector randomises per build is recovered here from the
deflattened loader itself.  Whatever cannot be proven is reported in
`Report.unknown` so it can be pinned in a JSON profile instead of silently
producing wrong output.
"""
import re

from . import prelude, deflatten, mutations, signatures as sigdb
from .spec import Spec


class Report:
    def __init__(self):
        self.stage1 = {}
        self.loops = []
        self.reader = None
        self.vm = None
        self.unknown = []
        self.handlers = {}      # opcode -> (signature, fields, xors)
        self.notes = []

    def warn(self, msg):
        self.notes.append(msg)


# --------------------------------------------------------------------------- helpers
_IFLINE = re.compile(r"^\s*if\s*\(?\s*(\w+)\s*(<=|>=|<|>|==|~=)\s*\(?\s*(-?\d+)\s*\)?\s*\)?\s*then\s*$")


def parse_lines(lines):
    """Turn rendered `if/else/end` block text into a small statement tree."""
    def walk(i, depth):
        nodes = []
        while i < len(lines):
            l = lines[i].strip()
            if l == 'end':
                return nodes, i + 1
            if l == 'else':
                return nodes, i
            if l.startswith('if ') and l.endswith(' then'):
                then, j = walk(i + 1, depth + 1)
                els = []
                if j < len(lines) and lines[j].strip() == 'else':
                    els, j = walk(j + 1, depth + 1)
                    if j < len(lines) and lines[j].strip() == 'end':
                        j += 1
                nodes.append(('if', lines[i], then, els))
                i = j
                continue
            nodes.append(('stmt', lines[i]))
            i += 1
        return nodes, i
    return walk(0, 0)[0]


def _narrow(op, num, lo, hi):
    if op == '>':
        return (max(lo, num + 1), hi), (lo, min(hi, num))
    if op == '>=':
        return (max(lo, num), hi), (lo, min(hi, num - 1))
    if op == '<':
        return (lo, min(hi, num - 1)), (max(lo, num), hi)
    if op == '<=':
        return (lo, min(hi, num)), (max(lo, num + 1), hi)
    if op == '==':
        return (num, num), (lo, hi)
    if op == '~=':
        return (lo, hi), (num, num)
    return None


def dispatch_ranges(lin, entry, var, lo=0, hi=255, follow_goto=True):
    """Resolve a dispatch tree on `var` into [(lo, hi, handler_state)]."""
    out = {}
    goto = re.compile(r"^" + re.escape(lin.state) + r"\s*=\s*(-?\d+)(?:\s*continue)?$")

    def leaf(state, a, b):
        if a <= b and (a, b) not in out:
            out[(a, b)] = state

    def descend(state, a, b, depth, seen):
        if a > b or depth > 40 or state in seen or state not in lin.blocks:
            leaf(state, a, b)
            return
        walk(parse_lines(lin.blocks[state]), state, a, b, depth, seen | {state})

    def walk(nodes, state, a, b, depth, seen):
        for kind, *rest in nodes:
            if kind != 'if':
                continue
            m = _IFLINE.match(rest[0])
            if m and m.group(1) == var:
                t, f = _narrow(m.group(2), int(m.group(3)), a, b)
                walk(rest[1], state, t[0], t[1], depth + 1, seen)
                walk(rest[2], state, f[0], f[1], depth + 1, seen)
                return
        if len(nodes) == 1 and nodes[0][0] == 'stmt' and follow_goto:
            m = goto.match(nodes[0][1].strip())
            if m:
                descend(int(m.group(1)), a, b, depth + 1, seen)
                return
        leaf(state, a, b)

    descend(entry, lo, hi, 0, frozenset())
    return sorted((a, b, s) for (a, b), s in out.items())


def _all_text(lin):
    return '\n'.join('\n'.join(v) for v in lin.blocks.values())


def _succ_text(lin, state):
    out = []
    for s in deflatten.successors(lin.blocks.get(state, []), lin.state):
        out.append((s, lin.text(s)))
    return out


# --------------------------------------------------------------------------- reader
def analyse_reader(lin, src, spec, rep):
    text = _all_text(lin)

    # ---- XOR keys, taken from the consumer of each raw read
    def key_after(fmt):
        keys = []
        for v, lines in lin.blocks.items():
            m = re.search(r"(\w+)\s*=\s*\w+\(\s*" + re.escape(fmt), '\n'.join(lines))
            if not m:
                continue
            for _s, t in _succ_text(lin, v):
                k = re.search(r"\w+\(\s*" + re.escape(m.group(1)) + r"\s*,\s*(\d+)\s*\)", t)
                if k:
                    keys.append(int(k.group(1)))
        return keys
    bk, wk = key_after('"B"'), key_after('"<I4"')
    spec.byte_key = _majority(bk, rep, 'byte_key')
    spec.word_key = _majority(wk, rep, 'word_key')

    # ---- varint key: applied to the accumulator of every varint loop
    accs = set(re.findall(r"(\w+)\s*=\s*\w+\(\s*\1\s*,\s*\w+\(\w+\(\w+,\s*127\s*\)", text))
    vk = []
    for acc in accs:
        for m in re.finditer(r"\w+\(\s*" + re.escape(acc) + r"\s*,\s*(\d+)\s*\)", text):
            if int(m.group(1)) > 255:
                vk.append(int(m.group(1)))
    for v, lines in lin.blocks.items():
        for m in re.finditer(r"=\s*\w+\(\s*\w+\s*,\s*(\d+)\s*\)", '\n'.join(lines)):
            pass
    spec.varint_key = _majority(vk, rep, 'varint_key')

    # ---- instruction field slots
    f = {}
    shifted = {}          # local var -> (shift, mask)
    signed = {}           # local var -> 'D' | 'E'
    for lhs, rhs in deflatten.assignments(text):
        m = re.fullmatch(r"\w+\(\s*\w+\(\s*\w+\s*,\s*(\d+)\s*\)\s*,\s*(\d+)\s*\)", rhs)
        if m:
            key = (int(m.group(1)), int(m.group(2)))
            nm = {(8, 255): 'A', (16, 255): 'B', (24, 255): 'C',
                  (16, 65535): 'Du', (8, 16777215): 'Eu'}.get(key)
            slot = re.fullmatch(r"\w+\[(\d+)\]", lhs)
            if nm and slot:
                f.setdefault(nm, int(slot.group(1)))
            elif nm:
                shifted[lhs] = nm
            continue
        m = re.fullmatch(r"IFEXP\(\s*\w+\s*<\s*(32768|8388608)\s*,.*", rhs)
        if m:
            signed[lhs] = 'D' if m.group(1) == '32768' else 'E'
            continue
        slot = re.fullmatch(r"\w+\[(\d+)\]", lhs)
        if slot and rhs in shifted:
            f.setdefault(shifted[rhs], int(slot.group(1)))
        elif slot and rhs in signed:
            f.setdefault(signed[rhs], int(slot.group(1)))
    m = re.search(r"\[(\d+)\]\s*=\s*(\w+);\s*\w+\(\s*\w+\s*,\s*\{\}\s*\)", text)
    if m:
        f.setdefault('aux', int(m.group(1)))
    opvar = re.search(r"(\w+)\s*=\s*\w+\(\s*(\w+)\s*,\s*255\s*\);", text)
    rec = re.search(r"=\s*\{(\[\-?\d+\]\s*=[^{}]*)\}", text)
    if rec and opvar:
        pairs = dict(re.findall(r"\[(-?\d+)\]\s*=\s*([\w']+)", rec.group(1)))
        info = re.search(r"(\w+),(\w+),(\w+)=(\w+)\[1\],(\w+)\[2\],(\w+)\[3\]", text)
        for slot, val in pairs.items():
            if val == opvar.group(1):
                f.setdefault('op', int(slot))
            if info and val == info.group(2):
                f.setdefault('kmode', int(slot))
    spec_fields = f
    for need in ('A', 'B', 'C', 'Du', 'D', 'E', 'aux', 'op', 'kmode'):
        if need not in f:
            rep.unknown.append('instruction field slot: %s' % need)

    # ---- opcode info table
    m = re.search(r"=\s*(\w+)\[(\d+)\]\[\s*\w+\s*\+\s*1\s*\]", text)
    if m:
        try:
            spec.opinfo = opinfo_from_source(src, int(m.group(2)))
        except Exception as exc:
            rep.unknown.append('opcode info table (%s)' % exc)
    else:
        rep.unknown.append('opcode info table')

    # ---- constant type codes
    ctvar, centry = _const_dispatch(lin)
    if ctvar:
        spec.const_types = _classify_consts(lin, centry, ctvar)
    if not spec.const_types:
        rep.unknown.append('constant type codes')

    # ---- kmode codes
    kmap = _kmode_codes(lin, spec_fields)
    for name, code in kmap.items():
        setattr(spec, name, code)
    rep.reader = {'fields': spec_fields, 'kmodes': kmap}
    return spec_fields


def _majority(vals, rep=None, what=None):
    if not vals:
        if rep and what:
            rep.unknown.append(what)
        return 0
    best, n = 0, 0
    for v in set(vals):
        c = vals.count(v)
        if c > n:
            best, n = v, c
    return best


def opinfo_from_source(src, slot):
    key = '[%d]={' % slot
    i = src.index(key)
    j = src.index('}}', i)
    trip = re.findall(r"\{(\d+),(\d+),(true|false)\}", src[i:j + 2])
    if len(trip) != 256:
        raise ValueError('found %d entries, expected 256' % len(trip))
    return [[int(a), int(b), c == 'true'] for a, b, c in trip]


def _const_dispatch(lin):
    """Find the variable and entry state of the constant-type switch."""
    for v, lines in lin.blocks.items():
        txt = '\n'.join(lines)
        m = re.match(r"^\s*(\w+)\s*=\s*(\w+)\s*$", lines[0]) if lines else None
        mm = re.search(r"if\s*\(?\s*(\w+)\s*==\s*(\d+)\s*\)?\s*then", txt)
        if mm and re.search(r"\w+\s*=\s*\w+\(\s*\"B\"", lin.text(_pred(lin, v)) or ''):
            return mm.group(1), v
    # fall back: the switch that eventually reaches a `"<d"` read
    for v, lines in lin.blocks.items():
        txt = '\n'.join(lines)
        mm = re.search(r"if\s*\(?\s*(\w+)\s*==\s*(\d+)\s*\)?\s*then", txt)
        if mm and _reaches(lin, v, '"<d"'):
            return mm.group(1), v
    return None, None


def _pred(lin, v):
    for s, lines in lin.blocks.items():
        if v in deflatten.successors(lines, lin.state):
            return s
    return None


def _reaches(lin, start, needle, depth=12):
    seen, stack = set(), [(start, 0)]
    while stack:
        s, d = stack.pop()
        if s in seen or d > depth:
            continue
        seen.add(s)
        if needle in lin.text(s):
            return True
        for n in deflatten.successors(lin.blocks.get(s, []), lin.state):
            stack.append((n, d + 1))
    return False


def _classify_consts(lin, entry, var):
    out = {}
    for lo, hi, state in dispatch_ranges(lin, entry, var, 0, 15):
        if lo != hi:
            continue
        if _reaches(lin, state, '"<d"', 6):
            out[lo] = 'double'
        elif _reaches(lin, state, '"c"..', 16):
            out[lo] = 'string'
        elif _reaches(lin, state, ',127)', 16):
            out[lo] = 'int'
    # the branch that does nothing at all is the nil constant
    known = set(out)
    for lo, hi, state in dispatch_ranges(lin, entry, var, 0, 15):
        if lo == hi and lo not in known and len(lin.blocks.get(state, [])) <= 2:
            out[lo] = 'nil'
    return out


def _kmode_codes(lin, fields):
    """Map each constant-mode number onto the Spec attribute it drives."""
    inv = {v: k for k, v in fields.items()}
    entry = var = None
    for v, lines in lin.blocks.items():
        txt = "\n".join(lines)
        for lhs, rhs in deflatten.assignments(txt):
            m = re.fullmatch(r"(\w+)\[(\d+)\]", rhs)
            if m and fields.get('kmode') == int(m.group(2)):
                mm = re.search(r"if\s*\(?\s*" + re.escape(lhs) + r"\s*==", txt)
                if mm:
                    entry, var = v, lhs
                    break
        if entry is not None:
            break
    if entry is None:
        return {}
    out = {}
    for lo, hi, state in dispatch_ranges(lin, entry, var, 0, 15):
        if lo != hi:
            continue
        txt = lin.text(state).replace(' ', '')
        if ',30)' in txt:
            out['kmode_import'] = lo
            continue
        for lhs, rhs in deflatten.assignments(txt):
            if not re.fullmatch(r"\w+\[\d+\]", lhs):
                continue
            m = re.fullmatch(r"\w+\[\w+\(\w+\[\d+\],0,24\)\+1\]", rhs)
            if m:
                out['kmode_aux24'] = lo
                break
            if re.fullmatch(r"\w+\(\w+\[\d+\],0,16\)", rhs):
                out['kmode_aux16'] = lo
                break
            if re.fullmatch(r"\w+\(\w+\[\d+\],0,1\)==1", rhs):
                out['kmode_auxbool'] = lo
                break
            m = re.fullmatch(r"\w+\[\w+\[(\d+)\]\+1\]", rhs)
            if m:
                nm = inv.get(int(m.group(1)))
                if nm in ('A', 'B', 'C', 'D', 'E', 'aux'):
                    out['kmode_' + nm] = lo
                break
    return out


# --------------------------------------------------------------------------- vm
def vm_roles(lin):
    roles = {}
    text = _all_text(lin)
    m = re.search(r"(\w+)\s*=\s*(\w+)\[(\w+)\]\s*;\s*(\w+)\s*,\s*\w+\s*=\s*\1\[(\d+)\]", text)
    if m:
        roles.update(INSN=m.group(1), CODE=m.group(2), PC=m.group(3),
                     OPC=m.group(4), OPFIELD=int(m.group(5)))
    insn = roles.get('INSN')
    if insn:
        c = {}
        for m in re.finditer(r"(\w+)\[" + re.escape(insn) + r"\[\d+\]\]", text):
            c[m.group(1)] = c.get(m.group(1), 0) + 1
        if c:
            roles['REG'] = max(c, key=c.get)
        c = {}
        for m in re.finditer(r"(\w+)\[" + re.escape(insn) + r"\[\d+\]\s*\+\s*1\]", text):
            c[m.group(1)] = c.get(m.group(1), 0) + 1
        if c:
            roles['UPV'] = max(c, key=c.get)
    return roles


class Normaliser:
    """Rewrite a handler into a build-independent canonical form."""

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

    def line(self, txt):
        r, insn = self.roles, self.roles.get('INSN')

        def fld(m):
            nm = self.slot2name.get(int(m.group(1)), 'f%s' % m.group(1))
            if nm not in self.fieldseq:
                self.fieldseq.append(nm)
            return 'I<%d>' % self.fieldseq.index(nm)
        if insn:
            txt = re.sub(re.escape(insn) + r"\[(\d+)\]", fld, txt)
        for role in ('CODE', 'PC', 'REG', 'UPV', 'OPC'):
            if r.get(role):
                txt = re.sub(r"\b" + re.escape(r[role]) + r"\b", role, txt)
        txt = re.sub(re.escape(self.state) + r"\s*=\s*(-?\d+)",
                     lambda m: 'GOTO @%d' % self.canon(int(m.group(1))), txt)

        def xr(m):
            self.xors.append((m.group(1), int(m.group(2))))
            return 'XOR(%s,#)' % m.group(1)
        txt = re.sub(r"\w+\(\s*(I<\d+>|[A-Za-z_]\w*)\s*,\s*(\d+)\s*\)", xr, txt)

        def loc(m):
            n = m.group(0)
            if n in ('GOTO', 'XOR', 'IFEXP', 'L', 'I', 'CODE', 'PC', 'REG', 'UPV', 'OPC') \
                    or n in KEYWORDS_LUA:
                return n
            self.locals.setdefault(n, 't%d' % len(self.locals))
            return self.locals[n]
        txt = re.sub(r"\b[A-Za-z_]\w*\b", loc, txt)
        return re.sub(r"\s+", '', txt)


KEYWORDS_LUA = {'true', 'false', 'nil', 'and', 'or', 'not', 'if', 'then', 'else',
                'end', 'return', 'continue', 'local', 'while', 'for', 'do', 'until',
                'repeat', 'break', 'in', 'function'}


def handler_signature(lin, entry, norm, stop):
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
        for l in lin.blocks[v]:
            lines.append(norm.line(l))
    return '\n'.join(lines), list(norm.fieldseq), list(norm.xors)


def analyse_vm(lin, spec, fields, rep):
    roles = vm_roles(lin)
    rep.vm = {'roles': roles}
    if 'OPC' not in roles:
        rep.unknown.append('VM dispatch roles')
        return
    # the fetch block jumps into the dispatch tree
    fetch = None
    for v, lines in lin.blocks.items():
        if re.search(re.escape(roles['OPC']) + r"\s*,?\s*\w*\s*=\s*" +
                     re.escape(roles['INSN']) + r"\[\d+\]", '\n'.join(lines)):
            fetch = v
            break
    entry = None
    if fetch is not None:
        succ = deflatten.successors(lin.blocks[fetch], lin.state)
        if succ:
            entry = succ[0]
    if entry is None:
        rep.unknown.append('opcode dispatch entry')
        return
    stop = {lin.entry, fetch, entry}
    ranges = dispatch_ranges(lin, entry, roles['OPC'])
    # narrower ranges win where an equality test left a wide fall-through
    ranges = sorted(ranges, key=lambda r: -(r[1] - r[0]))
    norm = Normaliser(fields, roles, lin.state)
    for lo, hi, state in ranges:
        sig, fseq, xors = handler_signature(lin, state, norm, stop)
        name = sigdb.SIGNATURES.get(sig)
        for op in range(lo, hi + 1):
            rep.handlers[op] = (state, sig, fseq, xors)
            if name:
                spec.ops[op] = name
        if name:
            masks = {}
            for fname, val in xors:
                if fname.startswith('I<'):
                    idx = int(fname[2:-1])
                    if idx < len(fseq):
                        masks[fseq[idx]] = val
            if masks:
                spec.masks.setdefault(name, {})['xor'] = masks
    rep.vm['ranges'] = ranges
    rep.vm['entry'] = entry
    spec.mutations = mutations.extract(lin, ranges, roles, fields, stop)
    return ranges


# --------------------------------------------------------------------------- top level
def analyse(source, profile=None):
    rep = Report()
    src, rep.stage1 = prelude.normalise(source)
    spec = Spec()
    loops = deflatten.loop_offsets(src)
    rep.loops = loops
    lins = []
    for lo in loops:
        try:
            chunks = deflatten.deflatten(src, lo['offset'], lo['state'])
            lins.append((lo, deflatten.Linear(chunks, lo['state'], lo['entry'])))
        except Exception as exc:
            rep.warn('failed to deflatten loop at %d: %s' % (lo['offset'], exc))
    reader = vm = None
    for lo, lin in lins:
        t = _all_text(lin)
        if '"<I4"' in t and '"c"..' in t:
            reader = lin
        elif '"<d"' not in t and len(lin.blocks) > (len(vm.blocks) if vm else 0):
            vm = lin
    if reader is None:
        rep.unknown.append('bytecode reader loop')
        return spec, rep, src
    fields = analyse_reader(reader, src, spec, rep)
    if vm is not None:
        analyse_vm(vm, spec, fields, rep)
    else:
        rep.unknown.append('interpreter loop')
    m = re.search(r'=\s*("(?:\\.|[^"\\])*")\s*\.\.\s*\w+', src)
    if m:
        from .lualex import lua_unescape
        spec.str_prefix = lua_unescape(m.group(1)[1:-1])
    else:
        rep.unknown.append('per-string key prefix')
    if profile:
        _merge_profile(spec, profile)
    return spec, rep, src


def _merge_profile(spec, prof):
    for k, v in prof.__dict__.items():
        if k == 'opinfo' and not v:
            continue
        if k == 'ops' and v:
            spec.ops.update(v)
            continue
        if k == 'masks' and v:
            spec.masks.update(v)
            continue
        if k == 'mutations' and v:
            spec.mutations.update(v)
            continue
        if v not in (0, b'', {}, [], None):
            setattr(spec, k, v)
