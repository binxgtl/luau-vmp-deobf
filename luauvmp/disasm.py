"""Stage 6a - annotated disassembly of the recovered proto tree."""
import re


def kstr(v):
    if isinstance(v, bytes):
        try:
            return repr(v.decode('utf-8'))
        except Exception:
            return repr(v)
    if isinstance(v, float) and v == int(v) and abs(v) < 1e15:
        return str(int(v))
    return repr(v)


def dis_proto(p, spec, out, path='main'):
    out.append('')
    out.append('==== proto %s  (params=%d, maxstack=%d, nups=%d, code=%d, k=%d, protos=%d)' %
               (path, p['numparams'], p['maxstack'], p['nups'],
                len(p['code']), len(p['k']), len(p['protos'])))
    for i, ins in enumerate(p['code']):
        if ins is None:
            out.append('%4d      | (aux)' % (i + 1))
            continue
        op = ins['op']
        nm = spec.name(op) or 'OP%d' % op
        parts = []
        masks = spec.masks.get(nm, {}).get('xor', {})
        if masks:
            dec = []
            for fld, mask in masks.items():
                if fld in ins:
                    dec.append('%s*=%d' % (fld, ins[fld] ^ mask))
            if dec:
                parts.append('[' + ' '.join(dec) + ']')
        for f in ('A', 'B', 'C', 'D', 'E'):
            if f in ins:
                parts.append('%s=%s' % (f, ins[f]))
        if ins.get('aux'):
            parts.append('aux=%d' % ins['aux'])
        for f in ('K', 'K1', 'K2', 'KN', 'KC'):
            if f in ins:
                parts.append('%s=%s' % (f, kstr(ins[f])))
        extra = '   <- mutated from op%d' % ins['mutated_from'] if 'mutated_from' in ins else ''
        out.append('%4d %5s| %-14s %s%s' % (i + 1, op, nm, ' '.join(parts), extra))
    if p['k']:
        out.append('  -- constants:')
        for i, v in enumerate(p['k']):
            out.append('     [%d] %s' % (i, kstr(v)))
    for j, sp in enumerate(p['protos']):
        dis_proto(sp, spec, out, path + '.%d' % j)


def disassemble(root, spec):
    out = []
    dis_proto(root, spec, out)
    return '\n'.join(out)


def collect_strings(root):
    """Every printable string constant reachable from the proto tree, in order."""
    seen = []

    def walk(p):
        for ins in p['code']:
            if not ins:
                continue
            for f in ('K', 'K1', 'K2'):
                v = ins.get(f)
                if isinstance(v, bytes) and v:
                    try:
                        s = v.decode('utf-8')
                    except Exception:
                        continue
                    if re.fullmatch(r'[ -~\n\t\r]{1,400}', s):
                        seen.append(s)
        for c in p['protos']:
            walk(c)
    walk(root)
    return list(dict.fromkeys(seen))
