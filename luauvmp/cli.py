"""Command line interface."""
import argparse
import io
import os
import sys

from . import prelude, container, devirt, disasm, decompile, luraph
from .analyse import analyse
from .spec import Spec


def load_image(path):
    """Read a bytecode image captured at run time.

    A staged loader only decrypts its real image while running, so the image
    arrives from outside the file.  Accept it either raw or base64 - whichever
    the capture hook happened to write.
    """
    with open(path, 'rb') as fh:
        raw = fh.read()
    stripped = bytes(c for c in raw if c not in (32, 13, 10, 9))
    b64chars = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    if stripped and set(stripped) <= b64chars and len(stripped) % 4 == 0:
        import base64
        try:
            return base64.b64decode(stripped, validate=True)
        except Exception:
            pass
    return raw


def read_source(path):
    with io.open(path, encoding='utf-8', errors='surrogateescape') as fh:
        return fh.read()


def build(path, profile=None, verbose=False, image=None):
    src = read_source(path)
    prof = Spec.load(profile) if profile else None
    spec, rep, norm = analyse(src, prof)
    missing = spec.validate()
    if verbose:
        _report(rep, spec)
    if missing:
        sys.stderr.write('incomplete VM spec:\n  - %s\n' % '\n  - '.join(missing))
        sys.stderr.write('run `luauvmp inspect` and pin the missing values with --profile\n')
    if image:
        data = load_image(image)
        if verbose:
            sys.stderr.write('  payload             : %s (%d bytes, external)\n'
                             % (image, len(data)))
    else:
        blob = prelude.find_payload(norm)
        if not blob:
            raise SystemExit('no base64 payload found')
        chain = prelude.payload_pipeline(norm, blob) or ['base64', 'lzss']
        if verbose:
            sys.stderr.write('  payload pipeline    : %s\n' % ' -> '.join(chain))
        data = container.unpack(blob, chain)
    root, used = container.parse(data, spec)
    if used != len(data):
        sys.stderr.write('warning: consumed %d of %d payload bytes\n' % (used, len(data)))
    devirt.apply_mutations(root, spec.mutation_rules())
    str_ops = set(spec.ops_named('DECSTR'))
    imp_ops = set(spec.ops_named('DECIMPORT'))
    devirt.decrypt_strings(root, str_ops, imp_ops, spec.str_prefix, spec.dec_offset)
    return spec, rep, norm, root, data


def _report(rep, spec):
    out = sys.stderr
    out.write('-- stage 1 ------------------------------------------------\n')
    st = rep.stage1.get('strings', {})
    out.write('  string helper       : %s (%d call sites, %d printable)\n'
              % (st.get('helper'), st.get('count', 0), st.get('printable', 0)))
    out.write('  jump-table helpers  : %d, %d call sites resolved\n'
              % (rep.stage1['states']['helpers'], rep.stage1['states']['resolved']))
    out.write('  dispatch loops      : %d\n' % len(rep.loops))
    out.write('-- stage 3 ------------------------------------------------\n')
    out.write('  byte key            : %d\n' % spec.byte_key)
    out.write('  word key            : %d\n' % spec.word_key)
    out.write('  varint key          : %d\n' % spec.varint_key)
    out.write('  string key prefix   : %r\n' % spec.str_prefix)
    if rep.reader:
        out.write('  instruction fields  : %s\n' % rep.reader['fields'])
        out.write('  constant modes      : %s\n' % rep.reader['kmodes'])
    out.write('  constant types      : %s\n' % spec.const_types)
    named = sum(1 for op in rep.handlers if op in spec.ops)
    out.write('  identified opcodes  : %d/%d slots, %d distinct operations\n'
              % (named, len(rep.handlers), len(set(spec.ops.values()))))
    if rep.unknown:
        out.write('  UNRESOLVED          : %s\n' % '; '.join(rep.unknown))
    if rep.notes:
        out.write('  notes               : %s\n' % '; '.join(rep.notes))
    out.write('-----------------------------------------------------------\n')


def cmd_deobf(args):
    if luraph.detect(read_source(args.input)):
        raise SystemExit("Luraph v14.x loader detected - not a luau-vmp script. "
                         "Use `luauvmp luraph %s` to unpack it." % args.input)
    spec, rep, norm, root, data = build(args.input, args.profile, args.verbose, args.image)
    base = args.output or os.path.splitext(args.input)[0]
    src = decompile.decompile(root, spec)
    _write(base + '.deobf.lua', src)
    if args.disasm:
        _write(base + '.disasm.txt', disasm.disassemble(root, spec))
    if args.strings:
        _write(base + '.strings.txt', '\n'.join(disasm.collect_strings(root)))
    if args.spec:
        spec.save(base + '.spec.json')
        print('wrote %s.spec.json' % base)


def cmd_inspect(args):
    src = read_source(args.input)
    if luraph.detect(src):
        raise SystemExit("Luraph v14.x loader detected - not a luau-vmp script. "
                         "Use `luauvmp luraph %s` to unpack it." % args.input)
    prof = Spec.load(args.profile) if args.profile else None
    spec, rep, norm = analyse(src, prof)
    _report(rep, spec)
    base = args.output or os.path.splitext(args.input)[0]
    if args.normalised:
        _write(base + '.normalised.lua', norm)
    if args.handlers:
        lines = []
        named = {}
        for op, (state, sig, fseq, xors) in sorted(rep.handlers.items()):
            named.setdefault((state, sig), []).append(op)
        for (state, sig), ops in named.items():
            name = spec.ops.get(ops[0], '<UNIDENTIFIED>')
            lines.append('=' * 72)
            lines.append('opcodes %s  handler L%s  -> %s' % (_ranges(ops), state, name))
            lines.append('=' * 72)
            lines.append(sig)
            lines.append('')
        _write(base + '.handlers.txt', '\n'.join(lines))


def _ranges(ops):
    ops = sorted(ops)
    out, start, prev = [], ops[0], ops[0]
    for o in ops[1:]:
        if o != prev + 1:
            out.append('%d-%d' % (start, prev) if start != prev else str(start))
            start = o
        prev = o
    out.append('%d-%d' % (start, prev) if start != prev else str(start))
    return ','.join(out)


def cmd_luraph(args):
    src = read_source(args.input)
    if not luraph.detect(src):
        raise SystemExit('no Luraph v14.x loader detected in %s' % args.input)
    vm, bytecode = luraph.unpack(src)
    base = args.output or os.path.splitext(args.input)[0]
    with open(base + '.vm.lua', 'wb') as fh:
        fh.write(vm)
    with open(base + '.bytecode.bin', 'wb') as fh:
        fh.write(bytecode)
    print('wrote %s.vm.lua (%d bytes) - Luraph VM interpreter source'
          % (base, len(vm)))
    print('wrote %s.bytecode.bin (%d bytes) - Luraph VM bytecode'
          % (base, len(bytecode)))


def cmd_unpack(args):
    src = read_source(args.input)
    if luraph.detect(src):
        return cmd_luraph(args)
    norm, _ = prelude.decrypt_strings(prelude.fold_arith(src))
    blob = prelude.find_payload(norm)
    if not blob:
        raise SystemExit('no base64 payload found')
    data = container.unpack(blob, prelude.payload_pipeline(norm, blob) or ['base64', 'lzss'])
    base = args.output or os.path.splitext(args.input)[0]
    with open(base + '.bytecode.bin', 'wb') as fh:
        fh.write(data)
    print('wrote %s.bytecode.bin (%d bytes)' % (base, len(data)))


def _write(path, text):
    with io.open(path, 'w', encoding='utf-8', errors='replace') as fh:
        fh.write(text)
    print('wrote %s (%d bytes)' % (path, len(text)))


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog='luauvmp', description='Static deobfuscator for Luau VM-protected scripts')
    sub = ap.add_subparsers(dest='cmd', required=True)

    d = sub.add_parser('deobf', help='full pipeline: unpack, devirtualise, decompile')
    d.add_argument('input')
    d.add_argument('-o', '--output', help='output basename (default: input without extension)')
    d.add_argument('-p', '--profile', help='JSON spec profile to merge over auto-analysis')
    d.add_argument('--image', metavar='FILE',
                   help='decode this bytecode image instead of the one in the file, '
                        'using the VM spec recovered from it (for staged loaders; '
                        'raw or base64)')
    d.add_argument('--disasm', action='store_true', help='also write the disassembly')
    d.add_argument('--strings', action='store_true', help='also write recovered strings')
    d.add_argument('--spec', action='store_true', help='also write the recovered VM spec')
    d.add_argument('-v', '--verbose', action='store_true')
    d.set_defaults(func=cmd_deobf)

    i = sub.add_parser('inspect', help='report the recovered VM spec without decompiling')
    i.add_argument('input')
    i.add_argument('-o', '--output')
    i.add_argument('-p', '--profile')
    i.add_argument('--normalised', action='store_true', help='dump the normalised loader')
    i.add_argument('--handlers', action='store_true', help='dump canonical opcode handlers')
    i.set_defaults(func=cmd_inspect)

    u = sub.add_parser('unpack', help='only unpack the payload out')
    u.add_argument('input')
    u.add_argument('-o', '--output')
    u.set_defaults(func=cmd_unpack)

    l = sub.add_parser('luraph', help='unpack a Luraph v14.x loader (base85 + range coder)')
    l.add_argument('input')
    l.add_argument('-o', '--output')
    l.set_defaults(func=cmd_luraph)

    args = ap.parse_args(argv)
    return args.func(args) or 0


if __name__ == '__main__':
    sys.exit(main())
