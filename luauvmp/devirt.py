"""Stage 5 - devirtualise: undo runtime instruction mutation and string encryption.

The VM does two things at execution time that a plain disassembler would miss:

  1. Self-modifying opcodes.  An instruction whose C field matches a magic value
     rewrites itself in place as a *different* opcode with XOR-masked operands and
     re-dispatches.  Several real Luau operations are only reachable this way.
  2. Lazy string decryption.  Pseudo-instructions decrypt the constant of the
     *following* instruction (strings) or the import names two slots ahead, then
     neuter themselves.  Both are deterministic, so we can apply them statically.
"""


def apply_mutations(proto, rules):
    """rules: {(op, C_value): (new_op, xor_A, xor_B)}"""
    for ins in proto['code']:
        if not ins:
            continue
        seen = 0
        while seen < 8:
            key = (ins['op'], ins.get('C'))
            if key not in rules:
                break
            new_op, xa, xb = rules[key]
            ins.setdefault('origA', ins.get('A', 0))
            ins.setdefault('origB', ins.get('B', 0))
            ins.setdefault('origC', ins.get('C', 0))
            ins['mutated_from'] = ins['op']
            ins['A'] = ins.get('A', 0) ^ xa
            ins['B'] = ins.get('B', 0) ^ xb
            ins['C'] = 0
            ins['op'] = new_op
            ins['kmode'] = None
            ins['aux'] = 0
            ins.pop('K', None)
            seen += 1
    for c in proto['protos']:
        apply_mutations(c, rules)


def _xor(data, key, prefix):
    key = prefix + key
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def decrypt_strings(proto, str_ops, import_op, prefix):
    """Run the decrypt pseudo-ops statically over the whole proto tree."""
    code = proto['code']
    n = 0
    for i, ins in enumerate(code):
        if not ins:
            continue
        if ins['op'] in str_ops:
            tgt = code[i + 1] if i + 1 < len(code) else None
            key = ins.get('K')
            if tgt and isinstance(tgt.get('K'), bytes) and isinstance(key, bytes):
                tgt['K'] = _xor(tgt['K'], key, prefix)
                ins['meta'] = 'decrypts +1'
                n += 1
        elif ins['op'] == import_op:
            tgt = code[i + 2] if i + 2 < len(code) else None
            if not tgt:
                continue
            cnt = ins.get('KN', 1)
            for src, dst in (('K', 'K'), ('K1', 'K1'), ('K2', 'K2')):
                need = {'K': 1, 'K1': 2, 'K2': 3}[src]
                if cnt >= need and isinstance(ins.get(src), bytes) and isinstance(tgt.get(dst), bytes):
                    tgt[dst] = _xor(tgt[dst], ins[src], prefix)
            ins['meta'] = 'decrypts import +2'
            n += 1
    for c in proto['protos']:
        n += decrypt_strings(c, str_ops, import_op, prefix)
    return n
