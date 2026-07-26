"""Stage 4 - unpack the payload and deserialise the bytecode container.

    base64  ->  LZSS  ->  proto tree

The LZSS variant and the container layout are both described by a `Spec`
recovered in stage 3, so a build that rolls different keys still parses.
"""
import base64
import struct


# --------------------------------------------------------------------------- lzss
def lua_sub(s, i, j=None):
    """Lua's string.sub index semantics, which the decompressor depends on."""
    n = len(s)
    if j is None:
        j = n
    if i < 0:
        i = max(n + i + 1, 1)
    elif i == 0:
        i = 1
    if j < 0:
        j = n + j + 1
    elif j > n:
        j = n
    return b'' if i > j else s[i - 1:j]


def lzss_decompress(data, window_bits=11, len_bits=5, min_match=3):
    """Control-byte LZSS: bit set -> literal, bit clear -> big-endian offset/len pair."""
    window = 1 << window_bits
    mask = (1 << len_bits) - 1
    out, win, o, n = [], b'', 1, len(data)
    while o <= n:
        ctrl = data[o - 1]
        o += 1
        for _ in range(8):
            piece = None
            if ctrl & 1:
                if o <= n:
                    piece = lua_sub(data, o, o)
                    o += 1
            elif o + 1 <= n:
                a = (data[o - 1] << 8) | data[o]
                o += 2
                start = len(win) - (a >> len_bits)
                ln = (a & mask) + min_match
                piece = lua_sub(win, start, start + ln - 1)
            ctrl >>= 1
            if piece is not None:
                out.append(piece)
                win = lua_sub(win + piece, -window)
    return b''.join(out)


def unpack(blob, **kw):
    return lzss_decompress(base64.b64decode(blob), **kw)


# --------------------------------------------------------------------------- reader
def s16(v):
    return v - 65536 if v >= 32768 else v


def s24(v):
    return v - 16777216 if v >= 8388608 else v


class Reader:
    def __init__(self, data, spec):
        self.d = data
        self.p = 0
        self.spec = spec

    def byte(self):
        v = self.d[self.p]
        self.p += 1
        return v ^ self.spec.byte_key

    def word(self):
        v = struct.unpack_from('<I', self.d, self.p)[0]
        self.p += 4
        return v ^ self.spec.word_key

    def double(self):
        v = struct.unpack_from('<d', self.d, self.p)[0]
        self.p += 8
        return v

    def varint(self):
        val = 0
        for i in range(5):
            b = self.byte()
            val = (val | ((b & 127) << (i * 7))) & 0xFFFFFFFF
            if not b & 128:
                break
        return val ^ self.spec.varint_key

    def raw(self, n):
        v = self.d[self.p:self.p + n]
        self.p += n
        return v


def read_proto(r, spec):
    p = {
        'maxstack': r.byte(),
        'numparams': r.byte(),
        'nups': r.byte(),
    }
    # ---- code
    size = r.varint()
    code, skip, i = [], False, 0
    while i < size:
        i += 1
        if skip:
            skip = False
            code.append(None)          # slot consumed by the previous aux word
            continue
        insn = r.word()
        op = insn & 255
        typ, kmode, hasaux = spec.opinfo[op]
        ins = {'op': op, 'kmode': kmode, 'type': typ, 'aux': 0, 'raw': insn}
        code.append(ins)
        if typ == spec.type_abc:
            ins['A'] = (insn >> 8) & 255
            ins['B'] = (insn >> 16) & 255
            ins['C'] = (insn >> 24) & 255
        elif typ == spec.type_ad:
            ins['A'] = (insn >> 8) & 255
            ins['Du'] = (insn >> 16) & 65535
            ins['D'] = s16(ins['Du'])
        elif typ == spec.type_ae:
            ins['E'] = s24((insn >> 8) & 0xFFFFFF)
        if hasaux:
            ins['aux'] = r.word()
            ins['hasaux'] = True
            skip = True
    p['code'] = code
    # ---- constants
    size = r.varint()
    consts = []
    for _ in range(size):
        kt = r.byte()
        kind = spec.const_types.get(kt)
        if kind == 'double':
            consts.append(r.double())
        elif kind == 'string':
            n = r.varint()
            consts.append(r.raw(n) if n else b'')
        elif kind == 'int':
            consts.append(r.varint())
        elif kind == 'boolean':
            consts.append(r.byte() != 0)
        elif kind == 'table':
            consts.append({})
        elif kind == 'nil':
            consts.append(None)
        else:
            raise ValueError('unknown constant type %d at offset %d' % (kt, r.p))
    p['k'] = consts
    resolve_constants(code, consts, spec)
    # ---- children
    p['protos'] = [read_proto(r, spec) for _ in range(r.varint())]
    return p


def resolve_constants(code, consts, spec):
    """The reader folds constants straight into each instruction record.

    A constant mode that indexes by a field the instruction's layout never
    decoded belongs to an opcode the compiler does not emit; skip it rather than
    inventing a value.
    """
    def k(idx):
        return consts[idx] if 0 <= idx < len(consts) else None

    for ins in code:
        if not ins:
            continue
        km, aux = ins['kmode'], ins['aux']
        need = {spec.kmode_D: 'D', spec.kmode_E: 'E',
                spec.kmode_B: 'B', spec.kmode_A: 'A', spec.kmode_C: 'C'}.get(km)
        if need and need not in ins:
            continue
        if km == spec.kmode_D:
            ins['K'] = k(ins['D'])
        elif km == spec.kmode_E:
            ins['K'] = k(ins['E'])
        elif km == spec.kmode_auxbool:
            ins['K'] = (aux & 1) == 1
            ins['KC'] = ((aux >> 31) & 1) == 1
        elif km == spec.kmode_aux16:
            ins['K'] = aux & 0xFFFF
        elif km == spec.kmode_import:
            n = aux >> 30
            ins['KN'] = n
            ins['K'] = k((aux >> 20) & 1023)
            if n >= 2:
                ins['K1'] = k((aux >> 10) & 1023)
            if n == 3:
                ins['K2'] = k(aux & 1023)
        elif km == spec.kmode_aux24:
            ins['K'] = k(aux & 0xFFFFFF)
            ins['KC'] = ((aux >> 31) & 1) == 1
        elif km == spec.kmode_B:
            ins['K'] = k(ins['B'])
        elif km == spec.kmode_aux:
            ins['K'] = k(aux)
        elif km == spec.kmode_A:
            ins['K'] = k(ins['A'])
        elif km == spec.kmode_C:
            ins['K'] = k(ins['C'])


def parse(data, spec):
    r = Reader(data, spec)
    root = read_proto(r, spec)
    return root, r.p
