"""Luraph v14.x unpacker.

Luraph does not wrap Luau bytecode the way luau-vmp does; it compiles the
script into its own custom VM bytecode and ships that inside an obfuscated
loader.  The loader is a single base85 payload that expands (through a range
coder) into two streams:

  * the VM interpreter  - a Luau *source* string that is loadstring'ed
  * the VM bytecode     - the custom bytecode blob handed to the interpreter

This module implements the static side of that loader so both streams can be
recovered without executing anything.
"""

import re
import struct

# Luraph marker used in the header (""LPH"" + version byte)
MAGIC = b"LPH"

# Probability tables in the range coder are initialised to 1024; every
# arithmetic primitive mirrors the Lua source recovered from a v14.7 sample.
_INIT = 1024.0


def detect(source):
    """Return True when *source* looks like a Luraph v14.x loader."""
    if "LPH" not in source:
        return False
    # base85 decode helper signature - present in every v14.x loader
    if "52200625" not in source and "*614125" not in source:
        return False
    # two [==[ ... ]==] payload literals (small interpreter + big bytecode)
    return len(re.findall(r"\[==\[.*?\]==\]", source, re.S)) >= 2


def extract_payloads(source):
    """Return the raw [==[ ]==] payload strings, in order."""
    return re.findall(r"\[==\[(.*?)\]==\]", source, re.S)


def decode_base85(payload, drop=5):
    """Decode one Luraph base85 blob.

    The loader strips the leading 4-byte magic (``string.sub(P, 5)``), then
    replaces the zero-run marker ``z`` with five ``!`` characters and finally
    maps every 5-character group to 4 little-endian bytes:

        H = (b5-33) + (b4-33)*85 + (b3-33)*7225
          + (b2-33)*614125 + (b1-33)*52200625
    """
    data = payload[drop - 1:]
    data = data.replace("z", "!!!!!")
    out = bytearray()
    n = len(data)
    for i in range(0, n - 4, 5):
        b1, b2, b3, b4, b5 = (ord(c) for c in data[i:i + 5])
        value = ((b5 - 33) + (b4 - 33) * 85 + (b3 - 33) * 7225
                 + (b2 - 33) * 614125 + (b1 - 33) * 52200625)
        out += struct.pack("<I", value & 0xFFFFFFFF)
    return bytes(out)


def decompress(data):
    """Adaptive range-coder + LZ77 decompressor used by Luraph v14.7.

    Faithful port of the decoder recovered from the loader (the ``R`` local
    in the sample).  Returns the raw bytes, or ``False`` when the stream is
    corrupt and decoding aborted early.
    """

    size = len(data)
    pos = 0

    def next_byte():
        nonlocal pos
        b = data[pos]
        pos += 1
        return b

    # state machine for the literal/match state (index 0 unused)
    f_tab = [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5]

    low = 0xFFFFFFFF
    code = 0
    for _ in range(5):
        code = code * 256 + next_byte()

    def read_bits(count):
        """Decode *count* equiprobable bits (binary mode)."""
        nonlocal low, code
        value = 0
        for _ in range(count, 0, -1):
            low //= 2
            value *= 2
            if not (code < low):
                code -= low
                value += 1
            if low <= 0x00FFFFFF:
                low *= 256
                code = code * 256 + next_byte()
        return value

    def decode_bit(table, index):
        """Decode one bit with an adaptive probability table."""
        nonlocal low, code
        u = low // 2048
        c = table[index]
        r = u * c
        if code < r:
            low = r
            u = (2048 - c) // 32
            c += u
            bit = 0
        else:
            low -= r
            u = c // 32
            code -= r
            c -= u
            bit = 1
        table[index] = c
        if low <= 0x00FFFFFF:
            low *= 256
            code = code * 256 + next_byte()
        return bit

    def decode_unary(table, base, count):
        index = 1
        for _ in range(1, count + 1):
            index = index * 2 + decode_bit(table, index)
        return index - base

    def decode_tree(table, bits, offset=0):
        value = 0
        index = 1
        for _ in range(0, bits):
            b = decode_bit(table, index + offset)
            index = index * 2 + b
            value = value * 2 + b
        return value

    def decode_tree_lsb(table, bits, offset=0):
        """H_func: decode *bits* with a tree whose bits accumulate LSB-first."""
        value = 0
        index = 1
        for b in range(0, bits):
            bit = decode_bit(table, offset + index)
            index = index * 2 + bit
            value += bit * (1 << b)
        return value

    def decode_matched(context, table):
        """Decode a byte when the high bits match a predicted byte."""
        u = 1
        for c in range(7, -1, -1):
            b = (context >> c) & 1
            bit = decode_bit(table, u + b * 256 + 256)
            u = u * 2 + bit
            if b != bit:
                while u < 0x100:
                    u = u * 2 + decode_bit(table, u)
                break
        return u % 256

    def decode_length(table, index):
        if decode_bit(table, 1) == 0:
            return decode_unary(table[3][index], 8, 3)
        if decode_bit(table, 2) == 0:
            return 8 + decode_unary(table[4][index], 8, 3)
        return decode_unary(table[5], 256, 8) + 16

    def row(rows, cols):
        return [[_INIT] * cols for _ in range(rows)]

    def col(count):
        return [_INIT] * count

    def dist_model():
        return [None, _INIT, _INIT, row(1, 8), row(1, 8), col(256)]

    contexts = row(8, 0x300)          # literal context tables (8 x 768)
    state = row(12, 1)                # state bit tables (12 x 1)
    length_low = col(12)              # length coder tables
    length_mid = col(12)
    length_high = col(12)
    dist_slot = col(12)
    dist_special = row(12, 1)
    dist_align = row(4, 64)
    length_low2 = col(115)
    length_mid2 = col(16)
    dist_model_low = dist_model()
    len_model_high = dist_model()
    rep0 = 0
    rep1 = 0
    rep2 = 0
    rep3 = 0
    out = [0]
    length = 0
    state_idx = 0

    while pos <= size:
        if decode_bit(state[state_idx], 0) == 0:
            # literal byte
            ctx = out[length]
            table = contexts[ctx // 32]
            length += 1
            if state_idx < 7:
                out.append(decode_tree(table, 8))
            else:
                out.append(decode_matched(out[length - rep0 - 1], table))
            state_idx = f_tab[state_idx]
        else:
            match_len = None
            if decode_bit(length_low, state_idx) != 0:
                if decode_bit(length_mid, state_idx) == 0:
                    if decode_bit(dist_special[state_idx], 0) == 0:
                        state_idx = 9 if state_idx < 7 else 11
                        match_len = 1
                else:
                    if decode_bit(length_high, state_idx) == 0:
                        rep = rep1
                    else:
                        if decode_bit(dist_slot, state_idx) == 0:
                            rep = rep2
                        else:
                            rep = rep3
                            rep3 = rep2
                        rep2 = rep1
                    rep1 = rep0
                    rep0 = rep
                if match_len is None:
                    state_idx = 8 if state_idx < 7 else 11
                    match_len = 2 + decode_length(len_model_high, 0)
            else:
                rep3 = rep2
                rep2 = rep1
                rep1 = rep0
                match_len = 2 + decode_length(dist_model_low, 0)
                slot = match_len - 2
                if 4 <= slot:
                    slot = 3
                rep0 = decode_tree(dist_align[slot], 6)
                if rep0 >= 4:
                    slot = rep0
                    bits = slot // 2 - 1
                    rep0 = (2 + slot % 2) * (1 << bits)
                    if slot < 14:
                        rep0 += decode_tree_lsb(length_low2, bits, rep0 - slot)
                    else:
                        rep0 = (rep0 + read_bits(bits - 4) * 16
                                + decode_tree_lsb(length_mid2, 4))
                        if rep0 == 0xFFFFFFFF:
                            return bytes(out[1:length + 1])
                state_idx = 7 if state_idx < 7 else 10
                if rep0 >= length:
                    return False
            end = length + match_len
            for i in range(length + 1, end + 1):
                out.append(out[i - rep0 - 1])
            length = end

    result = bytearray()
    i = 1
    while i <= length:
        end = i + 7996
        if end > length:
            end = length
        result += bytes(out[i:end + 1])
        i += 7997
    return bytes(result)


def unpack(source):
    """Unpack a Luraph v14.x loader.

    Returns ``(vm_source, bytecode)`` - the loadstring'ed VM interpreter and
    the custom bytecode blob handed to it.
    """
    payloads = extract_payloads(source)
    if len(payloads) < 2:
        raise ValueError("expected two Luraph payloads, found %d" % len(payloads))
    streams = []
    for payload in payloads:
        coded = decode_base85(payload, drop=5)
        try:
            streams.append(decompress(coded))
        except (IndexError, ValueError):
            # truncated / corrupt range-coder stream
            streams.append(False)
    vm, bytecode = streams[0], streams[1]
    if vm is False or bytecode is False:
        raise ValueError("Luraph stream decompression aborted (corrupt loader?)")
    return vm, bytecode
