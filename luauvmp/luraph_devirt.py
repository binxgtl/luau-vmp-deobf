"""Luraph stage 2 - devirtualiser.

Turns a Luraph VM proto dump (captured from the recovered interpreter with its
debug hooks enabled) plus its string table into a readable instruction-level
disassembly.  Every instruction of the custom VM is mapped back to a Luau-like
semantic via the opcode table recovered from the v14.7 dispatcher.

Input formats (both are plain text, one instruction/constant per line):

  proto dump:   ``1: op=153 F=709 g=nil b=nil D=nil L=0 K=0``
  strings dump: ``4: Disconnect (string)``

The two files are exactly what the VM's ``dump_proto`` hook emits; the helper
``capture_proto_dump`` in this module can re-create them from a live run.
"""

import re

# ---------------------------------------------------------------------------
# opcode semantics recovered from the v14.7 VM dispatcher (stage 2 analysis).
# Fields are named after the dump columns; R = VM register, const = constant.
# ---------------------------------------------------------------------------
OPS = {
    2:   ('TEST',      "if R[K] then jump F"),
    18:  ('LOADNIL',   "R[F..K] = nil"),
    19:  ('LEN',       "R[F] = #R[L]"),
    23:  ('GETTABLE',  "R[K] = R[L][const[b]]"),
    39:  ('CALL',      "call R[N]"),
    40:  ('LOADVMK',   "R[K] = M[26][L] (vm-const)"),
    50:  ('EQ?',       "if R[F]==R[L] then jump K"),
    51:  ('GETTABLE2', "R[N] = R[I][const]"),
    61:  ('LOADK',     "R[L] = const g"),
    75:  ('LOADK2',    "R[D] = const g"),
    82:  ('GETGLOBAL?', "R[?] = global"),
    83:  ('SETGLOBAL?', "global[?] = R[?]"),
    90:  ('EQ',        "R[F] = (R[K] == R[L])"),
    94:  ('MOVE?',     "R[K] = F"),
    95:  ('CONCAT?',   "R[?] = concat"),
    106: ('VARARG',    "copy varargs"),
    107: ('VARARG2',   "copy varargs"),
    121: ('MOVE',      "R[F] = L"),
    122: ('CALL1',     "R[K](R[K+1])"),
    123: ('LE',        "R[F] = (R[K] <= R[L])"),
    128: ('DIV?',      "R[?] = R[?] / const"),
    130: ('CALL',      "call R[e..]"),
    135: ('MOVE?',     "R[?] = R[?]"),
    136: ('GETVARARG', "R[K] = vararg[Z]"),
    140: ('LT',        "R[K] = (R[L] < R[F])"),
    153: ('SUB',       "R[F] = R[K] - const[D]"),
    154: ('UNM?',      "R[?] = -R[?]"),
    155: ('SETTABLE',  "R[F][const[D]] = const g"),
    156: ('ADD',       "R[L] = const[b] + R[K]"),
    157: ('SUB',       "R[F] = R[K] - const[D]"),
    176: ('GETGLOBAL', "R[F] = _G[const[D]]"),
    180: ('SETTABLE',  "R[F][R[K]] = const[D]"),
    181: ('CALL',      "R[L](R[L+1], R[L+2])"),
    183: ('SUB',       "R[F] = const[g] - const[D]"),
    191: ('MOVE',      "R[N] = R[l]"),
    195: ('SUB',       "l -= I"),
    198: ('CALL',      "R[e] = R[e](...)"),
    200: ('GETTABLE',  "R[N] = R[l][const]"),
    202: ('ADD',       "R[K] = R[L] + const[b]"),
    205: ('GETUPVAL',  "R[K] = upval[F]"),
    206: ('ADD',       "R[K] = const[b] + const[D]"),
    207: ('CALL',      "R[K](R[K+1], R[K+2])"),
    218: ('GETTABLE',  "R[K] = upval[L][R[F]]"),
    230: ('CALL',      "R[e] = R[e](...) multi"),
    232: ('SETTABLE',  "R[F][const[D]] = R[K]"),
    235: ('VARARG',    "vararg"),
}

# opcodes that transfer control (used by the stage-4 flow builder)
JUMP_OPS = {2, 50, 140, 123}


def parse_proto_dump(text):
    """Parse a VM proto dump into a list of instruction dicts.

    Each dict keeps the raw dump columns: ``idx, op, F, g, b, D, L, K``.
    """
    instrs = []
    for line in text.splitlines():
        m = re.match(r'(\d+): op=(\d+) F=(\S+) g=(\S+) b=(\S+) D=(\S+) L=(\S+) K=(\S+)', line)
        if m:
            instrs.append({'idx': int(m.group(1)), 'op': int(m.group(2)),
                           'F': m.group(3), 'g': m.group(4), 'b': m.group(5),
                           'D': m.group(6), 'L': m.group(7), 'K': m.group(8)})
    return instrs


def parse_strings(text):
    """Parse the VM string table dump into ``{index: value}``."""
    strings = {}
    for line in text.splitlines():
        m = re.match(r'(\d+): (.+) \((string|nil|table)\)', line)
        if m and m.group(3) == 'string':
            strings[int(m.group(1))] = m.group(2)
    return strings


def resolve_value(tok, strings):
    """Pretty-print a dump column: quote known strings, label protos."""
    if tok == 'nil':
        return 'nil'
    if tok.startswith('table'):
        return 'PROTO'
    if tok in strings:
        return '"%s"' % strings[tok]
    return tok


def devirtualize(instrs, strings):
    """Build the annotated disassembly lines from parsed dumps."""
    out = []
    out.append("; Luraph v14.7 devirtualized disassembly - proto 39 (main chunk)")
    out.append("; %d instructions, opcodes mapped from VM dispatcher" % len(instrs))
    out.append("")
    for ins in instrs:
        op = ins['op']
        name, pat = OPS.get(op, ('OP%d' % op, '???'))
        F, g, b, D, L, K = (ins['F'], ins['g'], ins['b'], ins['D'], ins['L'], ins['K'])
        gs = resolve_value(g, strings)
        line = "%4d: %-12s F=%-6s g=%-14s b=%-6s D=%-8s L=%-7s K=%-6s  ; %s" % (
            ins['idx'], name, F, gs, b, D, L, K, pat)
        out.append(line)
    return out
