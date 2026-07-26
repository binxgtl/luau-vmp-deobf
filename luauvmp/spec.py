"""The VM specification: everything the protector randomises per build.

A spec can be produced automatically (`luauvmp.analyse`) or loaded from a JSON
profile.  Auto-analysis fills in what it can prove from the loader; anything it
cannot prove is reported so it can be pinned in a profile by hand.
"""
import json


CANONICAL_OPS = [
    'MOVE', 'LOADNIL', 'LOADB', 'LOADN', 'LOADK', 'GETIMPORT',
    'GETTABLE', 'SETTABLE', 'GETTABLEKS', 'SETTABLEKS', 'GETTABLEN', 'SETTABLEN',
    'NAMECALL', 'CALL', 'RETURN',
    'JUMP', 'JUMPIF', 'JUMPIFNOT', 'JUMPIFEQ', 'JUMPIFNOTEQ', 'JUMPIFLE',
    'JUMPIFNOTLE', 'JUMPIFLT', 'JUMPIFNOTLT', 'JUMPXEQKNIL', 'JUMPXEQKB',
    'JUMPXEQKS',
    'ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'ADDK', 'SUBK', 'MULK', 'DIVK', 'MODK',
    'AND', 'OR', 'ANDK', 'ORK', 'NOT', 'MINUS', 'CONCAT', 'LEN',
    'NEWTABLE', 'SETLIST', 'GETUPVAL', 'SETUPVAL', 'CLOSEUPVALS',
    'NEWCLOSURE', 'NEWCLOSURE2', 'GETVARARGS',
    'FORNPREP', 'FORNLOOP', 'FORGPREP', 'FORGPREP_F', 'FORGLOOP',
    'NOP', 'DECSTR', 'DECIMPORT',
]


class Spec:
    """Container format + opcode map for one protected build."""

    def __init__(self, **kw):
        # container keys
        self.byte_key = 0
        self.word_key = 0
        self.varint_key = 0
        # operand layout type codes (from the 256-entry info table)
        self.type_abc = 1
        self.type_ad = 7
        self.type_ae = 2
        # constant-mode codes
        self.kmode_D = 0
        self.kmode_E = 1
        self.kmode_auxbool = 2
        self.kmode_aux16 = 3
        self.kmode_import = 4
        self.kmode_aux24 = 5
        self.kmode_B = 6
        self.kmode_aux = 7
        self.kmode_none = 8
        self.kmode_A = 9
        self.kmode_C = 10
        # constant type codes
        self.const_types = {}
        # 256 x [type, kmode, hasaux]
        self.opinfo = []
        # opcode number -> canonical name
        self.ops = {}
        # opcode -> {'xor': {field: mask}} for handlers with baked operand masks
        self.masks = {}
        # canonical name -> [field, ...] in canonical operand order
        self.roles = {}
        # opcode -> {reference field: this build's field}
        self.fieldmap = {}
        # runtime instruction mutation: "op,C" -> [new_op, xor_A, xor_B]
        self.mutations = {}
        # DECSTR / DECIMPORT: how far ahead the patched instruction sits
        self.dec_offset = {}
        # per-string XOR key prefix
        self.str_prefix = b''
        self.__dict__.update(kw)

    # ------------------------------------------------------------------ lookup
    def name(self, op):
        return self.ops.get(op)

    def mutation_rules(self):
        out = {}
        for k, v in self.mutations.items():
            if isinstance(k, str):
                a, b = k.split(',')
                k = (int(a), int(b))
            out[k] = tuple(v)
        return out

    def ops_named(self, name):
        return [o for o, n in self.ops.items() if n == name]

    # ------------------------------------------------------------------ io
    def to_json(self):
        d = dict(self.__dict__)
        d['const_types'] = {str(k): v for k, v in self.const_types.items()}
        d['ops'] = {str(k): v for k, v in self.ops.items()}
        d['fieldmap'] = {str(k): v for k, v in self.fieldmap.items()}
        d['masks'] = {str(k): v for k, v in self.masks.items()}
        d['mutations'] = {('%d,%d' % k if isinstance(k, tuple) else k): list(v)
                          for k, v in self.mutations.items()}
        d['str_prefix'] = list(self.str_prefix)
        return json.dumps(d, indent=1)

    @classmethod
    def from_json(cls, text):
        d = json.loads(text)
        d['const_types'] = {int(k): v for k, v in d.get('const_types', {}).items()}
        d['ops'] = {int(k): v for k, v in d.get('ops', {}).items()}
        d['fieldmap'] = {int(k): v for k, v in d.get('fieldmap', {}).items()}
        d['masks'] = {int(k) if str(k).lstrip('-').isdigit() else k: v
                      for k, v in d.get('masks', {}).items()}
        d['str_prefix'] = bytes(d.get('str_prefix', []))
        return cls(**d)

    @classmethod
    def load(cls, path):
        with open(path, encoding='utf-8') as fh:
            return cls.from_json(fh.read())

    def save(self, path):
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(self.to_json())

    # ------------------------------------------------------------------ checks
    def validate(self):
        missing = []
        if not self.opinfo or len(self.opinfo) != 256:
            missing.append('opinfo (256-entry opcode table)')
        if not self.const_types:
            missing.append('const_types')
        if not self.ops:
            missing.append('ops (opcode -> canonical name)')
        for need in ('DECSTR', 'DECIMPORT', 'CALL', 'RETURN'):
            if not self.ops_named(need):
                missing.append('opcode for %s' % need)
        return missing
