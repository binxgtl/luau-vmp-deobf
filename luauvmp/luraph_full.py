"""Build-independent Luraph full-prototype devirtualisation.

This module consumes the typed multi-prototype IR emitted by the safe Luau
capture hook and an opcode-semantics map recovered from the *same* dispatcher.
Unlike :mod:`luraph_devirt`, it does not assume the v14.7 reference opcode map
and it does not stop at a single root prototype.

The output is an instruction-level pseudo-Luau IR.  It is devirtualised (every
custom opcode is replaced by its concrete dispatcher semantics), but it is not
claimed to reconstruct original local names or original structured source.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Union
import json
import math
import re


@dataclass(frozen=True)
class ProtoRef:
    id: int


@dataclass(frozen=True)
class OpaqueTable:
    text: str


Value = Union[None, bool, int, float, str, ProtoRef, OpaqueTable]


@dataclass
class Instruction:
    proto: int
    pc: int
    e: Value
    opcode: int
    p: Value
    o: Value
    h: Value
    underscore: Value
    b: Value


@dataclass
class Proto:
    id: int
    parent: int
    parent_field: int
    parent_pc: int
    instruction_count: int
    field1: Value
    field3: Value
    field5: Value
    max_register: Value
    instructions: List[Instruction] = field(default_factory=list)


@dataclass
class Program:
    protos: Dict[int, Proto]
    declared_count: int

    @property
    def instruction_count(self) -> int:
        return sum(len(p.instructions) for p in self.protos.values())


def decode_typed(token: str) -> Value:
    if token == "N":
        return None
    if token == "B0":
        return False
    if token == "B1":
        return True
    if token.startswith("D"):
        value = float(token[1:])
        if value.is_integer() and abs(value) <= 2**53:
            return int(value)
        return value
    if token.startswith("S"):
        return bytes.fromhex(token[1:]).decode("utf-8", "surrogateescape")
    if token.startswith("P") and token[1:].isdigit():
        return ProtoRef(int(token[1:]))
    if token.startswith("T{"):
        return OpaqueTable(token)
    return OpaqueTable(token)


def parse_full_ir(lines: Iterable[str]) -> Program:
    protos: Dict[int, Proto] = {}
    declared = 0
    for raw in lines:
        line = raw.rstrip("\n")
        if not line:
            continue
        cols = line.split("\t")
        tag = cols[0]
        if tag == "META" and len(cols) >= 3 and cols[1] == "protos":
            declared = int(cols[2])
        elif tag == "P":
            if len(cols) != 10:
                raise ValueError("bad proto row: %r" % line[:200])
            pid = int(cols[1])
            protos[pid] = Proto(pid, int(cols[2]), int(cols[3]), int(cols[4]),
                                int(cols[5]), decode_typed(cols[6]),
                                decode_typed(cols[7]), decode_typed(cols[8]),
                                decode_typed(cols[9]))
        elif tag == "I":
            if len(cols) != 10:
                raise ValueError("bad instruction row: %r" % line[:200])
            pid = int(cols[1])
            if pid not in protos:
                raise ValueError("instruction precedes proto %d" % pid)
            opv = decode_typed(cols[4])
            if not isinstance(opv, int):
                raise ValueError("opcode is not an integer at proto %d pc %s" % (pid, cols[2]))
            protos[pid].instructions.append(Instruction(
                pid, int(cols[2]), decode_typed(cols[3]), opv,
                decode_typed(cols[5]), decode_typed(cols[6]),
                decode_typed(cols[7]), decode_typed(cols[8]),
                decode_typed(cols[9])))
    if declared and declared != len(protos):
        raise ValueError("IR declares %d protos but contains %d" % (declared, len(protos)))
    for p in protos.values():
        if p.instruction_count != len(p.instructions):
            raise ValueError("proto %d declares %d instructions but contains %d" %
                             (p.id, p.instruction_count, len(p.instructions)))
    return Program(protos, declared or len(protos))


def load_full_ir(path: Union[str, Path]) -> Program:
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        return parse_full_ir(fh)


def load_semantics(path: Union[str, Path]) -> Dict[int, str]:
    data = json.load(open(path, encoding="utf-8"))
    out: Dict[int, str] = {}
    for key, value in data.items():
        out[int(key)] = value if isinstance(value, str) else value.get("source", "")
    return out


def lua_quote(s: str) -> str:
    raw = s.encode("utf-8", "surrogateescape")
    pieces = ['"']
    for b in raw:
        if b == 34:
            pieces.append('\\"')
        elif b == 92:
            pieces.append('\\\\')
        elif b == 10:
            pieces.append('\\n')
        elif b == 13:
            pieces.append('\\r')
        elif b == 9:
            pieces.append('\\t')
        elif 32 <= b <= 126:
            pieces.append(chr(b))
        else:
            pieces.append("\\%03d" % b)
    pieces.append('"')
    return "".join(pieces)


def render_value(value: Value) -> str:
    if value is None:
        return "nil"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, ProtoRef):
        return "PROTO[%d]" % value.id
    if isinstance(value, OpaqueTable):
        return "__opaque(%s)" % lua_quote(value.text)
    if isinstance(value, str):
        return lua_quote(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "(0/0)"
        if math.isinf(value):
            return "math.huge" if value > 0 else "-math.huge"
        return repr(value)
    return str(value)


_HELPERS = {
    7: "__get_env", 10: "coroutine.wrap", 22: "bit32.bxor",
    27: "__unpack_range", 30: "__bind_upvalues", 34: "table.create",
    40: "table.move", 49: "__pack_varargs", 50: "__make_closure",
}


def _replace_helpers(text: str) -> str:
    for idx, name in _HELPERS.items():
        text = re.sub(r"\bA\[%d(?:\.0)?\]" % idx, name, text)
    return re.sub(r"\bA\[32(?:\.0)?\]", "VMCONST", text)


def substitute_semantics(source: str, ins: Instruction) -> str:
    vals = {
        "E": render_value(ins.e), "p": render_value(ins.p),
        "o": render_value(ins.o), "H": render_value(ins.h),
        "_": render_value(ins.underscore), "B": render_value(ins.b),
    }
    text = source
    for name in ("E", "p", "o", "H", "_", "B"):
        text = re.sub(r"\b%s\[u\]" % re.escape(name), lambda _m, v=vals[name]: v, text)
    text = re.sub(r"\bX\b", str(ins.opcode), text)
    text = re.sub(r"\bu\b", "pc", text)
    text = re.sub(r"\bc\b", "R", text)
    return _replace_helpers(text).strip()


_MANUAL_NAMES = {
    4: "LOADNIL", 12: "LEN", 14: "RETURN1", 16: "GETTABLE_K",
    28: "GETGLOBAL", 41: "VARARG_COPY", 43: "CALL_GENERIC",
    46: "ADD_RR", 47: "NOT", 62: "MOVE", 75: "RETURN_RANGE",
    78: "LOADNIL_RANGE", 81: "NEWTABLE_ARRAY", 82: "NEWTABLE",
    84: "FORLOOP", 85: "TFORLOOP", 95: "RETURN0", 102: "EQ_RR",
    106: "SETGLOBAL", 107: "SELF_K", 110: "SETTABLE_KR",
    113: "SETTABLE_KK", 117: "GETTABLE_R", 131: "UNM",
    147: "SETUPVAL", 151: "GETUPVAL_R", 152: "SETTABLE_RR",
    153: "GETUPVAL", 158: "SETTABLE_RK", 174: "LOADK",
    182: "TEST_TRUE", 186: "JMP", 190: "CLOSURE",
    197: "TEST_FALSE", 214: "LOAD_VMCONST", 216: "VARARG_PREP",
}


def infer_name(opcode: int, source: str) -> str:
    if opcode in _MANUAL_NAMES:
        return _MANUAL_NAMES[opcode]
    compact = re.sub(r"\s+", "", source)
    if not compact:
        return "NOP"
    if "return" in source:
        return "RETURN_FRAGMENT"
    if re.search(r"\bu\s*=", source):
        return "BRANCH_FRAGMENT"
    if "c[" in source or "(c)[" in source:
        return "REGISTER_OP"
    return "STATE_FRAGMENT"


def render_instruction(ins: Instruction, semantics: Mapping[int, str]) -> str:
    source = semantics.get(ins.opcode)
    if source is None:
        raise KeyError("missing semantics for opcode %d" % ins.opcode)
    name = infer_name(ins.opcode, source)
    body = substitute_semantics(source, ins)
    fields = "E=%s p=%s o=%s H=%s _=%s B=%s" % tuple(
        render_value(x) for x in (ins.e, ins.p, ins.o, ins.h, ins.underscore, ins.b))
    lines = ["%06d  %-20s ; op=%d %s" % (ins.pc, name, ins.opcode, fields)]
    lines.extend("          " + ln for ln in body.splitlines()) if body else lines.append("          -- no state change")
    return "\n".join(lines)


def render_proto(proto: Proto, semantics: Mapping[int, str]) -> str:
    out = [
        "-- proto %d parent=%d field=%d pc=%d instructions=%d maxreg=%s" %
        (proto.id, proto.parent, proto.parent_field, proto.parent_pc,
         len(proto.instructions), render_value(proto.max_register)),
        "-- Direct dispatcher semantics. R=register file, pc=VM program counter.", ""]
    out.extend(render_instruction(ins, semantics) for ins in proto.instructions)
    return "\n".join(out) + "\n"


def write_program(program: Program, semantics: Mapping[int, str], out_dir: Union[str, Path]) -> dict:
    out_dir = Path(out_dir)
    proto_dir = out_dir / "protos"
    proto_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "prototypes": len(program.protos),
        "instructions": program.instruction_count,
        "opcode_slots": len({i.opcode for p in program.protos.values() for i in p.instructions}),
        "files": [],
    }
    for pid in sorted(program.protos):
        path = proto_dir / ("proto_%04d.pseudo.lua" % pid)
        path.write_text(render_proto(program.protos[pid], semantics), encoding="utf-8", errors="surrogateescape")
        manifest["files"].append(str(path.relative_to(out_dir)))
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    with (out_dir / "all_protos.index.txt").open("w", encoding="utf-8") as fh:
        for pid in sorted(program.protos):
            p = program.protos[pid]
            fh.write("proto %d parent=%d parent_pc=%d instructions=%d\n" %
                     (pid, p.parent, p.parent_pc, len(p.instructions)))
    return manifest
