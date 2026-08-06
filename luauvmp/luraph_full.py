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
from typing import Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple, Union
import json
import math
import os
import re
import tempfile


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
    e: Value       # W[2] / E[u]
    opcode: int    # W[4] / L[u]
    p: Value       # W[6] / p[u]
    o: Value       # W[7] / o[u]
    h: Value       # W[8] / H[u]
    underscore: Value  # W[9] / _[u]
    b: Value       # W[11] / B[u]


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
    """Decode the typed cell format used by ``luraph_full_ir.tsv``."""
    if token == "N":
        return None
    if token == "B0":
        return False
    if token == "B1":
        return True
    if token.startswith("D"):
        raw = token[1:]
        value = float(raw)
        if value.is_integer() and abs(value) <= 2**53:
            return int(value)
        return value
    if token.startswith("S"):
        return bytes.fromhex(token[1:]).decode("utf-8", "surrogateescape")
    if token.startswith("P") and token[1:].isdigit():
        return ProtoRef(int(token[1:]))
    if token.startswith("T{"):
        return OpaqueTable(token)
    # F / X... and future capture types stay explicit instead of being lost.
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
            protos[pid] = Proto(
                id=pid,
                parent=int(cols[2]),
                parent_field=int(cols[3]),
                parent_pc=int(cols[4]),
                instruction_count=int(cols[5]),
                field1=decode_typed(cols[6]),
                field3=decode_typed(cols[7]),
                field5=decode_typed(cols[8]),
                max_register=decode_typed(cols[9]),
            )
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
                proto=pid, pc=int(cols[2]), e=decode_typed(cols[3]), opcode=opv,
                p=decode_typed(cols[5]), o=decode_typed(cols[6]),
                h=decode_typed(cols[7]), underscore=decode_typed(cols[8]),
                b=decode_typed(cols[9]),
            ))
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
        if isinstance(value, str):
            out[int(key)] = value
        else:
            out[int(key)] = value.get("source", "")
    return out


def lua_quote(s: str) -> str:
    """Lossless readable Lua string literal, including binary/surrogate bytes."""
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
    text = re.sub(r"\bA\[32(?:\.0)?\]", "VMCONST", text)
    return text


def substitute_semantics(source: str, ins: Instruction) -> str:
    """Substitute the current instruction's decoded operand cells."""
    vals = {
        "E": render_value(ins.e),
        "p": render_value(ins.p),
        "o": render_value(ins.o),
        "H": render_value(ins.h),
        "_": render_value(ins.underscore),
        "B": render_value(ins.b),
    }
    text = source
    # Replace indexed operands before replacing standalone PC/opcode symbols.
    for name in ("E", "p", "o", "H", "_", "B"):
        text = re.sub(r"\b%s\[u\]" % re.escape(name), lambda _m, v=vals[name]: v, text)
    text = re.sub(r"\bX\b", str(ins.opcode), text)
    text = re.sub(r"\bu\b", "pc", text)
    text = re.sub(r"\bc\b", "R", text)
    text = _replace_helpers(text)
    return text.strip()


_MANUAL_NAMES = {
    4: "LOADNIL", 6: "SUB_RR", 10: "CALL2_NORET", 12: "LEN",
    14: "RETURN1", 16: "GETTABLE_K", 21: "MUL_KR", 23: "JLE_RR",
    27: "SETUPVAL_K", 28: "GETGLOBAL", 31: "JLT_RR", 34: "GT_RR",
    35: "DIV_RR", 41: "VARARG_COPY", 43: "CALL_GENERIC", 44: "MOD_RK",
    46: "ADD_RR", 47: "NOT", 52: "JLT_KR", 53: "JNE_RK",
    54: "JLE_RR", 56: "TABLE_MOVE", 57: "GE_KK", 60: "GETUPVAL_K",
    62: "MOVE", 70: "BXOR", 75: "RETURN_RANGE", 77: "CONCAT_KR",
    78: "LOADNIL_RANGE", 79: "GE_RR", 81: "NEWTABLE_ARRAY",
    82: "NEWTABLE", 83: "SUB_KK", 84: "FORLOOP", 85: "TFORLOOP",
    86: "EQ_KK", 87: "EQ_RK", 89: "RETURN_MULTI", 93: "CALL2_RET1",
    95: "RETURN0", 98: "MUL_RK", 99: "TAILCALL1", 102: "EQ_RR",
    104: "MOD_RR", 105: "CALL_MULTI_NORET", 106: "SETGLOBAL",
    107: "SELF_K", 110: "SETTABLE_KR", 113: "SETTABLE_KK",
    114: "JLE_RK", 117: "GETTABLE_R", 121: "JLT_RR", 122: "JLE_KR",
    127: "MUL_RR", 128: "SUB_RK", 130: "CALL_MULTI_NORET",
    131: "UNM", 132: "LT_KR", 134: "NE_KR", 135: "POW_KR",
    136: "CALL1_RET1", 137: "CALL1_NORET", 138: "CALL0_NORET",
    146: "JLT_RK", 147: "SETUPVAL", 151: "GETUPVAL_R",
    152: "SETTABLE_RR", 153: "GETUPVAL", 156: "LE_RR",
    157: "GE_RK", 158: "SETTABLE_RK", 160: "JEQ_RR",
    166: "ADD_KR", 167: "LT_RR", 168: "NE_RR", 170: "CALL_MULTI_RET1",
    172: "JLE_RK", 173: "ADD_KK", 174: "LOADK", 176: "SETUPVAL_KK",
    177: "JNE_RR", 178: "SUB_KR", 182: "TEST_TRUE", 186: "JMP",
    187: "JLE_KR", 188: "SETUPVAL_TABLE", 189: "ADD_RK",
    190: "CLOSURE", 192: "GT_RK", 193: "GE_KR", 194: "CONCAT_RK",
    195: "SETUPVAL_RR", 197: "TEST_FALSE", 201: "LT_KK",
    202: "JNE_KR", 203: "NE_RK", 204: "LE_RK", 206: "CALL_MULTI_RET1",
    207: "CONCAT_RR", 208: "LE_KK", 209: "LT_RK", 210: "TAILCALL0",
    212: "BXOR_RR", 214: "LOAD_VMCONST", 216: "VARARG_PREP",
    219: "GT_KR", 220: "JLT_KR", 222: "JEQ_RK", 226: "CALL0_RET1",
    227: "LE_KR",
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


def _prepare_semantic(source: str) -> str:
    """Pre-normalise one dispatcher body once per opcode.

    Older versions repeatedly ran the helper and identifier regular expressions
    for every instruction. Large captures can contain more than 100k
    instructions, so doing this once per used opcode removes the dominant
    writer cost without changing the emitted text.
    """
    return _replace_helpers(source)


def prepare_semantics(semantics: Mapping[int, str]) -> Dict[int, Tuple[str, str]]:
    """Return ``opcode -> (display_name, prepared_source)``."""
    return {
        int(op): (infer_name(int(op), source), _prepare_semantic(source))
        for op, source in semantics.items()
    }


def substitute_prepared(source: str, ins: Instruction) -> str:
    """Fast operand substitution for a pre-normalised semantic body."""
    vals = {
        "E[u]": render_value(ins.e),
        "p[u]": render_value(ins.p),
        "o[u]": render_value(ins.o),
        "H[u]": render_value(ins.h),
        "_[u]": render_value(ins.underscore),
        "B[u]": render_value(ins.b),
    }
    text = source
    # Exact string replacement is substantially faster than six regex scans and
    # is safe because the capture format uses these canonical operand tokens.
    for token, value in vals.items():
        text = text.replace(token, value)
    text = re.sub(r"\bX\b", str(ins.opcode), text)
    text = re.sub(r"\bu\b", "pc", text)
    text = re.sub(r"\bc\b", "R", text)
    return text.strip()


def render_instruction(ins: Instruction, semantics: Mapping[int, str],
                       prepared: Optional[Mapping[int, Tuple[str, str]]] = None) -> str:
    source = semantics.get(ins.opcode)
    if source is None:
        raise KeyError("missing semantics for opcode %d" % ins.opcode)
    if prepared is None:
        name = infer_name(ins.opcode, source)
        body = substitute_semantics(source, ins)
    else:
        try:
            name, source = prepared[ins.opcode]
        except KeyError:
            raise KeyError("missing prepared semantics for opcode %d" % ins.opcode)
        body = substitute_prepared(source, ins)
    fields = "E=%s p=%s o=%s H=%s _=%s B=%s" % tuple(render_value(x) for x in
             (ins.e, ins.p, ins.o, ins.h, ins.underscore, ins.b))
    lines = ["%06d  %-20s ; op=%d %s" % (ins.pc, name, ins.opcode, fields)]
    if body:
        lines.extend("          " + ln for ln in body.splitlines())
    else:
        lines.append("          -- no state change")
    return "\n".join(lines)


def iter_render_proto(proto: Proto, semantics: Mapping[int, str],
                      prepared: Optional[Mapping[int, Tuple[str, str]]] = None) -> Iterator[str]:
    """Yield a prototype incrementally instead of building one giant string."""
    yield "-- proto %d parent=%d field=%d pc=%d instructions=%d maxreg=%s\n" % (
        proto.id, proto.parent, proto.parent_field, proto.parent_pc,
        len(proto.instructions), render_value(proto.max_register))
    yield "-- Direct dispatcher semantics. R=register file, pc=VM program counter.\n\n"
    for ins in proto.instructions:
        yield render_instruction(ins, semantics, prepared)
        yield "\n"


def render_proto(proto: Proto, semantics: Mapping[int, str]) -> str:
    prepared = prepare_semantics(semantics)
    return "".join(iter_render_proto(proto, semantics, prepared))


def _atomic_text_writer(path: Path):
    """Open a UTF-8 temporary file and atomically replace *path* on success."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    return os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape"), Path(tmp_name)


def _commit_atomic(fh, tmp: Path, target: Path) -> None:
    fh.flush()
    os.fsync(fh.fileno())
    fh.close()
    os.replace(str(tmp), str(target))
    os.chmod(target, 0o644)


def write_program(program: Program, semantics: Mapping[int, str], out_dir: Union[str, Path],
                  split_protos: bool = False, bundle_name: str = "program.pseudo.lua") -> dict:
    """Write the devirtualised program efficiently.

    The default release layout is one streaming bundle plus an index.  This
    avoids creating thousands of files and keeps large captures bounded in
    memory. ``split_protos=True`` additionally emits the historical per-proto
    files for workflows that need them.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    prepared = prepare_semantics(semantics)
    used_opcodes = {i.opcode for p in program.protos.values() for i in p.instructions}
    missing = sorted(used_opcodes.difference(prepared))
    if missing:
        raise KeyError("missing semantics for opcode(s): %s" % ", ".join(map(str, missing)))

    manifest = {
        "format_version": 2,
        "prototypes": len(program.protos),
        "instructions": program.instruction_count,
        "opcode_slots": len(used_opcodes),
        "output_mode": "bundle+split" if split_protos else "bundle",
        "bundle": bundle_name,
        "files": [bundle_name, "all_protos.index.txt"],
    }

    bundle = out_dir / bundle_name
    fh, tmp = _atomic_text_writer(bundle)
    try:
        fh.write("-- Luraph full-prototype devirtualisation bundle\n")
        fh.write("-- prototypes=%d instructions=%d opcode_slots=%d\n\n" % (
            manifest["prototypes"], manifest["instructions"], manifest["opcode_slots"]))
        for pid in sorted(program.protos):
            fh.writelines(iter_render_proto(program.protos[pid], semantics, prepared))
            fh.write("\n")
        _commit_atomic(fh, tmp, bundle)
    except Exception:
        try:
            fh.close()
        finally:
            tmp.unlink(missing_ok=True)
        raise

    if split_protos:
        proto_dir = out_dir / "protos"
        proto_dir.mkdir(parents=True, exist_ok=True)
        for pid in sorted(program.protos):
            path = proto_dir / ("proto_%04d.pseudo.lua" % pid)
            pfh, ptmp = _atomic_text_writer(path)
            try:
                pfh.writelines(iter_render_proto(program.protos[pid], semantics, prepared))
                _commit_atomic(pfh, ptmp, path)
            except Exception:
                try:
                    pfh.close()
                finally:
                    ptmp.unlink(missing_ok=True)
                raise
            manifest["files"].append(str(path.relative_to(out_dir)))

    index = out_dir / "all_protos.index.txt"
    ifh, itmp = _atomic_text_writer(index)
    try:
        for pid in sorted(program.protos):
            p = program.protos[pid]
            ifh.write("proto %d parent=%d parent_pc=%d instructions=%d\n" %
                      (pid, p.parent, p.parent_pc, len(p.instructions)))
        _commit_atomic(ifh, itmp, index)
    except Exception:
        try:
            ifh.close()
        finally:
            itmp.unlink(missing_ok=True)
        raise

    manifest_path = out_dir / "manifest.json"
    mfh, mtmp = _atomic_text_writer(manifest_path)
    try:
        json.dump(manifest, mfh, indent=2, sort_keys=True)
        mfh.write("\n")
        _commit_atomic(mfh, mtmp, manifest_path)
    except Exception:
        try:
            mfh.close()
        finally:
            mtmp.unlink(missing_ok=True)
        raise
    return manifest
