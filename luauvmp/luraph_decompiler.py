"""Compile-checked Luau source backend for sample-local Luraph captures."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Optional, Sequence, Tuple, Union
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile

from .luraph_full import (
    Instruction, Program, Proto, prepare_semantics, substitute_prepared,
)
from .luraph_lift import clean_statement, decode_branch, return_expression


class DecompileError(RuntimeError):
    """Raised when source generation or compile validation fails."""


@dataclass(frozen=True)
class Block:
    start: int
    instructions: Tuple[Instruction, ...]
    fallthrough: Optional[int]


def build_blocks(proto: Proto, semantics: Mapping[int, str]) -> List[Block]:
    if not proto.instructions:
        return []
    pcs = [ins.pc for ins in proto.instructions]
    index = {pc: i for i, pc in enumerate(pcs)}
    leaders, terminators = {pcs[0]}, set()
    for i, ins in enumerate(proto.instructions):
        source = semantics[ins.opcode]
        branch = decode_branch(source, ins)
        if branch is None and return_expression(source, ins) is None:
            continue
        terminators.add(ins.pc)
        if branch is not None and branch.target in index:
            leaders.add(branch.target)
        if i + 1 < len(pcs):
            leaders.add(pcs[i + 1])
    starts = sorted(leaders, key=index.__getitem__)
    blocks = []
    for n, start in enumerate(starts):
        begin = index[start]
        limit = index[starts[n + 1]] if n + 1 < len(starts) else len(pcs)
        end = limit
        for pos in range(begin, limit):
            if pcs[pos] in terminators:
                end = pos + 1
                break
        blocks.append(Block(start, tuple(proto.instructions[begin:end]),
                            pcs[end] if end < len(pcs) else None))
    return blocks


def _indent(text: str) -> List[str]:
    return ["            " + line if line else "            "
            for line in text.splitlines()]


def _raw(ins: Instruction, prepared: Mapping[int, Tuple[str, str]]) -> str:
    _name, semantic = prepared[ins.opcode]
    body = substitute_prepared(semantic, ins)
    return re.sub(r"^\s*local\s+W\s*=\s*57(?:\.0)?\s*;\s*", "", body)


def decompile_proto(proto: Proto, semantics: Mapping[int, str],
                    prepared: Mapping[int, Tuple[str, str]]) -> Tuple[str, dict]:
    blocks = build_blocks(proto, semantics)
    maxreg = int(proto.max_register) if isinstance(proto.max_register, int) else 0
    lines, clean_count, fallback_count = [], 0, 0
    lines.extend([
        "PROTO[%d] = function(__captured, __env, ...)" % proto.id,
        "    local I = __captured or {}",
        "    __env = __env or getfenv()",
        "    local R = table.create(%d)" % max(1, maxreg + 1),
        "    local argv = table.pack(...)",
        "    for argi = 1, argv.n do R[argi - 1] = argv[argi] end",
        "    local pc = %d" % (blocks[0].start if blocks else 1),
        "    local Z = -1",
        "    local e = {}",
        "    local __open_upvalues = {}",
        "    local m, O, U, Y, r, k, F, J, d, C, S, N, b, K",
        "    local L, H, W, X, V, n, h, q, y, j, t, a, i, k, x, v, s",
        "    local M, T, g, z, P, B, w, l, Q, G",
        "    local __s_A, __s_I, __s_E, __s_p, __s_o, __s_H, __s__, __s_B",
        "    local __s_L, __s_X, __s_c, __s_u, __s_R",
    ])
    if not blocks:
        return "\n".join(lines + ["    return", "end"]), {
            "blocks": 0, "clean_instructions": 0, "fallback_instructions": 0,
        }
    lines.append("    while true do")
    for block_index, block in enumerate(blocks):
        lines.append("        %s pc == %d then" %
                     ("if" if block_index == 0 else "elseif", block.start))
        terminated = False
        for pos, ins in enumerate(block.instructions):
            source = semantics[ins.opcode]
            branch, ret = decode_branch(source, ins), return_expression(source, ins)
            next_pc = (block.instructions[pos + 1].pc
                       if pos + 1 < len(block.instructions) else block.fallthrough)
            lines.append("            -- pc=%d opcode=%d" % (ins.pc, ins.opcode))
            if ret is not None:
                raw = re.sub(r"return(?:\s+[^;]*)?;\s*$", "", _raw(ins, prepared),
                             count=1, flags=re.S)
                if raw.strip():
                    lines.extend(_indent(raw)); fallback_count += 1
                else:
                    clean_count += 1
                lines.append("            return%s" % ((" " + ret) if ret else ""))
                terminated = True
                break
            if branch is not None:
                if branch.unconditional and branch.target is not None:
                    lines.append("            pc = %d" % branch.target); clean_count += 1
                elif branch.condition is not None and branch.target is not None:
                    if block.fallthrough is None:
                        lines.append("            if %s then pc = %d else return end" %
                                     (branch.condition, branch.target))
                    else:
                        lines.append("            if %s then pc = %d else pc = %d end" %
                                     (branch.condition, branch.target, block.fallthrough))
                    clean_count += 1
                else:
                    if next_pc is not None:
                        lines.append("            pc = %d" % next_pc)
                    lines.extend(_indent(_raw(ins, prepared))); fallback_count += 1
                terminated = True
                break
            if next_pc is not None:
                lines.append("            pc = %d" % next_pc)
            clean = clean_statement(source, ins)
            if clean is None:
                lines.extend(_indent(_raw(ins, prepared))); fallback_count += 1
            else:
                lines.extend(_indent(clean)); clean_count += 1
        if not terminated:
            lines.append("            %s" %
                         ("return" if block.fallthrough is None
                          else "pc = %d" % block.fallthrough))
    lines.extend([
        "        else",
        "            error(\"invalid decompiled pc \" .. tostring(pc) .. \" in proto %d\")" % proto.id,
        "        end",
        "    end",
        "end",
    ])
    return "\n".join(lines), {
        "blocks": len(blocks), "clean_instructions": clean_count,
        "fallback_instructions": fallback_count,
    }


def render_program(program: Program, semantics: Mapping[int, str]) -> Tuple[str, dict]:
    prepared = prepare_semantics(semantics)
    lines = [
        "-- Decompiled from a sample-local Luraph VM capture.",
        "-- Synthetic names are used; program.pseudo.lua is the audit ground truth.",
        "local PROTO = {}",
        "local VMCONST = setmetatable({}, { __index = function(_, key) return key end })",
        "local A = setmetatable({}, { __index = function(_, key)",
        "    return function(...) error(\"unmodelled VM helper \" .. tostring(key), 0) end",
        "end })",
        "local function __opaque(_) return {} end",
        "local function __unpack_range(first, regs, last) return table.unpack(regs, first, last) end",
        "local function __bind_upvalues(_, _) end",
        "local function __open_cell(registers, index)",
        "    return { open = true, registers = registers, index = index }",
        "end",
        "local function __closed_cell(value)",
        "    return { open = false, value = value }",
        "end",
        "local function __upget(cell)",
        "    if cell == nil then return nil end",
        "    if cell.open then return cell.registers[cell.index] end",
        "    return cell.value",
        "end",
        "local function __upset(cell, value)",
        "    if cell.open then cell.registers[cell.index] = value else cell.value = value end",
        "end",
        "local function __close_cell(cell)",
        "    if cell ~= nil and cell.open then",
        "        cell.value = cell.registers[cell.index]",
        "        cell.open = false",
        "        cell.registers = nil",
        "        cell.index = nil",
        "    end",
        "end",
        "local function __closure(id, captured, env)",
        "    return function(...) return PROTO[id](captured, env, ...) end",
        "end",
        "local function __make_closure(proto, captured)",
        "    local id = type(proto) == \"table\" and proto.__id or proto",
        "    return __closure(id, captured, getfenv())",
        "end",
        "local function __pack_varargs(...) return select(\"#\", ...), table.pack(...) end",
        "local function __get_env() return getfenv() end",
        "",
    ]
    totals = {
        "format_version": 1, "prototypes": len(program.protos),
        "instructions": program.instruction_count, "blocks": 0,
        "clean_instructions": 0, "fallback_instructions": 0,
    }
    for pid in sorted(program.protos):
        text, metrics = decompile_proto(program.protos[pid], semantics, prepared)
        lines.extend([text, ""])
        for key in ("blocks", "clean_instructions", "fallback_instructions"):
            totals[key] += metrics[key]
    totals["clean_ratio"] = (round(totals["clean_instructions"] / totals["instructions"], 6)
                             if totals["instructions"] else 1.0)
    lines.extend(["return function(...)",
                  "    return PROTO[0]({}, getfenv(), ...)", "end", ""])
    return "\n".join(lines), totals


def write_decompiled(program: Program, semantics: Mapping[int, str],
                     out_dir: Union[str, Path],
                     filename: str = "program.decompiled.luau") -> dict:
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    source, metrics = render_program(program, semantics)
    target = out / filename
    fd, tmp_name = tempfile.mkstemp(prefix=target.name + ".", suffix=".tmp", dir=str(out))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape") as fh:
            fh.write(source); fh.flush(); os.fsync(fh.fileno())
        os.replace(tmp, target)
    except Exception:
        tmp.unlink(missing_ok=True); raise
    metrics = dict(metrics); metrics["file"] = filename
    (out / "decompiler.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return metrics


def _runtime_command(runtime: Union[str, Sequence[str]]) -> List[str]:
    command = shlex.split(runtime) if isinstance(runtime, str) else list(runtime)
    if not command:
        raise DecompileError("empty Luau runtime command")
    if len(command) == 1 and shutil.which(command[0]) is None:
        raise DecompileError("Lune was not found for decompiled-source compile validation")
    return command


def compile_check(source: Union[str, Path], work_dir: Union[str, Path],
                  runtime: Union[str, Sequence[str]] = "lune", timeout: int = 120,
                  progress=None) -> None:
    """Compile, but never execute, the generated Luau source with Lune."""
    source_path, work = Path(source).resolve(), Path(work_dir)
    runner = work / "compile_decompiled.luau"
    quoted = str(source_path).replace("\\", "\\\\").replace('"', '\\"')
    runner.write_text(
        'local fs = require("@lune/fs")\nlocal luau = require("@lune/luau")\n'
        'local source = fs.readFile("%s")\n'
        'local ok, result = pcall(luau.compile, source, { optimizationLevel = 1, debugLevel = 1 })\n'
        'if not ok then error(result) end\nprint("[decompile] compile check passed")\n' % quoted,
        encoding="utf-8")
    if progress is not None:
        progress("[decompile] compiling generated Luau (not executing it)")
    try:
        result = subprocess.run(_runtime_command(runtime) + ["run", str(runner)],
                                cwd=str(work), text=True, capture_output=True,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise DecompileError("decompiled Luau compile check timed out") from exc
    except OSError as exc:
        raise DecompileError("failed to start Lune compile check: %s" % exc) from exc
    output = "\n".join(x for x in (result.stdout, result.stderr) if x).strip()
    if progress is not None:
        for line in output.splitlines(): progress(line)
    if result.returncode != 0:
        raise DecompileError("decompiled Luau did not compile: %s" %
                             (output or "unknown error"))
