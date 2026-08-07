"""Render large decompiled CFGs without pathological Luau elseif depth."""
from __future__ import annotations

from typing import Mapping, Tuple
import re

from . import luraph_decompiler as backend
from .luraph_full import Instruction, Proto, substitute_prepared
from .luraph_lift import clean_statement, decode_branch, return_expression

_INSTALLED = False
_GROUP_SIZE = 48


def _indent(text: str):
    return ["                " + line if line else "                "
            for line in text.splitlines()]


def _raw(ins: Instruction, prepared: Mapping[int, Tuple[str, str]]) -> str:
    _name, semantic = prepared[ins.opcode]
    body = substitute_prepared(semantic, ins)
    return re.sub(r"^\s*local\s+W\s*=\s*57(?:\.0)?\s*;\s*", "", body)


def _render_block(lines, block, block_index, semantics, prepared):
    clean_count = 0
    fallback_count = 0
    lines.append("            %s pc == %d then" %
                 ("if" if block_index == 0 else "elseif", block.start))
    terminated = False
    for pos, ins in enumerate(block.instructions):
        source = semantics[ins.opcode]
        branch = decode_branch(source, ins)
        ret = return_expression(source, ins)
        next_pc = (block.instructions[pos + 1].pc
                   if pos + 1 < len(block.instructions) else block.fallthrough)
        lines.append("                -- pc=%d opcode=%d" % (ins.pc, ins.opcode))
        if ret is not None:
            raw = re.sub(r"return(?:\s+[^;]*)?;\s*$", "", _raw(ins, prepared),
                         count=1, flags=re.S)
            if raw.strip():
                lines.extend(_indent(raw)); fallback_count += 1
            else:
                clean_count += 1
            lines.append("                return%s" % ((" " + ret) if ret else ""))
            terminated = True
            break
        if branch is not None:
            if branch.unconditional and branch.target is not None:
                lines.append("                pc = %d" % branch.target); clean_count += 1
            elif branch.condition is not None and branch.target is not None:
                if block.fallthrough is None:
                    lines.append("                if %s then pc = %d else return end" %
                                 (branch.condition, branch.target))
                else:
                    lines.append("                if %s then pc = %d else pc = %d end" %
                                 (branch.condition, branch.target, block.fallthrough))
                clean_count += 1
            else:
                if next_pc is not None:
                    lines.append("                pc = %d" % next_pc)
                lines.extend(_indent(_raw(ins, prepared))); fallback_count += 1
            terminated = True
            break
        if next_pc is not None:
            lines.append("                pc = %d" % next_pc)
        clean = clean_statement(source, ins)
        if clean is None:
            lines.extend(_indent(_raw(ins, prepared))); fallback_count += 1
        else:
            lines.extend(_indent(clean)); clean_count += 1
    if not terminated:
        lines.append("                %s" %
                     ("return" if block.fallthrough is None
                      else "pc = %d" % block.fallthrough))
    return clean_count, fallback_count


def decompile_proto(proto: Proto, semantics: Mapping[int, str], prepared):
    blocks = backend.build_blocks(proto, semantics)
    maxreg = int(proto.max_register) if isinstance(proto.max_register, int) else 0
    lines = [
        "PROTO[%d] = function(P, I, ...)" % proto.id,
        "    P = P or {}",
        "    I = I or getfenv()",
        "    local R = table.create(%d)" % max(1, maxreg + 1),
        "    local argv = table.pack(...)",
        "    for argi = 1, argv.n do R[argi - 1] = argv[argi] end",
        "    local pc = %d" % (blocks[0].start if blocks else 1),
        "    local Z = -1",
        "    local e = {}",
        "    local m, O, U, Y, r, k, F, J, d, C, S, N, b, K",
        "    local L, H, W, X, V, n, h, q, y, j, t, a, i",
    ]
    if not blocks:
        return "\n".join(lines + ["    return", "end"]), {
            "blocks": 0, "clean_instructions": 0, "fallback_instructions": 0,
        }

    clean_count = 0
    fallback_count = 0
    lines.append("    while true do")
    groups = [blocks[index:index + _GROUP_SIZE]
              for index in range(0, len(blocks), _GROUP_SIZE)]
    for group_index, group in enumerate(groups):
        upper = group[-1].start
        lines.append("        %s pc <= %d then" %
                     ("if" if group_index == 0 else "elseif", upper))
        for block_index, block in enumerate(group):
            clean, fallback = _render_block(
                lines, block, block_index, semantics, prepared)
            clean_count += clean
            fallback_count += fallback
        lines.extend([
            "            else",
            "                error(\"invalid decompiled pc \" .. tostring(pc) .. \" in proto %d\")" % proto.id,
            "            end",
        ])
    lines.extend([
        "        else",
        "            error(\"invalid decompiled pc \" .. tostring(pc) .. \" in proto %d\")" % proto.id,
        "        end",
        "    end",
        "end",
    ])
    return "\n".join(lines), {
        "blocks": len(blocks),
        "clean_instructions": clean_count,
        "fallback_instructions": fallback_count,
    }


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    backend.decompile_proto = decompile_proto
    _INSTALLED = True
