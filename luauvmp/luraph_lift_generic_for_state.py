"""Lift the coroutine-backed generic-for adapter used by public v14.7.

This pass activates only after runtime identity telemetry has rewritten the two
randomized helper callees to the trusted builtins ``coroutine.wrap`` and
``coroutine.yield``.  It recognizes the complete setup/step pair, preserves the
persistent numeric-loop scratch stack, and replaces the VM branch prefix with an
ordinary Luau coroutine iterator adapter.

No helper slot numbers are hard-coded here.  If identity proof or any def/use
shape is missing, the original semantic fallback remains unchanged.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple
import json
import re

from . import luraph_decompiler, luraph_lift, luraph_recover


_INSTALLED = False
_ORIGINAL_DECOMPILE = None
_ORIGINAL_RECOVER = None


def _compact(source: str) -> str:
    return re.sub(r"\s+", "", source).rstrip(";")


def classify_setup(source: str) -> bool:
    text = _compact(source)
    return re.fullmatch(
        r"f=\(?\{\[5\]=Z,\[2\]=f,\[1\]=N,\[4\]=g\}\)?;"
        r"T=\(?o\[u\]\)?;"
        r"M=coroutine\.wrap\(function\(\.\.\.\)"
        r"coroutine\.yield\(\);"
        r"forf,Oin\.\.\.docoroutine\.yield\(true,f,O\);end;end\);"
        r"M\(c\[T\],c\[T\+1\],c\[T\+2\]\);"
        r"Z=M;u=\(?_\[u\]\)?",
        text,
    ) is not None


def classify_step(source: str) -> bool:
    text = _compact(source)
    return re.fullmatch(
        r"M=\(?_\[u\]\)?;h,n,W=Z\(\);ifhthen"
        r"\(?c\)?\[M\+1\]=n;c\[M\+2\]=\(?W\)?;"
        r"u=\(?H\[u\]\)?;end",
        text,
    ) is not None


def resolved_if_count(source: str) -> int:
    return 1 if classify_step(source) else 0


def recover_dispatch(factory, runtime_facts, output, text_output=None):
    result = _ORIGINAL_RECOVER(factory, runtime_facts, output, text_output)
    output_path = Path(output)
    data = json.loads(output_path.read_text(encoding="utf-8"))
    changed = False
    for item in data.values():
        if not isinstance(item, dict) or not classify_step(item.get("source", "")):
            continue
        raw_unknown = int(item.get("unknown_ifs", 0))
        if raw_unknown <= 0:
            continue
        item["unknown_ifs"] = raw_unknown - 1
        item["generic_for_resolved_ifs"] = 1
        changed = True
    if not changed:
        return result
    output_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if text_output is not None:
        lines = []
        for opcode in sorted(int(key) for key in data):
            item = data[str(opcode)]
            lines.extend([
                "=== OPCODE %d | unknown_if=%s ===" % (opcode, item.get("unknown_ifs", 0)),
                item.get("source", ""),
                "",
            ])
        Path(text_output).write_text("\n".join(lines), encoding="utf-8")
    return data


def _span(marker: str, pc_line: Optional[str], raw_lines) -> str:
    lines = [marker]
    if pc_line is not None:
        lines.append(pc_line)
    lines.extend(raw_lines)
    return "\n".join(lines)


def _value(ins, field: str) -> str:
    return luraph_lift.value_expr(luraph_lift.field_value(ins, field))


def _setup_replacement(ins) -> str:
    target = _value(ins, "_")
    table_index = _value(ins, "o")
    return "\n".join([
        "            -- pc=%d opcode=%d" % (ins.pc, ins.opcode),
        "            f = {[5] = Z, [2] = f, [1] = N, [4] = g}",
        "            T = %s" % table_index,
        "            M = coroutine.wrap(function(...)",
        "                coroutine.yield()",
        "                for __iter_a, __iter_b in ... do",
        "                    coroutine.yield(true, __iter_a, __iter_b)",
        "                end",
        "            end)",
        "            M(R[T], R[T + 1], R[T + 2])",
        "            Z = M",
        "            pc = %s" % target,
    ])


def _step_replacement(ins, fallthrough: Optional[int]) -> str:
    base = _value(ins, "_")
    target = _value(ins, "H")
    lines = [
        "            -- pc=%d opcode=%d" % (ins.pc, ins.opcode),
        "            M = %s" % base,
        "            h, n, W = Z()",
        "            if h then",
        "                R[M + 1] = n",
        "                R[M + 2] = W",
        "                pc = %s" % target,
        "            else",
    ]
    if fallthrough is None:
        lines.append("                return")
    else:
        lines.append("                pc = %d" % fallthrough)
    lines.append("            end")
    return "\n".join(lines)


def decompile_proto(proto, semantics, prepared):
    source, metrics = _ORIGINAL_DECOMPILE(proto, semantics, prepared)
    replacements = 0
    used_setup = False
    for block in luraph_decompiler.build_blocks(proto, semantics):
        for pos, ins in enumerate(block.instructions):
            semantic = semantics[ins.opcode]
            setup = classify_setup(semantic)
            step = classify_step(semantic)
            if not setup and not step:
                continue
            next_pc = (
                block.instructions[pos + 1].pc
                if pos + 1 < len(block.instructions)
                else block.fallthrough
            )
            marker = "            -- pc=%d opcode=%d" % (ins.pc, ins.opcode)
            raw = luraph_decompiler._indent(luraph_decompiler._raw(ins, prepared))
            old = _span(
                marker,
                ("            pc = %d" % next_pc) if next_pc is not None else None,
                raw,
            )
            if source.count(old) != 1:
                raise luraph_decompiler.DecompileError(
                    "generic-for fallback span changed for proto %d pc %d" %
                    (proto.id, ins.pc)
                )
            replacement = (
                _setup_replacement(ins)
                if setup
                else _step_replacement(ins, block.fallthrough)
            )
            source = source.replace(old, replacement, 1)
            replacements += 1
            used_setup = used_setup or setup

    if not replacements:
        return source, metrics
    if used_setup:
        anchor = "    local Z = -1\n"
        declaration = "    local f\n"
        if declaration not in source:
            if source.count(anchor) != 1:
                raise luraph_decompiler.DecompileError(
                    "generic-for scratch declaration anchor changed for proto %d" % proto.id
                )
            source = source.replace(anchor, anchor + declaration, 1)
    metrics = dict(metrics)
    metrics["fallback_instructions"] -= replacements
    metrics["clean_instructions"] += replacements
    metrics["generic_for_state_instructions"] = (
        metrics.get("generic_for_state_instructions", 0) + replacements
    )
    return source, metrics


def install() -> None:
    global _INSTALLED, _ORIGINAL_DECOMPILE, _ORIGINAL_RECOVER
    if _INSTALLED:
        return
    _ORIGINAL_RECOVER = luraph_recover.recover_dispatch
    luraph_recover.recover_dispatch = recover_dispatch
    _ORIGINAL_DECOMPILE = luraph_decompiler.decompile_proto
    luraph_decompiler.decompile_proto = decompile_proto
    _INSTALLED = True
