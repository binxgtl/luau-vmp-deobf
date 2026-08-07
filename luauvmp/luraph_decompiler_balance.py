"""Keep generated Luau CFG dispatch below the compiler recursion limit.

After sample-local semantic normalization, large public Luraph prototypes can
contain thousands of recognized basic blocks.  ``luraph_decompiler`` historically
rendered those blocks as one flat ``if/elseif pc == ...`` chain.  Luau represents
that chain recursively and rejects sufficiently large prototypes before any code
is executed.

This layer is source-structural only.  It groups an already-generated flat PC
dispatch into bounded inner chains and a small outer range dispatch.  Individual
block bodies, conditions, fallthroughs, returns, metrics, and payload-execution
policy are unchanged.
"""
from __future__ import annotations

import re
from typing import List, Sequence, Tuple

from . import (
    luraph_decompiler,
    luraph_lift,
    luraph_lift_pairs,
    luraph_lift_chains,
    luraph_lift_forloops,
    luraph_lift_calls,
    luraph_lift_straightline,
    luraph_lift_closures,
    luraph_lift_close_upvalues,
    luraph_lift_raw_upvalue_lvalues,
)


_CHUNK_SIZE = 64
_FIRST = re.compile(r"^        if pc == (?P<pc>-?[0-9]+) then$")
_NEXT = re.compile(r"^        elseif pc == (?P<pc>-?[0-9]+) then$")


def _indent_one(lines: Sequence[str]) -> List[str]:
    return [("    " + line) if line else line for line in lines]


def _parse_dispatch(lines: Sequence[str], start: int):
    """Parse one exact flat dispatcher emitted by ``decompile_proto``.

    Return ``(end, branches, invalid_body)`` where ``end`` is the line index of
    the closing ``    end`` for ``while true do``. Return ``None`` for anything
    not matching the backend's exact shape; unknown source is never rewritten.
    """
    if start + 2 >= len(lines) or lines[start] != "    while true do":
        return None
    first = _FIRST.match(lines[start + 1])
    if first is None:
        return None

    headers: List[Tuple[int, int]] = [(start + 1, int(first.group("pc")))]
    final_else = None
    outer_if_end = None
    cursor = start + 2
    while cursor < len(lines):
        line = lines[cursor]
        match = _NEXT.match(line)
        if match is not None:
            headers.append((cursor, int(match.group("pc"))))
        elif line == "        else":
            final_else = cursor
            probe = cursor + 1
            while probe < len(lines):
                if lines[probe] == "        end":
                    if probe + 1 < len(lines) and lines[probe + 1] == "    end":
                        outer_if_end = probe
                        break
                probe += 1
            break
        cursor += 1

    if final_else is None or outer_if_end is None or not headers:
        return None

    pcs = [pc for _index, pc in headers]
    if pcs != sorted(pcs) or len(set(pcs)) != len(pcs):
        return None

    branches = []
    for pos, (header_index, pc) in enumerate(headers):
        body_start = header_index + 1
        body_end = headers[pos + 1][0] if pos + 1 < len(headers) else final_else
        branches.append((pc, list(lines[body_start:body_end])))
    invalid_body = list(lines[final_else + 1:outer_if_end])
    return outer_if_end + 1, branches, invalid_body


def _render_balanced(branches, invalid_body, chunk_size: int) -> List[str]:
    output = ["    while true do"]
    chunks = [branches[index:index + chunk_size]
              for index in range(0, len(branches), chunk_size)]
    for chunk_index, chunk in enumerate(chunks):
        last_pc = chunk[-1][0]
        output.append(
            "        %s pc <= %d then" %
            ("if" if chunk_index == 0 else "elseif", last_pc)
        )
        for branch_index, (pc, body) in enumerate(chunk):
            output.append(
                "            %s pc == %d then" %
                ("if" if branch_index == 0 else "elseif", pc)
            )
            output.extend(_indent_one(body))
        output.append("            else")
        output.extend(_indent_one(invalid_body))
        output.append("            end")
    output.append("        else")
    output.extend(invalid_body)
    output.append("        end")
    output.append("    end")
    return output


def balance_pc_dispatches(source: str, chunk_size: int = _CHUNK_SIZE) -> str:
    """Balance only exact generated PC dispatch chains larger than ``chunk_size``."""
    if chunk_size < 2:
        raise ValueError("pc dispatch chunk size must be at least 2")
    trailing_newline = source.endswith("\n")
    lines = source.splitlines()
    output: List[str] = []
    cursor = 0
    while cursor < len(lines):
        parsed = _parse_dispatch(lines, cursor)
        if parsed is None:
            output.append(lines[cursor])
            cursor += 1
            continue
        end, branches, invalid_body = parsed
        if len(branches) <= chunk_size:
            output.extend(lines[cursor:end + 1])
        else:
            output.extend(_render_balanced(branches, invalid_body, chunk_size))
        cursor = end + 1
    result = "\n".join(output)
    return result + ("\n" if trailing_newline else "")


_ORIGINAL_RENDER = None
_INSTALLED = False


def render_program(program, semantics):
    if _ORIGINAL_RENDER is None:
        raise luraph_decompiler.DecompileError(
            "balanced decompiler renderer is unavailable"
        )
    source, metrics = _ORIGINAL_RENDER(program, semantics)
    balanced = balance_pc_dispatches(source)
    metrics = dict(metrics)
    metrics["balanced_pc_dispatch"] = balanced != source
    metrics["pc_dispatch_chunk_size"] = _CHUNK_SIZE
    return balanced, metrics


def install() -> None:
    global _ORIGINAL_RENDER, _INSTALLED
    if _INSTALLED:
        return
    # Install multi-instruction hooks here because this function is deliberately
    # the final structural-wiring point before decompiler rendering. The hooks
    # are looked up dynamically by the backend and therefore cannot be
    # snapshotted before installation.
    luraph_lift_pairs.install()
    luraph_lift_chains.install()
    luraph_lift_forloops.install()
    luraph_lift_calls.install()
    luraph_lift_straightline.install()
    # Closure lifting needs access to the complete Program so a ProtoRef can be
    # checked against the captured child descriptor table. Its renderer wrapper
    # is installed before balancing snapshots the composed renderer.
    luraph_lift_closures.install()
    # Close-upvalue lifting composes after closure construction because both use
    # the same recovered raw-cell layout. It also wraps terminal return handling
    # so close+return superinstructions preserve evaluation order and arity.
    luraph_lift_close_upvalues.install()
    # Preserve the two grouped raw-cell lvalue spellings without globally
    # stripping parentheses from arbitrary assignment targets.
    luraph_lift_raw_upvalue_lvalues.install()
    # ``luraph_fallback_safety`` imports the decompiler before the public lift
    # wrappers are installed, so its module globals still point at the original
    # functions. Rebind to the final composed lifter here, after every lift pass
    # has been installed and immediately before the renderer is wrapped.
    luraph_decompiler.clean_statement = luraph_lift.clean_statement
    luraph_decompiler.decode_branch = luraph_lift.decode_branch
    luraph_decompiler.return_expression = luraph_lift.return_expression
    _ORIGINAL_RENDER = luraph_decompiler.render_program
    luraph_decompiler.render_program = render_program
    _INSTALLED = True
