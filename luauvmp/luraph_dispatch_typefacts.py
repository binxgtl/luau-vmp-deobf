"""Carry safe prototype-array type facts through public dispatcher specialization."""
from __future__ import annotations

from typing import Dict
import json

from tools import recover_luraph_dispatch as core
from tools import recover_luraph_dispatch_v147 as public

_INSTALLED = False
_ORIGINAL_METADATA = None
_TABLE_ROLES = {"E", "p", "o", "H", "_", "B", "L"}
_STATIC_LOOP_BUDGET = 512


class _StaticLoopAbort(Exception):
    """Internal fail-closed signal for a loop that is not provably static."""


def _metadata(source: str):
    metadata = _ORIGINAL_METADATA(source)
    raw = {
        match.group("key"): match.group("value").strip()
        for match in public._META.finditer(source)
    }
    try:
        canonical = json.loads(raw.get("CANONICAL_VARS", "{}"))
    except json.JSONDecodeError:
        canonical = {}
    table_names = {
        actual for actual, role in canonical.items()
        if role in _TABLE_ROLES
    }
    # Identity mappings are intentionally omitted by the normalizer. Including
    # the canonical spellings is harmless: a name that is not present in the
    # factory is never read by ExprParser.
    table_names.update(_TABLE_ROLES)
    metadata["prototype_table_names"] = tuple(sorted(table_names))
    return metadata


def _raw_control(node):
    if not isinstance(node, core.Raw):
        return None
    text = core.toktext(node.toks).strip()
    if text == "continue":
        return "continue"
    if text == "break":
        return "break"
    # A selected return changes reachability outside the loop. Rather than
    # partially model function-level termination, leave that loop untouched.
    if text == "return" or text.startswith("return "):
        return "return"
    return None


def _execute_static_block(nodes, opcode, values, metadata, environment, budget):
    """Execute only control decisions proven constant, returning emitted path.

    Raw semantic statements are preserved verbatim while their simple local
    assignments update the abstract environment.  Unknown conditions, dynamic
    loops/for statements, functions, or selected returns abort the whole static
    loop attempt so the caller can retain the original AST unchanged.
    """
    output = []
    for node in nodes:
        budget[0] -= 1
        if budget[0] < 0:
            raise _StaticLoopAbort()

        control = _raw_control(node)
        if control is not None:
            if control == "return":
                raise _StaticLoopAbort()
            return output, control

        if isinstance(node, core.Raw):
            public._simple_assign(node, opcode, values, environment, metadata)
            output.append(node)
            continue

        if isinstance(node, core.If):
            chosen = None
            for condition, body in node.branches:
                value = public.eval_cond(
                    condition, opcode, values, environment, metadata
                )
                if value is core.UNKNOWN:
                    raise _StaticLoopAbort()
                if value is True:
                    chosen = body
                    break
            if chosen is None:
                chosen = node.else_body or []
            nested, signal = _execute_static_block(
                chosen, opcode, values, metadata, environment, budget
            )
            output.extend(nested)
            if signal is not None:
                return output, signal
            continue

        if isinstance(node, core.Do):
            nested, signal = _execute_static_block(
                node.body, opcode, values, metadata, environment, budget
            )
            output.extend(nested)
            if signal is not None:
                return output, signal
            continue

        if isinstance(node, (core.While, core.Repeat)):
            nested = _try_unroll_loop(
                node, opcode, values, metadata, environment, budget
            )
            if nested is None:
                raise _StaticLoopAbort()
            output.extend(nested)
            continue

        # Numeric/generic for-loops and nested functions may carry intentional
        # runtime semantics.  They are not anti-tamper state machines here.
        raise _StaticLoopAbort()
    return output, None


def _try_unroll_loop(node, opcode, values, metadata, environment, budget=None):
    """Return a statically selected loop path or ``None`` when not provable."""
    trial = dict(environment)
    local_budget = budget if budget is not None else [_STATIC_LOOP_BUDGET]
    emitted = []
    try:
        for _iteration in range(_STATIC_LOOP_BUDGET):
            if isinstance(node, core.While):
                condition = public.eval_cond(
                    node.cond, opcode, values, trial, metadata
                )
                if condition is core.UNKNOWN:
                    raise _StaticLoopAbort()
                if condition is False:
                    environment.clear(); environment.update(trial)
                    return emitted

            body, signal = _execute_static_block(
                node.body, opcode, values, metadata, trial, local_budget
            )
            emitted.extend(body)
            if signal == "break":
                environment.clear(); environment.update(trial)
                return emitted

            if isinstance(node, core.Repeat):
                condition = public.eval_cond(
                    node.cond, opcode, values, trial, metadata
                )
                if condition is core.UNKNOWN:
                    raise _StaticLoopAbort()
                if condition is True:
                    environment.clear(); environment.update(trial)
                    return emitted
            # normal completion and ``continue`` both start the next iteration
            # (for repeat-until, after evaluating its condition above).
        raise _StaticLoopAbort()
    except _StaticLoopAbort:
        return None


def specialize(nodes, opcode, values, metadata, environment=None):
    """Specialize while retaining type identities and folding proven state loops."""
    table_names = set(metadata.get("prototype_table_names", ()))
    stable = {
        "q", metadata["opcode_name"], metadata["helper_name"],
        *table_names,
    }
    if environment is None:
        environment = {
            "q": ("closure_q",),
            metadata["opcode_name"]: opcode,
            metadata["helper_name"]: core.KnownTable("A"),
        }
        for name in table_names:
            environment[name] = core.KnownTable("proto:" + name)
    else:
        environment = dict(environment)
        for name in table_names:
            environment.setdefault(name, core.KnownTable("proto:" + name))

    output = []
    for node in nodes:
        if isinstance(node, core.Raw):
            public._simple_assign(node, opcode, values, environment, metadata)
            output.append(node)
        elif isinstance(node, core.If):
            picked = False
            unknown = []
            for condition, body in node.branches:
                value = public.eval_cond(
                    condition, opcode, values, environment, metadata
                )
                if value is True:
                    output.extend(specialize(
                        body, opcode, values, metadata, dict(environment)
                    ))
                    picked = True
                    break
                if value is core.UNKNOWN:
                    unknown.append((condition, specialize(
                        body, opcode, values, metadata, dict(environment)
                    )))
            if picked:
                continue
            else_body = (
                specialize(node.else_body or [], opcode, values, metadata,
                           dict(environment))
                if node.else_body is not None else None
            )
            if unknown:
                output.append(core.If(unknown, else_body))
                environment = {
                    key: value for key, value in environment.items()
                    if key in stable
                }
            elif else_body is not None:
                output.extend(else_body)
        elif isinstance(node, (core.While, core.Repeat)):
            unrolled = _try_unroll_loop(
                node, opcode, values, metadata, environment
            )
            if unrolled is not None:
                # Run normal specialization over the selected straight-line path
                # once more so any now-constant nested conditions are removed.
                output.extend(specialize(
                    unrolled, opcode, values, metadata, dict(environment)
                ))
                continue

            nested = {
                key: item for key, item in environment.items()
                if key in stable
            }
            body = specialize(node.body, opcode, values, metadata, nested)
            if isinstance(node, core.While):
                value = public.eval_cond(
                    node.cond, opcode, values, environment, metadata
                )
                if value is False:
                    continue
                output.append(core.While(node.cond, body))
            else:
                output.append(core.Repeat(body, node.cond))
            environment = nested
        elif isinstance(node, core.For):
            nested = {
                key: item for key, item in environment.items()
                if key in stable
            }
            output.append(core.For(
                node.header, specialize(node.body, opcode, values, metadata, nested)
            ))
        elif isinstance(node, core.Do):
            output.append(core.Do(specialize(
                node.body, opcode, values, metadata, dict(environment)
            )))
        elif isinstance(node, core.Function):
            output.append(core.Function(
                node.prefix,
                specialize(node.body, opcode, values, metadata, dict(environment)),
            ))
        else:
            output.append(node)
    return output


def install() -> None:
    global _INSTALLED, _ORIGINAL_METADATA
    if _INSTALLED:
        return
    _ORIGINAL_METADATA = public._metadata
    public._metadata = _metadata
    public.specialize = specialize
    _INSTALLED = True
