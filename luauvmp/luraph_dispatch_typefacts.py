"""Carry safe prototype-array type facts through public dispatcher specialization."""
from __future__ import annotations

from typing import Dict
import json

from tools import recover_luraph_dispatch as core
from tools import recover_luraph_dispatch_v147 as public

_INSTALLED = False
_ORIGINAL_METADATA = None
_TABLE_ROLES = {"E", "p", "o", "H", "_", "B", "L"}


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


def specialize(nodes, opcode, values, metadata, environment=None):
    """Specialize like the public engine while retaining table type identities."""
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
        elif isinstance(node, core.While):
            value = public.eval_cond(
                node.cond, opcode, values, environment, metadata
            )
            nested = {
                key: item for key, item in environment.items()
                if key in stable
            }
            body = specialize(node.body, opcode, values, metadata, nested)
            if value is False:
                continue
            output.append(core.While(node.cond, body))
            environment = nested
        elif isinstance(node, core.For):
            nested = {
                key: item for key, item in environment.items()
                if key in stable
            }
            output.append(core.For(
                node.header, specialize(node.body, opcode, values, metadata, nested)
            ))
        elif isinstance(node, core.Repeat):
            nested = {
                key: item for key, item in environment.items()
                if key in stable
            }
            output.append(core.Repeat(
                specialize(node.body, opcode, values, metadata, nested), node.cond
            ))
            environment = nested
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
