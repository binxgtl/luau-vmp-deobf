"""Recover and lift the public-v14.7 runtime environment table.

The public families randomize both the helper-table slot containing ``getfenv``
and the local that receives its result.  Treating an arbitrary scratch table as
the environment would silently corrupt GETGLOBAL/SETGLOBAL semantics, so this
layer requires a complete structural evidence chain:

1. the recovered VM aliases ``getfenv`` directly;
2. that exact alias is stored in a numeric runtime-helper slot;
3. the extracted factory calls that helper slot with zero arguments; and
4. the receiving local is uniquely observed as an indexed table in recovered
   dispatcher semantics, after excluding all already-proven VM structural roles.

Only then is the local canonicalized to ``__ENV``.  The source lifter maps exact
GETGLOBAL/SETGLOBAL shapes to the per-prototype ``__env`` parameter.  Ambiguous
or incomplete evidence is left unchanged for normal fallback handling.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Set
import json
import re

from . import luraph_lift, luraph_recover
from . import luraph_public_v147 as public
from . import luraph_semantic_collisions as collisions
from . import luraph_semantic_normalize as normalize


_INSTALLED = False
_ORIGINAL_RECOVER = None
_ORIGINAL_CLEAN = None
_ID = r"[A-Za-z_]\w*"
_NUMBER = normalize._NUMBER_TEXT
_STRUCTURAL_TARGETS = {"A", "I", "E", "p", "o", "H", "_", "B", "L", "X", "c", "u"}


def _code_only(source: str) -> str:
    """Mask comments and string literals while preserving source offsets."""
    pieces = []
    cursor = 0
    for token in public._tokens(source):
        pieces.append(" " * (token.start - cursor))
        if token.kind == "string":
            pieces.append(" " * (token.end - token.start))
        else:
            pieces.append(source[token.start:token.end])
        cursor = token.end
    pieces.append(" " * (len(source) - cursor))
    return "".join(pieces)


def _getfenv_helper_slots(vm_source: str) -> Set[int]:
    """Return runtime helper slots proven to hold a direct ``getfenv`` alias."""
    code = _code_only(vm_source)
    aliases = {
        match.group("alias")
        for match in re.finditer(
            r"(?<![A-Za-z0-9_.])(?P<alias>" + _ID + r")\s*=\s*getfenv"
            r"(?![A-Za-z0-9_.])",
            code,
        )
    }
    slots: Set[int] = set()
    for alias in aliases:
        pattern = re.compile(
            r"(?:\(\s*" + _ID + r"\s*\)|(?<![A-Za-z0-9_.])" + _ID + r")"
            r"\s*\[\s*(?P<slot>" + _NUMBER + r")\s*\]\s*=\s*"
            r"\(?\s*" + _ID + r"\." + re.escape(alias) + r"\s*\)?"
        )
        for match in pattern.finditer(code):
            slot = normalize._integer(match.group("slot"))
            if slot is not None:
                slots.add(slot)
    return slots


def _factory_getfenv_candidates(factory_source: str, helper: str,
                                  slots: Set[int]) -> Set[str]:
    """Find locals receiving a zero-argument call to a proven getfenv slot."""
    if not helper or not slots:
        return set()
    code = _code_only(factory_source)
    declaration = re.compile(
        r"\blocal\s+(?P<lhs>[^;=]+?)\s*=\s*(?P<rhs>[^;]+);"
    )
    call = re.compile(
        r"^\(?\s*" + re.escape(helper) + r"\s*\[\s*(?P<slot>"
        + _NUMBER + r")\s*\]\s*\(\s*\)\s*\)?$"
    )
    candidates: Set[str] = set()
    for match in declaration.finditer(code):
        lhs = [item.strip() for item in match.group("lhs").split(",")]
        rhs = normalize._split_commas(match.group("rhs"))
        # Lua permits fewer RHS values than LHS values.  Position still proves
        # the receiver for every explicitly present RHS expression.
        for index, expression in enumerate(rhs):
            if index >= len(lhs) or re.fullmatch(_ID, lhs[index]) is None:
                continue
            hit = call.fullmatch(expression.strip())
            if hit is None:
                continue
            slot = normalize._integer(hit.group("slot"))
            if slot in slots:
                candidates.add(lhs[index])
    return candidates


def _factory_mapping(factory_source: str) -> Dict[str, str]:
    raw = normalize._metadata(factory_source).get("CANONICAL_VARS", "{}")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(value, dict):
        return {}
    return {str(key): str(target) for key, target in value.items()}


def infer_environment_name(factory_source: str, vm_source: str,
                           semantics: dict) -> Optional[str]:
    """Return the raw factory local proven to be the runtime environment table."""
    metadata = normalize._metadata(factory_source)
    if metadata.get("PUBLIC_V147") != "1":
        return None
    helper = metadata.get("HELPER_VAR", "")
    slots = _getfenv_helper_slots(vm_source)
    candidates = _factory_getfenv_candidates(factory_source, helper, slots)
    if not candidates:
        return None

    mapping = _factory_mapping(factory_source)
    # A helper result that is also a proven register/opcode/operand/helper role
    # is a different lexical binding or a false candidate; never reinterpret it
    # as the environment based only on its spelling.
    excluded = {
        source for source, target in mapping.items()
        if target in _STRUCTURAL_TARGETS
    }
    candidates.difference_update(excluded)
    if not candidates:
        return None

    scores: Dict[str, int] = {name: 0 for name in candidates}
    for value in semantics.values():
        if not isinstance(value, dict):
            continue
        raw = value.get("raw_source") or value.get("source", "")
        code = _code_only(raw)
        for name in candidates:
            scores[name] += len(re.findall(
                r"\b" + re.escape(name) + r"\s*\[", code
            ))

    positive = [(score, name) for name, score in scores.items() if score > 0]
    if not positive:
        return None
    positive.sort(reverse=True)
    if len(positive) > 1 and positive[0][0] == positive[1][0]:
        return None
    return positive[0][1]


def _canonical_environment_name(factory_source: str, raw_name: str) -> str:
    mapping = collisions.collision_safe_mapping(_factory_mapping(factory_source))
    return mapping.get(raw_name, raw_name)


def _write_text_output(path: Optional[Path], data: dict) -> None:
    if path is None:
        return
    lines = []
    for opcode in sorted(int(key) for key in data):
        item = data[str(opcode)]
        lines.append("=== OPCODE %d | unknown_if=%s ===" % (
            opcode, item.get("unknown_ifs", 0)
        ))
        lines.append(item.get("source", ""))
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def recover_dispatch(factory, runtime_facts, output, text_output=None):
    result = _ORIGINAL_RECOVER(factory, runtime_facts, output, text_output)
    factory_path = Path(factory)
    vm_path = factory_path.with_name("interpreter.vm.luau")
    if not vm_path.is_file():
        return result

    output_path = Path(output)
    data = json.loads(output_path.read_text(encoding="utf-8"))
    factory_source = factory_path.read_text(
        encoding="utf-8", errors="surrogateescape"
    )
    vm_source = vm_path.read_text(encoding="utf-8", errors="surrogateescape")
    raw_name = infer_environment_name(factory_source, vm_source, data)
    if raw_name is None:
        return result
    canonical_name = _canonical_environment_name(factory_source, raw_name)

    changed = False
    for value in data.values():
        if not isinstance(value, dict):
            continue
        source = value.get("source", "")
        rewritten = normalize.canonicalize_source(
            source, {canonical_name: "__ENV"}
        )
        if rewritten != source:
            value["source"] = rewritten
            value["environment_canonicalized"] = True
            changed = True
    if not changed:
        return result

    output_path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_text_output(
        Path(text_output) if text_output is not None else None, data
    )
    return data


def clean_environment_statement(source, ins):
    """Lift exact GETGLOBAL/SETGLOBAL shapes after ``__ENV`` proof."""
    text = luraph_lift.compact(source).rstrip(";")
    for _ in range(2):
        updated = text.replace("(__ENV)", "__ENV")
        updated = re.sub(r"\((__ENV\[@[EpoH_B]\])\)", r"\1", updated)
        if updated == text:
            break
        text = updated

    match = re.fullmatch(
        r"R\[@(?P<dst>[EpoH_B])\]=__ENV\[@(?P<key>[EpoH_B])\]", text
    )
    if match:
        dst = luraph_lift.reg_expr(
            luraph_lift.field_value(ins, match.group("dst"))
        )
        key = luraph_lift.value_expr(
            luraph_lift.field_value(ins, match.group("key"))
        )
        return "%s = __env[%s]" % (dst, key)

    match = re.fullmatch(
        r"__ENV\[@(?P<key>[EpoH_B])\]=R\[@(?P<src>[EpoH_B])\]", text
    )
    if match:
        key = luraph_lift.value_expr(
            luraph_lift.field_value(ins, match.group("key"))
        )
        src = luraph_lift.reg_expr(
            luraph_lift.field_value(ins, match.group("src"))
        )
        return "__env[%s] = %s" % (key, src)

    match = re.fullmatch(
        r"__ENV\[@(?P<key>[EpoH_B])\]=@(?P<src>[EpoH_B])", text
    )
    if match:
        key = luraph_lift.value_expr(
            luraph_lift.field_value(ins, match.group("key"))
        )
        value = luraph_lift.value_expr(
            luraph_lift.field_value(ins, match.group("src"))
        )
        return "__env[%s] = %s" % (key, value)
    return None


def clean_statement(source, ins):
    existing = _ORIGINAL_CLEAN(source, ins)
    if existing is not None:
        return existing
    return clean_environment_statement(source, ins)


def install() -> None:
    global _INSTALLED, _ORIGINAL_RECOVER, _ORIGINAL_CLEAN
    if _INSTALLED:
        return
    _ORIGINAL_RECOVER = luraph_recover.recover_dispatch
    luraph_recover.recover_dispatch = recover_dispatch
    _ORIGINAL_CLEAN = luraph_lift.clean_statement
    luraph_lift.clean_statement = clean_statement
    _INSTALLED = True
