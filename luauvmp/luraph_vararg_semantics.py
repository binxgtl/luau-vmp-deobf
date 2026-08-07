"""Prove and lift randomized public-v14.7 vararg transfer operations.

No helper slot is hard-coded.  The pass requires three independent facts from
the same capture:

* runtime_A.tsv identifies a helper slot as the trusted builtin ``select`` by
  object identity (recorded by :mod:`luraph_runtime_identities`);
* the recovered VM assigns a vararg packer that calls that exact select slot and
  returns ``count, {...}``; and
* the extracted factory assigns the two packer results to a unique count/table
  pair used by dispatcher semantics.

Only three complete copy shapes are normalized.  The raw semantic remains in
``raw_source`` for audit, while the normalized ``source`` receives a private
marker consumed by the source lifter.  Ambiguous/incomplete evidence is left
untouched.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Set, Tuple
import json
import re

from . import luraph_lift, luraph_recover
from . import luraph_public_v147 as public
from . import luraph_semantic_collisions as collisions
from . import luraph_semantic_normalize as normalize
from .luraph_runtime_identities import install as _install_runtime_identities


_INSTALLED = False
_ORIGINAL_RECOVER = None
_ORIGINAL_CLEAN = None
_ID = r"[A-Za-z_]\w*"
_FIELD = r"[EpoH_B]"
_NUMBER = normalize._NUMBER_TEXT
_ALLOWED_SCRATCH = {
    "M", "V", "h", "r", "z", "Y", "W", "n", "T", "S", "N", "g",
    "K", "C", "Z", "e", "m", "O", "U", "F", "J", "d", "b", "y",
    "t", "a", "i", "w", "l", "Q", "G", "P",
    "__s_A", "__s_I", "__s_E", "__s_p", "__s_o", "__s_H", "__s__",
    "__s_B", "__s_L", "__s_X", "__s_c", "__s_u", "__s_R",
}


def _runtime_builtin_slots(path: Path, name: str) -> Set[int]:
    result: Set[int] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        cols = line.split("\t")
        if len(cols) != 5:
            continue
        index, kind, text, _truth, _classes = cols
        if kind == "function" and text == "builtin:" + name:
            try:
                result.add(int(index))
            except ValueError:
                pass
    return result


def _slot_token(value: str) -> Optional[int]:
    return normalize._integer(value)


def infer_packer_slot(vm_source: str, helper: str,
                      select_slots: Set[int]) -> Optional[int]:
    if not helper or not select_slots:
        return None
    assignment = re.compile(
        r"(?:\(\s*" + re.escape(helper) + r"\s*\)|(?<![A-Za-z0-9_])"
        + re.escape(helper) + r")\s*\[\s*(?P<slot>" + _NUMBER
        + r")\s*\]\s*=\s*\(?\s*(?P<function>function)\s*\(\s*\.\.\.\s*\)",
        re.S,
    )
    candidates = []
    for match in assignment.finditer(vm_source):
        end = public._function_end(vm_source, match.start("function"))
        body = vm_source[match.end():end]
        count_match = re.search(
            r"\blocal\s+(?P<count>" + _ID + r")\s*=\s*"
            + re.escape(helper) + r"\s*\[\s*(?P<select>" + _NUMBER
            + r")\s*\]\s*\(\s*([\"'])#\3\s*,\s*\.\.\.\s*\)",
            body,
            re.S,
        )
        if count_match is None:
            continue
        select_slot = _slot_token(count_match.group("select"))
        if select_slot not in select_slots:
            continue
        count = count_match.group("count")
        if re.search(
            r"\breturn\s+" + re.escape(count)
            + r"\s*,\s*\{\s*\.\.\.\s*\}\s*;?",
            body,
            re.S,
        ) is None:
            continue
        # The empty case must return the same count plus a helper-table value;
        # this proves the second result is the packed argument table on both paths.
        if re.search(
            r"\breturn\s+" + re.escape(count) + r"\s*,\s*"
            + re.escape(helper) + r"\s*\[\s*" + _NUMBER + r"\s*\]\s*;?",
            body,
            re.S,
        ) is None:
            continue
        slot = _slot_token(match.group("slot"))
        if slot is not None:
            candidates.append(slot)
    unique = sorted(set(candidates))
    return unique[0] if len(unique) == 1 else None


def _factory_mapping(factory_source: str) -> Dict[str, str]:
    raw = normalize._metadata(factory_source).get("CANONICAL_VARS", "{}")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else {}


def infer_factory_varargs(factory_source: str, helper: str,
                          packer_slot: int) -> Optional[Tuple[str, str]]:
    pattern = re.compile(
        r"\blocal\s+(?P<count>" + _ID + r")\s*,\s*(?P<table>" + _ID
        + r")\s*=\s*(?:\(\s*" + re.escape(helper) + r"\s*\)|"
        + re.escape(helper) + r")\s*\[\s*" + str(packer_slot)
        + r"(?:\.0)?\s*\]\s*\(\s*\.\.\.\s*\)",
        re.S,
    )
    matches = [(m.group("count"), m.group("table")) for m in pattern.finditer(factory_source)]
    unique = list(dict.fromkeys(matches))
    return unique[0] if len(unique) == 1 and unique[0][0] != unique[0][1] else None


def _canonical_vararg_names(factory_source: str,
                            raw: Tuple[str, str]) -> Tuple[str, str]:
    mapping = collisions.collision_safe_mapping(_factory_mapping(factory_source))
    return mapping.get(raw[0], raw[0]), mapping.get(raw[1], raw[1])


def _compact(source: str) -> str:
    text = re.sub(r"\s+", "", source)
    atom = r"(?:" + _ID + r"|[EpoH_B]\[u\]|c)"
    for _ in range(4):
        updated = re.sub(r"\((" + atom + r")\)", r"\1", text)
        if updated == text:
            break
        text = updated
    return text.rstrip(";")


def _scratch(*names: str) -> bool:
    return all(name in _ALLOWED_SCRATCH for name in names)


def classify_vararg(source: str, count_name: str,
                    table_name: str) -> Optional[Tuple[str, Tuple[str, ...], str, int]]:
    """Return ``(kind, scratch_names, operand_field, resolved_ifs)``."""
    text = _compact(source)
    count = re.escape(count_name)
    table = re.escape(table_name)

    match = re.fullmatch(
        r"(?P<n>" + _ID + r")=(?P<field>" + _FIELD + r")\[u\];"
        r"for" + count + r"=1,(?P=n)do"
        r"c\[" + count + r"\]=" + table + r"\[" + count + r"\];end"
        r"(?P<cursor>" + _ID + r")=(?P=n)\+1",
        text,
    )
    if match and _scratch(match.group("n"), match.group("cursor")):
        return "prefix", (match.group("n"), match.group("cursor")), match.group("field"), 0

    match = re.fullmatch(
        r"(?P<dst>" + _ID + r")=(?P<field>" + _FIELD + r")\[u\];"
        r"(?P<off>" + _ID + r")=0;"
        r"for" + count + r"=(?P=dst),(?P=dst)\+\((?P<cfield>" + _FIELD
        + r")\[u\]-1\)do"
        r"c\[" + count + r"\]=" + table + r"\[(?P<cursor>" + _ID
        + r")\+(?P=off)\];(?P=off)\+=1;end",
        text,
    )
    if match and _scratch(match.group("dst"), match.group("off"), match.group("cursor")):
        return (
            "fixed",
            (match.group("dst"), match.group("off"), match.group("cursor"), match.group("cfield")),
            match.group("field"),
            0,
        )

    # Remaining-vararg copy. Luraph spells the clamp as either an empty then
    # branch plus else or as the direct positive branch; both are equivalent and
    # are accepted only when every subsequent def/use backreference matches.
    prefix = (
        r"(?P<dst>" + _ID + r")=(?P<field>" + _FIELD + r")\[u\];"
        r"(?P<len>" + _ID + r")=" + count + r"-(?P<used>" + _ID + r")-1;"
    )
    suffix = (
        r"(?P<off>" + _ID + r")=0;for" + count + r"=(?P=dst),(?P=dst)\+(?P=len)do"
        r"c\[" + count + r"\]=" + table + r"\[(?P<cursor>" + _ID
        + r")\+(?P=off)\];(?P=off)\+=1;end"
        r"(?P<top>" + _ID + r")=(?P=dst)\+(?P=len)"
    )
    clamp_forms = [
        r"ifnot\((?P=len)<0\)thenelse(?P=len)=-1;end",
        r"if(?P=len)<0then(?P=len)=-1;end",
    ]
    for clamp in clamp_forms:
        match = re.fullmatch(prefix + clamp + suffix, text)
        if match and _scratch(
            match.group("dst"), match.group("len"), match.group("used"),
            match.group("off"), match.group("cursor"), match.group("top"),
        ):
            return (
                "remaining",
                (
                    match.group("dst"), match.group("len"), match.group("used"),
                    match.group("off"), match.group("cursor"), match.group("top"),
                ),
                match.group("field"),
                1,
            )
    return None


def _marker(kind: str, names: Tuple[str, ...], field: str) -> str:
    return "__LUAUVMP_VARARG_%s(%s,@%s)" % (
        kind.upper(), ",".join(names), field
    )


def recover_dispatch(factory, runtime_facts, output, text_output=None):
    result = _ORIGINAL_RECOVER(factory, runtime_facts, output, text_output)
    factory_path = Path(factory)
    vm_path = factory_path.with_name("interpreter.vm.luau")
    if not vm_path.is_file():
        return result
    factory_source = factory_path.read_text(encoding="utf-8", errors="surrogateescape")
    metadata = normalize._metadata(factory_source)
    if metadata.get("PUBLIC_V147") != "1":
        return result
    helper = metadata.get("HELPER_VAR", "")
    select_slots = _runtime_builtin_slots(Path(runtime_facts), "select")
    packer = infer_packer_slot(
        vm_path.read_text(encoding="utf-8", errors="surrogateescape"),
        helper,
        select_slots,
    )
    if packer is None:
        return result
    raw_names = infer_factory_varargs(factory_source, helper, packer)
    if raw_names is None:
        return result
    count_name, table_name = _canonical_vararg_names(factory_source, raw_names)

    output_path = Path(output)
    data = json.loads(output_path.read_text(encoding="utf-8"))
    changed = False
    for entry in data.values():
        if not isinstance(entry, dict):
            continue
        source = entry.get("source", "")
        classified = classify_vararg(source, count_name, table_name)
        if classified is None:
            continue
        kind, names, field, resolved = classified
        entry["source"] = _marker(kind, names, field)
        entry["vararg_structural"] = True
        if resolved:
            raw_unknown = int(entry.get("unknown_ifs", 0))
            entry["unknown_ifs"] = max(0, raw_unknown - resolved)
            entry["vararg_resolved_ifs"] = min(raw_unknown, resolved)
        changed = True
    if not changed:
        return result
    output_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if text_output is not None:
        lines = []
        for opcode in sorted(int(key) for key in data):
            entry = data[str(opcode)]
            lines.extend([
                "=== OPCODE %d | unknown_if=%s ===" % (opcode, entry.get("unknown_ifs", 0)),
                entry.get("source", ""),
                "",
            ])
        Path(text_output).write_text("\n".join(lines), encoding="utf-8")
    return data


def clean_statement(source, ins):
    existing = _ORIGINAL_CLEAN(source, ins)
    if existing is not None:
        return existing
    text = source.strip().rstrip(";")

    match = re.fullmatch(
        r"__LUAUVMP_VARARG_PREFIX\((?P<n>" + _ID + r"),(?P<cursor>" + _ID
        + r"),@(?P<field>" + _FIELD + r")\)", text
    )
    if match:
        n, cursor = match.group("n"), match.group("cursor")
        value = luraph_lift.value_expr(luraph_lift.field_value(ins, match.group("field")))
        return "\n".join([
            "%s = %s" % (n, value),
            "for __arg_i = 1, %s do R[__arg_i] = argv[__arg_i] end" % n,
            "%s = %s + 1" % (cursor, n),
        ])

    match = re.fullmatch(
        r"__LUAUVMP_VARARG_FIXED\((?P<dst>" + _ID + r"),(?P<off>" + _ID
        + r"),(?P<cursor>" + _ID + r"),(?P<countfield>" + _FIELD
        + r"),@(?P<field>" + _FIELD + r")\)", text
    )
    if match:
        dst, off, cursor = match.group("dst"), match.group("off"), match.group("cursor")
        dst_value = luraph_lift.value_expr(luraph_lift.field_value(ins, match.group("field")))
        count_value = luraph_lift.value_expr(luraph_lift.field_value(ins, match.group("countfield")))
        return "\n".join([
            "%s = %s" % (dst, dst_value),
            "%s = 0" % off,
            "for __arg_i = %s, %s + (%s - 1) do" % (dst, dst, count_value),
            "    R[__arg_i] = argv[%s + %s]" % (cursor, off),
            "    %s += 1" % off,
            "end",
        ])

    match = re.fullmatch(
        r"__LUAUVMP_VARARG_REMAINING\((?P<dst>" + _ID + r"),(?P<len>" + _ID
        + r"),(?P<used>" + _ID + r"),(?P<off>" + _ID + r"),(?P<cursor>"
        + _ID + r"),(?P<top>" + _ID + r"),@(?P<field>" + _FIELD + r")\)", text
    )
    if match:
        dst, length, used = match.group("dst"), match.group("len"), match.group("used")
        off, cursor, top = match.group("off"), match.group("cursor"), match.group("top")
        dst_value = luraph_lift.value_expr(luraph_lift.field_value(ins, match.group("field")))
        return "\n".join([
            "%s = %s" % (dst, dst_value),
            "%s = argv.n - %s - 1" % (length, used),
            "if %s < 0 then %s = -1 end" % (length, length),
            "%s = 0" % off,
            "for __arg_i = %s, %s + %s do" % (dst, dst, length),
            "    R[__arg_i] = argv[%s + %s]" % (cursor, off),
            "    %s += 1" % off,
            "end",
            "%s = %s + %s" % (top, dst, length),
        ])
    return None


def install() -> None:
    global _INSTALLED, _ORIGINAL_RECOVER, _ORIGINAL_CLEAN
    if _INSTALLED:
        return
    _install_runtime_identities()
    _ORIGINAL_RECOVER = luraph_recover.recover_dispatch
    luraph_recover.recover_dispatch = recover_dispatch
    _ORIGINAL_CLEAN = luraph_lift.clean_statement
    luraph_lift.clean_statement = clean_statement
    _INSTALLED = True
