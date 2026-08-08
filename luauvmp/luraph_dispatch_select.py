"""Select the full public-v14.7 dispatcher from multi-mode factories.

Public Luraph factories contain several interpreters selected by a prototype
mode field.  Small helper modes commonly expose only 10-15 instruction classes,
while the application mode dispatches the randomized 8-bit opcode space.  The
old recovery path trusted one syntactically first/last dispatcher marker and
therefore collapsed 001163/00a98 to 14/10 semantics.

This layer enumerates every loop that reads the *same physical opcode array*,
specializes each candidate over all 256 byte values, and chooses the candidate
with the greatest semantic discrimination.  Selection is entirely static: no
recovered closure or application code is executed.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple
import json
import re

from tools import recover_luraph_dispatch as core
from tools import recover_luraph_dispatch_v147 as public

_INSTALLED = False
_ORIGINAL_RECOVER = None


@dataclass
class Candidate:
    kind: str
    token_index: int
    opcode_name: str
    opcode_array: str
    pc_name: str
    body: Sequence[core.Node]


@dataclass
class SpecializedCandidate:
    candidate: Candidate
    results: Dict[str, dict]
    report: List[str]
    unique: int
    unknown_total: int


def _markers(source: str) -> Dict[str, str]:
    return {
        match.group("key"): match.group("value").strip()
        for match in public._META.finditer(source)
    }


def _opcode_array(source: str, metadata: Dict[str, str]) -> str:
    """Find the physical opcode-array local from canonical-variable metadata."""
    raw = metadata.get("CANONICAL_VARS", "{}")
    try:
        mapping = json.loads(raw)
    except json.JSONDecodeError:
        mapping = {}
    matches = sorted(name for name, canonical in mapping.items() if canonical == "L")
    if len(matches) == 1:
        return matches[0]

    # Fallback for factories produced before CANONICAL_VARS existed: inspect the
    # dispatcher named by the extractor and recover the array from its RHS.
    dispatch_name = metadata.get("DISPATCH_VAR")
    if not dispatch_name:
        raise RuntimeError("public factory has no dispatcher variable")
    pattern = re.compile(
        r"(?:while\s+true\s+do|repeat)\s+local\s+"
        + re.escape(dispatch_name)
        + r"\s*=\s*\(?\s*(?P<array>[A-Za-z_]\w*)\s*\[",
        re.S,
    )
    hit = pattern.search(source)
    if hit is None:
        raise RuntimeError("public opcode array could not be inferred")
    return hit.group("array")


def _loop_header(tokens: Sequence[core.Tok], index: int):
    """Return (kind, op, array, pc) for one generated dispatcher header."""
    length = len(tokens)
    if index >= length:
        return None
    if (tokens[index].v == "while" and index + 7 < length
            and tokens[index + 1].v == "true"
            and tokens[index + 2].v == "do"
            and tokens[index + 3].v == "local"):
        kind = "while"
        cursor = index + 4
    elif (tokens[index].v == "repeat" and index + 5 < length
          and tokens[index + 1].v == "local"):
        kind = "repeat"
        cursor = index + 2
    else:
        return None

    opcode = tokens[cursor].v
    if tokens[cursor].kind not in ("id", "kw"):
        return None
    cursor += 1
    if cursor >= length or tokens[cursor].v != "=":
        return None
    cursor += 1
    if cursor < length and tokens[cursor].v == "(":
        cursor += 1
    if cursor + 3 >= length:
        return None
    array = tokens[cursor].v
    if tokens[cursor].kind not in ("id", "kw"):
        return None
    cursor += 1
    if tokens[cursor].v != "[":
        return None
    pc = tokens[cursor + 1].v
    if tokens[cursor + 1].kind not in ("id", "kw"):
        return None
    if tokens[cursor + 2].v != "]":
        return None
    return kind, opcode, array, pc


def _candidates(source: str, tokens: Sequence[core.Tok], opcode_array: str) -> List[Candidate]:
    candidates: List[Candidate] = []
    for index in range(len(tokens)):
        header = _loop_header(tokens, index)
        if header is None:
            continue
        kind, opcode, array, pc = header
        if array != opcode_array:
            continue
        parser = core.Parser(list(tokens))
        parser.i = index
        node = parser.parse_while() if kind == "while" else parser.parse_repeat()
        body = node.body
        if len(body) < 2:
            continue
        # The first statement only loads opcode_array[pc].  Generated loops also
        # advance the PC as their final raw statement; neither belongs to an
        # individual opcode semantic body.
        semantic_body = body[1:-1] if len(body) >= 3 else body[1:]
        candidates.append(Candidate(
            kind=kind,
            token_index=index,
            opcode_name=opcode,
            opcode_array=array,
            pc_name=pc,
            body=semantic_body,
        ))
    return candidates


def _specialize(candidate: Candidate, runtime_values, base_metadata) -> SpecializedCandidate:
    metadata = dict(base_metadata)
    metadata["opcode_name"] = candidate.opcode_name
    results: Dict[str, dict] = {}
    report: List[str] = []
    unknown_total = 0
    for opcode in range(256):
        nodes = public.specialize(candidate.body, opcode, runtime_values, metadata)
        lines = core.render(nodes)
        text = "\n".join(lines)
        unknown = core.count_unknown_ifs(nodes)
        unknown_total += unknown
        results[str(opcode)] = {
            "source": text,
            "unknown_ifs": unknown,
            "lines": len(lines),
            "dispatch_opcode_name": candidate.opcode_name,
            "dispatch_pc_name": candidate.pc_name,
        }
        report.append(
            "-- opcode %d | unknown_if=%d\n%s\n" % (opcode, unknown, text)
        )
    unique = len({entry["source"] for entry in results.values()})
    return SpecializedCandidate(candidate, results, report, unique, unknown_total)


def _choose(items: Sequence[SpecializedCandidate]) -> SpecializedCandidate:
    if not items:
        raise RuntimeError("no public dispatcher candidates read the opcode array")
    ranked = sorted(
        items,
        key=lambda item: (-item.unique, item.unknown_total,
                          item.candidate.token_index),
    )
    best = ranked[0]
    if best.unique < 32:
        raise RuntimeError(
            "public dispatcher specialization collapsed to only %d unique semantics"
            % best.unique
        )
    if len(ranked) > 1:
        second = ranked[1]
        if (best.unique == second.unique
                and best.unknown_total == second.unknown_total
                and best.results != second.results):
            raise RuntimeError(
                "public dispatcher selection is ambiguous: %s/%s both score %d"
                % (best.candidate.opcode_name, second.candidate.opcode_name,
                   best.unique)
            )
    return best


def recover(factory: Path, runtime_values, output: Path, text_output: Path):
    source = Path(factory).read_text(encoding="utf-8", errors="surrogateescape")
    base_metadata = public._metadata(source)
    markers = _markers(source)
    opcode_array = _opcode_array(source, markers)
    tokens = public.lex(source)
    candidates = _candidates(source, tokens, opcode_array)
    specialized = [_specialize(candidate, runtime_values, base_metadata)
                   for candidate in candidates]
    best = _choose(specialized)

    output = Path(output)
    text_output = Path(text_output)
    output.write_text(
        json.dumps(best.results, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    header = (
        "-- selected public dispatcher: opcode=%s pc=%s array=%s kind=%s "
        "unique=%d unknown_total=%d candidates=%s\n\n"
        % (
            best.candidate.opcode_name,
            best.candidate.pc_name,
            best.candidate.opcode_array,
            best.candidate.kind,
            best.unique,
            best.unknown_total,
            ",".join(
                "%s:%d" % (item.candidate.opcode_name, item.unique)
                for item in sorted(specialized,
                                   key=lambda item: item.candidate.token_index)
            ),
        )
    )
    text_output.write_text(header + "\n".join(best.report), encoding="utf-8")
    return best.results


def install() -> None:
    global _INSTALLED, _ORIGINAL_RECOVER
    if _INSTALLED:
        return
    _ORIGINAL_RECOVER = public.recover
    public.recover = recover
    _INSTALLED = True
