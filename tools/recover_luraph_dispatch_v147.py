"""Dispatcher specializer for public single-stream Luraph v14.7 wrappers.

The legacy implementation assumed the opcode local was named ``X``, the helper
table was named ``A``, numeric literals never used Luau binary/underscore
syntax, and bit helpers lived only in ``A[32]``. Public v14.7 samples randomize
all of those details. This module consumes metadata emitted by the structural
factory extractor and keeps the same semantics JSON schema as the legacy path.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Sequence
import json
import re

from tools import recover_luraph_dispatch as core


_META = re.compile(r"^--\s*LUAUVMP_(?P<key>[A-Z0-9_]+)=(?P<value>.*)$", re.M)
_NUMBER = re.compile(
    r"(?:0[xX][0-9A-Fa-f_]+|0[bB][01_]+|"
    r"(?:[0-9][0-9_]*\.[0-9_]*|\.[0-9_]+|[0-9][0-9_]*)"
    r"(?:[eE][+-]?[0-9_]+)?)"
)
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _long_bracket_end(source: str, start: int) -> Optional[int]:
    match = re.match(r"\[(=*)\[", source[start:])
    if match is None:
        return None
    close = "]" + match.group(1) + "]"
    position = source.find(close, start + len(match.group(0)))
    return None if position < 0 else position + len(close)


def lex(source: str) -> List[core.Tok]:
    """Tokenize the Luau subset used by dispatcher factories."""
    output: List[core.Tok] = []
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("--", index):
            long_end = _long_bracket_end(source, index + 2)
            if long_end is not None:
                index = long_end
            else:
                newline = source.find("\n", index + 2)
                index = length if newline < 0 else newline + 1
            continue
        if char in ('"', "'"):
            quote = char
            cursor = index + 1
            while cursor < length:
                if source[cursor] == "\\":
                    cursor += 2
                    continue
                if source[cursor] == quote:
                    cursor += 1
                    break
                cursor += 1
            output.append(core.Tok(source[index:cursor], index, cursor, "str"))
            index = cursor
            continue
        if char == "[":
            long_end = _long_bracket_end(source, index)
            if long_end is not None:
                output.append(core.Tok(source[index:long_end], index, long_end, "str"))
                index = long_end
                continue
        match = _NUMBER.match(source, index)
        if match is not None:
            output.append(core.Tok(match.group(0), index, match.end(), "num"))
            index = match.end()
            continue
        match = _IDENTIFIER.match(source, index)
        if match is not None:
            value = match.group(0)
            kind = "kw" if value in core.KEYWORDS else "id"
            output.append(core.Tok(value, index, match.end(), kind))
            index = match.end()
            continue
        hit = next((operator for operator in core.MULTI
                    if source.startswith(operator, index)), None)
        if hit is not None:
            output.append(core.Tok(hit, index, index + len(hit), "op"))
            index += len(hit)
            continue
        output.append(core.Tok(char, index, index + 1, "op"))
        index += 1
    return output


def _number(value: str):
    cleaned = value.replace("_", "")
    if cleaned.lower().startswith("0b"):
        return int(cleaned[2:], 2)
    if cleaned.lower().startswith("0x"):
        return int(cleaned[2:], 16)
    return float(cleaned) if any(char in cleaned for char in ".eE") else int(cleaned)


class ExprParser(core.ExprParser):
    def __init__(
        self,
        tokens: Sequence[core.Tok],
        opcode: int,
        runtime_values,
        environment=None,
        *,
        opcode_name: str,
        helper_name: str,
        nested_helpers: Dict[int, Dict[int, str]],
    ):
        self.t = list(tokens)
        self.i = 0
        self.X = opcode
        self.A = runtime_values
        self.env = environment or {}
        self.opcode_name = opcode_name
        self.helper_name = helper_name
        self.nested_helpers = nested_helpers

    def parse(self, minbp=0, stop=None):  # noqa: C901 - mirrors the legacy parser
        stop = stop or set()
        if self.i >= len(self.t) or self.peek() in stop:
            return core.UNKNOWN
        token = self.take()
        value = token.v
        if value == "(":
            left = self.parse(0, {")"})
            if self.peek() == ")":
                self.take()
        elif value == "not":
            item = self.parse(90, stop)
            left = core.UNKNOWN if item is core.UNKNOWN else (not core.truthy(item))
        elif value == "-":
            item = self.parse(90, stop)
            left = (core.UNKNOWN if item is core.UNKNOWN
                    or not isinstance(item, (int, float)) else -item)
        elif value == "#":
            item = self.parse(90, stop)
            left = (core.UNKNOWN if item is core.UNKNOWN
                    else (len(item) if hasattr(item, "__len__") else core.UNKNOWN))
        elif value == self.opcode_name:
            left = self.X
        elif value == "true":
            left = True
        elif value == "false":
            left = False
        elif value == "nil":
            left = None
        elif token.kind == "num":
            try:
                left = _number(value)
            except ValueError:
                left = core.UNKNOWN
        elif token.kind == "str":
            try:
                left = bytes(value[1:-1], "utf8").decode("unicode_escape")
            except Exception:
                left = value[1:-1]
        elif value == self.helper_name:
            left = core.KnownTable("A")
        elif token.kind in ("id", "kw") and value in self.env:
            left = self.env[value]
        else:
            left = core.UNKNOWN

        while self.i < len(self.t):
            operator = self.peek()
            if operator == "[":
                self.take()
                key = self.parse(0, {"]"})
                if self.peek() == "]":
                    self.take()
                if isinstance(left, core.KnownTable) and isinstance(key, (int, float)):
                    index = int(key)
                    if left.name == "A" and index in self.nested_helpers:
                        left = core.KnownTable("A%d" % index)
                    elif left.name == "A":
                        runtime = self.A.get(index)
                        left = core.UNKNOWN if runtime is None else runtime.value
                    elif left.name.startswith("A"):
                        try:
                            table_index = int(left.name[1:])
                        except ValueError:
                            left = core.UNKNOWN
                        else:
                            name = self.nested_helpers.get(table_index, {}).get(index)
                            left = core.KnownFunc(name) if name else core.UNKNOWN
                    else:
                        left = core.UNKNOWN
                else:
                    left = core.UNKNOWN
                continue
            if operator == "(":
                self.take()
                arguments = []
                if self.peek() != ")":
                    while self.i < len(self.t):
                        arguments.append(self.parse(0, {",", ")"}))
                        if self.peek() == ",":
                            self.take()
                            continue
                        break
                if self.peek() == ")":
                    self.take()
                left = (core.apply_known_func(left, arguments)
                        if isinstance(left, core.KnownFunc) else core.UNKNOWN)
                continue
            break

        precedence = {
            "or": 10, "and": 20,
            "==": 30, "~=": 30, "<": 30, ">": 30, "<=": 30, ">=": 30,
            "+": 40, "-": 40,
            "*": 50, "/": 50, "%": 50, "//": 50,
            "^": 60,
        }
        while self.i < len(self.t):
            operator = self.peek()
            if operator in stop:
                break
            binding = precedence.get(operator, -1)
            if binding < minbp:
                break
            self.take()
            right = self.parse(binding + (0 if operator == "^" else 1), stop)
            left = core.applyop(operator, left, right)
        return left


def _parser(tokens, opcode, values, environment, metadata):
    return ExprParser(
        tokens,
        opcode,
        values,
        environment,
        opcode_name=metadata["opcode_name"],
        helper_name=metadata["helper_name"],
        nested_helpers=metadata["nested_helpers"],
    )


def eval_cond(tokens, opcode, values, environment, metadata):
    try:
        parser = _parser(tokens, opcode, values, environment, metadata)
        value = parser.parse()
        if parser.i != len(parser.t):
            return core.UNKNOWN
        return core.UNKNOWN if value is core.UNKNOWN else core.truthy(value)
    except Exception:
        return core.UNKNOWN


def _simple_assign(raw, opcode, values, environment, metadata):
    tokens = raw.toks
    if not tokens:
        return
    index = 1 if tokens[0].v == "local" else 0
    if (index + 2 <= len(tokens) - 1
            and tokens[index].kind in ("id", "kw")
            and tokens[index + 1].v in ("=", "+=", "-=", "*=", "/=", "//=", "%=")):
        name = tokens[index].v
        operator = tokens[index + 1].v
        right = tokens[index + 2:]
        try:
            parser = _parser(right, opcode, values, environment, metadata)
            value = parser.parse()
            if parser.i != len(parser.t):
                value = core.UNKNOWN
        except Exception:
            value = core.UNKNOWN
        if operator == "=":
            environment[name] = value
        else:
            old = environment.get(name, core.UNKNOWN)
            environment[name] = core.applyop(
                operator[0] if operator != "//=" else "//", old, value
            )
    elif (len(tokens) >= 2 and tokens[0].v == "local"
          and tokens[1].kind in ("id", "kw")):
        environment[tokens[1].v] = core.UNKNOWN


def specialize(nodes, opcode, values, metadata, environment=None):
    stable = {"q", metadata["opcode_name"], metadata["helper_name"]}
    environment = dict(environment or {
        "q": ("closure_q",),
        metadata["opcode_name"]: opcode,
        metadata["helper_name"]: core.KnownTable("A"),
    })
    output = []
    for node in nodes:
        if isinstance(node, core.Raw):
            _simple_assign(node, opcode, values, environment, metadata)
            output.append(node)
        elif isinstance(node, core.If):
            picked = False
            unknown = []
            for condition, body in node.branches:
                value = eval_cond(condition, opcode, values, environment, metadata)
                if value is True:
                    output.extend(specialize(body, opcode, values, metadata,
                                             dict(environment)))
                    picked = True
                    break
                if value is core.UNKNOWN:
                    unknown.append((condition, specialize(
                        body, opcode, values, metadata, dict(environment)
                    )))
            if picked:
                continue
            else_body = (specialize(node.else_body or [], opcode, values, metadata,
                                    dict(environment))
                         if node.else_body is not None else None)
            if unknown:
                output.append(core.If(unknown, else_body))
                environment = {key: value for key, value in environment.items()
                               if key in stable}
            elif else_body is not None:
                output.extend(else_body)
        elif isinstance(node, core.While):
            value = eval_cond(node.cond, opcode, values, environment, metadata)
            nested = {key: item for key, item in environment.items() if key in stable}
            body = specialize(node.body, opcode, values, metadata, nested)
            if value is False:
                continue
            output.append(core.While(node.cond, body))
            environment = nested
        elif isinstance(node, core.For):
            nested = {key: item for key, item in environment.items() if key in stable}
            output.append(core.For(
                node.header, specialize(node.body, opcode, values, metadata, nested)
            ))
        elif isinstance(node, core.Repeat):
            nested = {key: item for key, item in environment.items() if key in stable}
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


def _metadata(source: str):
    values = {match.group("key"): match.group("value").strip()
              for match in _META.finditer(source)}
    if values.get("PUBLIC_V147") != "1":
        raise RuntimeError("factory is not marked as public Luraph v14.7")
    helper_name = values.get("HELPER_VAR")
    opcode_name = values.get("DISPATCH_VAR")
    if not helper_name or not opcode_name:
        raise RuntimeError("public factory metadata is incomplete")
    try:
        raw_nested = json.loads(values.get("NESTED_HELPERS", "{}"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("invalid nested-helper metadata") from exc
    nested = {
        int(table): {int(index): str(name) for index, name in slots.items()}
        for table, slots in raw_nested.items()
    }
    return {
        "helper_name": helper_name,
        "opcode_name": opcode_name,
        "nested_helpers": nested,
    }


def recover(factory: Path, runtime_values, output: Path, text_output: Path):
    source = factory.read_text(encoding="utf-8", errors="surrogateescape")
    metadata = _metadata(source)
    tokens = lex(source)
    while_index = None
    for index in range(len(tokens) - 5):
        if (tokens[index].v == "while"
                and tokens[index + 1].v == "true"
                and tokens[index + 2].v == "do"
                and tokens[index + 3].v == "local"
                and tokens[index + 4].v == metadata["opcode_name"]):
            while_index = index
            break
    if while_index is None:
        raise RuntimeError(
            "dispatcher while for opcode local %s was not found"
            % metadata["opcode_name"]
        )
    parser = core.Parser(tokens)
    parser.i = while_index
    dispatcher = parser.parse_while()
    if len(dispatcher.body) < 3:
        raise RuntimeError("public dispatcher body is unexpectedly small")
    body = dispatcher.body[1:-1]

    results = {}
    report = []
    for opcode in range(256):
        specialized = specialize(body, opcode, runtime_values, metadata)
        lines = core.render(specialized)
        text = "\n".join(lines)
        unknown = core.count_unknown_ifs(specialized)
        results[str(opcode)] = {
            "source": text,
            "unknown_ifs": unknown,
            "lines": len(lines),
        }
        report.append(
            "-- opcode %d | unknown_if=%d\n%s\n" % (opcode, unknown, text)
        )

    unique = len({entry["source"] for entry in results.values()})
    if unique < 32:
        raise RuntimeError(
            "public dispatcher specialization collapsed to only %d unique semantics"
            % unique
        )
    output.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    text_output.write_text("\n".join(report), encoding="utf-8")
    return results
