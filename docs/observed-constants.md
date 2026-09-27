# Replaying observed constants

Luraph v15 can decrypt constants only after a runtime path materializes them.
This repository now accepts **recorded** operand observations for an existing
typed prototype capture. It does not include a v15 capture backend or execute a
protected payload. Treat observations from third-party tooling as untrusted
until verified independently; the SHA-256 binding detects stale inputs, not
fabricated observations.

Prepare a `facts.json` file with an SHA-256 digest of the exact `full_ir.tsv`
bytes and a list of observed changes:

```json
{
  "format_version": 1,
  "ir_sha256": "<64 lowercase hex characters>",
  "facts": [
    {"proto": 0, "pc": 1, "operand": "E", "before": "S6f6c64", "after": "S6e6577"}
  ]
}
```

The cell encoding matches `full_ir.tsv`: `N` is nil, `B0`/`B1` are booleans,
`D...` is a number, and `S` followed by UTF-8 hex is a string. The supported
operands are `E`, `p`, `o`, `H`, `_`, and `B`; opcode replacement is forbidden.
The old value must match the capture exactly. Unknown locations, duplicate
facts, non-concrete observed values, and mismatched digests fail before any
in-memory change is made.

```bash
luauvmp luraph-full artifacts/full_ir.tsv artifacts/opcode_semantics.json \
  --constant-facts facts.json -o recovered
```

This artifact mode writes `constant_facts.json` with the IR digest, facts-file
digest, and number of applied observations. Its pseudo-source remains an audit
view, and applying facts alone does not establish fully correct semantics.
The report therefore marks `strict_quality_gate: false` and
`path_complete: false`. An observation from one path cannot be promoted to an
all-path fact: a self-modifying VM may use different cells at the same PC on
different paths. Opcode mutation is excluded from this replay format.
The ordinary one-command v14.x pipeline is unaffected. A v15 integration
requires a sample-local capture producer, bounded runtime execution policy,
dispatcher recovery for that family, and regression samples before claiming
v15 support.
