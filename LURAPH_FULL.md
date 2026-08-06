# One-command Luraph full-prototype pipeline

The primary workflow accepts the original protected loader directly:

```bash
luauvmp luraph-full protected.lua -o recovered
```

The command treats each file as a potentially unique VM build and performs:

1. static base85/range-code unpacking;
2. extraction of the embedded VM interpreter and custom bytecode;
3. patching of the payload-closure constructor into a capture callback;
4. prototype and runtime-fact capture under a restricted Lune environment;
5. dispatcher specialisation from the same sample;
6. opcode coverage validation across the complete prototype tree;
7. streaming, atomic output of dispatcher-free pseudo-Luau.

The returned payload closure is never called. The loaded VM parser receives a
minimal standard-library environment without `require`, filesystem, network,
process, Roblox, or executor APIs.

## Requirements

- Python 3.9+
- Lune on `PATH`, or `--runtime /path/to/lune`

## Output

The default output contains one auditable `program.pseudo.lua` bundle,
`manifest.json`, `pipeline.json`, a prototype index, and the intermediate
capture artifacts under `artifacts/`. Use `--split-protos` when individual
prototype files are useful.

## Artifact compatibility mode

The v0.2 interface remains available:

```bash
luauvmp luraph-full full_ir.tsv opcode_semantics.json -o recovered
```

## What “full” means

Every captured prototype is processed and every opcode used by the capture must
have semantics recovered from that same sample. “Full” does not imply recovery
of original local names, comments, formatting, remote code absent from the
loader, or the exact original source-level control-flow spelling.
