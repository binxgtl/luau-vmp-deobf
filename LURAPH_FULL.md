# Build-independent Luraph full-prototype pipeline

The legacy `luraph-devirt` command keeps its v14.7 reference opcode table for
compatibility. It is not safe to reuse that table across unrelated builds.
The release pipeline instead treats every protected file as a potentially
unique VM build:

1. statically unpack the loader into VM source and custom bytecode;
2. capture a typed multi-prototype IR without invoking the payload closure;
3. specialise the dispatcher from that same sample for every opcode value;
4. validate that every opcode used by the capture has semantics;
5. stream every prototype into one dispatcher-free pseudo-Luau bundle.

## Commands

Unpack one loader without executing it:

```bash
luauvmp luraph protected.lua -o recovered
```

Recover sample-local dispatcher semantics:

```bash
python tools/recover_luraph_dispatch.py \
  luraph_interpreter_factory.luau luraph_runtime_A.tsv \
  -o luraph_opcode_semantics.json
```

Devirtualise all captured prototypes:

```bash
luauvmp luraph-full luraph_full_ir.tsv luraph_opcode_semantics.json \
  -o full-devirt
```

The default output is a streaming `program.pseudo.lua` bundle plus a manifest
and prototype index. Per-prototype files are opt-in because creating thousands
of files is slower and unnecessary for most workflows:

```bash
luauvmp luraph-full full_ir.tsv semantics.json -o out --split-protos
```

Scan a regression corpus and group structurally similar VM builds:

```bash
luauvmp luraph-corpus samples/Luraph/v14.7 -o corpus.json --strict
```

The corpus command only runs the static unpacker. It never executes recovered
VM source, Roblox APIs, network requests, filesystem payload code, or the
returned payload closure.

## Output contract

`manifest.json` records:

- format version;
- prototype and instruction counts;
- number of opcode slots used;
- bundle/split output mode;
- all generated files.

The devirtualiser rejects incomplete semantics maps before writing output.
Writes are streamed, bounded in memory, and atomically replaced so interrupted
runs do not leave a valid-looking partial bundle.

## What “full” means here

The output replaces every captured custom opcode with the concrete semantics
of the same sample's dispatcher and processes the complete prototype tree. It
is instruction-level full devirtualisation.

It does **not** claim to recover information destroyed by compilation, such as
original local names, comments, formatting, or the exact source-level choice
between equivalent control-flow constructs. Code downloaded from a remote
server is also outside the input and cannot be recovered from the loader alone.
