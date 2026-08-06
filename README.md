# luau-vmp-deobf

Static and sandbox-assisted analysis for Luau scripts protected by custom
bytecode VMs, including **Luraph v14.x**.

The Luraph pipeline derives its opcode semantics from the VM embedded in the
same input. It does not assume that two builds share opcode numbers, dispatcher
branches, operands, constants, or identifier names.

## Install

Requirements:

- Python 3.9+
- [Lune](https://lune-org.github.io/docs/getting-started/1-installation/) on
  `PATH`

```bash
git clone https://github.com/binxgtl/luau-vmp-deobf.git
cd luau-vmp-deobf
python -m pip install -e .

luauvmp --help
lune --version
```

## Luraph: one command

Use **0.4.0 or newer** for source decompilation:

```bash
luauvmp luraph-full protected.lua -o recovered
```

The command performs five stages:

```text
protected.lua
  -> statically unpack the outer loader
  -> intercept root-closure execution before the payload can run
  -> capture the complete prototype tree under a restricted Lune environment
  -> recover dispatcher semantics from this sample's VM
  -> devirtualise every captured instruction
  -> build basic blocks and emit compile-checked Luau source
```

Useful options:

```bash
luauvmp luraph-full protected.lua -o recovered --force
luauvmp luraph-full protected.lua -o recovered --timeout 600
luauvmp luraph-full protected.lua -o recovered --runtime C:\path\to\lune.exe
luauvmp luraph-full protected.lua -o recovered --split-protos
luauvmp luraph-full protected.lua -o recovered --keep-failed
```

### Output

```text
recovered/
├── program.decompiled.luau   # valid Luau source; compile-checked, never executed
├── program.pseudo.lua        # instruction-level audit representation
├── decompiler.json           # CFG/lifting/fallback metrics
├── manifest.json
├── pipeline.json
├── all_protos.index.txt
└── artifacts/
    ├── interpreter.vm.luau
    ├── interpreter.capture.luau
    ├── interpreter.factory.luau
    ├── bytecode.bin
    ├── full_ir.tsv
    ├── runtime_A.tsv
    ├── opcode_semantics.json
    ├── opcode_semantics.txt
    ├── capture_runner.luau
    └── compile_decompiled.luau
```

`program.decompiled.luau` contains ordinary Luau functions, a register table per
prototype, reconstructed basic blocks, direct branches, direct returns, table
operations, globals, arithmetic, comparisons, common calls, and closure
references. The generated file is passed to `luau.compile` through Lune. It is
**not loaded or executed**.

Uncommon super-instructions are not silently discarded. Their recovered
sample-local semantic body is retained in the relevant basic block and counted
as a fallback in `decompiler.json`. `program.pseudo.lua` remains the auditable
ground truth for every instruction.

## What the source backend recovers

The decompiler currently recovers:

- the complete prototype tree;
- sample-local opcode meaning;
- basic blocks and direct CFG edges;
- register assignments and constants;
- globals and table accesses;
- arithmetic, comparisons, concatenation, length and unary operations;
- common fixed-arity calls;
- direct jumps, conditional branches and returns;
- child-prototype closure references;
- valid Luau syntax verified by the local Lune compiler.

The current source backend can retain a `pc` state machine when control flow is
heavily flattened or when a super-instruction cannot yet be safely structured.
That is decompiled Luau, but it is not a claim that original `if`/`while` layout
or original local names have been recovered.

Compilation and virtualization can permanently destroy:

- original local/upvalue names;
- comments and formatting;
- exact source-level control-flow spelling;
- code downloaded later from a remote server.

## Safety boundary

The outer loader is unpacked statically. Before the recovered VM parser is run,
`luraph-full` replaces the parser's immediate root-closure construction-and-call
site with a capture callback. Instrumentation fails closed unless the expected
early execution site and final closure return are both found exactly once.

The capture environment does not expose Roblox, executor, network, filesystem,
or process APIs. A restricted `debug` compatibility layer and sandboxed
`loadstring` are provided only for VM bootstrap compatibility. The generated
source is compiled but never executed.

Decoded artifacts can still contain credentials or identifiers already embedded
in the input. Review output before publishing it.

## Artifact mode

Externally captured IR and semantics can still be processed directly:

```bash
luauvmp luraph-full full_ir.tsv opcode_semantics.json -o recovered
```

Artifact mode remains the instruction-level devirtualizer in this release. The
five-stage raw-loader path above is the source-decompiler path being validated
against live Lune captures.

Individual stages remain available:

```bash
luauvmp luraph protected.lua -o stage1

python tools/recover_luraph_dispatch.py \
  interpreter.factory.luau runtime_A.tsv \
  -o opcode_semantics.json
```

## Corpus regression

```bash
luauvmp luraph-corpus samples/Luraph/v14.7 \
  -o luraph-corpus.json --strict
```

The corpus command unpacks and fingerprints samples without running recovered
VM source.

## Reference scale

The source backend has been exercised locally against the large reference
capture used during development:

- 1,204 prototypes;
- 127,505 custom instructions;
- 54,953 reconstructed basic blocks;
- 92,717 instructions lifted to clean source statements;
- 34,788 instructions retained as explicit semantic fallbacks;
- 72.7% clean-lift ratio;
- about 16 MB of generated Luau source.

These numbers describe that reference capture, not a guaranteed ratio for every
Luraph build. The live Windows/Lune sample that motivated this release must
still pass its own stage-5 compile check before that sample is considered
end-to-end verified.

## Other custom Luau VMs

```bash
luauvmp deobf sample.lua --disasm --strings --spec -v
luauvmp inspect sample.lua --handlers --normalised
luauvmp unpack sample.lua
```

## Development

```bash
python -m pytest -q
python -m py_compile luauvmp/*.py tools/*.py
```

When adding a Luraph family, preserve these invariants:

1. never invoke the protected root or returned payload closure;
2. recover semantics from the same sample;
3. reject missing opcode semantics;
4. keep `program.pseudo.lua` as the instruction-level audit artifact;
5. preserve unsupported semantics instead of guessing or dropping them;
6. compile-check generated Luau without executing it;
7. add minimized regression fixtures rather than protected payloads.

## Scope and intent

Use this project only on code you are authorised to inspect.

## License

MIT — see `LICENSE`.
