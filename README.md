# luau-vmp-deobf

Static and sandbox-assisted devirtualisation for Luau scripts protected by
custom bytecode VMs, including **Luraph v14.x**.

The project derives VM details from each input instead of assuming one global
opcode map. Luraph builds can randomise identifiers, dispatcher branches,
operands, constants and opcode numbers independently, so the full pipeline
recovers semantics from the VM embedded in the same sample.

## Install

Requirements:

- Python 3.9+
- [Lune](https://lune-org.github.io/docs/getting-started/1-installation/) on
  `PATH` for the one-command Luraph pipeline

```bash
git clone https://github.com/binxgtl/luau-vmp-deobf.git
cd luau-vmp-deobf
python -m pip install -e .
```

Check both commands:

```bash
luauvmp --help
lune --version
```

## Luraph: one command

```bash
luauvmp luraph-full protected.lua -o recovered
```

That single command performs the complete instruction-level pipeline:

```text
protected.lua
  -> static base85/range-code unpack
  -> recovered interpreter + custom bytecode
  -> patch payload-closure construction
  -> safe prototype capture under Lune
  -> recover runtime helper facts
  -> specialise this sample's dispatcher
  -> validate every opcode used by every prototype
  -> emit one dispatcher-free pseudo-Luau bundle
```

Useful options:

```bash
luauvmp luraph-full protected.lua -o recovered --force
luauvmp luraph-full protected.lua -o recovered --runtime /path/to/lune
luauvmp luraph-full protected.lua -o recovered --timeout 600
luauvmp luraph-full protected.lua -o recovered --split-protos
```

`--split-protos` additionally writes one file per prototype. The default is a
single streaming bundle because large samples may contain more than one
thousand functions.

### Output

```text
recovered/
├── program.pseudo.lua
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
    └── capture_runner.luau
```

`pipeline.json` records prototype/instruction counts, opcode coverage, elapsed
time and `payload_executed: false`.

### Safety boundary

The loader itself and the returned payload closure are not executed.

The only dynamic step is the recovered VM's **bytecode parser**. Before Lune
loads it, `luraph-full` replaces the one call that constructs the executable
payload closure with a capture callback. The callback serialises prototypes and
returns a disabled function. The loaded parser receives a restricted standard-
library environment without `require`, filesystem, network, process, Roblox or
executor APIs.

Decoded artifacts can still contain secrets already present in the input. Do
not publish raw output before checking for tokens, webhooks, cookies, hardware
identifiers or private URLs.

## Luraph artifact mode

The v0.2 workflow remains available for debugging or externally captured data:

```bash
luauvmp luraph-full full_ir.tsv opcode_semantics.json -o recovered
```

Individual stages are also available:

```bash
# Static unpack only
luauvmp luraph protected.lua -o stage1

# Recover dispatcher semantics manually
python tools/recover_luraph_dispatch.py \
  interpreter.factory.luau runtime_A.tsv \
  -o opcode_semantics.json
```

## Corpus regression

Safely unpack and fingerprint a directory without running recovered VM source:

```bash
luauvmp luraph-corpus samples/Luraph/v14.7 \
  -o luraph-corpus.json --strict
```

The corpus manifest groups structurally similar interpreter builds while still
recording their exact hashes and unpack failures.

## Other custom Luau VMs

For the original base64/LZSS custom-VM pipeline:

```bash
luauvmp deobf sample.lua --disasm --strings --spec -v
luauvmp inspect sample.lua --handlers --normalised
luauvmp unpack sample.lua
```

For staged images captured separately:

```bash
luauvmp deobf sample.lua --image stage2.bin --strings -v
```

## What “full” means

For Luraph, “full” means:

- the complete captured prototype tree is processed;
- opcode semantics come from the same sample's dispatcher;
- every opcode used by the capture must have a recovered semantic;
- custom instructions are replaced with dispatcher-free pseudo-Luau;
- incomplete maps fail before a valid-looking output is written.

It does **not** mean byte-identical recovery of the original source. Compilation
can destroy local names, comments, formatting and the exact choice between
semantically equivalent control-flow constructs. Code fetched from a remote
server is not present in the loader and cannot be recovered from that loader
alone.

## Validation scale

The streaming writer has been regression-tested at the large reference scale:

- 1,204 prototypes
- 127,505 custom instructions
- all 256 opcode slots represented
- approximately 11 MB of generated pseudo-Luau

No protected sample or decoded payload is bundled in this repository.

## Development

```bash
python -m pytest -q
```

When adding a new Luraph family, preserve these invariants:

1. never call the returned payload closure;
2. recover dispatcher semantics from the same sample;
3. reject missing opcode semantics;
4. keep the instruction-level bundle as the auditable ground truth;
5. add a minimized regression fixture rather than a real protected payload.

## Scope and intent

This is an analysis tool for reading unfamiliar protected code before deciding
whether it is safe to run. Only analyse files you are authorised to inspect.

## License

MIT — see `LICENSE`.
