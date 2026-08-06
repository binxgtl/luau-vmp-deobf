# luau-vmp-deobf

Static and sandbox-assisted analysis for Luau scripts protected by custom
bytecode VMs, including staged **Luraph v14.x** loaders.

The Luraph pipeline derives opcode semantics from the interpreter embedded in
the same input. It does not assume stable opcode numbers or helper slots.

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

```bash
luauvmp luraph-full protected.lua -o recovered
```

The default pipeline is:

```text
protected.lua
  -> static loader unpack
  -> strict first-tree capture
  -> detect a staged Luraph bootstrap
  -> run only that bootstrap decoder in a lexical sandbox
  -> capture the returned application tree before its closure is constructed
  -> recover the sample-local dispatcher
  -> extract exact embedded Luau source strings when present
  -> emit instruction-level pseudo-Luau and compile-checked structural Luau
```

A staged sample reports progress similar to:

```text
[1/7] statically unpacking loader
[2/7] strictly capturing the parsed prototype tree
[3/7] finalising staged tree in sandbox (final payload disabled)
[4/7] recovering sample-local dispatcher semantics
[5/7] extracted 3 embedded Luau source chunk(s)
[6/7] devirtualising the complete prototype tree
[7/7] decompiling and compile-checking Luau source
```

Useful options already supported by the CLI:

```bash
luauvmp luraph-full protected.lua -o recovered --force
luauvmp luraph-full protected.lua -o recovered --timeout 600
luauvmp luraph-full protected.lua -o recovered --split-protos
```

To forbid execution of even a detected bootstrap decoder, set strict mode in
the environment before running the same command:

```bash
# Windows cmd
set LUAUVMP_STRICT_CAPTURE=1
luauvmp luraph-full protected.lua -o recovered --force

# POSIX shells
LUAUVMP_STRICT_CAPTURE=1 luauvmp luraph-full protected.lua -o recovered --force
```

Strict mode can intentionally stop at an intermediate tree. For staged samples
that tree may contain only the Luraph runtime and not the protected application.
The staged instruction budget defaults to 5,000,000 and can be changed with
`LUAUVMP_INSTRUCTION_BUDGET`.

## Output

When the final tree contains source passed to `loadstring`, exact source
constants are the most useful result:

```text
recovered/
├── embedded_main.luau
├── embedded_sources/
│   ├── 001_proto_....luau
│   ├── 002_proto_....luau
│   └── index.json
├── program.decompiled.luau
├── program.pseudo.lua
├── decompiler.json
├── manifest.json
├── pipeline.json
└── artifacts/
    ├── interpreter.vm.luau
    ├── interpreter.capture.luau
    ├── interpreter.finalize.luau
    ├── bootstrap_ir.tsv
    ├── final_ir.tsv
    ├── final_runtime_A.tsv
    ├── opcode_semantics.json
    ├── capture_runner.luau
    └── finalize_runner.luau
```

### Which output should I read?

1. **`embedded_main.luau`** — exact decoded Luau string from the application,
   when one exists. This is the closest result to authored source.
2. **`embedded_sources/*.luau`** — additional exact decoded modules.
3. **`program.pseudo.lua`** — complete instruction-level audit ground truth.
4. **`program.decompiled.luau`** — structural CFG/register lifting. Unsupported
   super-instructions remain quoted as `__semantic_fallback` data; compile
   success alone does not prove behavioral equivalence.

Not every protected program embeds source strings. Bytecode-only programs can
only produce pseudo/structural output, and compilation cannot recover original
names, comments or formatting.

## Safety model

The pipeline has two different dynamic boundaries:

- **Strict capture:** the recovered parser may parse its custom bytecode, but
  the first protected root closure is intercepted before execution.
- **Staged finalisation:** only when the strict tree matches the Luraph bootstrap
  signature, that bootstrap is allowed to run under a lexical sandbox and an
  instruction budget. The final application closure is replaced with a capture
  callback before construction and is never invoked.

The staged runner lexically shadows `require`, filesystem, network, process,
Roblox and common executor APIs. `getfenv()` and `_G` expose a closed table.
`pipeline.json` records:

```json
{
  "bootstrap_executed": true,
  "final_payload_executed": false,
  "capture_kind": "finalised-staged"
}
```

This is stronger than running the application, but it is not the same as a
purely static analysis. Use `LUAUVMP_STRICT_CAPTURE=1` when even sandboxed
bootstrap execution is unacceptable.

Decoded artifacts may contain webhooks, tokens, hardware identifiers or private
URLs already present in the input. Review output before sharing it.

## Runtime facts and dispatcher recovery

Versions through 0.4.1 accidentally serialised `runtimeState[1]`, the payload
environment slot, rather than the actual Luraph helper table. On affected
samples this produced 64 `nil` facts and anti-tamper-polluted opcode semantics.
Version 0.5.0 captures the helper table itself and rejects empty or implausible
runtime facts before dispatcher recovery.

Every opcode used by the final tree must have a recovered semantic before output
is committed.

## Artifact mode

For externally captured typed IR and a matching dispatcher map:

```bash
luauvmp luraph-full final_ir.tsv opcode_semantics.json -o recovered
```

Static loader unpack only:

```bash
luauvmp luraph protected.lua -o stage1
```

Corpus fingerprinting without VM execution:

```bash
luauvmp luraph-corpus samples/Luraph/v14.7 \
  -o luraph-corpus.json --strict
```

## Other custom Luau VMs

```bash
luauvmp deobf sample.lua --disasm --strings --spec -v
luauvmp inspect sample.lua --handlers --normalised
luauvmp unpack sample.lua
```

For separately captured staged images:

```bash
luauvmp deobf sample.lua --image stage2.bin --strings -v
```

## Development

```bash
python -m pytest -q
python -m py_compile luauvmp/*.py tools/*.py
```

No protected sample or decoded payload is included in the repository.

## Scope and intent

Use this project only on files you are authorised to inspect. It is designed to
help review unfamiliar protected code before deciding whether it is safe to run.

## License

MIT — see `LICENSE`.
