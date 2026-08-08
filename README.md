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
- Internet access for the default [lua.expert](https://lua.expert/) readability
  post-pass. Use `--no-lua-expert` for a fully local run.

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
  -> compile program.decompiled.luau to standard luauc without executing it
  -> POST the base64 luauc to https://api.lua.expert/decompile
  -> write program.luaexpert.luau as an advisory readability view
```

The strict devirtualization quality gate is always completed locally before the
lua.expert post-pass. The remote result cannot reduce fallback counts, resolve
dispatcher branches, or change the payload-execution safety flags.

A staged sample reports progress similar to:

```text
[1/7] statically unpacking loader
[2/7] strictly capturing the parsed prototype tree
[3/7] finalising staged tree in sandbox (final payload disabled)
[4/7] recovering sample-local dispatcher semantics
[5/7] extracted 3 embedded Luau source chunk(s)
[6/7] devirtualising the complete prototype tree
[7/7] decompiling and compile-checking Luau source
[lua.expert] compiling already-devirtualized Luau locally; the resulting luauc bytes will be uploaded to a third-party service
lua.expert: wrote program.luaexpert.luau (...-byte luauc upload)
```

Useful options already supported by the CLI:

```bash
luauvmp luraph-full protected.lua -o recovered --force
luauvmp luraph-full protected.lua -o recovered --timeout 600
luauvmp luraph-full protected.lua -o recovered --api-timeout 60
luauvmp luraph-full protected.lua -o recovered --split-protos
luauvmp luraph-full protected.lua -o recovered --no-lua-expert
```

`--no-lua-expert` keeps the entire run local and stops after the compile-checked
structural devirtualization output.

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
├── program.luaexpert.luau
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

`program.luaexpert.luau` is omitted when `--no-lua-expert` is used.

### Which output should I read?

1. **`embedded_main.luau`** — exact decoded Luau string from the application,
   when one exists. This is the closest result to authored source.
2. **`embedded_sources/*.luau`** — additional exact decoded modules.
3. **`program.luaexpert.luau`** — lua.expert's readability-oriented decompile of
   the locally generated structural program. It is derived output, not audit
   ground truth and not a claim of original names/comments/formatting.
4. **`program.pseudo.lua`** — complete instruction-level audit ground truth.
5. **`program.decompiled.luau`** — local structural CFG/register lifting used by
   the strict quality gate and as the input to the lua.expert post-pass.

For a fail-closed fully-devirtualized result, require all three decompiler
metrics in `pipeline.json`: `compile_checked: true`, `fallback_instructions: 0`,
and `unresolved_dispatcher_conditionals: 0`. The public v14.7 corpus workflow
enforces the same gate while also requiring both payload-execution flags to be
`false`.

The `pipeline.json` `lua_expert` entry is explicitly advisory and has
`strict_quality_gate: false`.

Not every protected program embeds source strings. Bytecode-only programs can
only produce pseudo/structural output, and compilation cannot recover original
names, comments or formatting.

## Safety model

The pipeline has two local dynamic boundaries plus an optional/disableable
third-party network post-pass:

- **Strict capture:** the recovered parser may parse its custom bytecode, but
  the first protected root closure is intercepted before execution.
- **Staged finalisation:** only when the strict tree matches the Luraph bootstrap
  signature, that bootstrap is allowed to run under a lexical sandbox and an
  instruction budget. The final application closure is replaced with a capture
  callback before construction and is never invoked.
- **lua.expert readability post-pass:** after local devirtualization and compile
  validation succeed, `program.decompiled.luau` is compiled to standard luauc
  without execution and those luauc bytes are uploaded to lua.expert. The raw
  Luraph virtual bytecode in `artifacts/bytecode.bin` is never sent to
  lua.expert. Use `--no-lua-expert` when third-party upload is unacceptable.

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
URLs already present in the input. The default lua.expert post-pass sends the
compiled structural program to a third-party service, so use
`--no-lua-expert` for sensitive inputs that must stay local and review output
before sharing it.

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

Legacy artifact mode remains local because it writes the supplied typed IR and
semantics directly rather than running the protected-loader pipeline.

Static loader unpack only:

```bash
luauvmp luraph protected.lua -o stage1
```

Corpus fingerprinting without VM execution:

```bash
luauvmp luraph-corpus samples/Luraph/v14.7 \
  -o luraph-corpus.json --strict
```

## lua.expert direct luauc mode

Standard Luau compiler bytecode can also be sent directly to lua.expert:

```bash
python -m luauvmp.lua_expert input.luac -o output.luau
```

The API request uses one JSON field named `script` containing base64-encoded
luauc bytes and expects plain-text Luau in response. See `docs/lua-expert.md`.

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
