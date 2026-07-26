# luau-vmp-deobf

Static deobfuscator for Luau scripts protected by a **custom bytecode VM**
(base64 → LZSS → re-serialised Luau bytecode, executed by a control-flow-flattened
interpreter written in Luau itself).

It never runs the sample. Everything is recovered by reading the loader:

```
loader.lua ──▶ fold arithmetic noise
           ──▶ decrypt XOR'd string literals
           ──▶ resolve the flattener's lazy jump tables
           ──▶ deflatten the dispatch loops
           ──▶ derive the VM spec (keys, fields, opcode map, mutation rules)
           ──▶ base64 + LZSS the payload
           ──▶ deserialise the proto tree
           ──▶ devirtualise (opcode mutation + lazy string decryption)
           ──▶ disassemble / decompile
```

Nothing about the VM is hard-coded. The protector re-rolls its keys, opcode
numbering, field layout and identifiers on every build, so the tool derives all
of it from the sample and tells you what it could not prove.

## Install

Python 3.9+, no dependencies.

```bash
git clone https://github.com/binxgtl/luau-vmp-deobf
cd luau-vmp-deobf
pip install -e .
```

## Use

```bash
luauvmp deobf sample.txt --disasm --strings -v
```

Writes `sample.deobf.lua`, plus optionally an annotated disassembly, the
recovered string table and the VM spec as JSON.

Inspect what was recovered without decompiling:

```bash
luauvmp inspect sample.txt --handlers --normalised
```

`--handlers` dumps every opcode handler in canonical form. Anything the
signature database does not recognise is printed as `<UNIDENTIFIED>` — paste it
into `luauvmp/signatures.py` (or send a PR) and the opcode is supported.

Only unpack the raw bytecode:

```bash
luauvmp unpack sample.txt
```

If auto-analysis misses something on a new build, pin it by hand:

```bash
luauvmp deobf sample.txt --profile profiles/foxname-2026-07.json
```

A profile is a partial `Spec` merged over auto-analysis, so you only list the
fields that need overriding.

## What gets recovered

| Layer | Recovered by |
|---|---|
| Arithmetic constant noise (`12958+-12788`) | `prelude.fold_arith` |
| XOR'd string literals | `prelude.decrypt_strings` — the helper is found by call-site fingerprint |
| Control-flow flattening | `prelude.resolve_states` + `deflatten` — the memoised `T[k] = bxor(a,K1) - bxor(b,K2)` jump tables are evaluated statically |
| Dispatch loop shape (`while ... do` or `repeat ... until`) | `deflatten.loop_offsets` |
| Payload decode chain — base64 alone, or base64 + LZSS | `prelude.payload_pipeline` |
| String helper declared inline or pre-declared | `prelude.find_string_helper` |
| Byte / varint / instruction-word XOR keys | `analyse.analyse_reader` |
| Instruction field slots (A, B, C, D, E, aux, K, KC, K1, K2, KN, kmode, opcode) | `analyse.analyse_reader` |
| Operand layout codes (ABC / AD / AE) | `analyse._type_codes` |
| Constant type codes — nil, int, double, string, boolean, table | `analyse._classify_consts` |
| Constant-mode codes (all ten) | `analyse._kmode_codes` |
| Opcode numbering | `analyse.analyse_vm` — handler fingerprinting against `signatures.py` |
| Per-handler XOR masks (CALL, LOADN, NEWCLOSURE) | fingerprint by-product |
| Operand roles, when a build shuffles which slot is dest/src | signature field order, zipped against the reference build |
| Self-modifying instruction rules | `mutations.extract` (path-sensitive) |
| Lazy per-string / per-import decryption | `devirt.decrypt_strings` |
| Heap-boxed upvalues | `decompile` (`bN --[[byref]]`) |

## Tested on

| Sample | Loader | Bytecode | Protos | Result |
|---|---|---|---|---|
| build A | 101 KB | 35 KB (100% parsed) | 65 | 1 155 lines, every opcode identified |
| build B | 240 KB | 193 KB (100% parsed) | 700+ | 7 800 lines, every opcode identified |
| build C | 253 KB | 137 KB (100% parsed) | 1 | staged loader; first stage recovered in full |

Build C is a *MoonVeil v1.4.5* build and stages its payload: the bytecode in the
file is a 28-instruction stub that decrypts a second bytecode image and feeds it
back to the same loader.  The container, the opcodes and the stub all come out,
but the second stage is keyed on a value the stub computes at run time, so
static analysis stops there - see `docs/format.md`.

The two builds share no keys, no opcode numbers, no field slots, no constant
type codes and not even the same dispatch loop shape — everything was derived
per sample.  Build B additionally uses boolean and empty-table constants and a
`repeat ... until` dispatch loop, both of which the analyser picks up on its own.

## Output quality

The decompiler reconstructs strings, imports, control flow, method calls, table
constructors and closures.

It is a *readable* reconstruction, not a byte-exact recompile: registers become
`vN` temporaries, and a handful of register-phi patterns are materialised as
explicit locals. Anything it cannot model is left as a comment rather than
silently guessed.

## Adding support for a new build

1. `luauvmp inspect sample.txt --handlers -v`
2. Check the `UNRESOLVED` line — if empty, the container format was fully derived.
3. For each `<UNIDENTIFIED>` handler, read the canonical form, decide which Luau
   operation it is, and add `signature: 'NAME'` to `luauvmp/signatures.py`.
   `tools/gen_signatures.py` regenerates the file from a labelled sample.
4. Re-run `deobf`.

## Scope and intent

This is an analysis tool: it exists to make it possible to read what an
obfuscated script actually does before running it. The protector this targets is
routinely used to hide credential-harvesting, telemetry and remote-execution
channels inside otherwise ordinary game scripts.

No sample is bundled. Point the tool at a file you already have.

## Licence

MIT — see `LICENSE`.
