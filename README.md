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

## Luraph v14.x support

`luauvmp` can also unpack **Luraph v14.7** loaders (and other builds that share
the same base85 + range-coder scheme).  Luraph does not wrap Luau bytecode the
way luau-vmp does; it compiles the script into its own custom VM bytecode, so
the goal of this stage is recovery of the two streams the loader builds at
runtime:

```
loader.lua -> base85 decode (5 chars -> 4 bytes, "z" zero-runs)
           -> adaptive range coder + LZ77 decompress
           -> [0] VM interpreter source (loadstring'ed, ~94 KB)
           -> [1] custom VM bytecode blob (handed to the interpreter)
```

```
$ luauvmp luraph protected.lua
wrote protected.vm.lua      (Luraph VM interpreter source)
wrote protected.bytecode.bin (Luraph VM bytecode)
```

`luauvmp unpack` detects Luraph loaders automatically, and `deobf`/`inspect`
will tell you when a file is a Luraph (rather than luau-vmp) target.  The
recovered interpreter is still obfuscated (state-machine handlers + arithmetic
noise); feeding it to a devirtualiser is the next stage for full source
recovery.

### Detection

* `LPH` magic + the base85 constants (`*52200625`, `*614125`) in the header
* two `[==[ ... ]==]` payload literals (small interpreter, big bytecode)

## MoonVeil, and other staged loaders

Some builds - *MoonVeil v1.4.5* among them - do not put the script in the file at
all.  Run the tool normally first:

```bash
luauvmp deobf sample.txt -v
```

If the decompiled output is only a handful of lines and looks like this, the
payload is staged:

```lua
local v1 = up1(<blob>)                       -- load the key proto
local v3 = up0(v1, {})
local v4 = up1(up2(<big blob>, "<key>", up3(v3())))   -- load the real script
return up0(v4, {})(...)
```

The container, the opcodes and this stub all come out of the file, but the second
image is decrypted with a value the stub computes while running, so it is not in
the file to be found.

### Capturing the second image without running the script

You do not have to execute the payload to get it - only the stub.  Hook the
loader (the local the tail call hands the payload to, `y` below), count the
calls, and on the one that receives the second image write it out and return an
empty function.  Insert this at the `y = <loader>` assignment near the end of the
file:

```lua
y = gc                                  -- the loader, as the file already had it
do
    local real, n = y, 0
    y = function(bc, env)
        n = n + 1
        if n >= 3 then                  -- 1: outer payload, 2: key proto
            writefile("stage2.b64", base64_encode(bc))
            return function() end       -- captured; never executed
        end
        return real(bc, env)
    end
end
```

Run the patched file in any Luau executor.  Nothing from the second image runs:
the stub loads it, receives an empty function, calls it, and stops.  Check the
call sizes if you want to be sure - on the reference sample they were 136 534,
2 754 and 128 231 bytes.

### Decoding the capture

The captured image is an ordinary container, so hand it back with `--image`.  The
VM spec still comes from the loader; only the bytecode comes from the capture.
Raw or base64 both work:

```bash
luauvmp deobf sample.txt --image stage2.b64 --strings -v
```

On the reference sample that produced 128 231 bytes parsed byte-exact, 287
protos and ~3 900 lines of Lua with no unknown opcodes.

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
| build C | 253 KB | 137 KB (100% parsed) | 1 | staged loader, first stage recovered in full |
| build C stage 2 | - | 128 KB (100% parsed) | 287 | 3 900 lines, every opcode identified |

Build C is a *MoonVeil v1.4.5* build and stages its payload: the bytecode in the
file is a 28-instruction stub that decrypts a second image and feeds it back to
the same loader.  The second image is keyed on a value the stub computes at run
time, so it cannot be decrypted from the file alone - but it only takes hooking
the loader to capture it *without executing it*, after which this tool decodes it
like any other container.  `docs/format.md` has the hook.

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
