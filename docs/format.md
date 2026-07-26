# The protector, layer by layer

Notes from reverse-engineering three builds; one identifies itself in a header
comment as *MoonVeil Obfuscator v1.4.5*.  Every constant below is per-build
random - the tool derives them rather than assuming them.

## 1. Loader source obfuscation

* Identifiers are mangled to two-character names.
* Every integer literal is expanded into arithmetic noise: `170` is emitted as
  `12958+-12788`, `1` as `-3210+3211`, and so on. Constant folding removes it.
* String literals are stored XOR-encrypted and decrypted by one helper:

  ```lua
  local Da = function(cipher, key)
      local out = ''
      for i = 1, #cipher do
          out = out .. char(bxor(byte(cipher, i), byte(key, (i-1) % #key + 1)))
      end
      return out
  end
  ```

  The helper is located by looking for the identifier called most often with two
  string literals.

## 2. Control-flow flattening

Three functions - the bytecode reader, the interpreter and the entry wrapper -
are flattened into a dispatch loop.  Some builds use `while state ~= X do`,
others `repeat ... until state == X`; both look like

```lua
local T, F = {}, function(a, b, k) T[k] = bxor(a, K1) - bxor(b, K2) return T[k] end
state = <entry>
while state ~= <exit> do
    if state >= 33904 then ... elseif state < 45711 then ... end
end
```

Successor states are never literals: each is written `T[k] or F(a, b, k)`, so a
naive reader sees only opaque calls. Because `F` is pure, every call site folds
to a constant. After folding, the binary-search tree is parsed and each leaf's
reachable state range recovered, which yields a plain state graph.

## 3. Payload packing

`base64 -> LZSS -> bytecode`, though not every build compresses: one applies
base64 only.  Which decoders run is read off the loader's own call chain around
the payload literal, since Lua lets the call drop its parentheses (`decode'...'`).

The LZSS variant uses a control byte per 8 items;
a set bit is a literal, a clear bit is a big-endian 16-bit word split into an
11-bit backward offset and a 5-bit length (+3), against a 2048-byte window.

The window is maintained with Lua `string.sub` semantics, including the fact
that a match running past the end of the window is *truncated* rather than
repeated — an emulation detail that must be reproduced exactly.

## 4. Bytecode container

Not stock Luau bytecode: the protector re-serialises it.

```
proto := u8  maxstacksize  ^ BYTE_KEY
         u8  numparams     ^ BYTE_KEY
         u8  nups          ^ BYTE_KEY
         varint sizecode   ^ VARINT_KEY
         sizecode × ( u32 instruction ^ WORD_KEY [ , u32 aux ^ WORD_KEY ] )
         varint sizek      ^ VARINT_KEY
         sizek × ( u8 type ^ BYTE_KEY , payload )
         varint sizep      ^ VARINT_KEY
         sizep × proto
```

There is no header, no version byte and no global string table: the file *is*
the root proto, read recursively from offset 0.

Every varint byte is XOR'd individually before accumulation, so the length
prefix of a string is itself masked.

Constant payloads: `double` (8 bytes LE), `string` (masked varint length + raw
bytes), `int` (masked varint), `boolean` (one masked byte), `table` (nothing,
yields an empty table) and `nil` (nothing).  Not every build emits all six, and
the type codes are shuffled per build.

Each instruction record carries a `kmode` taken from a 256-entry info table
`{operand_layout, kmode, has_aux}`. After the constant table is read, a patch
pass folds the right constant straight into each instruction, following the
kmode: index by D, by E, by A, by B, by C, by aux, low 16 bits of aux, low 24
bits of aux plus the sign bit, a boolean from aux bit 0, or the Luau import
encoding (2-bit count + three 10-bit ids).

Only three operand layouts decode anything: ABC (three bytes from bits 8/16/24),
AD (byte + signed 16) and AE (signed 24). The other layout codes exist purely to
pad the info table with plausible-looking junk.  Which numeric code selects which
layout is itself randomised - one build uses 1/7/2, another 8/4/5.

## 5. Opcode obfuscation

* Opcode numbers are spread across the full 0..255 range; the interpreter
  dispatches through a binary search, so each real handler owns a *range* of
  values and only one value per range is ever emitted.
* Operand roles are shuffled per opcode: `ADD` writes C and reads A/B, `SUB`
  writes A and reads C/B, and so on.
* Some handlers XOR their operands with baked constants — in the reference build
  `CALL` uses `A^62, B^192, C^124`, `LOADN` uses `dest^200, value^34144`, and one
  of the two `NEWCLOSURE` forms uses `dest^95, proto^25107`.

The tool handles this by fingerprinting: each handler is rewritten with
identifiers, field slots, state labels and XOR constants erased, and the
resulting canonical text is looked up in a signature database. Field slots and
XOR constants are captured as a by-product, so shuffled operand roles are picked
up automatically.

## 6. Self-modifying instructions

Ten handlers start with a guard on the C field:

```
op113 with C == 225  ->  rewrite as op120, A ^= 107, B ^= 64, C = 0
op120 with C == 70   ->  rewrite as op113, A ^= 52,  B ^= 148
op142 with C == 107  ->  rewrite as op19,  A ^= 190, B ^= 93
...
```

The handler rewinds the pc, overwrites the instruction record in place and falls
back into the dispatch loop, so the rewritten opcode executes instead. Five real
operations (`MOVE`, `LEN`, `SETUPVAL`, `CLOSEUPVALS`, `GETUPVAL`) are reachable
*only* this way and never appear in the serialised stream.

Because the rewrite is deterministic, the tool applies it statically. Original
operands are kept as `origA`/`origB`/`origC`, which matters because closure
capture descriptors are stored in instruction slots that are never dispatched
and must not be mutated.

## 7. Lazy string decryption

String constants are stored encrypted and decrypted the first time the
surrounding code runs, by two pseudo-instructions:

* one decrypts the constant of the **following** instruction,
* one decrypts the one, two or three import names of the instruction **two**
  slots ahead (skipping its own aux word).

Both use a repeating-key XOR whose key is `PREFIX .. <this instruction's own
constant>`, then rewrite their own opcode field to a no-op so they only ever run
once. The prefix is a short literal in the interpreter (`"\20}\21+"` in the
reference build).

Since both are deterministic and position-based, they are applied statically
before disassembly, which is why the output contains plaintext strings.

## 8. Upvalue lifting

Locals captured by more than one closure are lifted into heap "boxes" allocated
by a helper passed in as the root proto's single upvalue. A box is a
self-referential table where `box[2][box[1]]` is the value, so reads compile to
`GETTABLEN box,1 / GETTABLEN box,0 / GETTABLE` and writes to `SETTABLE`.

The decompiler recognises the pattern and restores an ordinary named local.

## 9. Plaintext leftovers

The reference build leaves a small table of closures **unencrypted** in the
loader, referenced from the bytecode by name. They are the pieces the protector
could not express in its own bytecode (varargs-heavy remote calls), and they leak
a useful amount of the script's behaviour before any of the above is undone.


## 10. Staged payloads

One build does not put the script in the bytecode at all.  The image in the file
is a 28-instruction stub:

```lua
local stage2a = load(<1.6 KB blob>)
local key     = box(stage2a, {})
local stage2  = load(decompress(<89 KB blob>, "<short key>", derive(key())))
return box(stage2, {})(...)
```

The constants are still encrypted after the usual lazy-decrypt pass, because the
decryption key is produced by *running* the first stage.  Everything up to and
including that stub is recovered statically.

To get the second image you have to let the stub run, but you do not have to let
the *script* run.  Hook the loader function - the local the tail call passes the
payload to - count its invocations, and on the one that receives the second image
record the string and hand back an empty function:

```lua
y = gc
do local real = y
   local n = 0
   y = function(bc, env)
       n = n + 1
       if n >= 3 then                       -- 1: outer payload, 2: key proto
           writefile("stage2.b64", base64_encode(bc))
           return function() end            -- captured, never executed
       end
       return real(bc, env)
   end
end
```

The captured image is an ordinary container in the same format, so feeding it
back through `container.parse` with the spec recovered from the loader decodes it
completely.  On the sample this yielded 128 231 bytes, 287 protos and 3 900 lines
of Lua with no unknown opcodes.
