# Offline Luraph artifact mode

`luauvmp-artifacts` finishes devirtualisation from files captured on another
machine. It never evaluates the recovered interpreter or protected payload.

Use a typed prototype tree and a semantics map recovered from the same VM:

```bash
luauvmp-artifacts final_ir.tsv opcode_semantics.json -o recovered
```

When only the extracted dispatcher factory and runtime helper facts are
available, semantics can be recovered as part of the same command:

```bash
luauvmp-artifacts final_ir.tsv \
  --factory interpreter.factory.luau \
  --runtime-facts runtime_A.tsv \
  -o recovered
```

The output includes `program.pseudo.lua`, `program.decompiled.luau`, manifests,
and copies of the exact input artifacts. The structural source is not executed.
Use `--compile-check` to ask Lune to compile it without running it.

The factory, runtime facts, typed IR, and any precomputed semantics must all come
from the same protected sample. Mixing artifacts can produce plausible-looking
but incorrect output, so every opcode used by the tree is validated before the
output directory is committed.
