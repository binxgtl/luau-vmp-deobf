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

## Automatic strict fallback

`luauvmp luraph-full` first performs strict parser capture. Some staged loaders
then require a sample-local bootstrap finalizer, which can exceed its bounded
instruction budget or deliberately fail to converge. The pipeline now records
that error and continues from the strict capture by default, producing the same
pseudo and structural outputs as artifact mode.

Check `pipeline.json` before treating output as final application code:

- `capture_kind: "finalised-staged"` means the staged application capture
  completed.
- `capture_kind: "strict-fallback"` means dispatcher recovery and
  devirtualisation succeeded from the pre-finalization tree.
- `finalization_error` preserves a bounded explanation of the fallback.

Set `LUAUVMP_FINALIZE_FALLBACK=0` to restore fail-fast behavior for workflows
that require a completed staged capture.
