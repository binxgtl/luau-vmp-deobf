# Build-independent Luraph full-prototype pipeline

The original `luraph-devirt` command is retained for compatibility, but its
reference v14.7 opcode table is not safe for unrelated builds.  The new path
uses artifacts recovered from the same sample:

1. capture a typed multi-prototype IR without invoking the payload;
2. specialise the extracted dispatcher for all 256 opcode values;
3. replace every custom instruction in every prototype with its concrete
   dispatcher semantics.

```bash
python tools/recover_luraph_dispatch.py \
  luraph_interpreter_factory.luau luraph_runtime_A.tsv \
  -o luraph_opcode_semantics.json

luauvmp luraph-full luraph_full_ir.tsv luraph_opcode_semantics.json \
  -o full-devirt
```

The output is instruction-level pseudo-Luau. It intentionally preserves VM
scratch state (`m`, `O`, `U`, `Y`, etc.) where several custom instructions form
one super-instruction. This is full opcode devirtualisation, not a claim that
original variable names, comments, or exact structured source can be recovered.

## Safety boundary

The capture stage must patch the VM factory to expose parsed prototypes and
must not call the returned payload closure. Network, filesystem and Roblox
executor APIs should remain unavailable during capture.
