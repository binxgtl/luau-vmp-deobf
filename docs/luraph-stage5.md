# Luraph Stage 5 — Runtime trace

`tools/luraph_trace.lua` runs the recovered Luraph VM interpreter (stage 1
output) under the [Lune](https://lune-org.github.io/docs) Luau runtime with an
auto-stubbing Roblox environment, recording every global access and stub
interaction.

```bash
lune run tools/luraph_trace.lua final.vm.lua final.bytecode.bin vm_trace.log
```

## Reference v14.7 sample — what the VM does before aborting

The recovered interpreter compiles cleanly, then touches, in order:

| order | global | note |
|---|---|---|
| 1 | `table` | table library setup |
| 2-9 | `bit32` | **heavy use** - the deobf helpers are bitwise (bxor/bnot/band) |
| 10-12 | `string` | string.byte / sub / rep helpers |
| 13 | `buffer` | bytecode blob access |
| 14 | `select` | vararg handling |
| 15 | `getfenv` | environment introspection (executor check) |
| 16-18 | `coroutine`, `math` | scheduler + arithmetic noise |
| 19 | `type`, `unpack` | VM runtime helpers |

then aborts with:

```
attempt to yield across metamethod/C-call boundary
```

That error is the anti-tamper / executor-detection layer refusing a
non-Roblox host: the VM calls `coroutine.yield` (or `task.wait`) from inside
a context Lune does not allow yielding in.  This confirms the static findings
of stages 3-4 (26 executor-detect CONFIG entries, `Path2DControlPoint` crash
API) and means a full dynamic trace of the key-system HTTP call needs a host
that can actually yield - a real Roblox/executor, or a patched VM where the
yield is replaced with a no-op.

## What a patched run would need

* `coroutine.yield` -> `return` (neutralise the yield boundary check)
* `getfenv`/`getgenv` -> return a table with all Roblox globals pre-filled
* `HttpService:PostAsync`/`GetAsync` -> log-and-return to capture the key
  request URL/payload the payload sends.
