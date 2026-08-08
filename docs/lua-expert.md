# lua.expert backend

`lua.expert` is an optional third-party decompiler for **standard Luau compiler bytecode (luauc)**. Its documented API is:

- `POST https://api.lua.expert/decompile`
- `Content-Type: application/json`
- request JSON: `{ "script": "<base64-encoded-luauc>" }`
- response: decompiled Luau as plain text
- documented rate limit: 500 requests/minute

This is **not** a Luraph virtual-bytecode decoder. Never send `artifacts/bytecode.bin` from a Luraph capture directly to this endpoint.

## Direct luauc decompile

```bash
python -m luauvmp.lua_expert input.luac -o output.luau
```

The command base64-encodes the local luauc bytes and uploads them to `api.lua.expert`.

## Decompile a Luau source through lua.expert

```bash
python -m luauvmp.lua_expert program.decompiled.luau \
  --source \
  --runtime lune \
  -o program.luaexpert.luau
```

`--source` first invokes Lune's `luau.compile` locally. The source is **compiled only, never executed**. The generated luauc bytes are then uploaded to lua.expert and deleted from the temporary directory after the request.

## Luraph wrapper

For a one-command safe Luraph pipeline plus the optional remote readability pass:

```bash
python -m luauvmp.luraph_lua_expert protected.lua \
  -o recovered \
  --runtime lune
```

Order of operations:

1. Run the normal local Luraph pipeline.
2. Recover sample-local semantics and typed IR.
3. Produce `program.decompiled.luau`.
4. Enforce the normal compile/fallback/unresolved-condition quality checks locally.
5. Compile that already-devirtualized Luau source to standard luauc without executing it.
6. Upload only those compiled luauc bytes to lua.expert.
7. Write the remote result as `program.luaexpert.luau`.

`program.luaexpert.luau` is an **advisory/readability artifact**. It does not contribute to `fallback_instructions`, dispatcher-condition proofs, payload-execution flags, or any strict devirtualization quality gate.

## Privacy / network behavior

Using either command explicitly sends bytecode to a third-party service. Do not enable it for material that must remain offline or private. The default Luraph pipeline remains local/offline with respect to lua.expert.

The client uses a bounded HTTP timeout and a 16 MiB maximum response size. Empty, oversized, non-UTF-8, HTTP-error, and network-failure responses fail closed.
