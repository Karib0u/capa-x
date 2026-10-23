# capa-x web

A small local UI: drop a Windows PE (x86 / x64), get every recovered function
decompiled and the capa rule matches mapped onto them. Analysis runs entirely
on your machine.

```sh
cargo build --release -p capa-x-cli --features decompiler   # from the repo root
cd web && npm install && npm run dev                        # http://localhost:5173
```

`server/server.mjs` (no dependencies) runs `capa-x --json` and
`capa-x --decompile-all` in parallel and streams NDJSON to the React app.
Rules are read from `CAPA_RULES_DIR`, `./rules`, or the main checkout's
`rules/` when run from a git worktree. Override the binary with `CAPA_X_BIN`.
