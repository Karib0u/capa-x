# capa-x web

A browser UI: drop a Windows PE (x86 / x64), get every recovered function
decompiled and the capa rule matches mapped onto them. There is no backend:
the Rust engine and the native Ghidra decompiler are compiled to WebAssembly
and run in Web Workers, so the binary never leaves the page.

One-time toolchain setup (macOS shown):

```sh
brew install emscripten
rustup target add wasm32-unknown-emscripten
```

Then, from `web/`:

```sh
npm install
npm run prepare-assets   # build the wasm module and bundle the capa rules
npm run dev              # http://localhost:5173
npm run build            # static site in dist/ -- serve it from any static host
```

`prepare-assets` runs two steps you can repeat on their own:

- `npm run build:wasm` builds `capa-x-cli --features decompiler` for
  `wasm32-unknown-emscripten` (see `../.cargo/config.toml` for the link
  flags), copies `capa-x.js` / `capa_x.wasm` into `src/wasm/`, and copies the
  signature databases and Function ID packs into `public/sigs/`.
- `npm run pack-rules` writes `public/rules.json` from `CAPA_RULES_DIR`,
  `../rules`, or the main checkout's `rules/` when run from a git worktree.

All outputs are generated and git-ignored.

## How it runs

`src/analyze.ts` first downloads what the engine needs (`src/engine/assets.ts`,
with a progress bar in the header): the wasm module (~13 MB, compiled once and
shared with every worker), the three FLIRT databases, the Function ID pack for
the sample's architecture only (x86 or x64), and the rules. The browser caches
them. The signature data is deliberately not embedded in the wasm build: native
builds still embed it, and on Emscripten `capa-x/src/bundled.rs` reads it from
`/sigs` in the module's in-memory file system.

Then it starts workers (`src/engine/engine.worker.ts`), each with its own module
instance: one runs `capa-x --json --jobs 1` against the mounted rules, and up to
four run `capa-x --decompile-all --shard I/N`, which splits the recovered
functions round-robin and streams NDJSON lines back as they print. The page
keeps the first copy of any function more than one shard reports.

Notes:

- The decompiler's output can depend on which functions the same session
  decompiled earlier (callee prototypes it inferred). On the test sample, 1 of
  420 functions printed a callee differently when sharded (`FUN_1400091a4` vs a
  cast of its address). Sharding is therefore deterministic per shard count, but
  not byte-identical to an unsharded run; `--shard` is only for the web UI.
- Each worker holds its own engine and signatures in memory, hence the cap of
  four decompiler workers.
