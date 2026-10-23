#!/bin/sh
# Builds the capa-x CLI (capabilities + native Ghidra decompiler) for the browser:
# WebAssembly via Emscripten, then copies the module next to the UI sources.
# Needs: `rustup target add wasm32-unknown-emscripten` and `emcc` (brew install emscripten).
set -eu
cd "$(dirname "$0")/../.."
command -v emcc >/dev/null || { echo "emcc not found: install Emscripten (brew install emscripten)" >&2; exit 1; }
cargo build --release -p capa-x-cli --features decompiler --target wasm32-unknown-emscripten
out=target/wasm32-unknown-emscripten/release
mkdir -p web/src/wasm
cp "$out/capa-x.js" "$out/capa_x.wasm" web/src/wasm/
# Signature databases and Function ID packs are not embedded in the wasm build: the page fetches
# them (only the Function ID pack for the sample's architecture) from public/sigs.
mkdir -p web/public/sigs
cp capa-x/sigs/*.sig capa-x/sigs/fid-*.pack web/public/sigs/
ls -lh web/src/wasm web/public/sigs
