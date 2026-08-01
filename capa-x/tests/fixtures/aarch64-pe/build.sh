#!/bin/sh
# Rebuilds capa-x's AArch64 PE fixture corpus from src/.
#
# Unlike the Mach-O corpus's build.sh, this one needs tooling beyond a bare
# macOS dev machine: no Windows SDK is available in this environment
# (that's the whole reason these fixtures exist -- see MANIFEST.md), so
# this uses Homebrew's LLVM (`brew install llvm`, already a project-wide
# prerequisite for nothing else -- it happened to already be installed
# when this corpus was built) plus its `lld` package specifically for
# `lld-link` (`brew install lld`; LLVM's own bottle does not include it).
#
# Run from this directory: ./build.sh

set -eu
cd "$(dirname "$0")"

LLVM_BIN="$(brew --prefix llvm)/bin"
LLD_BIN="$(brew --prefix lld)/bin"
export PATH="$LLD_BIN:$PATH"

CLANG="$LLVM_BIN/clang"
LLVM_LIB="$LLVM_BIN/llvm-lib"

echo "clang: $($CLANG --version | head -1)"
echo "lld:   $("$LLD_BIN/lld-link" --version 2>&1 | head -1 || true)"

TARGET=aarch64-pc-windows-msvc

# --- a stub import library, so the exe fixture below can have a real
#     (resolved-at-link-time) import without needing a real DLL or the
#     Windows SDK's own .lib files. ---

"$LLVM_LIB" "/def:src/fake.def" /machine:arm64 /out:fake.lib

# --- exe with an import (+ .pdata, always emitted for ARM64) --------------

"$CLANG" --target=$TARGET -fuse-ld=lld -nostdlib \
    -Wl,/entry:entry_point -Wl,/subsystem:console \
    -o exe-with-import.exe src/fixture_exe.c fake.lib

# --- dll with exports (+ .pdata) -------------------------------------------

"$CLANG" --target=$TARGET -fuse-ld=lld -nostdlib \
    -Wl,/dll -Wl,/entry:dll_entry -Wl,/noimplib \
    -o dll-with-export.dll src/fixture_dll.c

python3 capture_oracles.py

echo "done."
