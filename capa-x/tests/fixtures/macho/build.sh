#!/bin/sh
# Rebuilds capa-x's Mach-O fixture corpus from src/.
#
# Uses only the system toolchain already present on any macOS dev machine
# (Xcode Command Line Tools' clang, lipo, strip, otool) -- no extra
# packages. Deterministic modulo the toolchain version, which is why
# MANIFEST.md records `clang --version`'s output alongside every fixture's
# sha256: a rebuild with a different Xcode/CLT version is expected to
# change bytes (timestamps, minor codegen differences) without changing
# structure, and the oracle JSON files are what the tests actually compare
# against, not a byte-for-byte fixture match.
#
# Run from this directory: ./build.sh

set -eu
cd "$(dirname "$0")"

SDK="$(xcrun --show-sdk-path)"
CLANG="xcrun clang"

echo "clang: $($CLANG --version | head -1)"
echo "SDK:   $SDK"

# --- thin x86_64 / arm64 executables, thin x86_64 dylib -------------------

$CLANG -arch x86_64 -isysroot "$SDK" -O0 -o thin-x86_64-exe src/fixture_exe.c
$CLANG -arch arm64 -isysroot "$SDK" -O0 -o thin-arm64-exe src/fixture_exe.c
$CLANG -arch x86_64 -isysroot "$SDK" -O0 -dynamiclib -o thin-x86_64.dylib src/fixture_dylib.c
$CLANG -arch arm64 -isysroot "$SDK" -O0 -dynamiclib -o thin-arm64.dylib src/fixture_dylib.c

# --- fat (x86_64 + arm64) executable and dylib -----------------------------

lipo -create -output fat-x86_64-arm64-exe thin-x86_64-exe thin-arm64-exe
lipo -create -output fat-x86_64-arm64.dylib thin-x86_64.dylib thin-arm64.dylib

# --- stripped vs symbol-bearing --------------------------------------------
# thin-x86_64-exe (above) keeps the local symbol table clang emits by
# default; this is the explicit symbol-bearing/stripped pair.

cp thin-x86_64-exe symbols-x86_64-exe
cp thin-x86_64-exe stripped-x86_64-exe
strip -x stripped-x86_64-exe # -x: strip local symbols, keep the binary loadable

# --- malformed set ----------------------------------------------------------
# Derived from thin-x86_64-exe by direct byte patching -- see patch_malformed.py.

python3 patch_malformed.py

# --- structure oracles (clean fixtures only) -------------------------------

python3 capture_oracles.py

echo "done."
