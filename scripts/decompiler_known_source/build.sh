#!/bin/sh
# Builds the known-source corpus with MinGW gcc and LLVM clang (mingw target) on macOS.
# Output: out/<build>/ks.debug.exe (DWARF, truth) and out/<build>/ks.exe (stripped, decompiled).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HERE/out}
LLVM=${LLVM:-/opt/homebrew/opt/llvm/bin}
MINGW=${MINGW:-/opt/homebrew/opt/mingw-w64}
SRC="$HERE/src/arith.c $HERE/src/data.c $HERE/src/win.c $HERE/src/main.c"
FLAGS="-g -std=c11 -Wall -Wno-unused-function -fno-omit-frame-pointer"

build() { # name compiler-command strip
    name=$1 cc=$2 strip=$3
    mkdir -p "$OUT/$name"
    # shellcheck disable=SC2086
    $cc $FLAGS $SRC -luser32 -o "$OUT/$name/ks.debug.exe"
    $strip -o "$OUT/$name/ks.exe" "$OUT/$name/ks.debug.exe"
    $cc --version | head -1 > "$OUT/$name/compiler.txt"
}

for opt in O0 O2; do
    for arch in x86_64 i686; do
        tc=$MINGW/toolchain-$arch
        gcclib=$(ls -d "$tc"/lib/gcc/$arch-w64-mingw32/* | head -1)
        build "gcc-$arch-$opt" "$MINGW/bin/$arch-w64-mingw32-gcc -$opt" "$LLVM/llvm-strip"
        build "clang-$arch-$opt" \
            "$LLVM/clang -$opt --target=$arch-w64-mingw32 --sysroot=$tc/$arch-w64-mingw32 -fuse-ld=lld -L$gcclib" \
            "$LLVM/llvm-strip"
    done
done
