#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# GCC/MinGW is development-only. The checked-in PE runs on no host during tests.
"${MINGW_CC:-x86_64-w64-mingw32-gcc}" -O1 -fno-ident -fno-stack-protector \
  -nostdlib -shared -Wl,--no-insert-timestamp -Wl,--entry,0 \
  -o tests/decompiler/fixtures.dll tests/decompiler/fixtures.c -lkernel32
