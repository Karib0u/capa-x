#!/bin/sh
# Rebuilds web/public/demo.exe (the "try a demo" sample) from demo.rs: a harmless 64-bit Windows
# program built without a C runtime or a Windows toolchain (needs `rustup target add
# x86_64-pc-windows-msvc`).
set -eu
cd "$(dirname "$0")"
rustc demo.rs --edition 2021 --target x86_64-pc-windows-msvc --crate-type bin \
  -C opt-level=2 -C panic=abort -C debuginfo=0 -C strip=symbols \
  -C linker=rust-lld -C linker-flavor=lld-link \
  -C link-arg=/entry:entry -C link-arg=/subsystem:console -C link-arg=/nodefaultlib \
  -C link-arg=/brepro -C link-arg=/opt:ref -o ../public/demo.exe
rm -f ../public/demo.pdb
ls -l ../public/demo.exe
