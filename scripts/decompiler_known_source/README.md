# Known-source corpus (step 15a, MinGW and clang slice; development only)

Small C programs we write and build ourselves, so the right answer is known. Each function in `src/`
targets one thing a decompiler can get wrong (sign and width, argument slots, struct returns, switch
tables, varargs, x87 and 64-bit helpers on x86-32, `__stdcall`/`__fastcall`, Win32 imports, a stack probe,
a call that does not return). Python here is development tooling and never runs in the product.

Needs, on macOS: Homebrew `mingw-w64` and `llvm` (clang, lld, llvm-dwarfdump, llvm-objdump, llvm-readobj),
a CLI and examples built with the decompiler feature, and optionally Ghidra 12.1.4.

```sh
D=scripts/decompiler_known_source
$D/build.sh                                   # 8 builds: gcc and clang, x86-64 and x86-32, -O0 and -O2
for b in $D/out/*/; do python3 -I $D/truth.py $b/ks.debug.exe $b/truth.json; done
cargo build --release -p capa-x-cli --features decompiler
cargo build --release -p capa-x --features decompiler --examples
# Optional third column: full Ghidra on the same stripped files.
export GHIDRA_HOME=$HOME/tools/ghidra_12.1.4_PUBLIC
for b in $D/out/*/; do
  python3 -c "import json,sys;t=json.load(open('$b/truth.json'));json.dump([{'address':f['entry'],'role':f['name']} for f in t['functions']],open('$b/ghidra-addresses.json','w'))"
  scripts/decompiler_baseline/run_ghidra_addresses.sh $b/ks.exe $b/ghidra.json $b/ghidra-addresses.json
done
python3 -I $D/compare.py $D/out target/release/examples    # static checks -> out/report.json
python3 -I $D/difftest.py $D/out target/release/capa-x     # recompile and run -> out/difftest.json
python3 -I $D/show.py gcc-x86_64-O2 ks_collatz             # one function: source, native, Ghidra
```

- `build.sh`: `ks.debug.exe` keeps DWARF and COFF symbols (the truth); `ks.exe` is stripped and is the
  only file the decompilers see.
- `truth.py`: functions, prototypes and `noreturn` from DWARF; every call and tail jump in each function's
  range from `llvm-objdump`, named through the symbol table and the import address table.
- `compare.py`: function discovery, return shape and class, argument slots (one per parameter on x64,
  4-byte stack slots on x86-32), float versus integer parameters, x86-32 convention from the decorated name,
  callees resolved by address. With `ghidra.json` each mismatch is marked N (native only), B (both) or G.
- `difftest.py`: for every function of `src/arith.c`, compiles the decompiled `--unit` for the host with
  data symbols filled from the image and libgcc helpers shimmed, and runs it against the source function on
  400 inputs packed in the Windows ABI's slots. Only our own builds of our own sources run.

Results: [decompiler-baseline-results.md](../../docs/decompiler-baseline-results.md#step-15a-known-source-corpus-mingw-and-clang).
