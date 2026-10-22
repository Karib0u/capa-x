# Function ID tooling (development only)

Java and Python here never run in the product. They export Ghidra's Function ID
databases into `capa-x/sigs/fid-x64.pack` and `fid-x86.pack` and produce the ground truth that the
Rust hasher is checked against. Use the Ghidra release in `PINNED.md`.

## Regenerate the pack

```sh
export GHIDRA_HOME=$HOME/tools/ghidra_12.1.4_PUBLIC
D=$GHIDRA_HOME/Ghidra/Features/FunctionID/data
mkdir -p scripts/decompiler_fid/out
"$GHIDRA_HOME/support/analyzeHeadless" "$(mktemp -d)" p -import tests/decompiler/fixtures.dll -noanalysis \
  -scriptPath scripts/decompiler_fid -postScript ExportFid.java "$PWD/scripts/decompiler_fid/out" \
  $D/vs2012_x64.fidbf $D/vs2015_x64.fidbf $D/vs2017_x64.fidbf $D/vs2019_x64.fidbf $D/vsOlder_x64.fidbf -deleteProject
python3 -I scripts/decompiler_fid/pack_fid.py scripts/decompiler_fid/out capa-x/sigs/fid-x64.pack \
  --variants Release vs2012_x64 vs2015_x64 vs2017_x64 vs2019_x64 vsOlder_x64
```

`pack_fid.py` documents the file layout. Debug-runtime libraries are left out on
purpose: they are 46% of the records for 1.7% more matches on the validation set.

x86-32: the same two steps with a PE32 program and the `*_x86.fidbf` databases:

```sh
"$GHIDRA_HOME/support/analyzeHeadless" "$(mktemp -d)" p -import PE32_SAMPLE -noanalysis \
  -scriptPath scripts/decompiler_fid -postScript ExportFid.java "$PWD/scripts/decompiler_fid/out32" \
  $D/vs2012_x86.fidbf $D/vs2015_x86.fidbf $D/vs2017_x86.fidbf $D/vs2019_x86.fidbf $D/vsOlder_x86.fidbf -deleteProject
python3 -I scripts/decompiler_fid/pack_fid.py scripts/decompiler_fid/out32 capa-x/sigs/fid-x86.pack \
  --variants Release vs2012_x86 vs2015_x86 vs2017_x86 vs2019_x86 vsOlder_x86
```

## Validate the hasher against Ghidra

`DumpFidHashes.java` runs after Ghidra's own auto-analysis (which applies its Function
ID databases) and writes Ghidra's hash quad, instruction masks, operand objects,
call graph and applied FID name for every function.

```sh
export GHIDRA_HOME=$HOME/tools/ghidra_12.1.4_PUBLIC
scripts/decompiler_fid/run_truth.sh tests/testfiles/SAMPLE scripts/decompiler_fid/out/truth/SAMPLE.tsv
cargo build --release -p capa-x --features decompiler --examples
target/release/examples/fid_truth scripts/decompiler_fid/out/truth/*.tsv      # masks, operands, hashes
# x86-32 truth: add --bits=32 and FID_SAMPLES=tests/testfiles (immediates that point into the image are addresses)
target/release/examples/fid_names capa-x/sigs/fid-x64.pack scripts/decompiler_fid/out/truth/*.tsv  # scoring, names
target/release/examples/fid_pe tests/testfiles/SAMPLE                          # end to end on a PE
```

`DumpRegisters.java` prints Ghidra's x86-64 register offsets, which
`capa-x/src/fid/x86.rs` re-derives by formula.
