# Decompiler baseline harness (development only)

Python and Java here are development tooling; none of it runs in the product.
Run from the repository root. Needs initialized submodules (`tests/testfiles`)
and a Ghidra install with a built `decompile` executable for your platform
(Ghidra 12.1.4 ships none for macOS arm64: build it with `make ghidra_opt` in
`Ghidra/Features/Decompiler/src/decompile/cpp` and copy it to
`Ghidra/Features/Decompiler/os/<platform>/decompile`).

```sh
export GHIDRA_HOME=$HOME/tools/ghidra_12.1.4_PUBLIC
T=tests/testfiles O=scripts/decompiler_baseline/out
python3 -I scripts/decompiler_baseline/select_samples.py $T 24 20261021 scripts/decompiler_baseline/samples.json
python3 -c "import json;print(*[s['name'] for s in json.load(open('scripts/decompiler_baseline/samples.json'))['samples']],sep='\n')" > $O/names.txt
scripts/decompiler_baseline/run_ghidra_all.sh $T $O/names.txt $O/ghidra 3
cargo build --release -p capa-x --features decompiler --examples
python3 -I scripts/decompiler_baseline/run_native.py $T $O/ghidra $O/native target/release/examples/decompiler_corpus
python3 -I scripts/decompiler_baseline/compare.py $O/ghidra $O/native $O/comparison.json
```

Function-set agreement (discovery, phase 3) needs no decompiler:

```sh
mkdir -p $O/g $O/n
xargs -P 3 -n 1 sh -c 'scripts/decompiler_baseline/run_ghidra_functions.sh "$T/$0" "$O/g/$0.json"' < $O/names.txt
cargo build --release -p capa-x --example function_set
for n in $(cat $O/names.txt); do target/release/examples/function_set $T/$n > $O/n/$n.json; done
python3 -I scripts/decompiler_baseline/compare_functions.py $O/g $O/n $O/functions.json
python3 -I scripts/decompiler_baseline/classify_functions.py $T $O/names.txt $O/g target/release/examples/function_set $O/classes
```
