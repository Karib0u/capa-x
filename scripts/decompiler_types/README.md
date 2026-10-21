# Prototype pack generation (development only)

Regenerates `capa-x-ghidra/data/winapi64.pack` from Ghidra's bundled data type
archives. Java runs only here, never in the build or at runtime. Use the same
Ghidra release as `PINNED.md`.

```sh
export GHIDRA_HOME=$HOME/tools/ghidra_12.1.4_PUBLIC
T=$GHIDRA_HOME/Ghidra/Features/Base/data/typeinfo
mkdir -p scripts/decompiler_types/out
"$GHIDRA_HOME/support/analyzeHeadless" "$(mktemp -d)" p -import tests/decompiler/fixtures.dll -noanalysis \
  -scriptPath scripts/decompiler_types -postScript ExportPrototypes.java \
  "$PWD/scripts/decompiler_types/out/proto.tsv" "$T/win32/windows_vs12_64.gdt" "$T/generic/generic_clib_64.gdt" -deleteProject
python3 -I scripts/decompiler_types/pack_prototypes.py scripts/decompiler_types/out/proto.tsv capa-x-ghidra/data/winapi64.pack
cargo test --release -p capa-x-ghidra --features native packed_archive
```

`ProbeArchive.java` prints a summary of any `.gdt` archive. The export skips
intrinsics headers (`*intrin.h`) and keeps the first definition of each function
name, in the order the archives are listed.
