# Development reference

Generated on 2026-10-21 by `scripts/decompiler_reference.sh` using the
Ghidra 11.4.2 PUBLIC release, Java 21, and default PE auto-analysis. The
source and processor version are pinned in `PINNED.md`.

The fixture was compiled with MinGW GCC 16.2.0 using
`scripts/build_decompiler_fixtures.sh`. Its SHA-256 is
`bd6662fce7bc09116542a16b94b602f19d8c45e272138dbd973bcf7f5f2b358e`.

These are reference pseudocode snapshots, not compilable source or runtime
inputs. The fixture source is `../fixtures.c`. Parameter and local names,
core type aliases and inferred local array sizes may differ between the
standalone native adapter and Ghidra's full-program analyzer.
