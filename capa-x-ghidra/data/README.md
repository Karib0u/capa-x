# Prototype pack

`winapi64.pack` is generated, not hand-edited. Source: Ghidra 12.1.4
(`Ghidra_12.1.4_build`, commit 8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc)
`Ghidra/Features/Base/data/typeinfo/win32/windows_vs12_64.gdt` and
`generic/generic_clib_64.gdt`. Contents: 28,312 function prototypes and 8,052
named types in Ghidra's decompiler marshalling. Format and regeneration:
`scripts/decompiler_types/pack_prototypes.py` and its README. Use is described
in `docs/decompiler.md`.
