# Prototype packs

`winapi64.pack` is generated, not hand-edited. Source: Ghidra 12.1.4
(`Ghidra_12.1.4_build`, commit 8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc)
`Ghidra/Features/Base/data/typeinfo/win32/windows_vs12_64.gdt` and
`generic/generic_clib_64.gdt`. Contents: 28,312 function prototypes and 8,052
named types in Ghidra's decompiler marshalling. Format and regeneration:
`scripts/decompiler_types/pack_prototypes.py` and its README. Use is described
in `docs/decompiler.md`.

`winapi32.pack` is the x86-32 counterpart. Source: the same Ghidra 12.1.4
`windows_vs12_32.gdt` and `generic/generic_clib.gdt`. Contents: 28,186 function prototypes and 8,006
named types, 1.3 MB, exported with an x86-32 program so that pointer sizes and calling convention
names come from `x86win.cspec`. SHA-256
`e0f34736405c34f99f479c657bdfbcc64299eaeeb210f2ef31ce8c6f0ecd2727`.
