# Pinned native Ghidra sources

Upstream: https://github.com/NationalSecurityAgency/ghidra

The authoritative version and commit are in [PINNED.md](../../PINNED.md).
This is a source subset from Ghidra 12.1.4, developed by the US National
Security Agency and Ghidra contributors, licensed under Apache-2.0. See
[LICENSE](LICENSE) and the attribution and license headers in each file.
Generated parser sources retain their upstream parser-generator notices.

`cpp/` comes from `Ghidra/Features/Decompiler/src/decompile/cpp/`.
`specs/` comes from `Ghidra/Processors/x86/data/languages/` and contains the
x86-64 and x86-32 SLEIGH inputs, included instruction definitions, both processor
contexts and both Windows compiler specifications (`x86-64-win.cspec`, `x86win.cspec`).
Upstream `x86.ldefs` identifies the languages as `x86:LE:64:default` and
`x86:LE:32:default`, version 4.6, compiler `windows`.
Both are pinned to the same source commit. No JVM components are included.

Vendored files are unmodified. `SHA256SUMS` records their original contents.
From this directory, verify with `shasum -a 256 -c SHA256SUMS`.
The build compiles only CORE, DECCORE, SLEIGH, `sleigh_arch`, and
`inject_sleigh`, using the source groups in the upstream Makefile. The
SLEIGH compiler is a build-time executable; it compiles the pinned x86-64 and
x86-32 specifications into binaries embedded in the final library with the XML specs.

## Build-directory integration patches

`capa-x-ghidra/build.rs` copies only modified translation units to OUT_DIR
and asserts each original hook occurs exactly once before changing it:

- `sleigh.cc`: load the embedded SLA stream instead of opening a runtime file;
  check the request budget before translating an instruction.
- `action.cc`: check the budget at action iterations and p-code rule processing.
- `op.cc` and `varnode.cc`: check the budget before creating analysis objects.

`native/hooks.hh` declares these hooks. The deadline and work counter are
thread-local and active only during an explicit request. A thrown budget
exception crosses the bridge as a Rust error. Failed sessions are rejected
on subsequent calls and their state is released on drop. No native thread
is abandoned or asynchronously terminated.

To update, deliberately change PINNED.md, copy the same upstream paths,
regenerate SHA256SUMS, review every hook and specification change, rebuild,
and regenerate the fixture reference with the matching Ghidra release.
