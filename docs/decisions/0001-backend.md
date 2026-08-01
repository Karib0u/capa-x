# ADR 0001: Own the static code-recovery backend

- Status: Accepted

## Context

capa-x needs function, basic-block, and instruction recovery for PE and ELF
on x86 and x64. The open question was whether to adopt lancelot as the
recovery layer before committing to an in-tree implementation. The decision
gate requires all four format and architecture combinations, useful function
and basic-block recovery, API-resolution hooks, and an acceptable maintenance
posture. iced-x86 remains the required instruction decoder in either case.

The spike used lancelot 0.10.0 from crates.io and commit
`e4f5191d4b8011eaa4024582f8912e0837507488` from its upstream repository. It
built successfully with Rust 1.96.0 on macOS. The latest release was published
on 2026-07-09, and the repository has active CI and recent releases. Maintenance
status is therefore not a reason to reject it.

## Method

Ten pinned capa-testfiles were selected to cover PE32, PE32+, executable, DLL,
driver, packed PE, ELF32, ELF64, stripped, and dynamically linked inputs.
Vivisect was loaded through pinned capa 9.4.0 with the pinned FLIRT signatures,
the same analysis path used by `capa -vv`.
The selection is preserved in `scripts/corpus-layout.txt`. Function counts
include library functions; `capa -vv` reports those separately in its metadata.

For each input the spike compared:

- function start addresses from `vw.getFunctions()` and lancelot's workspace;
- global basic-block start addresses from both recovered CFGs;
- whether lancelot could construct a workspace;
- whether its public model exposes imports and references needed for API
  resolution.

The address-set comparison measures recovery boundaries, not edge semantics or
instruction parity. That is sufficient for this gate because unsupported input
formats already decide the result.

## Results

`V/L/C` below means Vivisect count, lancelot count, and common addresses.
Precision is `C/L`; recall is `C/V`.

| Sample | Kind | Functions V/L/C (P/R) | Blocks V/L/C (P/R) | Result |
|---|---|---:|---:|---|
| `Practical Malware Analysis Lab 01-01.exe_` | PE32 EXE | 13/14/13 (92.9%/100%) | 91/92/91 (98.9%/100%) | supported |
| `Practical Malware Analysis Lab 03-02.dll_` | PE32 DLL | 43/38/36 (94.7%/83.7%) | 394/324/321 (99.1%/81.5%) | supported |
| `Practical Malware Analysis Lab 10-03.sys_` | PE32 driver | 5/-/- | 16/-/- | rejected: non-page-aligned section |
| `2a7429d60040465f9bd27bbae2beef88.exe_` | packed PE32 | 3/3/3 (100%/100%) | 38/39/37 (94.9%/97.4%) | supported |
| `52d8e95c9883cd16d7b44e3a7adc22d6.exe_` | PE32+ EXE | 72/71/69 (97.2%/95.8%) | 244/245/243 (99.2%/99.6%) | supported |
| `03b236b23b1ec37c663527c1f53af3fe.dll_` | PE32+ DLL | 1304/1246/1241 (99.6%/95.2%) | 20356/19912/19907 (100.0%/97.8%) | supported |
| `bb38149ff4b5c95722b83f24ca27a42b.elf_` | ELF32 shared object | 18/-/- | 40/-/- | rejected: unknown format |
| `1038a23daad86042c66bfe6c9d052d27048de9653bde5750dc0f240c792d9ac8.elf_` | ELF32 shared object | 61/-/- | 153/-/- | rejected: unknown format |
| `e17e6a79ed614f5468d0eed758629697.elf_` | ELF64 EXE | 437/-/- | 4716/-/- | rejected: unknown format |
| `microsocks.elf_` | ELF64 PIE | 81/-/- | 370/-/- | rejected: unknown format |

The supported PE results are promising. Four of five supported files recover
at least 95% of Vivisect function starts, and basic-block precision is high.
The PE32 DLL is the notable recall outlier. This makes lancelot a useful design
reference, but does not overcome the coverage gaps.

The API surface also has useful PE pieces: a map of normal imports keyed by IAT
address, operand-reference helpers including RIP-relative references, and thunk
detection. However, the workspace loader accepts PE and COFF only, the recovery
path is coupled to Zydis data structures, and the import loader does not cover
delay imports. ELF PLT/GOT resolution would have to be built separately.

## Decision

Do not adopt the `lancelot` crate as capa-x's recovery backend. Implement a
single in-tree recovery engine over the existing goblin PE/ELF parsers and use
iced-x86 as the only decoder.

The engine will share a format-neutral loaded-image, decoded-instruction, CFG,
and xref model. Format-specific code will supply seeds and external-symbol
bindings:

- PE: entry point, exports, TLS callbacks, x64 unwind entries, executable
  relocation targets, discovered call targets, and prologue fallback; regular
  and delay IAT bindings for API resolution.
- ELF: entry point, `STT_FUNC` and GNU IFUNC symbols, init/fini arrays,
  executable relocation targets, discovered call targets, and prologue
  fallback; PLT/GOT relocation bindings for API resolution.

The `lancelot-flirt` crate remains eligible for Phase 2. It is independent of
the lancelot workspace and does not force the Zydis recovery model into the
backend.

## Consequences

- PE and ELF use one recovery implementation and one instruction model.
- We avoid decoding every instruction twice through Zydis and iced-x86.
- Existing file-feature parsing behavior remains authoritative, including valid PE files
  with unusual section alignment.
- This path is larger than the lancelot adoption path, so the estimate
  increases from 3-5 weeks to 4-6 weeks.
- Recovery quality becomes an explicit Phase 1 gate. The ten spike samples are
  retained in `scripts/corpus-layout.txt`, and function/block boundary
  regressions are measured before feature extraction begins.

## References

- [lancelot 0.10.0](https://crates.io/crates/lancelot/0.10.0)
- [lancelot workspace format dispatch](https://github.com/williballenthin/lancelot/blob/e4f5191d4b8011eaa4024582f8912e0837507488/core/src/workspace/mod.rs)
- [lancelot PE analysis](https://github.com/williballenthin/lancelot/blob/e4f5191d4b8011eaa4024582f8912e0837507488/core/src/analysis/pe/mod.rs)
- [lancelot disassembly model](https://github.com/williballenthin/lancelot/blob/e4f5191d4b8011eaa4024582f8912e0837507488/core/src/analysis/dis.rs)
