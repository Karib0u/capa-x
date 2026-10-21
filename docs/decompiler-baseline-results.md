# Decompiler baseline versus full Ghidra (phase 0)

Measured 2026-10-21 on an Apple M1 Max (arm64), commit `870d1d8` of
`feat/native-decompiler` (embedded Ghidra engine, release build) against
full Ghidra 12.1.4 headless with default PE auto-analysis and a 30 s per-function
decompiler timeout. Plan: [decompiler-quality-plan.md](decompiler-quality-plan.md).

This is a Pareto-sized snapshot, not a corpus-wide result: 23 samples, 184
functions. Ghidra's output is the reference only for *context* (names, types,
prototypes, boundaries). It is not ground truth for source code, and the two
engine versions differ.

## Method

- Samples: seeded stratified selection of 24 native AMD64 PE files from
  `tests/testfiles` (EXE/DLL x size tercile, 8 KiB to 6 MiB, no .NET), from PE
  headers only. Seed 20261021. The list with SHA-256 values is
  `scripts/decompiler_baseline/samples.json`.
- Functions: up to eight per sample, chosen from *Ghidra's* function list before
  any output was read: the entry point, one export, the function referencing the
  most distinct imports, and non-thunk functions at size percentiles
  10/50/90/100 (then 25/75/99/5/60 to fill). Native decompiled the same addresses.
- One sample (`4b796a64...dll_`) was dropped: Ghidra's own PE loader fails with
  `Function entryPoint may not be created on defined data`.
- Ghidra 12.1.4 ships no macOS arm64 decompiler binary. It was built from the
  sources in the release (`make ghidra_opt`, arm64) and installed as
  `os/mac_arm_64/decompile`. Ghidra's three parallel headless jobs make its
  latencies noisy.
- Comparison is textual (regex on the C output): callee names, call argument
  counts, return void/non-void, parameter count, gotos, lines. These are proxies.

## Results

| Metric | Value |
|---|---|
| Functions compared | 184 (Ghidra produced text for all 184) |
| Native returned text | 179 (97.3%); 5 errors, all "native work limit exceeded" |
| Native flagged incomplete | 159 of 179 (88.8%) |
| Native not flagged incomplete | 20 (mostly functions of 3-91 bytes, plus one of 450 and one of 6,152) |
| Outputs with unknown-callee warning | 151 of 179 |
| Outputs with inferred-callee warning | 97 of 179 |
| Return void/non-void agrees | 91.6% (164/179) |
| Parameter count agrees | 82.7% (148/179) |
| Ghidra's named callees also named by native | 56.8% (364/641) |
| Argument count agrees on matched callees | 87.4% (318/364) |
| Calls to unnamed `FUN_` functions, Ghidra / native | 636 / 1,113 |
| Gotos, Ghidra / native | 372 / 397 |
| Output lines, Ghidra / native | 16,473 / 17,162 |
| Median per-function time, Ghidra / native | 30.7 ms / 15.2 ms (not comparable) |

Native "ok" (not incomplete) by role: entry 3 of 22, `most_imports` 0 of 23,
p75 0 of 16, p90 1 of 23. Larger and import-heavy functions are the ones that
fall short.

## What the gaps are

By first-cause class, from the data above:

1. **Missing callee names (context, phases 2 and 4).** Native misses 277 of 641
   named callees. The most common are Visual C runtime and libc functions that
   Ghidra names through Function ID: `__doserrno` (12), `free`, `memcpy`,
   `_free_base`, `_getptd`, `_initterm`, `operator_new`, `strlen`, `malloc`,
   `__security_init_cookie`, `memcpy_s`. A few are Win32 imports without a
   modeled prototype, e.g. `IsProcessorFeaturePresent`.
2. **Unknown callee prototypes (context, phase 2).** 151 outputs carry the
   warning, and it drives the 88.8% incomplete rate. Native has 1,113 unnamed
   calls against Ghidra's 636.
3. **Function interface (context, phases 2 and 5).** Parameter count differs in
   31 functions. The return void/non-void mismatches (15) are mostly this `entry` case (8). Examples: a wrapper where Ghidra recovers four parameters and
   native recovers none (`0x140001180` in `4f509bdf...`); and `entry`, where
   native applies a `DllEntryPoint(void*, uint4, void*)` signature and Ghidra
   does not, in eight DLLs, where it declares `void entry(...)` or a different return type. The latter
   is not an error in either direction without the source.
4. **Robustness (phase 1).** Five requests hit the work limit (three in
   `92d8ea10...`, one in `ad422987...`, one in `kernel32-64.dll_`). Native had no
   crashes and no initialization failures on this set.
5. **Structure (engine or recovery).** Gotos and lines are within about 8% and 4%
   of Ghidra, so control-flow structuring is not the main gap. Per-function
   differences were not individually classified.

## Effect of upgrading the embedded engine (11.4.2 to 12.1.4)

The vendored engine was then upgraded to 12.1.4, the same version as the
reference, and the native side rerun on the identical 184 addresses. Every
headline metric is unchanged: status per function (0 changes), 5 work-limit
errors, 88.8% incomplete, 56.8% callee names, 87.4% arity, 91.6% void agreement
and 82.7% parameter agreement. Native text changed in 21 of 184 functions (output
lines 17,162 to 16,985, median time 15.2 ms to 13.2 ms). The seven fixture
references are byte-identical under both versions. So the gaps above are context,
not the engine version, and the engine-version confounder is closed.

## Not yet done

- Function-set agreement (discovery) between recovery and Ghidra was not
  measured: only Ghidra's chosen functions were requested, so native-only and
  Ghidra-only functions are unseen. Recovery gaps (phase 3) need that comparison.
- A semantic check of the 91.6% and 82.7% agreement figures (they are textual).
- Latency, serial and warmed, on both sides.

## Reproducing

See [`scripts/decompiler_baseline/README.md`](../scripts/decompiler_baseline/README.md).
Raw Ghidra exports, native event logs and the per-function comparison are in
`scripts/decompiler_baseline/out/` (not committed; regenerate with the scripts).
