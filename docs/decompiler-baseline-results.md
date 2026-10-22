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

## Phase 2: archive prototypes and types

Imports from Windows system DLLs now take their prototype and types from a packed
export of Ghidra's Win32 and C library data type archives (see
[Prototype pack](decompiler.md#prototype-pack)). Same 184 addresses, same
reference, engine 12.1.4 on both sides:

| Metric | Before | After |
|---|---:|---:|
| Native returned text | 179 | 177 |
| Request errors (all work limit) | 5 | 7 |
| Flagged incomplete | 159 (88.8%) | 147 (83.1%) |
| Not flagged incomplete | 20 | 30 |
| Outputs with unknown-callee warning | 151 | 129 |
| Argument count agrees on matched callees | 87.4% (318/364) | **98.3% (348/354)** |
| Return void/non-void agrees | 91.6% | 91.5% |
| Parameter count agrees | 82.7% | 83.6% |
| Ghidra's named callees also named by native | 56.8% | 56.2% |
| Unnamed `FUN_` calls, Ghidra / native | 636 / 1,113 | 628 / 1,104 |
| Output lines, Ghidra / native | 16,473 / 16,985 | 16,248 / 16,827 |

Ten functions moved from incomplete to complete and two moved from output to a
work-limit error (both in `dc7cb53c...`, where more typed calls now trigger more
callee inference inside the shared budget). A typical import-heavy function
(`592cfd22...` at `0x1400010c0`) went from untyped `xunknown8` parameters and
calls that dropped their last arguments to `HWND`, `HANDLE`, `LPVOID` and
`SIZE_T` locals with all arguments present, close to Ghidra's own text.

What did not move, and why: callee *names* and the unknown-callee warnings
mostly concern internal and C runtime functions that Ghidra names through Function
ID, not imports. That is phase 4, with function boundaries from phase 3. Remaining
text differences visible in the example are cosmetic: native prefixes imports
with the module (`user32_FindWindowW`), prints Ghidra's `undefined1` as
`xunknown1`, and does not name string literals. Eight of 36,364 packed entries
still fail to decode and fall back to an unknown prototype (see the decompiler
documentation). Startup time was not measurably affected (about 37 ms in the
fixture benchmark); peak memory with the pack was not measured.

## Phase 1: failure isolation

After `00143de` (enrichment has its own budget, limit errors no longer poison the
session, inferred signatures are cached), the same 184 addresses give:

| Metric | After phase 2 | After phase 1 |
|---|---:|---:|
| Native returned text | 177 | 181 |
| Request errors (all work limit) | 7 | 3 |
| Not flagged incomplete | 30 | 30 |
| Outputs with inferred-callee warning | 117 | 75 |
| Parameter count agrees | 83.6% | 84.5% |
| Argument count agrees on matched callees | 98.3% | 98.3% |
| Ghidra's named callees also named by native | 56.2% | 56.2% |

The three remaining errors are still work-limit failures. The rest of the
metrics are unchanged, as expected: this phase changes failure behavior, not the
quality of successful output.

## Phase 4: Function ID names

`from_pe` now names unnamed functions from a pack of Ghidra's Function ID databases
(see [Function ID names](decompiler.md#function-id-names)) and applies the packed
prototype of recognized names. Measured on 2026-10-21 on the same 184 addresses
and the same full-Ghidra reference outputs, rerun for both columns on one machine
(engine 12.1.4; "before" is this commit with Function ID naming switched off):

| Metric | Before | After |
|---|---:|---:|
| Native returned text | 181 | 181 |
| Request errors (all work limit) | 3 | 3 |
| Flagged incomplete | 151 (83.4%) | 145 (80.1%) |
| Outputs with unknown-callee warning | 134 | 125 |
| Ghidra's named callees also named by native | 56.2% (359/639) | **75.6% (483/639)** |
| Argument count agrees on matched callees | 98.3% (353/359) | 97.3% (470/483) |
| Return void/non-void agrees | 91.7% | 93.9% |
| Parameter count agrees | 84.5% | 87.8% |
| Unnamed `FUN_` calls, Ghidra / native | 770 / 1,288 | 770 / 1,048 |
| Output lines, Ghidra / native | 18,864 / 19,420 | 18,864 / 19,316 |

Timing is not reported: the two runs were not isolated from background load.
The additional 124 named callees keep their arity almost as well (117 of 124 agree).
Warnings "Subroutine does not return" rose from 20 to 28 because recognized
`exit`-like names bring their no-return prototypes.

Not recovered and why: 156 of Ghidra's 639 named callees are still unnamed. In the
function-level replay, the largest remaining groups are C++ templates, operators and
constructors (which need a demangler) and functions that capa-x recovery does not
discover, so the cap is now phase 3. One sample (`c2d46d25...`) discovers none of the
285 functions Ghidra names. Hash fidelity against Ghidra is documented in
[`FID.md`](../capa-x/sigs/FID.md).

## Phase 3: function boundaries

Function-set agreement was measured for the first time, on all 23 samples and every
function Ghidra recovers (15,777 entries, non-external). Ghidra side:
`scripts/decompiler_baseline/FunctionList.java`; native side: the `function_set`
example; comparison: `compare_functions.py`, with first-cause clusters from
`classify_functions.py`. Same machine and Ghidra 12.1.4 as above.

| | Before | After |
|---|---:|---:|
| Ghidra functions also found by native (recall) | 12,553 (79.6%) | 14,737 (93.4%) |
| Native functions Ghidra also has (precision) | 96.3% | 97.1% |
| Ghidra-only functions | 3,224 | 1,040 |
| Native-only functions | 483 | 444 |
| Recall without the UPX-packed sample | 83.3% | 97.8% |

The UPX sample (`c2d46d...`, 711 Ghidra-only, 250 native-only) is packed, so both
sides see stub code only and it dominates what remains.

The Ghidra-only functions by what recovery knew, before and after:

| First cause | Before | After |
|---|---:|---:|
| Never discovered, no reference (data-named leaf funclets, and 355 in the packed sample) | 2,437 | 376 |
| Thunks (`jmp [import]` stubs) | 236 | 222 |
| Folded into another native function (tail-jump targets) | 207 | 98 |
| Seeded but not decodable (packed sample) | 340 | 340 |
| Referenced but not decoded | 4 | 4 |

Reading the first row: about 1,800 of the 2,437 were in one sample. MSVC leaf funclets
(C++ unwind and catch actions) have no `.pdata` entry and no caller, and appear only as
image-relative values in `.rdata`. Most of the 98 folded functions are in `kernel32`.
Of the remaining thunks, 176 are `kernel32` stubs that only data references reach, and 32 are unreferenced `jmp [import]` stubs in a MinGW DLL.

A second finding was a Vivisect limitation carried into native recovery: it stops reading `.pdata` at the
first entry it cannot read, so several samples lost most of their table (for
example `4f08636d...` went from 281 to 335 matching functions on that fix alone).
On the native side, 137 of the 163 native-only functions inside Ghidra functions were
the Vivisect `/GS` cookie-tail split, which does not belong in native recovery.

Fixes are listed under Function discovery in [decompiler.md](decompiler.md#function-discovery).
After them, native-only functions inside Ghidra functions are 40 (from 163). The
new sources also add native-only functions Ghidra does not have, mostly leaf
functions after `int3` padding that Ghidra left undefined (404 native-only
functions lie outside any Ghidra function, 250 of them in the packed sample).
The bytes look like real functions, but Ghidra is the only reference here.

The capability path was checked, not assumed: `features_parity`, the smoke corpus
(23 of 23 identical) and the outer corpus (200 of 200, 6,300 reference-matched rules,
0 divergences) against the pinned capa 10 reference, `cargo test --workspace` and
the `decompiler` feature tests. 60 newly found funclets in `ad4229...` all
decompile. The textual decompiler scorecard above was not rerun, because it needs the
full-Ghidra decompile pass; do that before relying on the callee-name
numbers.

## Not yet done

- A semantic scorecard rerun after phase 3 (see above).
- A semantic check of the 91.6% and 82.7% agreement figures (they are textual).
- Latency, serial and warmed, on both sides.

## Reproducing

See [`scripts/decompiler_baseline/README.md`](../scripts/decompiler_baseline/README.md).
Raw Ghidra exports, native event logs and the per-function comparison are in
`scripts/decompiler_baseline/out/` (not committed; regenerate with the scripts).
