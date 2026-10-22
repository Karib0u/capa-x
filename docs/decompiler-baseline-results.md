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

Scorecard on the same 184 addresses and the same full-Ghidra reference outputs,
both columns rerun on one machine (engine 12.1.4; "before" is the Function ID
commit `277d5d5`):

| Metric | Before | After |
|---|---:|---:|
| Native returned text | 181 | 181 |
| Flagged incomplete | 145 (80.1%) | 145 (80.1%) |
| Return void/non-void agrees | 93.9% | 93.9% |
| Parameter count agrees | 87.8% | 87.3% |
| Ghidra's named callees also named by native | 75.6% (483/639) | 75.7% (484/639) |
| Argument count agrees on matched callees | 97.3% | 97.1% |
| Gotos, Ghidra / native | 421 / 448 | 421 / 439 |
| Output lines, Ghidra / native | 18,864 / 19,316 | 18,864 / 19,229 |

Only 7 of the 184 texts changed. That is expected: the baseline functions were
chosen from Ghidra's list and mostly were already found, so this phase moves the
function set (above) more than these 184 functions. The one large change is
`0x180002f4c` in `4f08636d...`: its tail `jmp _seh_filter_exe` was folded into the
function (2,156 characters, a 12-line body) and is now a real tail call, which
matches Ghidra's `_seh_filter_dll` wrapper. One function lost a parameter in the
other direction (87.8% to 87.3%, one function). Unnamed calls and the three
work-limit errors are unchanged. A scorecard over functions the old recovery
missed is not possible with this selection; it would need the selection redrawn
from the new function set.

The capability path was checked, not assumed: `features_parity`, the smoke corpus
(23 of 23 identical) and the outer corpus (200 of 200, 6,300 reference-matched rules,
0 divergences) against the pinned capa 10 reference, `cargo test --workspace` and
the `decompiler` feature tests. 60 newly found funclets in `ad4229...` all
decompile.

Ghidra's outputs for this selection are stored in
`scripts/decompiler_baseline/reference/ghidra-12.1.4/` (about 3 MB: `decompile/`
for the 184 functions, `functions/` for every function of the 23 samples with body
ranges and incoming reference types). They depend only on the sample and the Ghidra
version, so rerun Ghidra only when either changes.

## Phase 5: effect models and data flow

Same 184 addresses and the same full-Ghidra reference outputs, both columns rerun on
one machine (engine 12.1.4; "before" is the Phase 3 commit `fa89615`). The change:
calls to `__security_check_cookie` and to the stack probes (`__chkstk` and relatives)
now use the compiler spec's call fixups (see [Effect models](decompiler.md#effect-models)),
replacing the hand-written RAX-preservation effect for the cookie check.

| Metric | Before | After |
|---|---:|---:|
| Native returned text | 181 | 181 |
| Flagged incomplete | 145 (80.1%) | **128 (70.7%)** |
| Not flagged incomplete | 36 | 53 |
| Return void/non-void agrees | 93.9% | 94.5% |
| Parameter count agrees | 87.3% | 87.8% |
| Ghidra's named callees also named by native | 75.7% (484/639) | 75.7% (484/639) |
| Argument count agrees on matched callees | 97.1% | 97.1% |
| Gotos, Ghidra / native | 421 / 439 | 421 / 426 |
| Output lines, Ghidra / native | 18,864 / 19,229 | 18,864 / 19,102 |
| `stack0x` address expressions, Ghidra / native | 5 / 63 | 5 / 5 |

23 of the 184 texts changed; the three work-limit errors are unchanged. Three effects:

- **Cookie check.** The notice appears in 22 of the 181 texts. The call and the dead `cookie ^ frame`
  computation disappear, as in Ghidra, so a callee such as `__GSHandlerCheckCommon`
  loses a spurious parameter and a void return (`void (uint8, int8, uint4 *)` to
  `uint8 (xunknown8, int8)`, Ghidra: `ulonglong (undefined8, longlong)`).
- **Stack probe.** A function with a large frame (`_write_nolock` in `10ebcf8c...`)
  used to print every local as `&stack0x...` and as `iStackX_8` slots because the
  probe left the stack pointer unknown. It now prints a normal frame, close to Ghidra's.
- **Incomplete flag.** Ghidra's `replaced with injection` comment is informational and no
  longer sets `incomplete`: 17 fewer functions are flagged. The comment itself is still in
  the text and the warnings.

The flag is now split: `unknown_callees` marks the callee-prototype cause. Of the 181
texts, 125 (69.1%) have it and only 3 (1.7%) are incomplete for any other reason, so the
remaining 70.7% is almost entirely missing callee prototypes, not unsound output. The flag drop is a definition change as much as an improvement: those functions still
have the generic "types are inferred" note, and remaining gaps (unknown callee
prototypes) still set the flag.

### Parameters from callees and call sites: measured, not adopted

Callee-body inference rejects a callee when any call inside it has an unlocked
prototype. Debug counts on this selection: 2,978 of 3,338 rejection events were that
reason (callees with an indirect call, an import without a prototype, or a function
without an inferred one), and the other 360 were decompiler warnings. That is the cluster behind `__acrt_FlsGetValue()`
and `_invalid_parameter(...)` losing arguments (Ghidra infers the arity from the callee body).
Three relaxations were tried and measured against the table above:

| Variant | Void | Params | Arity | Changed texts | Verdict |
|---|---:|---:|---:|---:|---|
| Accept callees with any unlocked call | 93.9% | 87.8% | 97.5% | 53 | Lost a return value (`FUN_18000adc4` became void) and gained spurious forwarded parameters in two float routines |
| Same, lock inputs only | 94.5% | 87.8% | 97.5% | 46 | Two functions gain agreement, two lose it (forwarded `xmm`/`rdx` registers become parameters) |
| Accept only callees whose unlocked calls are indirect | 94.5% | 87.8% | 97.1% | 8 | No metric moves |

None is better than neutral on the selected metrics and each adds failure modes that
are hard to see (extra parameters on callees that never read them), so inference stays
strict. A real fix needs to tell a register a callee reads from one it only forwards to an
unknown call; that is a change to how the engine's trial analysis is used, not a table.

Two other findings from the same pass:

- Several apparent argument-count mismatches were comparison artifacts. The checker
  reads the first call of each name, and Ghidra also prints `Process32NextW()` without
  arguments for the second call of a loop, exactly as native does.
- `_invalid_parameter(..., 0)`: Ghidra passes a fifth, stack-passed argument and native
  drops it. The callee's prototype is not in the packed archives (Ghidra infers it from
  the callee body), so the stack trial is judged by the same alias and local-range rules
  as any unknown callee. Same root cause as above.

The remaining shadow-space and local naming differences (`iStackX_10` against Ghidra's
`local_res10`, `xunknown8` against `undefined8`) are Ghidra's Java layer naming
conventions; they were left alone because renaming changes every consumer's output
without changing the analysis.

The capability path was checked: `cargo test --workspace` and the `decompiler` feature
tests (which include `features_parity`), and the smoke corpus (23 of 23 identical, 0
divergences over 731 reference-matched rules). The outer corpus was not rerun.

## Held-out benchmark

The 184-function baseline was drawn from Ghidra's function list on 23 samples, and
phases 2 to 5 were tuned against it. This set tests for overfitting. Measured 2026-10-22,
engine 12.1.4 on both sides, commit `8805445` plus the harness scripts.

- Samples: 24 native AMD64 PE files from `tests/testfiles` that are not in `samples.json`
  (79 eligible; EXE/DLL x size tercile; seed 20261022), listed with hashes in
  `scripts/decompiler_baseline/heldout.json`.
- Functions: 8 per sample, chosen from *capa-x's* function set (size percentiles 5 to 100,
  at least 8 bytes), 192 in total, before any output was read. Ghidra decompiled the same
  addresses; an address where Ghidra has no function is counted, not dropped.
- Ghidra's outputs are stored in `reference/ghidra-12.1.4-heldout/decompile/`.

The comparator matches a native call to Ghidra's name when it is `<module>_<name>` for any
imported DLL (`--any-module`). The old list of module prefixes missed names such as
`python38_PyModule_GetDict`. Both selections are rerun with the new matching below.

| Metric | Baseline (184, tuned) | Held-out (192) |
|---|---:|---:|
| Native returned text | 181 | 191 |
| Request errors (work limit) | 3 | 1 |
| Ghidra has no function at native's address | 0 | 6 (3.1%) |
| Flagged incomplete | 70.7% | 62.8% |
| Incomplete from unknown callee prototypes | 69.1% | 60.7% |
| Return void/non-void agrees | 94.5% | 97.3% |
| Parameter count agrees | 87.8% | 83.2% |
| Ghidra's named callees also named by native | 77.5% (495/639) | **65.5% (386/589)** |
| Argument count agrees on matched callees | 97.2% | 97.7% |
| Unnamed `FUN_` calls, Ghidra / native | 770 / 1,049 | 811 / 1,125 |
| Gotos, Ghidra / native | 421 / 426 | 558 / 546 |
| Output lines, Ghidra / native | 18,864 / 19,102 | 20,701 / 19,973 |

Reading it:

- **Robustness and structure generalize.** One work-limit error in 192, no crashes or
  initialization failures, gotos and line counts within 4% of Ghidra, arity 97.7%.
- **Callee naming does not.** 65.5% against 77.5%, a 12-point gap. The missed callees
  concentrate in a few samples: of 203 missed names, four samples account for 143
  (`82bf6347`, `932dab87`, `f53dfa29`, `0f33c2fe`) and `96abcbcb`, `c3ef997d` add more. Causes
  by sample: a statically linked MSVC C++ demangler (`DName::*`, which Ghidra names through
  Function ID and demangling), a Nim program (`nimFrame`, `popFrame`), a MinGW build,
  a Qt program (`QObject::connectImpl`), and CRT and libc names in non-Visual-C builds. By name: 80 CRT and libc, 49 other, 29
  C++, 10 Nim. This suggests the pack is strong on Visual C code and thin outside it (a reading of the
  clusters, not a per-name verification); demangling (phase 7) and a non-MSVC name source are the
  levers.
- **Parameter agreement is lower** (83.2% against 87.8%), consistent with callee knowledge.
- **Incomplete is lower** (62.8%), partly because more of the sample is small functions
  (146 of 191 are under 500 bytes; the 45 large ones are 91% incomplete).
- **Function-set agreement on native's picks:** Ghidra has a function at 186 of 192 addresses
  (96.9%). The six it lacks are small to median functions (p5 to p50). Why Ghidra has no function
  there was not classified.

What this changes in the plan: the tuned-set numbers overstate callee naming by about 12
points for the whole corpus, so the held-out set becomes a required column in the scorecard
next to the 184 functions. Data and string symbols and an x86-32 reference are the next
additions.

## Data and string symbols (metric)

Added 2026-10-22 as the first step of the data and string symbol work
([plan](decompiler-quality-plan.md)). `scripts/decompiler_baseline/data_symbols.py` reads
the comparison files and scores, per function, every data symbol address in Ghidra's text
(`DAT_<addr>` globals, `PTR_...` pointer cells, `s_`/`u_` string symbols) against native's
text for the same function: *referenced* (the address appears at all, as a `0x...` constant
or a `...Ram<16 hex>` name) and *named* (native prints a symbolic name). It also counts
inline `"..."` literals on both sides. Same texts and engine as the tables above.

| | Baseline (181 functions) | Held-out (185 functions) |
|---|---:|---:|
| Functions with a Ghidra data or string symbol | 87 | 104 |
| Symbols: string / pointer / global | 14 / 65 / 365 | 2 / 115 / 582 |
| Referenced by native | 94.1% (418/444) | 92.3% (645/699) |
| Named by native | **0.0%** (0/444) | **0.0%** (0/699) |
| Inline string literals, Ghidra / native | 276 / 136 | 216 / 77 |

The reference is already recovered (92 to 94%): native reads the same addresses, it prints
them as `uRam0000000140004098`, `xRam...` or a bare `0x140004000`. Nothing is named, because
the session has no data symbols. Strings split two ways: Ghidra either names the string
symbol (`u_Shell_TrayWnd_140004000`) or prints an inline literal, and native prints about
half (baseline) and about a third (held-out) as many literals as Ghidra. These are textual
proxies; the symbol counts are small for strings (24 across both sets), so the string rows
are weak evidence, while the literal counts are the better guide.

So the work is naming, not discovery: the target for the next step is `named` and the
literal gap, with `referenced` as a guard against regressions. Matching Ghidra's names
exactly is not required; a consistent `DAT_<addr>` and `s_`/`u_` convention on the same
addresses is.

## Data and string symbol naming

Implemented 2026-10-22 (see [Data and string symbols](decompiler.md#data-and-string-symbols)).
Same 184 and 192 addresses and the same Ghidra outputs as the metric above; the "before"
column is the metric's table, rerun with the same scripts and `--any-module` matching.

| | Baseline before | Baseline after | Held-out before | Held-out after |
|---|---:|---:|---:|---:|
| Ghidra's data symbol addresses referenced | 94.1% | 95.5% (424/444) | 92.3% | 98.3% (687/699) |
| Ghidra's data symbol addresses named | 0% | **90.3%** (401/444) | 0% | **98.1%** (686/699) |
| string / pointer / global named | 0 / 0 / 0 | 71.4 / 98.5 / 89.6% | 0 / 0 / 0 | 100 / 100 / 97.8% |
| Inline string literals, Ghidra / native | 276 / 136 | 276 / 244 | 216 / 77 | 216 / 190 |
| Engine `...Ram<hex>` names left in native text | not counted | 51 | not counted | 2 |
| Request errors | 3 | 3 | 1 | 1 |
| Flagged incomplete | 70.7% | 70.7% | 62.8% | 62.8% |
| Ghidra's named callees also named by native | 77.5% | 77.6% | 65.5% | 65.9% |
| Parameter count agrees | 87.8% | 87.8% | 83.2% | 83.2% |
| Output lines, Ghidra / native | 18,864 / 19,102 | 18,864 / 19,115 | 20,701 / 19,973 | 20,701 / 19,981 |
| Median request time, native | 8.1 ms | 10.3 ms | 4.7 ms | 6.3 ms |

The metric moved from 0% to 90 to 98%, and no other scorecard line regressed. Both sets also
gain inline literals because the string arrays are typed `char[n]`: native prints about
88% as many as Ghidra on both sets, up from 49% (baseline) and 36% (held-out).

Remaining baseline gaps are concentrated in the UPX-packed sample `c2d46d25` (49 of the
51 placeholder names): its data lives in sections the packed file does not map. The
remaining string miss is a short string below the 4-character minimum or one that Ghidra
treats as another type. String labels were fitted to Ghidra's names on these same two sets, so they are not an
independent check; names of globals match by construction. There is no precision measure
yet: the metric does not count names native invents where Ghidra has no symbol.

A request-order test (96 functions, three orders each) found no differing output, and
`cargo test -p capa-x --features decompiler --test decompiler` passes with a new test for
this feature. The capability path does not use this code. In this checkout the rules and
corpus tests that read `rules/` fail identically with and without the decompiler feature,
because the main checkout's `rules/` is not at the pinned commit; they were not changed.

### Precision of the names

`data_symbols.py` also checks the other direction: every `DAT_`/`PTR_`/`s_`/`u_` name native
prints, against Ghidra's text for the same function. *Agreed*: Ghidra names that address.
*Near*: Ghidra has a reference within 32 bytes below it (a field or element of a larger
Ghidra symbol: native prints `DAT_x` where Ghidra prints `DAT_y._8_8_`). *Unnamed*: Ghidra
shows the address but without a label. *Absent*: Ghidra's text mentions nothing close.
The metric now also reads Ghidra's pointer names of any target (`PTR_PTR__fmode_00404380`), so
the symbol counts in the two tables above are those of the corrected metric.

| Names native prints | Baseline | Held-out |
|---|---:|---:|
| Total (global / pointer / string) | 465 (385 / 75 / 5) | 754 (624 / 127 / 3) |
| Agreed | 401 (86.2%) | 686 (91.0%) |
| Near | 37 | 38 |
| Unnamed in Ghidra | 1 | 2 |
| Absent | 26 (5.6%) | 28 (3.7%) |

About 94% to 96% of the names agree with or sit inside a Ghidra symbol. The 54 absent names
are concentrated in a few functions (for example `c3ef997d` `0x140001950`, where Ghidra
decompiled 16 lines against native's 277, and several MinGW functions where Ghidra prints
the file's own symbol, `_refptr_mingw_initltsdrot_force`, for a cell native calls
`PTR_DAT_140029fe0`). In the cases read by hand the difference was the shape of the
function or a name that comes from the file's symbol table, not an invented symbol; I did
not review all 54. String names are too few (8 across both sets) to judge precision. All
four Ghidra string symbols native misses are in the packed sample, so the 4-character
minimum cost nothing on these sets and has no evidence behind it either way. A name source
for the file's own symbols (COFF symbol tables, as in MinGW builds) is the visible next gain
for globals.

## x86-32 baseline (phase 6a, step 1)

Measured 2026-10-22 on the same machine and Ghidra 12.1.4 as above, before any x86-32
decompiler work. The decompiler rejects PE32 today ("only native x86-64 PE images"), so
there is no native decompile column. What can be measured is function discovery, because
the capability recovery already handles 32-bit code, and what Ghidra produces, which is the
target.

- Samples: 24 native x86-32 PE files from `tests/testfiles` (237 eligible; no .NET, 8 KiB to
  6 MiB; EXE/DLL x size tercile; seed 20261023), hashes in
  `scripts/decompiler_baseline/samples-x86.json`. Four are the Practical Malware Analysis
  labs and one is a kernel driver (`.sys`). Packers were not filtered out.
- Ghidra: every function of each sample (`functions/`) and eight decompiled functions per
  sample chosen by the same rule as the x64 baseline (`decompile/`, 188 functions, all of
  which Ghidra decompiled). Stored in `reference/ghidra-12.1.4-x86/`.
- Native: the `function_set` example, i.e. the capability path's recovery, including the
  phase 3 sources that do not depend on `.pdata`.

| | x64 (after phase 3) | x86-32 |
|---|---:|---:|
| Ghidra functions | 15,777 | 14,182 |
| Ghidra functions also found by native (recall) | 14,737 (93.4%) | 12,543 (88.4%) |
| Native functions Ghidra also has (precision) | 97.1% | 85.0% |
| Ghidra-only / native-only | 1,040 / 444 | 1,639 / 2,208 |
| Recall without the single worst sample | 97.8% (packed sample) | 94.1% (`3b13b6f1`) |

Ghidra-only functions by what recovery knew:

| First cause | Count |
|---|---:|
| Folded into another native function | 1,194 (965 in `3b13b6f1`) |
| Never discovered | 410 (137 in `bc452cc1`, 140 in `d9630c17`, 95 in `1e9fc7f3`) |
| Thunks | 32 |
| Decoded but not made a function | 3 |

Native-only functions: 1,196 lie outside any Ghidra function and 1,012 lie inside one.
Large parts are single samples: 112 of the 150 native functions in the driver
`493167e8` sit inside one 8,910-byte Ghidra function that is probably not ordinary code.
None of these clusters has been looked at beyond their counts, and the packer status of the
large samples is unknown.

What this says about the work: discovery is not the blocker. Recall is 88% to 94% before any
x86-32 source, such as `.pdata` (absent here), prologue patterns or SEH tables, has been
added, and the larger cost is precision (85%). The Ghidra decompile exports show the calling
conventions the decompiler will have to model: of 188 functions, 58 print `__cdecl`, 18
`__thiscall`, 15 `__fastcall`, 2 `__stdcall` and 95 print no convention; 680 of their 1,229
callees are named.

## x86-32 decompiler (phase 6a)

Measured 2026-10-22, same machine and Ghidra 12.1.4 as above. The decompiler accepts PE32 now (see
[x86-32](decompiler.md#x86-32)). Reference: the 188 functions Ghidra decompiled in the x86-32 baseline
(`reference/ghidra-12.1.4-x86/decompile/`), chosen from Ghidra's list before any native output existed;
native runs the same addresses. Comparison with the same script and `--any-module` matching as the
x64 sets.

How the scorecard moved as the pieces were added:

| Step | Texts (of 188) | Callee names | Void agree | Params agree |
|---|---:|---:|---:|---:|
| PE32 accepted, specs only | 183 | 65.0% | 87.4% | 89.1% |
| + Function ID x86 pack | 183 | 75.7% | 89.1% | 89.6% |
| + callee failures tolerated, FID-conflict fixups | 186 | 76.2% | 88.7% | 89.8% |
| + import thunks, typed exports (final) | 186 | **89.2%** | **91.4%** | **91.9%** |

Final x86-32 against the two x64 sets (all three rerun with the final build):

| Metric | x86-32 (188) | x64 baseline (184) | x64 held-out (192) |
|---|---:|---:|---:|
| Native returned text | 186 | 181 | 191 |
| Request errors | 2 (work limit) | 3 | 1 |
| Flagged incomplete | 69.9% | 70.7% | 62.8% |
| Incomplete from unknown callee prototypes | 67.7% | 69.1% | 60.7% |
| Return void/non-void agrees | 91.4% | 94.5% | 97.3% |
| Parameter count agrees | 91.9% | 87.8% | 83.2% |
| Ghidra's named callees also named by native | 89.2% (536/601) | 82.0% (524/639) | 73.0% (430/589) |
| Argument count agrees on matched callees | 97.2% | 97.1% | 97.4% |
| Gotos, Ghidra / native | 576 / 553 | 421 / 426 | 558 / 546 |
| Output lines, Ghidra / native | 21,014 / 18,962 | 18,864 / 19,106 | 20,701 / 19,979 |
| Unnamed calls, Ghidra / native | 1,154 / 1,330 | 770 / 1,002 | 811 / 1,055 |
| Median request time, Ghidra / native | 9.1 / 13.4 ms | 11.6 / 9.6 ms | 8.4 / 6.9 ms |

The x86-32 callee naming is above the x64 sets because the sample selection differs (the 32-bit
files are mostly Visual C, which the Function ID data covers), not because the code is better.
The x86-32 numbers use only Ghidra's own list of functions, as the x64 baseline did, so they share
its selection bias; a held-out x86-32 set drawn from native's function set has not been made.

Side effects on x64, from the two changes that are not language specific: import thunks named
after their import and exports typed by name. Callee names on the baseline rose from 77.6% to 82.0%
and on the held-out set from 65.9% to 73.0%; the other metrics did not move. x64 output was
byte-identical to the previous build before those two changes (376 functions).

Data symbols on x86-32: of Ghidra's symbols, 43.2% are named, but one function (`0x4026a0` in `2c83f152`,
7,955 bytes, 3.9 s) dominates the count: its second analysis exceeds the 5 s deadline, so the
request falls back to the plain analysis and prints engine placeholder names. Without it, 91.3% (491 of 538)
are named and 93.9% referenced; of the names native prints, 98.6% of strings and 87.3% of globals agree
with Ghidra, 19 more are inside a larger Ghidra symbol.

Function ID on x86-32: Ghidra's hash agrees on 94.6% of 3,560 functions, and 824 of 826 names
both sides give are equal ([`FID.md`](../capa-x/sigs/FID.md)).

Robustness, outside the 188 functions: 100 random x86-32 PEs from `tests/testfiles`, 25 random
functions of at least 16 bytes each (2,229 in all): 2,223 returned text (99.7%); 6 errors (4 work limit,
1 instruction limit, 1 engine error); no initialization failure, no crash, none slower than 3 s.
This sweep runs the same seeded draw before and after changes and is not a held-out comparison with Ghidra.

Function discovery, the phase's exit criterion of 90% recall, is **not met**: 88.4% (94.1% without
one sample whose Ghidra functions are mostly jump stubs and hot-patch prologues that native folds into
other functions). Seeding code pointers found in data of x86 executables without relocations (the kind
Ghidra turns into functions from the data reference) was tried and measured: recall 88.4% to 89.0%,
precision 85.0% to 84.5%. That is a wash, so it was not adopted. Where native has functions Ghidra
lacks, the ones looked at were real code (stdcall methods after `ret N`, and SEH funclets). Both
numbers compare against Ghidra only.

## x86-32 held-out benchmark

Measured 2026-10-22, final build of phase 6a. Same method as the x64 held-out set: 24 x86-32 PE
files that are not among the 24 of the x86-32 baseline (213 eligible; seed 20261024), 179 functions
chosen from *native's* function set at size percentiles 5 to 100 before any output was read
(`heldout-x86.json`); Ghidra decompiled the same addresses and an address where it has no function is
counted (`reference/ghidra-12.1.4-x86-heldout/decompile/`). Packers were not filtered out.

| Metric | x86-32 tuned (188) | x86-32 held-out (179) |
|---|---:|---:|
| Ghidra has a function at native's address | 188 of 188 (its own list) | **156 of 179** (23 have none, 12.8%) |
| Native returned text | 186 | 172 (7 errors) |
| Errors | 2 work limit | 5 work limit, 2 instruction limit |
| Flagged incomplete | 69.9% | 62.8% |
| Incomplete from unknown callee prototypes | 67.7% | 61.6% |
| Return void/non-void agrees | 91.4% | 92.6% |
| Parameter count agrees | 91.9% | 88.6% |
| Ghidra's named callees also named by native | 89.2% (536/601) | **78.4%** (247/315) |
| Argument count agrees on matched callees | 97.2% | 97.6% |
| Gotos, Ghidra / native | 576 / 553 | 346 / 351 |
| Output lines, Ghidra / native | 21,014 / 18,962 | 20,363 / 20,495 |
| Unnamed calls, Ghidra / native | 1,154 / 1,330 | 1,021 / 1,510 |
| Median request time, Ghidra / native | 9.1 / 13.4 ms | 10.4 / 26.0 ms |
| Data symbols named (native names Ghidra's) | 91.3% (without one function) | 86.6% (367/424) |
| Names native prints that Ghidra agrees with | globals 87.3%, strings 98.6% | globals 94.5%, strings 100%, pointers 94.9% |
| Inline string literals, Ghidra / native | 143 / 133 | 111 / 97 |

Reading it:

- **Callee naming drops 11 points** (89.2% to 78.4%), the same size of drop as x64 (77.5% to 65.5%). The
  tuned 89.2% overstated what a new file gets. Structure (gotos, lines, arity) and the data
  symbols generalize.
- **12.8% of native's functions are not functions in Ghidra.** This is the function-set precision gap
  (85.0%) seen directly, at every size percentile from p5 to p99, which is not noise.
- **Missed names:** of 68 missed callees, 9 are `__security_check_cookie`, 14 are
  `FID_conflict` names (`memcpy`, `free` and two others, which Ghidra labels `FID_conflict:` and
  native leaves unnamed), the rest are other runtime and Win32 names, and one sample (`268d6183`) accounts for 24. The
  cookie check is a three-instruction helper below the Function ID minimum of four instructions, and
  the runtime signature subset has no x86 pattern for it, so it is neither named nor given its
  call fixup, unlike on x64.
- **Errors:** 7 in 179 (3.9%), against 1 in 192 on x64 held-out and 2 in 188 on the tuned x86 set. Five are
  work limits (functions of 22.6 kB, 19.0 kB, 7.4 kB and 4.5 kB at Ghidra, and one that is 381 bytes
  at Ghidra but not examined further). The two instruction-limit cases are the entry stubs of
  UPX-style packed files; Ghidra decompiles them with a "bad instruction data" warning.
- **Speed:** native's median is 26 ms, 2.5 times Ghidra's, against 1.5 times on the tuned set. It
  includes the second analysis for data symbols and larger inferred callee sets; not profiled further.

The 6a exit criteria hold on this set too except recall: callee naming is within 11 points of the x64
held-out figure, arity and void/non-void agreement are close, and there is no initialization failure. The
number to quote for naming on files not tuned against is 78%, not 89%.

## Step 11: gaps left by 6a

Measured 2026-10-22 with the same references and scripts as above, before and after the step.
Function sets come from `compare_functions.py` on the 24 x86-32 baseline samples; decompile
numbers from the stored Ghidra outputs (`--any-module`).

| Metric | Before | After |
|---|---:|---:|
| x86-32 function recall against Ghidra | 88.4% | **96.7%** |
| x86-32 function precision against Ghidra | 85.0% | **90.8%** |
| Ghidra-only / native-only functions | 1,639 / 2,208 | 467 / 1,383 |
| x86-32 tuned: texts / errors | 186 / 2 | 188 / 0 |
| x86-32 tuned: callee names | 89.2% (536/601) | 92.4% (573/620) |
| x86-32 held-out: texts / errors | 172 / 7 | 178 / 1 |
| x86-32 held-out: callee names | 78.4% (247/315) | 84.4% (286/339) |
| x86-32 held-out: argument count on matched callees | 97.6% | 96.5% |
| x64 baseline: errors / callee names | 3 / 82.0% | 1 / 83.0% |
| x64 held-out: errors / callee names | 1 / 73.0% | 0 / 74.7% |
| Flagged incomplete (x86 tuned / held-out) | 69.9% / 62.8% | 70.2% / 61.8% |

Other x64 and x86 metrics (void and parameter agreement, gotos, lines) moved by at most a point.
A robustness sweep over 100 random x86-32 and 60 random x64 PEs (12 random functions each) found no crash;
2 of 1,007 x86-32 requests failed in the engine and none of 709 on x64, also with deadlines of 40 ms.

What changed, in the order of effect:

- **Function boundaries (x86-32, native recovery only).**
  - A direct `jmp` target is a function when a jump stub reaches it (`jmp` alone, as in incremental-link
    jump tables, which was most of the 965 folded functions in `3b13b6f1`) or it follows `int3` padding at
    a 16-byte boundary. Other jump targets after a function end are loop heads (about 1,400 wrong against 77
    right), so they are not promoted.
  - A prologue-pattern address that flow had already decoded as part of another function is a function when
    it follows a function end or undecoded bytes.
  - Catch-block addresses (`HandlerType` whose type is a `std::type_info` or catch-all) and the frame-handler
    stub stored before a `FuncInfo` (magic `0x1993052x`) are functions. Ghidra makes these and not the
    unwind funclets, which stay inside their parent.
  - A relocation target inside code that was already walked is a switch arm or unwind block, not a function:
    1,031 one-instruction pseudo-functions removed (precision 85.8% to 90.8%).
  - A function view ends at a `jmp` to another function's entry, as Ghidra's does, so Function ID hashes are
    not computed over foreign code.
- **Names.**
  - The x86-32 `/GS` check (`cmp ecx, [cookie]; jne; ret; jmp`) is named `__security_check_cookie` with its
    archive prototype. Ghidra keeps the call in the text on x86-32, so no call fixup is applied.
  - `operator_new` and `operator_delete` come from `??2@` and `??3@`; `name@N` decorated names are accepted.
  - An ambiguous Function ID match is named `FID_conflict:<name>` as Ghidra does, choosing the candidate
    with the fewest leading underscores, then the shortest name. That agrees with Ghidra on 3 of the 4
    conflicts that could be checked, so treat it as a guess; no prototype or call fixup is applied from it.
- **Errors.**
  - Defaults rose to 10 s and 20M work units. A budget that ran out inside nested engine analysis (jump
    tables) used to surface as "No structure present"; it is now a work-limit error.
  - Flow past the instruction limit is retried truncated, with a warning.
  - A packer's zero-filled section is no longer mapped as code, which is what turned the two UPX entry
    stubs into 10,000-instruction walks (Ghidra reports bad instruction data there).
  - Latency: the slowest functions that used to fail now take up to 28 s (`0x4149c0` in `55d77ab1`,
    a 381-byte function whose Ghidra output is also 6,500 lines and took Ghidra 7 s). The one remaining
    error is a 22 kB function.
- **Fixes found on the way.**
  - An exception out of the action tree (a deadline during jump table recovery) left the root action
    half-run and crashed the next request with a null action. It reproduced on the commit before this step
    (deadline 1.5 s, 10M work); the tree is now re-derived after any such exception, with a test.
  - The `*_align` call fixups were listed but are commented out in `x86win.cspec`, so a file with
    `__EH_prolog3_*_align` failed to initialize; they are removed and the spec test ignores comments.
  - Recovered entries outside file-backed executable memory are skipped with a warning instead of reaching
    the engine.

Measured and not adopted: accepting a callee's inferred prototype when its only unlocked calls are indirect
cut the incomplete rate by 1 to 2 points and lowered argument agreement by 0.5 points; accepting any unlocked
call cut it by 13 and 9 points and lowered argument agreement by 4 and 2 points. 88% of the unknown calls are direct
calls (2,928 against 386 indirect), so the flag stays strict, as it did on x64.

Still open:

- **Remaining function differences** (x86-32): 287 Ghidra functions are undiscovered with no seed (mostly
  small unwind and catch funclets named only by data tables, which Ghidra makes functions of for some tables and
  not others, and MinGW functions such as `push ebp; push edi; push esi; push ebx`; neither pattern is mapped yet); 152 sit inside another function after a jump;
  1,014 native functions are outside any Ghidra function (static initializers, MinGW code Ghidra did not
  find), which are real code and not errors.
- **C runtime assembly routines** (`memset`, `memcpy`, `malloc`) stay unnamed; the cause is only partly known.
  Same Function ID databases as Ghidra. For `memset` in `268d6183` Ghidra's function has 46 code units and ours
  120, because our body follows a `jmp` into `__VEC_memzero`, which Ghidra makes a separate function and
  recovery leaves folded, so the hashes cover different bytes. For `memcpy` the counts are close (241 against
  243) and the cause is not found; `malloc`, `__lock` and `__errno` are not examined. The full FLIRT database
  names `memset` but adds 550 ms to initialization. `FID_conflict__memcpy` is 7 of the 95 callees still missed.
- **Qualified C++ names** (`Class::method`, constructors) need a demangler.

## Step 12: compile check with a real header

`scripts/decompiler_baseline/compile_check.py` now compiles each function's text alone with `clang
-fsyntax-only` for a Windows target (`x86_64-` or `i686-pc-windows-msvc`, clang 21), behind a header built by
`compile_header.py`:

- a prelude for Ghidra's pseudo-types (`undefinedN`, `xunknownN`, `intN`, `uintN`, `unkbyteN`, `code`, ...)
  and pseudo-operations (`CONCATnm`, `SUBnm`, `ZEXTnm`, `SEXTnm`, `CARRYn`, `SCARRYn`, `SBORROWn`,
  `POPCOUNT`, `LZCOUNT`), written by hand because they are decompiler built-ins and not in any archive;
- the Win32 and C library types the function names and a prototype for each callee the pack knows
  (a `<module>_` prefix is accepted), both read from `winapi64.pack` or `winapi32.pack`. Enumerations become
  integer typedefs;
- a stub for whatever is still undeclared: `FUN_` and other unknown callees, data symbols (typed from how the
  text uses them: called through, indexed, dereferenced), and Ghidra's register pseudo-variables.

Three results per function. **compiles**: clang accepts the text once everything undeclared is stubbed
(the successor of the crude number). **clean**: compiles, and the text contains none of the constructs
below, which need a decision before the function can be recompiled. **strict**: clean, and still compiles
with integer/pointer conversions as errors. A pass means well-formed C, not that the function is right.

| Set | Functions | Crude check (old) | compiles | clean | strict |
|---|---:|---:|---:|---:|---:|
| x64 held-out, native | 186 | 75 (40%) | 150 (81%) | 133 (72%) | 105 (56%) |
| x86-32 held-out, native | 155 | 75 (48%) | 138 (89%) | 92 (59%) | 79 (51%) |
| x64 tuned, native | 183 | | 147 (80%) | 119 (65%) | 101 (55%) |
| x86-32 tuned, native | 188 | | 164 (87%) | 115 (61%) | 95 (51%) |
| x64 held-out, Ghidra text | 186 | | 112 (60%) | 107 (58%) | 81 (44%) |
| x86-32 held-out, Ghidra text | 155 | | 116 (75%) | 91 (59%) | 69 (45%) |

Native compiles more often than Ghidra's text, but not because it is better C: the header names native's
pseudo-types, and Ghidra's text uses more types and names the pack lacks (`__acrt_ptd`, `DName`, C++
classes). Read the Ghidra rows as a sanity bound, not a comparison.

**Constructs that need a decision** (functions that contain each; held-out native, x64 / x86-32): register
reads `unaff_*`, `in_*`, `extraout_*` 24 / 32; sub-piece members such as `x._0_4_` 21 / 8; `stack0x`
addresses 1 / 27; `swi` 4 / 5; `halt_baddata` 0 / 2. The sub-piece member and the `stack0x` address are the
two largest groups that no header can fix; each needs a rule in step 13.

**What still fails after the blocker constructs** (first error, held-out native): 14 / 7 member access on a
local that native typed as an integer (the sub-piece case); a few calls whose argument count disagrees with the
pack's prototype (`SetWindowTheme()` with no arguments against three; three of the x64 ones are
`__acrt_iob_func`, whose pack prototype has no parameters, so those are the pack's, not the text's); locals of
a type that the pack has only as a forward declaration. These count real disagreements and are worth reading,
not only fixing in the header.

Unknown callees matter less than expected for this check: held-out x64 functions with unknown callees
compile 81 of 113, those without 69 of 73, because an unknown callee is stubbed with a generic declaration. The
stub is what step 13 has to replace with a marked guess.

Reproduce (needs the stored Ghidra references and the test files; see the baseline README):

```sh
python3 -I scripts/decompiler_baseline/compile_check.py LABEL comparison.json capa-x-ghidra/data/winapi64.pack
python3 -I scripts/decompiler_baseline/compile_check.py LABEL comparison.json capa-x-ghidra/data/winapi32.pack --x86 [--ghidra] [--out details.json]
```

## Step 13: self-contained unit

`capa-x FILE --decompile-function ADDR [--decompile-function ADDR ...] --unit [--json]` and
`DecompilerSession::decompile_unit` emit a translation unit (see [decompiler.md](decompiler.md#self-contained-unit)).
It is built in Rust from the embedded pack and the decompiled text; nothing runs Python or a compiler.
`scripts/decompiler_baseline/unit_check.py` runs the CLI over a selection and compiles each unit with
`clang -fsyntax-only` for a Windows target, adding nothing to the unit: the unit alone must be accepted.

| Selection | Units | Compile | Rest on the archive alone | Compile, when every callee is known |
|---|---:|---:|---:|---:|
| x64 held-out, one function each | 192 | 157 (82%) | 16 | 70 of 76 |
| x86-32 held-out, one function each | 179 | 161 (90%) | 21 | 67 of 72 |
| x64 held-out, sets of 5 | 48 | 18 (38%) | 0 | |
| x86-32 held-out, sets of 5 | 46 | 26 (57%) | 0 | |

(One x86-32 request hits the known 10 s deadline and is a request error, not a unit.) The goal of the
step, a function whose callees are all known compiles, holds for 92% (x64) and 93% (x86-32) of those functions; the rest
fail on the construct classes below, which are not about callees. Sets of five fail more often only because one
failing function fails the whole unit; the error classes are the same as for single functions.
"Rest on the archive alone" is low because almost every function reads a data symbol (`DAT_`, `PTR_`) or an
unknown callee, which are guesses: x64 held-out units carry 572 data-symbol, 418 callee and 23 register-read
guesses, and the x86-32 ones 798, 764 and 97 (plus 37 `stack0x` addresses). Those numbers are the work left for a data
pass over the image.

The `x._0_4_` sub-piece construct, the largest blocker in step 12 (21 of 186 x64 functions), is now rewritten
(185 rewritten on x64 held-out, 3 left of a width not handled, 231 and none on x86-32). What still fails
(first error, x64 held-out): member access on a local that is an integer (6); assignment to an array (4);
arithmetic on a value the text treats as an aggregate (4); calls whose argument count disagrees with the archive
(`__acrt_iob_func` is declared with no parameters in the archive, 3); a struct reached only through a pointer and then
dereferenced, which has a forward declaration and no body (3).

Reproduce (needs the sample files, clang, and a CLI built with the decompiler feature):

```sh
cargo build --release -p capa-x-cli --features decompiler
python3 -I scripts/decompiler_baseline/unit_check.py tests/testfiles scripts/decompiler_baseline/heldout.json target/release/capa-x
python3 -I scripts/decompiler_baseline/unit_check.py tests/testfiles scripts/decompiler_baseline/heldout-x86.json target/release/capa-x --x86 [--set 5]
```

## Not yet done

- A semantic check of the 91.6% and 82.7% agreement figures (they are textual).
- Latency, serial and warmed, on both sides.

## Reproducing

See [`scripts/decompiler_baseline/README.md`](../scripts/decompiler_baseline/README.md).
Ghidra's exports are committed (see Phase 3); native event logs and the per-function
comparison go to `scripts/decompiler_baseline/out/` (not committed).
