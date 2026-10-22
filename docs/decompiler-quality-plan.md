# Decompiler quality plan: reaching full-Ghidra output

Goal: make the embedded decompiler (`capa-x-ghidra` plus the `decompiler`
adapter) produce output as close as practical to what full Ghidra produces for
the same function, without a runtime JVM, Python or external disassembler.

The Ghidra decompiler core is already the real C++ engine, so algorithm parity
exists. Full Ghidra differs in the **context** it feeds that engine: function
boundaries, prototypes, types, library names and its Java analyzers. This plan
closes that context gap in order of measured payoff (Pareto), and measures every
step against full Ghidra, not IDA.

## Reference and scope

- Reference: full Ghidra, headless, default PE auto-analysis, decompiler
  timeout 30 s, version 12.1.4 (SHA-256
  `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`).
  The vendored engine was upgraded from 11.4.2 to the same 12.1.4 source, so the
  engine version is no longer a confounder (see the baseline results).
- No IDA in this plan. IDA numbers in earlier notes are historical only.
- Scope: native x86-64 PE under the Windows x64 convention. ELF, Mach-O and
  other architectures follow phase 6.
- Samples are never executed. `tests/testfiles/` and `rules/` are read-only.
- Everything Python or Java in this plan is development-time tooling and never
  runs in the shipped product.

## Metrics (the scorecard)

Per selected function, comparing native (N) against full Ghidra (G):

| Metric | Meaning |
|---|---|
| availability | N returned pseudocode when G did; N-only and G-only counts |
| errors | N request errors by class (work limit, instruction limit, init) |
| incomplete | share of N outputs flagged incomplete or carrying warnings |
| callee names | share of G's named callees that N names identically |
| call arity | share of matched calls where N and G pass the same number of arguments |
| return shape | N and G agree on void versus non-void |
| params | N and G agree on parameter count |
| structure | gotos and labels in N versus G |
| size | output lines, N versus G |
| latency | N request time versus G decompile time, excluding setup |

Each differing function is classed by first cause as **context** (missing
prototype, type, name or boundary), **recovery** (function discovery, thunk or
tail call) or **engine** (reproduced identically in G with the same inputs).
Only context and recovery items are worked on.

## Phase 0: baseline (this document's first deliverable)

1. Select samples and functions deterministically from PE headers and Ghidra's
   function list, before looking at any decompiler output.
2. Export G's selection and pseudocode with a headless script.
3. Run N on the same addresses with the `decompiler_corpus` example.
4. Compare and cluster failures by first cause. Record the machine, versions,
   hashes and commands next to the results.

Selection policy (Pareto: about 10% of the corpus, stratified):

- Eligible: native AMD64 PE files under `tests/testfiles` (about 105).
- Choose samples by stratified sampling over (EXE or DLL) x (size tercile),
  seeded and recorded, up to 24 samples.
- Per sample, choose up to 8 functions from G's analysis, never library thunks:
  the entry point, one export, the function referencing the most distinct
  imports, and application functions at size percentiles 10, 50, 90 and 100.
- Duplicate addresses are removed. The selection file is committed with results.

Exit criterion: a scorecard table plus the failure clusters, each labeled
context, recovery or engine.

## Phase 1: failure isolation and robustness

Targets request errors and session poisoning seen in the baseline.

- Run optional callee enrichment so its failure or work-limit never poisons the
  session or loses the selected function's output; retry without enrichment.
- Give the selected function the full work budget and enrichment its own.
- Add a partial-image mode that warns on a malformed import directory instead of
  refusing the whole image.
- Cache inferred callee signatures per session, invalidated by `set_signature`.
  Output must not depend on request order (add an order-shuffling test).

## Phase 2: type and prototype database (largest expected gain)

Targets unknown-callee warnings and missing struct and type recovery.

1. One-time, maintainer-run offline export from Ghidra's bundled data type
   archives: prototypes, calling conventions, noreturn flags, structs, enums and
   typedefs for Win32, and later libc and POSIX.
2. Compact interned binary table keyed by `(module, name)` and ordinal, lazily
   decoded. Budget: a few MB and about 1 ms lookup.
3. Resolve IAT entries to module-qualified prototypes and register referenced
   types in Ghidra's type factory on demand.
4. Unknown imports keep a generic prototype and the warning. Never invent a
   signature.
5. Document the source archive, Ghidra version and export script, the same way
   other generated tables are documented.

## Phase 3: function boundaries, thunks and tail calls

Lives in the shared `extract/recovery/` code, so the capability path must not
regress.

- Generalize the short-wrapper special case to a tail-call rule: a jump to a known
  function entry at the end of a stack-balanced function.
- Add discovery sources: x64 `.pdata` unwind tables, prologue patterns, code
  pointers in data and jump-table targets.
- Validate with the baseline's function-set agreement against G, and with the
  capa difftest loops in `AGENTS.md` (inner, mid and outer) on every change.

## Phase 4: runtime and library recognition

Status: Function ID part done (see the baseline results, "Phase 4"). It ran before
phase 3 and needs no change to the shared recovery code. FLIRT data conversion and
noreturn or calling-convention facts from FID are not done: Ghidra's databases carry
only names.

- Replace the 54-signature subset with a compact, lazily loaded index of Ghidra
  Function ID and FLIRT data converted offline. Loading everything cost about
  638 MiB, so hash-bucketed lookup is required.
- Gain: named CRT, STL and static library functions, and correct noreturn and
  calling-convention flags.

## Phase 5: targeted data-flow and cosmetic items

Driven strictly by the baseline clusters.

- A table of known effect models (RAX-preserving helpers, `__chkstk`,
  `__GSHandlerCheck`), extending the security-cookie mechanism. Done: compiler-spec
  call fixups, see [Effect models](decompiler.md#effect-models).
- Parameter identification from call sites as well as callee bodies. Investigated;
  no variant moved the metrics without regressing others, so nothing shipped (see
  [results](decompiler-baseline-results.md#phase-5-effect-models-and-data-flow)).
- Stack-argument and shadow-space handling in unusual patterns. The `__chkstk` fixup
  removed the one clear cluster (`stack0x` addresses); the remaining differences are
  naming conventions of Ghidra's Java layer and callee-prototype knowledge.

## Corpus composition and consequence

Counted with `file` over `tests/testfiles` (410 entries, capa's test set; recount on any
other corpus before committing to this order):

| Format | Count | Decompiler |
|---|---:|---|
| PE x86-32, native | about 235 (plus 18 .NET, out of scope) | Rejected: "only native x86-64 PE images" |
| PE x86-64 | about 105 | Supported |
| ELF x86-64 | about 18 | No |
| ELF x86-32 | 5 | No |
| ELF AArch64 | 1 | No |
| Mach-O | 0 | No |

A held-out sweep of 37 unseen PE samples found 23 (62%) were x86-32 and rejected. The
x86-64 remainder (14 samples, 350 functions) had no errors and 61% incomplete. x86-32 PE
therefore covers about twice what the decompiler handles today, and it was missing from
the earlier plan. Repo state that matters: `third_party/ghidra/specs/x86.slaspec` is
already vendored; only `x86-64-win.cspec`, `x86-64.pspec` and `winapi64.pack` exist;
loaders and recovery for ELF, Mach-O, AArch64 and x86-32 already exist for the capability
path (`extract/loader/*`, `extract/aarch64`).

## Phase 6: platforms

Rule: extract the `Platform` abstraction while adding the second platform, not before.
An abstraction drawn from one example is redrawn when the second arrives.

### 6a. x86-32 PE (next after the held-out benchmark)

Not a copy of the 64-bit path:

| Area | Change | Source / work |
|---|---|---|
| Language | `x86:LE:32:default`; second `.sla`, loaded lazily | `x86.slaspec` vendored; add `x86.pspec` |
| Compiler spec | `x86win.cspec`: cdecl, stdcall, fastcall, thiscall, unknown stack purge (`extrapop`) | Vendor from Ghidra 12.1.4 |
| Calling convention | Win32 APIs are `__stdcall` (callee pops). Wrong purge breaks arguments and stack shape | Port X86FunctionPurgeAnalyzer behavior; imports take the convention from the pack |
| Prototype pack | The 32-bit Win32 archive (`windows_vs12_32.gdt`) has different type sizes and packing | New `winapi32.pack` from the existing export script |
| Library names | Function ID databases for x86 VS2012 to VS2019, same compact-index design as x64 | Check the size budget; `common_symbols_win32.txt` |
| Effect models | Different call fixups: `_alloca_probe`, `__chkstk`, `__SEH_prolog4`, `__EH_prolog3`, cookie check (fastcall, `ecx`) | Extend the phase 5 table |
| Function discovery | No `.pdata`. Phase 3's recall gain came mostly from `.pdata`, which x86-32 lacks | Prologue patterns (FunctionStart), call targets, SEH4 scope tables, jump-table targets, FLIRT |
| Image loading | Base relocations and absolute addresses; imports through `jmp [abs]` | Check rebasing against Ghidra on the corpus |
| Compiler variants | MSVC, MinGW (`x86gcc`), Borland and Delphi (`x86delphi`, register convention) | Detect and record per sample; MSVC and MinGW first, Delphi as an explicit follow-up |
| Conventions | `thiscall` (`ecx`), `fs:[0]` SEH frames | Rely on the spec; verify on samples |

Main risk: function recall starts well below the x64 93%.

Steps:

1. Baseline first: select 24 x86-32 samples, export Ghidra references into
   `reference/ghidra-12.1.4-x86/`, measure function-set agreement. No code before this.
2. `from_pe` accepts PE32 and selects language and specs by machine type.
3. `winapi32.pack` and the 32-bit effect table.
4. x86-32 discovery sources and the Function ID pack.
5. Full scorecard plus the capa difftest loops; the capability path stays byte-identical.

Exit: 0 initialization errors on non-packed native PE32; function recall at or above 90%;
callee-name coverage, argument-count and void/non-void agreement within 10 points of the
x64 numbers. Effort: large; steps 1 and 2 are small, the pack, Function ID and discovery
are most of it.

### 6b. Extract `Platform`

From the two implementations that now exist. It owns the SLEIGH language, processor and
compiler specs, the loader (sections, imports, relocations), the prototype pack, the
library-name source, thunk rules, non-returning lists and the effect table.

- Data-only dispatch, no runtime plugins; lazy loading; the default build is unchanged.
- Measure binary size and build time with a second and third `.sla`; put each language
  behind its own feature if the cost matters.
- x64 outputs stay byte-identical (the 184-function reference checks it). Effort: medium.

### 6c. ELF x86-64 and x86-32

| Area | Work |
|---|---|
| Specs | `x86-64-gcc.cspec` (System V: `rdi, rsi, rdx, rcx, r8, r9`, red zone); `x86gcc.cspec` for 32-bit |
| Imports | PLT and GOT stubs including `.plt.sec` and IRELATIVE, mapped to libc names |
| Types | Generic C library and POSIX archives; a pack keyed by `(library, name)` |
| Names | `.dynsym` and `.symtab`; Ghidra ships no glibc Function ID data, so stripped static binaries need FLIRT or another signature source |
| Non-returning | Ghidra's ELF lists (`exit`, `abort`, `__stack_chk_fail`) |
| Quirks | TLS through `fs:`, `syscall` as a named operation (Linux syscall table), stack canary |
| Reuse | `golang.rs`, `libc_start_main.rs` recovery |

Effort: medium to large. About 23 ELF samples is a thin corpus; add ELF test files first.

### 6d. AArch64

`AARCH64.slaspec` with its `.cspec` (AAPCS64, `x0` to `x7`). Check `.sla` size and compile
time first. Fixed-width instructions ease discovery; check PAC and BTI and whether to
reuse `extract/aarch64`. ELF AArch64 first (Android, IoT), then PE ARM64. One sample in the
corpus, so low priority unless the real corpus has more.

### 6e. Mach-O (x86-64 and arm64)

Fat-binary slice selection, `__stubs` and `__la_symbol_ptr`, chained fixups (arm64e
pointer authentication), Ghidra's Mac type archive. No samples in the corpus: start only
when there are some. Objective-C message sends belong to phase 7.

### 6f. 32-bit ARM and MIPS

Only if the corpus contains IoT samples, and only after 6d.

## Phase 7: long tail, only if the scorecard justifies it

| Item | Gives | Cost | Note |
|---|---|---|---|
| String and data symbols (`DAT_`, `u_...` literals, global names) | The largest visible readability gap in side-by-side examples (strings print as raw addresses, globals as `uRam...`) | Medium: data-reference and string detection, optionally the n-gram model | Metric added ([results](decompiler-baseline-results.md#data-and-string-symbols-metric)): 92 to 94% of Ghidra's data addresses are referenced by native, 0% named, and native prints about a third to a half as many string literals. Ahead of 6c to 6e |
| Demangling (MSVC `?..@@`, Itanium `_Z`) | Readable C++ names; the largest group of the 156 unrecovered callee names | A demangler crate if the dependency policy allows | Justify the dependency per `AGENTS.md` |
| C++ RTTI and vtables | Class names, virtual calls, constructors | Large | MSVC first, then Itanium |
| Structured exception handling | `__try`/`__except`, `__CxxFrameHandler`, scope tables | Medium to large | Common in MSVC code |
| Go and Rust runtime awareness | Names from `pclntab`, panic and defer patterns | Medium each | `golang.rs` recovery exists |
| Wider jump-table coverage | Fewer switch gaps and gotos | Small to medium per measured miss | Extend `switch.rs` |
| PDB and DWARF types | Real types when debug info exists | Medium | Rare in malware |
| Packers (UPX and similar) | Recall: 711 Ghidra-only functions in the one packed sample | Large; needs emulation or static unpacking, and samples are never executed | Probably out of scope; document as a limit |
| Objective-C and Swift | Message sends, metadata | Large | After 6e and real samples |

## Order and status

Order by payoff per effort and dependency, not by phase number:

| Step | Phase | Status |
|---|---|---|
| 1 | Phase 0, baseline | Done ([results](decompiler-baseline-results.md)) |
| 2 | Phase 2, type and prototype pack | Done, with known leftovers (see results) |
| 3 | Phase 1, failure isolation | Done (`00143de`): request errors 7 to 3 on the baseline, session no longer poisoned by limits; 3 work-limit errors remain |
| 4 | Phase 4, library names (Function ID) | Done ([results](decompiler-baseline-results.md#phase-4-function-id-names)): callee names 56.2% to 75.7%; demangling and noreturn or calling-convention facts remain |
| 5 | Phase 3, boundaries, thunks, tail calls | Done ([results](decompiler-baseline-results.md#phase-3-function-boundaries)): function recall against Ghidra 79.6% to 93.4% (97.8% without the packed sample); difftest loops unchanged. Gated on the native backend, so the capability path is untouched |
| 6 | Phase 5, cosmetics and data-flow | Done ([results](decompiler-baseline-results.md#phase-5-effect-models-and-data-flow)): call fixups for the cookie check and stack probes; incomplete flag 80.1% to 70.7%; parameter-ID variants measured and not adopted. Gated on the native backend |
| 7 | Held-out benchmark | Done ([results](decompiler-baseline-results.md#held-out-benchmark)): callee naming 65.5% against 77.5% on the tuned set, robustness and structure generalize. A data and string symbol metric is still to add |
| 8 | Phase 6a, x86-32 PE | After the x86-32 Ghidra baseline (about 62% of sampled PE files are x86-32) |
| 9 | Phase 7, string and data symbols | Before the other platforms; helps all of them |
| 10 | Phase 6b, `Platform` extraction | After 6a, from the two implementations |
| 11 | Phases 6c to 6f and the rest of 7 | Only if the scorecard or the corpus asks |

Rerun the baseline after every step. A step that does not move its target metric
is investigated before the next one starts.

## Ghidra analyzers to port

The decompiler engine is Ghidra's own, so the gap is what Ghidra's Java
auto-analysis supplies. This ranks the analyzers shipped in 12.1.4 by effect on
decompiler output against effort. Port behavior verified against Ghidra on the
corpus, not code. An analyzer whose port does not move a metric is dropped.
Items marked (phase N) are the work of that phase.

**Port first**

| Analyzer | Why | Effort |
|---|---|---|
| StackVariableAnalyzer and decompiler parameter ID | Parameter and local detection; the wrapper and parameter-count mismatches (83.6% agreement) | Medium; the embedded engine already does part |
| FindNoReturnFunctionsAnalyzer, NoReturnFunctionAnalyzer | Non-returning detection changes control flow | Low to medium; extend `noreturn.rs` (phase 3) |
| SharedReturnAnalyzer, SharedReturnJumpAnalyzer | Tail calls (phase 3) | Medium |
| CreateThunkAnalyzer | Thunks and IAT stubs (phase 3) | Low |
| PEExceptionAnalyzer | x64 `.pdata` gives reliable function starts and ends (phase 3) | Low to medium |
| FidAnalyzer (Function ID) | Names CRT and libc code (phase 4); data lookup, not heuristics | Medium plus a compact index |
| X86FunctionPurgeAnalyzer | Stack purge, only for x86-32 stdcall | Low, 32-bit only |

**Port next**

| Analyzer | Why |
|---|---|
| FunctionStart* (BytePatterns) | Prologue-based discovery in stripped code |
| MicrosoftDemanglerAnalyzer, GnuDemanglerAnalyzer | Readable C++ names; prefer an existing Rust demangler crate if the dependency policy allows |
| ConstantPropagationAnalyzer | Resolves computed addresses and some indirect calls; large and risky |
| DecompilerSwitchAnalyzer | Extend `switch.rs` only where the corpus shows misses |
| CallFixupAnalyzer | Known helper effects such as the security cookie. Done in phase 5 through the spec's `<callfixup>` entries |
| ApplyDataArchiveAnalyzer | Covered by phase 2, with a stricter module policy |
| DataOperandReference, OperandReference, ScalarOperand | Constant-to-data references, strings and globals |

**Only if the corpus needs them**

RttiAnalyzer and GccExceptionAnalyzer (C++ classes and exceptions); the Go, Rust,
Swift, Objective-C and CFString analyzers (one per target language); DWARFAnalyzer
and PdbAnalyzer (types from debug info, rare in malware).

**Not worth porting**

The file-format analyzers (Android, DEX, iOS, DMG, Ext4, YAFFS, boot images),
EmbeddedMedia, Strings, CondenseFillerBytes, the emulation analyzers, TEB and
WindowsResourceReference.

Even with all of the above, this is not Ghidra's analysis: there is no program
database and no fixed-point interaction between analyzers. The goal is the
context the decompiler needs, checked against Ghidra case by case.

## Other Ghidra assets to port

Beyond analyzers, most of Ghidra's remaining value is curated data and
specifications, several already in the 12.1.4 install. Like the type pack, these
are exported once, offline, and embedded in compact form.

| Asset (in Ghidra 12.1.4) | What it gives | Phase / status |
|---|---|---|
| Function ID databases (`FunctionID/data/vs2012` to `vs2019` x64 `.fidbf`, `common_symbols_win64.txt`) | CRT and static library names | Phase 4, in progress |
| Non-returning lists (`PEFunctionsThatDoNotReturn`, `Elf...`, `Golang...`, `Rust...`, `MachO...`, `noReturnFunctionConstraints.xml`) | Curated `exit`/`abort`-style functions; control flow after them. Cheap, high value | Phase 3, next to the noreturn analyzers |
| Ordinal and export tables (`symbols/win64/*.exports`, `*.hints`) | Names for ordinal imports, which currently get no prototype | Phase 3 or 5 |
| Call fixups and p-code injection in the compiler spec (3 `callfixup` entries, 7 targets, in `x86-64-win.cspec`) | Helpers such as `__security_check_cookie` and `__chkstk` replaced by injected p-code | Done in phase 5: the fixups replace the hand-written RAX hack and apply to any recognized name |
| Function-start patterns (BytePatterns module data) | Prologue-based discovery in stripped code; not yet inspected | Phase 3, after `.pdata` |
| String n-gram model (`stringngrams/StringModel.sng`) | Better detection of real strings in data; optional | Phase 5 |
| Other compiler specs (`x86-64-gcc`, `-golang`, `-swift`, `x86win`, `x86gcc`, `x86borland`, `x86delphi`) and processor SLEIGH specs | Calling conventions, register effects and instruction semantics per target | Phase 6 |
| Other type archives (generic clib, Mac, Go, Rust) and Linux syscall number tables | Prototypes and named syscalls for ELF and Mach-O | Phase 6 |
| Loader semantics (import binding, forwarded and delay-load exports, relocations, ELF/Mach-O stubs) | Mapping the image as Ghidra would. Check capa-x's loaders against Ghidra on the corpus, starting with the sample Ghidra's own loader rejects | Phases 3 and 6 |
| Demangling, PDB and DWARF type import | Readable C++ names; types from debug info | Phase 7. Prefer a demangler crate if the dependency policy allows. |

Not worth porting: GUI and project services, version tracking, BSim, scripting,
the debugger, and the container and file-system importers.

## Risks

- Licensing of exported data: Ghidra is Apache-2.0. Anything derived from
  Microsoft SDK content gets a terms review and recorded provenance.
- Size and memory: tables are lazy and behind the `decompiler` feature; the
  default build is unchanged.
- Recovery regressions: phase 3 touches shared code; run the difftest loops.
- Determinism: tables and caches must not make output depend on request order or
  job count.
- Reference drift: the baseline records both Ghidra versions; rerun the baseline
  after any Ghidra bump.

## Reproducing the baseline

See `scripts/decompiler_baseline/README.md` for the exact commands, and
`docs/decompiler-baseline-results.md` for the recorded results.
