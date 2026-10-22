# Decompiler quality plan

Goal: the embedded decompiler (`capa-x-ghidra` plus the `decompiler` adapter) gives an analyst or
an AI agent output that is **semantically right, honest about what it does not know, and
C-compatible enough to recompile extracted functions**, without a runtime JVM, Python or external
disassembler. Ghidra, run headless, is the measuring stick, not the target: matching it is a means
to correctness, and Ghidra is itself sometimes wrong.

The Ghidra decompiler core is already the real C++ engine, so algorithm parity exists. Full Ghidra
differs in the **context** it feeds that engine: function boundaries, prototypes, types, library
names and its Java analyzers. This plan closes that context gap in order of measured payoff, and adds
two goals the parity work does not cover: compilable output and trustworthy flags.

## What "good" means

Four levels of parity with Ghidra, and two goals of their own. For an agent or human reader the first
two parity levels and both goals matter; the last two parity levels are tracked, not optimized.

| Level | Meaning | Matters | Today |
|---|---|---|---|
| P1 availability | native returns text where Ghidra does, without crashing | Yes | 96% to 99% of functions |
| P2 semantic | same callees, arguments, return shape, parameters, strings, flow | Yes | callee names 73% to 89% (held-out 73% and 78%), arguments 97%; 60% to 70% of outputs flagged incomplete |
| P3 structure | same statement skeleton, readable control flow | A little | gotos within 4% to 8% of Ghidra; identical skeleton on 13% to 32% of functions |
| P4 text | byte-identical text | No | 0% to 4% (comments and whitespace ignored) |
| C compilable | output compiles as C, and can be recompiled with a generated header and declarations | Yes (new) | 42% to 50% pass a crude syntax check (see Track C) |
| T trustworthy | when native is unsure it says so; "complete" means right | Yes (new) | flags exist; never audited |

100% parity (P4) is not a target. Ghidra's output depends on its program database and on analyzers
that run to a fixed point and depend on each other. Here each part of that context is rebuilt by a
heuristic. A recompilable result is also a different goal from Ghidra text: Ghidra's own output does not
compile (about a third of it passes the same crude check). Both goals are served by the tracks below.

## Reference and scope

- Reference: full Ghidra, headless, default auto-analysis, decompiler timeout 30 s, version
  12.1.4 (SHA-256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`). The vendored
  engine is the same 12.1.4 source, so the engine version is not a confounder.
- No IDA in this plan.
- Scope: native x86-64 and x86-32 PE (Windows conventions). ELF, Mach-O, other architectures and
  managed code are listed in the platform track. Packed files are a known limit: both Ghidra and native
  decompile the unpacker.
- Output language: C. Ghidra prints C; classes, virtual calls and templates stay C-level
  (pointer arithmetic, vtable loads) until RTTI is recovered (phase 7). "C++-compatible" means the same
  text also compiles as C++, measured as a secondary target.
- Samples are never executed. `tests/testfiles/` and `rules/` are read-only. Compiling decompiled
  text is safe and in scope; running it on the host would run code taken from a sample, which needs an
  explicit decision (see Decisions).
- Python and Java here are development-time tooling and never run in the shipped product.

## Where we are

Three held-out numbers are the ones to quote, because the tuned sets overstate quality by about 11 to
12 points of callee naming (details: [results](decompiler-baseline-results.md)).

| | x64 held-out | x86-32 held-out | x86-32 tuned |
|---|---:|---:|---:|
| Functions compared | 192 | 179 | 188 |
| Native returned text | 191 | 172 | 186 |
| Ghidra's named callees also named by native | 73.0% | 78.4% | 89.2% |
| Argument count agrees | 97.4% | 97.6% | 97.2% |
| Void/non-void agrees | 97.3% | 92.6% | 91.4% |
| Parameter count agrees | 83.2% | 88.6% | 91.9% |
| Flagged incomplete (unknown callee prototypes) | 62.8% (60.7%) | 62.8% (61.6%) | 69.9% (67.7%) |
| Data symbols named | 98.1% | 86.6% | 91.3% |
| Function set: Ghidra has a function at native's address | 96.9% | 87.2% | n/a |

Function-set agreement over every function of 23 x64 and 24 x86-32 samples: recall 93.4% and 88.4%,
precision 97.1% and 85.0%.

## Metrics (the scorecard)

Per selected function, comparing native (N) against full Ghidra (G). Every run reports all three
held-out sets and, where one exists, the tuned set.

| Metric | Meaning |
|---|---|
| availability | N returned pseudocode when G did; N-only and G-only counts |
| errors | N request errors by class (work limit, instruction limit, init) |
| incomplete | share of N outputs flagged incomplete or carrying warnings, and the share caused by unknown callees |
| callee names | share of G's named callees that N names identically (any `<module>_` prefix accepted) |
| call arity | share of matched calls where N and G pass the same number of arguments |
| return shape, params | N and G agree on void versus non-void, and on parameter count |
| data symbols | share of G's data and string symbol addresses that N names, and share of N's names that G agrees with |
| structure | gotos and labels, output lines, N versus G |
| function set | recall and precision of discovered functions against G |
| latency | N request time versus G decompile time, excluding setup |
| P3, P4 | identical token skeleton and identical text, as a share of compared functions (tracked only) |
| compile rate | share of N outputs that pass the compile check (Track C) |
| flag reliability | for a hand-checked sample, share of "complete" outputs that are right (Track S) |

Each differing function is classed by first cause as **context** (missing prototype, type, name or
boundary), **recovery** (function discovery, thunk or tail call) or **engine** (reproduced identically in
G with the same inputs). Only context and recovery items are worked on.

## Completed phases

Detail and numbers are in [the results](decompiler-baseline-results.md); this is the summary.

| Phase | What it did | Result |
|---|---|---|
| 0 Baseline | Seeded, stratified selection from PE headers and Ghidra's list; Ghidra's outputs stored | 23 x64 samples, 184 functions |
| 1 Failure isolation | Enrichment has its own budget and cannot lose the selected function; inferred signatures cached; request order never changes output | request errors 7 to 3 |
| 2 Type and prototype pack | Ghidra's Win32 and C library archives packed (`winapi64.pack`, later `winapi32.pack`) | argument count agreement 87.4% to 98.3% |
| 3 Function boundaries | `.pdata`, code named by data, tail jumps; gated on the native backend | recall 79.6% to 93.4% |
| 4 Library names | Ghidra's Function ID databases packed (`fid-x64.pack`, `fid-x86.pack`) | callee names 56.2% to 75.7% |
| 5 Effects and data flow | Compiler-spec call fixups; parameter-ID variants tried and not adopted | incomplete 80.1% to 70.7% |
| 6a x86-32 PE | Second language, packs, fixups, Function ID hashing, import thunks, tolerant flow errors | callee names 89.2% tuned, 78.4% held-out |
| 7 (part) Data and string symbols | `DAT_`, `PTR_`, `s_`, `u_` names from image bytes, per request | data symbols named 0% to 87% to 98% |
| Held-out benchmarks | x64 and x86-32, functions drawn from native's function set | tuned numbers overstate by 11 to 12 points |

## Gap inventory

One row per cause of a remaining difference, with the size measured so far and the track that owns it.

| Gap | Ghidra does | We do | Size | Track |
|---|---|---|---|---|
| Unknown callee prototypes | infers arguments from callee bodies without limit; applies archive prototypes by name | bounded, strict inference of up to 16 callees, four levels; archive prototypes for imports, thunks, exports, Function ID names | 60% to 70% of outputs flagged; three relaxations were measured in phase 5 and none helped | S2 |
| Function boundaries | fixed-point analyzers, data references, prologue patterns | `.pdata`, data pointers, tail jumps, call targets | recall 88.4% to 93.4%, precision 85.0% to 97.1% | S3 |
| Library and C++ names | Function ID, demangler, file symbols, RTTI | Function ID, simple MSVC names only | callee names 73% to 78% held-out; 14 of 68 x86-32 misses are `FID_conflict` | S1, S5 |
| Short runtime helpers on x86-32 | recognizes `__security_check_cookie` and applies its fixup | not recognized (below Function ID's four-instruction minimum) | 9 of 68 missed callees | S1 |
| Large functions | no work limit (30 s timeout) | 2M work units, 5 s per phase; data-symbol pass falls back when over budget | 5 of 7 x86-32 held-out errors | S4 |
| Speed | decompiles once | decompiles twice when data symbols apply; inference | median 26 ms against 10 ms (x86-32 held-out) | S4 |
| Compilable output | prints pseudocode; does not compile | same, with our type names | 42% to 50% pass a crude check | C |
| Naming layer | `undefined4`, `local_24`, `FindWindowW` | `xunknown4`, `iStack_24`, `kernel32_FindWindowW` | cosmetic, deterministic | R |
| Compilers other than MSVC | per-compiler spec (Delphi register convention, Borland) | Windows spec for all PE32 | not measured | P |
| Types and RTTI | structs from archives, RTTI analyzers | archive types for imports only | not measured | phase 7 |

## Track C: compilable output (new)

Goal: the text of a function, or of a set of functions, can be compiled again as C, with a
generated header and declarations, and the result is a faithful rendering of the function.

| Step | Work | Metric and target |
|---|---|---|
| C1 Measure properly | Replace the crude prelude of `scripts/decompiler_baseline/compile_check.py` with the real header (C2) and report compile rate per set, split by "has unknown callees" and not | baseline recorded; the crude figures are 77 of 185 (42%) x64 and 74 of 149 (50%) x86-32 |
| C2 Header | A generated header: the pseudo-types (`undefinedN`, `xunknownN`, `intN`, `uintN`, `byte`, `code`), the Win32 and C library types the pack describes (from the pack, not by hand), and the Ghidra pseudo-operations as inline functions or macros (`CONCAT`, `SUB`, `ZEXT`, `SEXT`, `CARRY`, `SCARRY`, `SBORROW`, `POPCOUNT`, `LZCOUNT`) | failures from unknown type names (the largest crude cluster) go to zero |
| C3 Self-contained unit | An option on the API and CLI that emits a translation unit for one function or a set: the header, a prototype for every callee (archive, inferred or `extern` with the generic form for `FUN_`), `extern` declarations for each data symbol with size and type, string symbols as arrays with their bytes, and the calling-convention keywords mapped to the compiler (`__fastcall`, `__thiscall`) | a function with all callees known compiles and links against stubs |
| C4 Constructs that cannot compile | List them from the C1 failures, each with a count and a rule: `(*pcRam...)(...)` calls through globals, `UNRECOVERED_JUMPTABLE`, `halt_baddata`, `swi`, register reads (`unaff_EBP`, `in_FS_OFFSET`), `stack0x` addresses, labels `code_r0x...` | each construct either compiles or is rewritten to a marked, compilable form |
| C5 Gate | Compile check on the fixtures in CI, and on the held-out sets in the scorecard; also as C++17 (secondary) | at least 90% for functions without unknown callees; unknown-callee functions reported separately |
| C6 Behaviour check (optional) | For pure, self-contained functions, compile the C and compare with the original code run in the vendored p-code emulator (`emulate.cc`) | an experiment with a measured coverage; not a gate. Host execution is not part of this |

Order: C1 and C2 first, because they are cheap and tell us which of C4 matters. C3 is the step that
makes "recompile extracted functions" possible; it depends on the callee prototypes from Track S.
A recompiled function with unknown callees is only as good as the declarations of those callees, so the
unit marks every guessed prototype.

## Track S: semantic correctness and honest flags

| Step | Work | Metric and stop rule |
|---|---|---|
| S1 Cheap names | x86-32 `__security_check_cookie` and other short helpers (a signature pattern or a rule below the four-instruction minimum, plus its fixup); `FID_conflict` candidates named when every candidate has the same plain name | held-out x86-32 callee names 78.4% to at least 82%; stop if an attempt gains less than a point |
| S2 Unknown callee prototypes | The largest gap. Candidates: apply archive prototypes to more name sources; call-site type propagation; a smarter trial for registers a callee reads against ones it forwards. Phase 5 measured three relaxations and none helped | share of outputs flagged by unknown callees; adopt a variant only if void, params and arity do not regress on all three sets; stop after two failed variants |
| S3 Function boundaries | Measured, not adopted: seeding code pointers from data in x86 executables (recall +0.6, precision -0.5). Next: SEH funclets as parts of their parent, jump stubs and hot-patch prologues folded into other functions (986 in one sample), `.pdata`-like sources for x86 (SEH tables) | held-out function recall and precision at least 92%; stop after two measured attempts that do not move both |
| S4 Large functions and speed | The data-symbol pass analyzes twice and gives up over budget; the five x86-32 work-limit errors; native is 2.5 times Ghidra's median on x86-32 | error rate at most 1% on held-out; median at most 1.5 times Ghidra's; profile first |
| S5 Names outside Visual C | Demangler (a crate, justified per `AGENTS.md`), COFF symbol tables (MinGW), Go and Rust symbol sources | measured on the held-out sets with the MinGW, Nim and Qt samples in them |
| S6 Flag audit | For 50 outputs each from "complete" and "incomplete", read the output against the machine code and record errors (wrong arguments, dropped returns, wrong control flow) | at least 95% of "complete" outputs correct; every missing-argument case flagged. Done by hand; the result is stored with its method |

S6 is the only item that tests whether the flags can be trusted, and it should not wait for the others:
the numbers it produces say which of S1 to S5 changes what a reader sees.

## Track P: platforms and compilers

- **Own files first.** Count formats, architectures and compilers in the files the tool is meant for
  before choosing anything below. Needs a directory from the maintainer. The test corpus is capa's, not
  necessarily the right distribution.
- **Delphi and Borland (x86-32).** Ghidra picks `x86delphi.cspec` or `x86borland.cspec` from the PE and
  uses a register convention (`__register`, arguments in `EAX`, `EDX`, `ECX`); native uses the Windows
  spec for every PE32. First check: run Ghidra and native on a few Delphi samples and compare how Ghidra
  chooses the compiler; then add detection and the two specs.
- **6b to 6f** below: the `Platform` abstraction, then ELF, AArch64, Mach-O and 32-bit ARM or MIPS, only as
  the file count says.
- **Phase 7** below: demangling, RTTI, SEH structure, Go and Rust.

## Track R: parity levels P3 and P4

Tracked on every run and not optimized. The one deliberate step is an optional Ghidra-compatible
naming mode (`undefined4`, `local_24`, no module prefix on imports). It is deterministic, would make the
remaining differences easier to see, and changes the output of everyone who turns it on, so it waits for
a decision.

## Decisions for the maintainer

1. Which files does the tool analyze (formats, compilers, rough share of Delphi, packed, .NET)?
2. Is a 60% to 70% incomplete rate acceptable, or is it the headline problem?
3. Is recompiling decompiled functions a compile-only goal, or must the result run? Running it on the
   host runs code taken from a sample, which `AGENTS.md` rules out for samples; the p-code emulator is the
   alternative.
4. Is an optional Ghidra-compatible naming mode acceptable?
5. Does speed in bulk matter (median 26 ms against Ghidra's 10 ms on x86-32)?

## Corpus composition and consequence

Counted with `file` over `tests/testfiles` (410 entries, capa's test set; recount on any
other corpus before committing to this order):

| Format | Count | Decompiler |
|---|---:|---|
| PE x86-32, native | about 235 (plus 18 .NET, out of scope) | Supported since phase 6a (was rejected) |
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

### 6a. x86-32 PE (done; see the status table)

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

Main risk, now measured: recall starts at 88.4% (94.1% without one sample) against x64's
93.4%, and precision at 85.0% against 97.1%, so the cost is mostly spurious functions.

Steps:

1. Baseline first: select 24 x86-32 samples, export Ghidra references into
   `reference/ghidra-12.1.4-x86/`, measure function-set agreement. No code before this.
   Done ([results](decompiler-baseline-results.md#x86-32-baseline-phase-6a-step-1)): recall 88.4%,
   precision 85.0%, from the existing recovery with no x86-32 work.
2. `from_pe` accepts PE32 and selects language and specs by machine type. Done.
3. `winapi32.pack` and the 32-bit effect table. Done.
4. Function ID pack. Done. Further discovery sources: one tried and not adopted; the rest not done.
5. Full scorecard plus the capa difftest loops; the capability path stays byte-identical. The scorecard is done;
   the difftest loops were not run, because the capability path was not touched (`features_parity` passes).

Exit: 0 initialization errors on non-packed native PE32; function recall at or above 90%;
callee-name coverage, argument-count and void/non-void agreement within 10 points of the
x64 numbers. Result: met except recall (88.4%; 94.1% without one sample). Effort: large; steps 1 and 2 are small, the pack, Function ID and discovery
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
| 7 | Held-out benchmark | Done ([results](decompiler-baseline-results.md#held-out-benchmark)): callee naming 65.5% against 77.5% on the tuned set, robustness and structure generalize |
| 8 | Phase 6a, x86-32 PE | Done, one exit criterion missed ([results](decompiler-baseline-results.md#x86-32-decompiler-phase-6a)): decompiles PE32; callee names 89.2%, void 91.4%, params 91.9%, arity 97.2%; 99.7% of 2,229 random functions decompile; function recall 88.4% (target 90%) |
| 9 | Phase 7, string and data symbols | Done ([results](decompiler-baseline-results.md#data-and-string-symbol-naming)): data symbols named 0% to 90% (baseline) and 98% (held-out), 94% to 96% of native's names agree with Ghidra's; string literals 36% to 88% of Ghidra's on the held-out set; about 30% more request time. |
| 10 | x86-32 held-out benchmark | Done ([results](decompiler-baseline-results.md#x86-32-held-out-benchmark)): callee naming 78.4% against 89.2% on the tuned set; 12.8% of native's functions are not functions in Ghidra; 7 errors in 179 |
| 11 | C1, C2: compile check with a real header | Next. Cheap, and it says which compile failures matter |
| 12 | S1: x86-32 cookie helper, `FID_conflict` names | Next. 23 of 68 missed callees on the x86-32 held-out set |
| 13 | S6: flag audit by hand | Next. Decides how much to trust everything else; does not depend on the other steps |
| 14 | C3, C4: self-contained unit and non-compilable constructs | After 11 and 13. The step that makes recompiling extracted functions possible |
| 15 | S4: large functions, speed | After 12. Five of seven x86-32 held-out errors; median 2.5 times Ghidra's |
| 16 | S3: function boundaries | After 15. Recall 88.4% and precision 85.0% on x86-32 |
| 17 | S2: unknown callee prototypes | The largest gap and the hardest; start with the measurements of 11 and 13 |
| 18 | Own files, then Delphi/Borland or ELF | Needs a directory from the maintainer; decides the platform track |
| 19 | S5 names outside Visual C, phase 6b `Platform` extraction | After 17 and 18 |
| 20 | C5, C6, Track R, phases 6c to 6f and the rest of phase 7 | Only if the scorecard or the corpus asks |

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

The compile check (crude, see Track C) is `scripts/decompiler_baseline/compile_check.py LABEL COMPARISON.json`.

See `scripts/decompiler_baseline/README.md` for the exact commands, and
`docs/decompiler-baseline-results.md` for the recorded results.
