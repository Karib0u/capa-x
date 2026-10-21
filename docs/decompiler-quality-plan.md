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

- Replace the 54-signature subset with a compact, lazily loaded index of Ghidra
  Function ID and FLIRT data converted offline. Loading everything cost about
  638 MiB, so hash-bucketed lookup is required.
- Gain: named CRT, STL and static library functions, and correct noreturn and
  calling-convention flags.

## Phase 5: targeted data-flow and cosmetic items

Driven strictly by the baseline clusters.

- A table of known effect models (RAX-preserving helpers, `__chkstk`,
  `__GSHandlerCheck`), extending the security-cookie mechanism.
- Parameter identification from call sites as well as callee bodies.
- Stack-argument and shadow-space handling in unusual patterns.

## Phase 6: platforms

After the Windows pipeline is solid, extract a `Platform` trait (compiler spec,
prototype table, thunk rules, loader). ELF x86-64 first, then AArch64, then
Mach-O.

## Phase 7: long tail, only if the scorecard justifies it

C++ RTTI and vtables, SEH structure, Go and Rust runtime awareness, PDB and DWARF
types, wider jump-table coverage.

## Order and status

Order by payoff per effort and dependency, not by phase number:

| Step | Phase | Status |
|---|---|---|
| 1 | Phase 0, baseline | Done ([results](decompiler-baseline-results.md)) |
| 2 | Phase 2, type and prototype pack | Done, with known leftovers (see results) |
| 3 | Phase 1, failure isolation | Done (`00143de`): request errors 7 to 3 on the baseline, session no longer poisoned by limits; 3 work-limit errors remain |
| 4 | Phase 4, library names (Function ID) | In progress; largest remaining gap (56% callee names) |
| 5 | Phase 3, boundaries, thunks, tail calls | Touches shared recovery code: run the difftest loops |
| 6 | Phase 5, cosmetics and data-flow | Cheap items early, the rest only from baseline clusters |
| 7 | Phases 6 and 7 | Only after the Windows pipeline is solid, and if the scorecard asks |

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
| CallFixupAnalyzer | Known helper effects such as the security cookie; already partly hand-modeled (phase 5) |
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
| Call fixups and p-code injection in the compiler spec (6 `callfixup` entries in `x86-64-win.cspec`) | Helpers such as `__security_check_cookie` and `__chkstk` replaced by injected p-code. Once phase 4 names the helper, the vendored spec's fixups can replace the hand-written RAX-preservation hack and cover more helpers | Phase 5, depends on phase 4 |
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
