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
  timeout 30 s. Installed version 12.1.4 (SHA-256
  `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`).
  The vendored engine is 11.4.2. The version difference is a known confounder:
  a diff that looks like an engine change is checked against 11.4.2 before it is
  treated as a context gap.
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
