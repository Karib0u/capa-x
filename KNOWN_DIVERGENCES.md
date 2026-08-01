# Known divergences vs Python capa

Every result difference between capa-x and the pinned Python capa
(`flare-capa` 9.4.0 + the vivisect it pins, see [`PINNED.md`](PINNED.md)) that
is **accepted rather than fixed**, one entry per *class* of difference.

## Why a document like this is the right answer

Documented divergence is upstream's own model for a backend, not a concession
this port invented. capa ships vivisect, IDA, idalib, Ghidra, Binary Ninja,
BinExport and dotnetfile backends, and nothing in its test suite compares any
two backends' capability output. Each is checked against hand-maintained
expectation tables, and where a backend genuinely disagrees, upstream *encodes
the disagreement*:

- `reference/capa/tests/fixtures.py:1540` — a separate `FEATURE_COUNT_TESTS_GHIDRA`
  table, carrying the comment that Ghidra "may render functions as labels, as
  well as provide differing amounts of call references". Three rows that
  contradict the vivisect table, kept side by side with it.
- `xfail:` expectation strings in the BinExport, idalib, Ghidra, dotnetfile and
  pefile tables (e.g. `"xfail: not implemented yet"`, `"xfail: name demangling
  is not implemented"`).

capa-x is a new backend and is held to the existing non-regression floor.
Every measured difference must map to an entry here; that requirement is part
of this project's release contract.

## Rules for an entry

1. **Name a root cause, not a symptom.** "Recovery differs" is not a root
   cause. An entry that cannot name one is a bug nobody has investigated yet,
   and it does not satisfy this requirement.
2. **One entry per class, not per sample.** Samples are evidence; list them.
3. **Cite the upstream mechanism** — the pinned Python/vivisect file and
   function whose behaviour we are not reproducing. Port-from-source rules
   apply here too (`AGENTS.md`): read it, don't recall it.
4. **`our-bug` is not a divergence.** If capa-x is simply wrong, fix it.
5. **State the direction** (do we report more, or fewer, matches) and the
   affected rules — a reader triaging a new diff needs to recognise the class.

## Schema

```markdown
### KD-00N — <short name of the class>

- **Class:** recovery / function extent | feature extraction | matching | loader
- **Direction:** capa-x reports fewer | more matches
- **Affects:** `rule name`, `rule name` (+N rules)
- **Samples:** <sha or filename> (0xADDR), <sha> (+N more)
- **Root cause:** <the mechanism, naming the pinned upstream file>
- **Upstream analogue:** <the comparable backend divergence upstream accepts>
- **Status:** accepted | tracked in the divergence record
```

## Entries

### KD-001 — FLIRT-recognized library functions are dropped, not flagged

- **Class:** feature extraction / matching scope
- **Direction:** capa-x reports fewer features at function scope
- **Affects:** no capa rule; visible only to the transcribed fixture table
- **Samples:** the `features_parity.rs` rows reported at the end of
  `feature_presence_matches_upstream_viv_expectations` (a run prints the
  current list; it is small and sample-dependent)
- **Root cause:** upstream separates extraction from matching — the raw
  extractor still yields a library function's own body, and only the matching
  layer skips it (`reference/capa/capa/capabilities/static.py:179`,
  `if extractor.is_library_function(f.address)`). capa-x reaches the same
  matching behaviour earlier, by never adding the function to
  `StaticFeatures.functions`
  (`capa-x/src/extract/recovery/flirt.rs:333`, `enrich_static_features`), so its body
  is not extractable at function scope at all. Freeze-driven input is
  unaffected and exactly matches upstream: no FLIRT backend exists there, and
  `NullStaticFeatureExtractor.is_library_function` never overrides the `False`
  default (see `capa-x/src/capabilities/static_analysis.rs:175`).
- **Upstream analogue:** `FEATURE_COUNT_TESTS_GHIDRA` — a backend whose
  function model differs is given its own expectations rather than being made
  to match vivisect's.
- **Status:** accepted. Equivalent for every result-level metric: real
  capa rules do not target a library thunk's own address, and matched-rule sets
  are unaffected. Revisit only if a rule ever needs library-function scope.

### KD-002 — function starts discovered by emulating unreferenced addresses

- **Class:** recovery / function extent
- **Direction:** capa-x reports fewer matches
- **Affects:** `encrypt data using RC4 PRGA`, `resolve function by parsing PE
  exports`, `enumerate PE sections`, `PEB access`, `shutdown system`,
  `open clipboard`, `set application hook`, `get keyboard layout` (+9 rules
  across the samples below)
- **Samples:** `a70052c45e907820187c7e6bcdc7ecca.exe_` (all 7 of its diffs),
  `70fd3347786ed7a4a43910e6778ef296.exe_` (3 of 4 missing),
  `112f9f0e8d349858a80dd8c14190e620.exe_` (4 of 6),
  `294b8db1…477bc.elf_` (2 of 4)
- **Root cause:** `vivisect/analysis/generic/emucode.py` takes every named or
  pointer-referenced address with no location yet, *emulates* from it
  (`emu.runFunction(va, maxhit=1)`), and makes a function when the trace looks
  like code — `watcher.looksgood()`: it reached a `ret`, raised no anomaly, and
  no single mnemonic is ≥67% of the trace. Nothing about that verdict is
  derivable from the byte pattern; it is the emulator's judgement of a run.
  Attributing every reference function to the analysis module that created it
  (snapshotting `vw.getFunctions()` between `amodlist` entries) puts 113 of
  `a70052c4`'s 123 unrecovered roots and 93 of `70fd3347`'s 98 in this module.
- **Upstream analogue:** `FEATURE_COUNT_TESTS_GHIDRA`'s comment that Ghidra
  "may render functions as labels" — a backend whose function set is built by a
  different method gets its own expectations.
- **Status:** accepted. `emucode.py`-discovered code is not reachable
  without porting an emulator, which is a separate project with its own
  justification.

### KD-003 — pointer targets classified as code by emulation

- **Class:** recovery / function extent
- **Direction:** both — capa-x reports fewer matches where upstream accepts
  a target, and more where upstream rejects one
- **Affects:** `decrypt data using AES via x86 extensions`,
  `parse credit card information`, `manually build AES constants`,
  `hook routines via dlsym RTLD_NEXT`, `link function at runtime on Linux`,
  `map or unmap memory on Linux`, `change memory permission on Linux` (+5 rules)
- **Samples:** `2f7f5fb5de175e770d7eae87666f9831.elf_` (1192 of its 1825
  unrecovered roots), `749cf36a…22c2.elf_` (11 rust-only functions, all 6 of
  its diffs), `294b8db1…477bc.elf_` (25 roots)
- **Root cause:** `generic/pointers.py` and `generic/pointertables.py` reach
  `makeFunction` only through `VivWorkspace.analyzePointer`
  (`vivisect/__init__.py:1997-2013`), whose decision is
  `isProbablyCode` — an entry-signature check *followed by the same emulation
  `emucode.watcher` performs* (`vivisect/__init__.py:1136-1161`). capa-x's
  stand-in is `plausible_relocation_function`'s decoded-mnemonic whitelist
  (`capa-x/src/extract/recovery/recovery.rs`), which is neither a superset nor a
  subset of that verdict, so the class diverges in both directions.
  `analyzePointer` also opens with `if self.getLocation(va) is not None:
  return None`; on `749cf36a` the reference reaches all 11 contested addresses
  as ordinary instructions inside functions `0x2003350`/`0x20043b0`, where
  capa-x's flow leaves gaps (316 instructions against 369 over the identical
  address range) and its relocation seeds then re-enter those gaps as separate
  functions.
- **Upstream analogue:** same as KD-002.
- **Status:** accepted, and re-confirmed by later measurement. The "closing
  the intra-function flow gaps removes the more-matches direction" hope this
  entry carried was **measured and refuted**: the gap-driven extras are
  not flow gaps but capa-x's own heuristic seeds (now KD-005),
  and `e17e6a79`'s pair is reachable only through data pointers this entry's
  own mechanism classifies.
- **More evidence.** The same mechanism also owns 10 of the 21 reference
  functions behind a measured set of missing rules, in the
  *fewer-matches* direction: `b5f0524e…a87.elf_` — all 3 of its diffs
  (`get file attributes`, `move file`, `set socket configuration`), functions
  `0x80724b0`, `0x807d2a0` via `generic/pointers.py:analyze` and `0x80a3d80`,
  `0x80a5860`, `0x80a2ad0`, `0x80a3120`, `0x808dd30` via
  `generic/pointertables.py:handleArray` — and `49a34cfb…bb6.exe_`
  (`contain obfuscated stackstrings`, `hash data with MD5`, one location of
  `parse credit card information`), functions `0x61c740`, `0x619500`,
  `0x52e3f0`, reached from `vivisect/base.py:_cb_opcode` →
  `guessDataPointer` → `followPointer`. `isFunctionSignature` is `False` at all
  of them, so the entry-signature half of `isProbablyCode` — the half v1 ported,
  measured and reverted — would not recover any of them either.

### KD-004 — the reference cannot name imports behind `R_X86_64_PC32` relocations

- **Class:** loader (reference-side)
- **Direction:** capa-x reports **more** matches — and is the correct side
- **Affects:** `change memory permission on Linux`, `create or open file`,
  `hook routines via dlsym RTLD_NEXT`, `link function at runtime on Linux`,
  `map or unmap memory on Linux`, `write file on Linux`
- **Samples:** `749cf36a…22c2.elf_` — all 6 of its diffs, at `0x2002629`,
  `0x2002647`, `0x200274f`, `0x2002d87`, `0x2003ac0`, `0x2003cb0`, `0x2003e10`,
  `0x2003fc0`, `0x2004070`, `0x2004235` (+ more of the same call sites)
- **Root cause:** `vivisect/parsers/elf.py:857-861`. For a *named* relocation
  whose type is not one of `R_386_JMP_SLOT` / `R_X86_64_GLOB_DAT` /
  `R_X86_64_IRELATIVE` / `R_386_COPY` / `R_386_32`, the loader logs
  `unknown reloc type` and falls through to `vw.makeName(rlva, dmglname)` —
  it names the slot but never calls `vw.makeImport`. On this sample the
  unhandled type is `2` (`R_X86_64_PC32`) and it covers exactly `fopen`,
  `fwrite`, `fputc`, `vfprintf`, `mmap`, `munmap`, `mprotect` and `dlsym`,
  which is precisely the symbol set the six rules above need. With no import,
  capa's viv extractor yields **no `api:` feature at all** in the three
  contested functions (verified directly against
  `VivisectFeatureExtractor.extract_insn_features`), so the reference cannot
  match. capa-x applies the relocations and matches. This is not
  FLIRT-related: `viv_utils.flirt.is_library_function` is `False` at every one
  of these addresses.
- **Upstream analogue:** the `xfail:` rows in the BinExport/idalib tables —
  a backend that resolves something the reference does not is given its own
  expectation rather than being made to under-report to match.
- **Status:** accepted, permanently. Fixing this would mean making
  capa-x *worse*. Recorded so the six extras are never counted against a
  precision gate.

### KD-005 — heuristic seed classes capa-x has and Vivisect does not

- **Class:** recovery / function extent
- **Direction:** capa-x reports **more** matches
- **Affects:** `allocate memory`, `allocate or change RW memory`,
  `connect to URL` (via `create HTTP request`), `contain loop`,
  `create UDP socket`, `delay execution`, `encrypt data using Salsa20 or
  ChaCha`, `enumerate PE sections`, `get current process memory mapping on
  Linux`, `PEB access`, `resolve function by parsing PE exports`,
  `set file attributes` (12 rules)
- **Samples:** by seed class — `SweepCallTarget`: `70fd3347…` (fn `0x407f10`),
  `82bf6347…` (`0x1400589ec`, `0x14005981a`), `9324d1a8…` (`0x407b60`),
  `971e599e…` (`0x44647f`); `Prologue`: `34dbc85e…elf_` (`0x4023b4`,
  `0x401eb7`), `a6e9d94e…elf_` (fn `0x200ad6b`); `Relocation`:
  `35f9cfe5…dll_` (fn `0x10002b30`), `a6594d95…exe_` (`0x140018e60`),
  `e5e8c139…elf_` (`0x2004b30`)
- **Root cause:** these matches sit in code the pinned workspace has no
  location for at all (`vw.getLocation(va) is None`; measured by
  `scripts/triage/attribute_extras.py`). capa-x reaches it from three seed sources
  with no Vivisect analogue: the raw `e8 <rel32>` byte sweep
  (`add_swept_call_seeds`, `capa-x/src/extract/recovery/recovery.rs`), the entry
  byte-pattern scan (`add_prologue_seeds`), and relocation-target candidates.
  Vivisect discovers functions by codeflow, emulation, and a prologue scan
  restricted to *still-undefined* space (`vivisect/analysis/generic/
  funcentries.py`); it never sweeps raw bytes for call encodings.
- **Upstream analogue:** `FEATURE_COUNT_TESTS_GHIDRA`'s "may render functions
  as labels, as well as provide differing amounts of call references" — a
  backend with a different function-discovery model gets its own expectations.
- **Status:** accepted, as a **measured trade**, not an assumption.
  Dropping the sweep in compatibility mode was measured on the full corpus:
  extras 37 → 30, but missing 62 → 73 and agreement 98.42% → 98.36%, with the
  `> 5-rule` sample count going 3 → 4. A variant requiring ≥ 2 distinct call
  sites to agree on a target was also behind the baseline. Both reverted; the
  heuristics buy more recall than the precision they cost. See
  KD-005.

### KD-006 — indirect jump targets recovered by emulating the switch table

- **Class:** recovery / function extent
- **Direction:** capa-x reports fewer matches
- **Affects:** `compute adler32 checksum`, `hash data with CRC32`,
  `resolve function by parsing PE exports`, `log keystrokes via Input Method
  Manager`
- **Samples:** `276f691a3df25481f59d79781799e35f.exe_` — all 3 of its diffs.
  Functions `0x14002f8d0` and `0x140030300`, plus the unwalked tail of
  `0x14002d780`, of which capa-x recovers 63 of the reference's 1,559
  instructions. Also `f5903519…c58.exe_` (fn `0x140079a90`), added by a
  corpus-wide re-run: capa-x recovers 84 of the reference's 287 basic
  blocks there, and **none** of the 203 it lacks has a static predecessor in
  the reference's own graph — they are switch arms reached only through the
  emulated table, the same mechanism as `276f691a`
- **Root cause:** both sides decode the same basic block and stop at the same
  instruction — the indirect `jmp` at `0x14002d83d`, which has no static
  branch target. The reference gets past it only through
  `vivisect/analysis/generic/switchcase.py:analyzeJmp`, registered as a
  *dynamic branch handler* on the workspace emulator's monitor
  (`vivisect/analysis/amd64/emulation.py:18`,
  `self.addDynamicBranchHandler(vag_switch.analyzeJmp)`) and therefore called
  from `prehook` while the function is being emulated. `getSwitchBase` walks
  back from the `jmp` for the `add`/`mov` pair that builds the target,
  evaluating operands *through the live emulator* (`addOp.getOperValue(1, emu)`)
  to check the base against the image base; on success `analyzeJmp` calls
  `makeJumpTable` and `makeCode`s every arm. The whole path is emulation:
  without an emulator there is no operand value to test, so capa-x's flow
  ends at the `jmp` and the 1,496 instructions of switch arms -- and the two
  functions called from them -- are never reached. `symswitchcase` is a named
  non-goal for the emulator-free backend.
- **Upstream analogue:** the `xfail:` rows in the idalib/BinExport tables — a
  backend without the reference's jump-table resolution is given its own
  expectation rather than being expected to match it.
- **Status:** accepted, downstream of the emulator decision. Measured
  by `scripts/triage/attribute_missing.py`.

### KD-007 — function starts created by the workspace emulator's call monitor

- **Class:** recovery / function extent
- **Direction:** capa-x reports fewer matches
- **Affects:** `calculate modulo 256 via x86 assembly`,
  `encrypt data using RC4 PRGA`, `use io_uring IO interface on Linux`, and one
  of the two upstream locations of `parse credit card information` on
  `49a34cfb` (the other is KD-003, so that rule belongs to both classes)
- **Samples:** `512a5575…c92.elf_` (all 3 of its diffs; functions `0x40b380`,
  `0x40e080`, `0x404c47`, `0x404e8f`, `0x4052ac`, `0x40556d`),
  `49a34cfb…bb6.exe_` (2 of its 4; functions `0x599940`, `0x5ff610`)
- **Root cause:** `vivisect/impemu/monitor.py`. Two hooks on the workspace
  emulator create functions that no static flow reaches:
  `AnalysisMonitor.apicall` (line 159) types each argument of an emulated call
  against the `impapi` tables and calls `vw.makeFunction(arg)` for any pointer
  argument the table names `funcptr`; `addAnalysisResults` (line 72) replays
  the operand dereferences the run evaluated and calls
  `vw.guessDataPointer(val, tsize)` on the discrete ones, which reaches
  `makeFunction` through the same `analyzePointer` → `isProbablyCode` path as
  KD-003. Both depend on values that exist only during emulation, and `apicall`
  additionally depends on the ~11.5k lines of `impapi` type tables
  (the emulator decision). Measured during metadata parity work: none of these eight
  functions is reachable by a call chain from any function capa-x recovers,
  and `isFunctionSignature` is `False` at every one, so neither codeflow nor
  `isProbablyCode`'s emulator-free half offers a way in.
- **Upstream analogue:** same as KD-002 — a backend whose function set is built
  by a different method gets its own expectations.
- **Status:** accepted, downstream of the emulator decision.

### KD-008 — code the reference decodes but never wraps in a function

- **Class:** matching scope (reference-side), reached through recovery
- **Direction:** capa-x reports **more** matches
- **Affects:** `connect to URL`, `contain loop` (×2 samples), `create
  directory`, `delete directory`, `delete registry key`, `decode data using
  Base64 via VBMI lookup table`, `enumerate files on Windows`, `enumerate files
  recursively` (9 extras)
- **Samples:** two shapes of the same cause. The address capa-x matched at
  is itself unowned — `9324d1a8…exe_` (`0x407c43`), `c2d46d25…exe_`
  (`0x14004a300` +4 more); or the *function start* is shared and capa-x
  keeps walking into unowned code — `1e9fc7f3…exe_` (fn `0x4028d2`, +19
  insns from `0x402940`), `31600ad0…exe_` (fn `0x401155`, +9 from `0x4011c7`),
  `50d5ee1c…exe_` (fns `0x402c2f`, `0x402d0e`; +18 and +64),
  `a563c50c…exe_` (fn `0x401490`, +95 from `0x4015cc`),
  `f53dfa29…exe_` (fn `0x1400083a0`, +57 from `0x14000842e`)
- **Root cause:** capa's viv extractor enumerates work by
  `vw.getFunctions()` (`capa/features/extractors/viv/extractor.py`'s
  `get_functions`), so a location the workspace holds *without* an owning
  function is decoded, named and cross-referenced upstream but never offered
  to the matcher at any scope. Vivisect creates such locations routinely:
  `vivisect/analysis/i386/importcalls.py` calls `makeCode` on the code around
  an import call without `makeFunction`, and codeflow's own `_cb_opcode`
  defines opcode locations before the codeblocks pass assigns them. Checked
  directly on `31600ad0`, `1e9fc7f3` and `a563c50c`: every instruction in the
  contested range has `vw.getLocation(va) is not None` and
  `vw.getFunction(va) is None`. capa-x has no equivalent notion — every
  instruction it decodes belongs to some function — so the same bytes are in
  scope for it and out of scope upstream. Measured by
  `scripts/triage/attribute_shared_extras.py` (`no reference function` and
  `walks past the reference`).
- **Upstream analogue:** `FEATURE_COUNT_TESTS_GHIDRA`'s note that Ghidra "may
  render functions as labels" — the same disagreement about what counts as a
  function, in the other direction.
- **Status:** accepted. Closing it means reproducing the reference's
  *location* model, not its codeflow: the bytes are recovered correctly on both
  sides, and the only difference is whether they sit inside a `makeFunction`
  boundary. That is a workspace-model project, not a codeflow fix. The correct
  first step is a Vivisect **workspace**.

### KD-009 — PE section names: the workspace's segment model, not pefile's

- **Class:** loader
- **Direction:** capa-x reports **more** matches
- **Affects:** `packed with Themida`, `(internal) packer file limitation`
- **Samples:** `2826b762…ba2.exe_` — both of its diffs, at sections `0x401000`
  and `0x46d000`
- **Root cause:** upstream's two backends disagree, and capa-x can only
  match one. `vivisect/parsers/pe.py:296` builds a segment name with
  `sec.Name.strip("\x00")`, which strips NULs from the *ends* only and keeps
  embedded ones, and `capa/features/extractors/viv/file.py:101` yields those
  segment names verbatim; `capa/features/extractors/pefile.py:103` instead
  takes `section.Name.partition(b"\x00")[0]`. On this sample the first section's
  raw 8-byte name is `"   \x00    "`, so the viv backend yields
  `section("   \x00    ")` and the pefile backend `section("   ")`. The rule
  needs `section("   ")` **and** `section("        ")`; the second matches on
  both sides, the first only on the pefile model. capa-x follows pefile,
  which is what the file-features gate compares it against
  (`scripts/difftest.py --mode file-features`), so it matches and the `--mode
  full` reference does not. The same split explains why the reference's segment
  list also carries a `PE_Header` segment capa-x has no section for
  (`pe.py`'s `vw.addSegment(baseaddr, len(header), "PE_Header", fname)`).
- **Upstream analogue:** this *is* the upstream analogue — two capa backends
  with different expectations for the same file feature, which is exactly what
  `FEATURE_COUNT_TESTS_GHIDRA` and the `xfail:` tables exist to record.
- **Status:** accepted. Switching to the viv model would break the
  file-features gate in the same measurement it fixed this one; the two cannot both be
  satisfied by a single extractor, and no gate ranks them.

### KD-010 — function extents split or merged inside shared code

- **Class:** recovery / function extent
- **Direction:** capa-x reports **more** matches
- **Affects:** `execute shellcode via indirect call`, `link function at runtime
  on Windows` (2 extras; the two on `e17e6a79` with the same shape are KD-003
  and the three on `749cf36a` are KD-004, both of which name their own cause)
- **Samples:** `29a76e41…exe_` — capa-x's `0x1400e1300` owns 329
  instructions the reference splits across `0x1400e1360`, `0x1400e14d0` and
  `0x1400e1870`; `3fdfb2d5…exe_` — capa-x starts a function at `0x4146a9`,
  which the reference holds inside `0x41467e`
- **Root cause:** both sides decode the same bytes and disagree only about
  where one function ends and the next begins, which changes what a
  function-scope rule can accumulate: a merged extent lets an `N or more`
  clause count features upstream keeps in separate units, and a split start
  gives a rule a smaller unit that upstream never evaluates on its own. The
  boundaries come from different machinery — upstream's from `makeFunction`
  calls issued by analysis modules over a workspace, capa-x's from its seed
  set plus codeflow — so neither is derivable from the other without the
  workspace model KD-008 also asks for. Measured by
  `scripts/triage/attribute_shared_extras.py` (`merged extent`,
  `reference mid-function`).
- **Upstream analogue:** `FEATURE_COUNT_TESTS_GHIDRA` — a backend whose
  function boundaries differ gets its own expectations.
- **Status:** accepted. Tracked as exact-address work, which is where
  boundary parity belongs; it is not a release gate.

### KD-011 — `.rsrc`-hosted code is not analysed

- **Class:** loader
- **Direction:** capa-x reports fewer matches
- **Affects:** `contain loop`, `packed with generic packer`
- **Samples:** `0cd2b334…cde3.exe_` — both of its diffs. The packer gives the
  file two `.y0da` sections and points the resource directory at the second
  (RVA `0xe6000`), which also holds the code the entry stub jumps to at
  `0x531cb3`
- **Root cause:** `vivisect/parsers/pe.py:267-268` skips a readable section
  whose RVA equals the resource directory's, but only when
  `viv.parsers.pe.loadresources` is false — and the pinned reference never sees
  that default, because capa reaches the loader through
  `viv_utils.getWorkspace`, which sets `loadresources = True`
  (`viv_utils/__init__.py:101`). Upstream therefore maps the section and
  recovers the code in it; capa-x skips it and its flow stops at the
  `jmp 0x531cb3` in the entry stub.
- **Upstream analogue:** none — capa-x is behind the reference here, and
  this entry records a *measured trade* rather than a model difference.
- **Status:** accepted as a deliberate trade, with the measurement.
  Mapping the section has now been implemented and measured **twice**, and the
  blocker moved between the two attempts. The `viv_utils` override of `nx`
  (`viv_utils/__init__.py:102`) was ported alongside the first attempt and
  **kept**, since it is result-neutral on the corpus and verifiably right — the
  pinned workspace maps `Practical Malware Analysis Lab 03-02.dll_`'s `.data`
  as `MM_READ|MM_WRITE`, with no `MM_EXEC`.

**First attempt.** Mapping the section sent recovery past its
200,000-instruction per-walk limit and turned a sample that under-reports by 2
rules into one that fails to analyse at all (`error: recovering PE code:
recovery limit exceeded`). Reverted, with the note that the blocker was the
limit rather than the loader.

**The limit is fixed, and it was not the real blocker.**
`recover_functions` no longer fails an image on a budget: a walk past
`MAX_INSNS_PER_FUNCTION` is abandoned with a diagnostic, the way
`vivisect/analysis/i386/importcalls.py`'s wave always has been. That change is
result-neutral on the corpus (92 diffs, 160/200 identical, reproduced exactly),
and it removes the hard error this entry was reopened against.

**Second attempt, with the limit fixed.** The sample now analyses, and the
result is still not takeable — for a different and better-understood reason:

| | missing | extra | diffs |
|---|---:|---:|---:|
| section skipped (shipped) | 2 | 0 | 2 |
| section mapped | 1 | 1 | 2 |

Corpus-wide the diff count is unchanged at 92 and no other sample moves; the
composition goes 62/30 → 61/31. `contain loop` is recovered, and
`contain pusha popa sequence` is **invented**. The rule needs
`count(mnemonic(pusha)): 2 or more` *within one function*, and capa-x's walk
from the entry runs through the `jmp 0x531cb3` and merges the entry stub's
`pusha` at `0x401000` with the resource-hosted one at `0x531cb3` — 200,000
instructions and two sections apart — into a single function extent. Upstream
does not: `scripts/triage/attribute_shared_extras.py` reports
`walks past the reference`, with 199,978 instructions in capa-x's function
belonging to no reference function at all, starting at `0x402fbe`.

So the loader is faithful and the *extent* is wrong, which makes this KD-010's
mechanism reached through a loader change rather than a loader divergence of
its own. Trading a missing rule for an invented one is the wrong direction
under the emulator-free backend contract, so the skip stays. **Reopen with
function-extent containment, not with the loader and no
longer with the limit:** the section is correct to map once capa-x stops
absorbing everything reachable from the entry into one function.

### KD-012 — no-return propagation costs two rules it does not buy back

- **Class:** recovery / function extent
- **Direction:** capa-x reports fewer matches
- **Affects:** `get OS version`, `PEB access`, `calculate modulo 256 via x86
  assembly`, `generate random numbers using a Mersenne Twister` (4 rules)
- **Samples:** `70fd3347…exe_` — fn `0x405ce4`, called from `0x4065b8`, which
  capa-x has, and fn `0x407e2c`, which capa-x marks no-return and walks
  22 of the reference's 31 instructions of; `749cf36a…elf_` — fn `0x200a4b0`,
  reached from `0x2002326` through six intermediate calls; `2f7f5fb5…elf_` —
  fn `0x406e90`, which capa-x marks no-return after 4 of 27 instructions
- **Root cause:** the *priced-in cost* of porting
  `vivisect/analysis/generic/noret.py` faithfully. Upstream sets `hasret` only
  for a leaf block ending in `IF_RET` or an unresolved `IF_BRANCH`; every other
  terminator — including a block that stops because the next bytes do not
  decode — leaves it false and marks the function no-return, which deletes the
  fallthrough at every call to it. capa-x used to treat a decode-cut leaf as
  returning, on the theory that propagating from its own recovery gap would
  truncate callers. Measured on the full corpus, the faithful rule is better by
  a clear margin (extras 34 → 30, missing 62 → 63, samples identical 159 →
  160), but it is not free: where capa-x's decode gap is *not* upstream's,
  the function is marked no-return and every call to it loses its fallthrough,
  and these four rules are what that costs.
- **Upstream analogue:** none needed — the rule now matches upstream exactly.
  What diverges is the input to it, which is KD-008's location model.
- **Status:** accepted as a measured trade; the full-corpus numbers are
  recorded in `docs/BENCHMARKS.md`. Revisit only together with the decode
  gaps themselves, never by re-introducing the deviation -- that was measured
  and is worse.

### KD-013 — AArch64 switch/jump-table dispatch is not resolved

- **Class:** recovery / function extent
- **Direction:** capa-x reports fewer matches
- **Affects:** `terminate process`
- **Samples:** `687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf_`
  — 1 of 1 diff on this sample, and the only J9 divergence across the 3-sample
  pinned AArch64 BinExport2 corpus
- **Root cause:** the function's dispatch is the standard AAPCS64
  `adrp`/`add`/`ldrsw`/`add`/`br` sequence (a PC-relative table load into an
  indirect branch). Ghidra resolves the arm count and every arm's target from
  a bounds check it recovers ahead of the `br` — a static analysis, not
  emulation, but one this port does not yet perform; capa-x's recovery
  stops at the `br` with no static `direct_target`, the same shape as
  KD-006's x86 switch case but reached by ISA-native structural analysis on
  the reference side instead of vivisect's emulated `analyzeJmp`. The call to
  the process-termination API lives in one of the unrecovered arms.
- **Upstream analogue:** the `xfail:` rows in the BinExport/idalib tables — a
  backend without the reference's jump-table resolution is given its own
  expectation rather than being expected to match it, the same posture KD-006
  documents for vivisect's switch-case emulation.
- **Status:** accepted; measured and root-caused during AArch64 acceptance.
  Reopen only with a static jump-table bounds analysis for the AAPCS64 dispatch
  pattern, not with a byte-pattern special case for this one sample.
