# Known divergences vs Python capa

Every result difference between capa-x and the pinned Python capa
(`flare-capa` and Vivisect versions in [`PINNED.md`](PINNED.md)),
one entry per *class* of difference. Resolved entries retain their IDs and
historical causes so earlier measurements remain interpretable.

## Current measured remainder

The latest 2026-10-20 run covers all 377 native x86/x64 and shellcode inputs.
Original capa rejects one malformed ELF. All 376 comparable inputs have
identical rule-name sets: 11,412 reference rule/sample matches, zero missing,
and zero extra. Exact rule and match-address sets agree on 326 inputs and
differ on 50, improved from 321 on the freshly measured preceding PR commit.
The extra `contain anti-disasm techniques` and `contain pusha popa sequence`
regressions described in KD-025 are resolved.
Match-location and evidence-tree compatibility are not complete.

The [match-address report](docs/validation/match-address-followup-2026-10-20.md)
records the fixes and links every remaining address difference. The
[earlier full validation](docs/validation/full-corpus-2026-10-20.md) and
[complete reference outputs](tests/reference-results/capa-10.0.0/README.md)
remain unchanged. The remaining address cases need further investigation;
the resolved mechanisms below do not assert that every remaining difference
has the same cause.

The earlier 200-sample regression run has zero rule-name differences,
with 6,300 reference-matched rules. The four formerly remaining
differences, KD-008 and KD-014 through KD-016, are resolved in compatibility
mode. See `docs/BENCHMARKS.md` for commands and validation.

This is measured matched-rule compatibility on the pinned corpus. It does
not assert identical instruction recovery or JSON evidence locations for
arbitrary binaries. Historical sample lists below retain earlier causes;
native recovery intentionally keeps its broader decoder and switch behavior.

## Why a document like this is the right answer

Documented divergence is upstream's own model for a backend, not a concession
this port invented. capa ships vivisect, IDA, idalib, Ghidra, Binary Ninja,
BinExport and dotnetfile backends, and nothing in its test suite compares any
two backends' capability output. Each is checked against hand-maintained
expectation tables, and where a backend genuinely disagrees, upstream *encodes
the disagreement*:

- `reference/capa/tests/fixtures.py:1540` : a separate `FEATURE_COUNT_TESTS_GHIDRA`
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
3. **Cite the upstream mechanism** : the pinned Python/vivisect file and
   function whose behaviour we are not reproducing. Port-from-source rules
   apply here too (`AGENTS.md`): read it, don't recall it.
4. **`our-bug` is not a divergence.** If capa-x is simply wrong, fix it.
5. **State the direction** (do we report more, or fewer, matches) and the
   affected rules : a reader triaging a new diff needs to recognise the class.

## Schema

```markdown
### KD-00N : <short name of the class>

- **Class:** recovery / function extent | feature extraction | matching | loader
- **Direction:** capa-x reports fewer | more matches
- **Affects:** `rule name`, `rule name` (+N rules)
- **Samples:** <sha or filename> (0xADDR), <sha> (+N more)
- **Root cause:** <the mechanism, naming the pinned upstream file>
- **Upstream analogue:** <the comparable backend divergence upstream accepts>
- **Status:** accepted | tracked in the divergence record | resolved
```

## Entries

### KD-001 : FLIRT-recognized library functions are dropped, not flagged

- **Class:** feature extraction / matching scope
- **Direction:** capa-x reports fewer features at function scope
- **Affects:** no capa rule; visible only to the transcribed fixture table
- **Samples:** the `features_parity.rs` rows reported at the end of
  `feature_presence_matches_upstream_viv_expectations` (a run prints the
  current list; it is small and sample-dependent)
- **Root cause:** upstream separates extraction from matching : the raw
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
- **Upstream analogue:** `FEATURE_COUNT_TESTS_GHIDRA` : a backend whose
  function model differs is given its own expectations rather than being made
  to match vivisect's.
- **Status:** accepted. Equivalent for every result-level metric: real
  capa rules do not target a library thunk's own address, and matched-rule sets
  are unaffected. Revisit only if a rule ever needs library-function scope.

### KD-002: function starts discovered by emulating unreferenced addresses

- **Class:** recovery / function extent
- **Direction:** historically fewer matches
- **Upstream mechanism:** `vivisect/analysis/generic/emucode.py:analyze`
  gathers named and `REF_PTR` targets with no defined location, evaluates
  them with `watcher` and `runFunction(maxhit=1)`, and repeats after accepted
  functions expose new references. A return or known no-return exit and the
  watcher's mnemonic-distribution check establish code.
- **Implementation:** `capa-x/src/extract/recovery/emucode.rs` tracks known
  registers, stack/private memory, effective addresses, and both branch
  paths using the existing decoder. `pointers.rs` gathers candidates and
  excludes existing instructions, typed data, and loader dead-data ranges.
  Emucode runs before signature fallback and does not restart for references
  created only by later passes. The native backend retains its prior policy.
- **Evidence:** the three remaining missing rules on `112f9f0e...exe_` and
  all four on `294b8db1...477bc.elf_` are recovered. Together with pointer
  discovery, this also recovers three missing rules on `70fd3347...exe_`;
  its `PEB access` discrepancy remains KD-014.
- **Corrected historical attribution:** the seven formerly missing rules on
  `a70052c4...exe_` are now resolved under KD-007.
  Live `makeFunction` tracing shows that `0x405c40`, `0x405e80`,
  `0x4051a0`, `0x406980`, and `0x406aa0` originate in
  `AnalysisMonitor.apicall`, before `generic.emucode.analyze`. Later emucode
  roots consume references from those functions. Counting functions created
  during a module previously hid this dependency. These historical misses
  belonged to KD-007, not an absent emucode pass.
- **Status:** the missing candidate-discovery mechanism is implemented.
  Support is bounded, not a claim of complete workspace-emulator parity:
  unsupported operations, unresolved computed branches, and resource limits
  produce contextual diagnostics. See
  [ADR 0007](docs/decisions/0007-candidate-evaluation.md).

### KD-003: pointer targets classified as code by emulation

- **Class:** recovery / function extent
- **Direction:** historically both fewer and more matches
- **Upstream mechanism:** `generic/pointers.py`, `generic/pointertables.py`,
  and operand dereferences reach `VivWorkspace.analyzePointer`. It rejects
  already defined locations, checks strings first, then calls
  `isProbablyCode`, which accepts a registered function signature or the
  same candidate evaluator used by emucode.
- **Implementation:** compatibility recovery replaces the first-mnemonic
  relocation whitelist with this signature/evaluation sequence. PE retains
  relocation source slots so instruction operands cannot masquerade as data
  pointers. ELF scans undefined pointer sources, including unaligned ones.
  PE does not run the ELF generic pointer scan. Instruction interiors,
  defined data, strings, and dead-data regions cannot become new starts.
- **Evidence:** `decrypt data using AES via x86 extensions` on
  `2f7f5fb5...elf_` and all three missing rules on `b5f0524e...a87.elf_`
  are recovered. The latter includes pointer-only roots `0x80724b0` and
  `0x807d2a0`. On `49a34cfb...exe_`, `contain obfuscated stackstrings`,
  `hash data with MD5`, and `parse credit card information` are restored;
  the RC4 miss was subsequently resolved under KD-007.
  All three former differences on `512a5575...c92.elf_` are also removed,
  without requiring the full call monitor.
- **Boundary regression coverage:** a relocated immediate must use emucode
  rather than the data-pointer signature shortcut. Otherwise `0x413420` on
  `6f99a2c8...exe_` is walked too early and its callee claims the shared
  function `0x40d22a`, losing `read file on Windows`.
- **Corrected attribution:** the six former extras on `749cf36a...22c2.elf_`
  were KD-004's import-classification difference, now resolved. The two historical extras on
  `e17e6a79...elf_` were caused by an absolute jump-table scan reading past
  an unsigned selector bound into adjacent tables. They are not evidence
  that a candidate evaluator accepts invalid function starts.
- **Status:** the documented pointer-classification misses are resolved by
  bounded candidate evaluation. Full workspace location and function-extent
  parity remain separate concerns. Unsupported evaluation paths retain
  diagnostics as described in ADR 0007.

### KD-004: ELF import relocation classification

- **Class:** loader
- **Direction:** historically more matches
- **Affects:** `change memory permission on Linux`, `create or open file`,
  `hook routines via dlsym RTLD_NEXT`, `link function at runtime on Linux`,
  `map or unmap memory on Linux`, `write file on Linux`
- **Sample:** `749cf36a...22c2.elf_`, formerly six differences.
- **Root cause:** Vivisect 1.3.2 `parsers/elf.py:parseRelocs` creates imports
  only for named `R_386_JMP_SLOT`, `R_X86_64_GLOB_DAT`, and
  `R_X86_64_IRELATIVE` relocations on either x86 architecture. Other types
  produce relocations or names. The sample uses `R_X86_64_PC32` for `fopen`,
  `fwrite`, `fputc`, `vfprintf`, `mmap`, `munmap`, `mprotect`, and `dlsym`.
  Binding these as imports supplied API features absent from the reference.
- **Implementation:** compatibility recovery now applies the reference's
  import classification, with a diagnostic for each excluded named binding.
  Native recovery and the standalone loaded-image API retain broader symbol
  resolution. AArch64 and file-only ELF import extraction are unchanged.
- **Status:** resolved for the compatibility backend. This deliberately
  prioritizes reference parity over recognizing additional valid APIs in
  that backend; the native loader retains those detections.

### KD-005: heuristic function seeds outside the reference model

- **Class:** recovery / function extent
- **Direction:** historically more matches
- **Affected samples:** `34dbc85e...elf_`, `70fd3347...exe_`,
  `82bf6347...exe_`, `9324d1a8...exe_`, `971e599e...exe_`,
  `a6e9d94e...elf_`, and `e5e8c139...elf_`.
- **Root cause:** raw `e8 <rel32>` scans and broad prologue patterns seeded
  functions that the reference never defines. Earlier removal experiments
  lost more genuine matches than they removed extras, so the heuristics
  were retained as a measured trade. That result predates candidate and
  callback recovery.
- **Resolution:** x86/x64 compatibility recovery now uses the reference's
  registered entry signatures after pointer, emucode, and callback discovery.
  Broad prologue and raw call sweeps remain available to the native backend;
  AArch64 keeps its existing recovery policy.
  Removing the sweeps eliminates ten extras on six samples. The only new
  miss in the initial experiment, `create pipe` on `74e0758e...exe_`, was
  traced to unsupported `lock xadd` at `0x4037e8`. Supporting that operation
  lets relocation slot `0x40b3f4` recover function `0x4037bc`, exactly through
  the reference's `generic/relocations.py` path, without a raw call sweep.
- **ELF relocation correction:** `e5e8c139...elf_` has an
  `R_X86_64_RELATIVE` relocation at RVA `0x6c08`, with addend `0x4b30`
  and a zero stored pointer. `vivisect/parsers/elf.py:loadElfRelocs` reads
  the stored pointer for this relocation type. Compatibility recovery no
  longer substitutes the RELA addend and invents function `0x2004b30`.
  Native recovery retains its addend behavior.
- **Status:** resolved for the listed extras. Synthetic tests distinguish
  native sweeps from compatibility signatures, and real fixtures guard the
  relocation-created pipe function and the zero-slot ELF case.

### KD-006 : indirect jump targets recovered by emulating the switch table

- **Class:** recovery / function extent
- **Direction:** capa-x reports fewer matches
- **Affects:** `compute adler32 checksum`, `hash data with CRC32`,
  `resolve function by parsing PE exports`, `log keystrokes via Input Method
  Manager`
- **Samples:** `276f691a3df25481f59d79781799e35f.exe_` : all 3 of its diffs.
  Functions `0x14002f8d0` and `0x140030300`, plus the unwalked tail of
  `0x14002d780`, of which capa-x recovers 63 of the reference's 1,559
  instructions. Also `f5903519…c58.exe_` (fn `0x140079a90`), added by a
  corpus-wide re-run: capa-x recovers 84 of the reference's 287 basic
  blocks there, and **none** of the 203 it lacks has a static predecessor in
  the reference's own graph : they are switch arms reached only through the
  emulated table, the same mechanism as `276f691a`
- **Root cause:** both sides decode the same basic block and stop at the same
  instruction : the indirect `jmp` at `0x14002d83d`, which has no static
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
- **Upstream analogue:** the `xfail:` rows in the idalib/BinExport tables : a
  backend without the reference's jump-table resolution is given its own
  expectation rather than being expected to match it.
- **Status:** resolved for the documented missing capabilities by bounded
  static recovery in `capa-x/src/extract/recovery/switch.rs`. The resolver
  requires an unsigned `cmp`/`ja` or `jae` guard, a RIP-relative `lea`
  establishing the base, and a validated load/add/jump register chain.
  It supports unsigned 32-bit RVAs, signed 32-bit offsets, and an optional
  byte selector table. It reads only indexes admitted by the guard and
  rejects the entire dispatch if any table access or target is invalid.
  All three missing rules on `276f691a` are recovered, along with
  `log keystrokes via Input Method Manager` on `f5903519`.
  The latter also exposes a valid additional match under KD-008 below.
  General emulated switches, including bases established outside this local
  sequence, remain outside this implementation.

### KD-007: callback and evaluated data-pointer function discovery

- **Class:** recovery / function extent
- **Direction:** historically fewer matches
- **Affected rules:** the seven former misses on `a70052c4...exe_`,
  `enumerate gui resources` on `253309d8...dll_`, `delete registry key`
  on `c335a9d4...exe_`, and RC4 on `49a34cfb...exe_`.
- **Upstream mechanism:** `vivisect/impemu/monitor.py:AnalysisMonitor.apicall`
  creates functions for concrete arguments named `funcptr` in the Windows
  API tables. The x86 subclass in `analysis/i386/calling.py:prehook` also
  records discrete LEA addresses. `addAnalysisResults` follows pointers
  stored at those addresses through `guessDataPointer`.
- **Implementation:** `callbacks.rs` reuses the bounded interpreter to track
  x86 stack and Windows x64 register/stack arguments. Its API positions are
  derived from Vivisect 1.3.2's Windows tables. Imported calls, register-held
  imports, and direct jump thunks are supported. Unknown calls invalidate
  argument state; unsupported instructions and budgets produce diagnostics.
  Explicit callbacks can enter executable sections marked as dead data,
  matching `apicall` rather than the heuristic candidate classifier.
- **Evidence:** `CreateThread` discovers the missing roots on `a70052c4`
  and `c335a9d4`. The latter's callback `0x402820` shares its section with
  import data and would be wrongly rejected by a dead-data heuristic.
  On `49a34cfb`, LEA at `0x5a02bb` references pointer slot `0x6a6b3c`,
  which points to `0x599030`; that function calls RC4 at `0x599940`.
  The slot itself is never promoted to a function. The x64 monitor has no
  corresponding LEA hook, so this extra pointer-source behavior is x86 only.
- **Status:** resolved for all ten listed missing rules. Full workspace
  emulation, dynamically resolved API identities, and arbitrary computed
  dereferences remain outside the bounded implementation. See ADR 0007.

### KD-008: code decoded after a function's ownership is assigned

- **Class:** recovery / matching scope
- **Direction:** historically more matches
- **Resolved rules:** `create directory`, `delete directory`,
  `delete registry key`, `enumerate files on Windows`, and
  `enumerate files recursively` across four samples, six differences total.
- **Resolved samples:** `1e9fc7f3...exe_` (function `0x4028d2`, continuation
  `0x402940`), `31600ad0...exe_` (`0x401155`, `0x4011c7`),
  `50d5ee1c...exe_` (`0x402c2f` and `0x402d0e`), and `a563c50c...exe_`
  (`0x401490`, `0x4015cc`). Earlier extras on `9324d1a8` and `c2d46d25`
  disappeared with the compatibility seed policy in KD-005.
- **Root cause:** `i386/importcalls.py:analyze` calls `makeCode` on loose
  import-call fragments. `envi/codeflow.py:addCodeFlow` descends into a
  direct callee before resuming the fragment. `base.py:_cb_function` runs
  `generic/codeblocks.py:analyzeFunction` immediately. When the callee meets
  already decoded fragment instructions, its view stops at the fragment's
  current end. The continuation decoded afterward remains unowned.
  Live tracing confirms that the three continuation addresses above have no
  location when `analyzeFunction` runs and become opcode locations later in
  the same import-call pass. This is an analysis-order difference, not a
  need to discard valid instructions globally.
- **Implementation:** compatibility import-call discovery runs after emucode
  and before function signatures. An explicit task stack completes callee
  views before resuming the loose fragment, retaining those views while
  later instructions and callees are still discovered. Native recovery
  keeps complete final graph views. Undefined PE relocation operands are
  typed pointer locations and cannot seed the import-call scan, matching
  `generic/relocations.py` and `VivWorkspace.findPointers`. This protects
  the signature-created function `0x40d22a` on `6f99a2c8`.
- **Resolved rule/sample:** `check for unmoving mouse cursor` on `f5903519`.
  The static switch resolver reaches `GetCursorPos` at `0x14007b1ad` and
  `0x14007b25e` under `0x140079a90`. Both sites are unowned in the reference
  but lie inside PE runtime-function interval `[0x140079a90, 0x14007bdd0)`.
  A fresh trace corrects the earlier ownership attribution: these sites
  have no opcode locations at all. `VivWorkspace.iterJumpTable` visits
  consecutive RVA entries and stops when `isProbablyCode` rejects an arm,
  even if a byte selector skips that entry. The first table stops at
  `0x140079c3b`; the nested table stops at its first entry, `0x14007b17e`.
  Both candidates encounter a concrete divide-by-zero anomaly.
  Compatibility switch recovery now applies the bounded candidate evaluator
  in table order. Inconclusive evaluations retain a diagnostic and the
  statically validated arm; definite rejections stop the table.
- **Corrected attribution:** the Base64 extra on `f53dfa29` is an EVEX
  decoder limitation in the reference, now KD-016.
- **Status:** the documented import-call and switch differences are resolved.
  Native recovery retains the statically validated switch arms.
  Synthetic tests cover recursive
  discovery, a separately reachable return, continuation discovery, native
  behavior, and relocation exclusion. Real samples guard the boundaries.

### KD-009: PE section names in full and file-only analysis

- **Class:** loader / file features
- **Direction:** historically more matches
- **Affects:** `packed with Themida`, `(internal) packer file limitation`
- **Sample:** `2826b762...ba2.exe_`, formerly two differences.
- **Root cause:** `vivisect/parsers/pe.py` uses `sec.Name.strip("\x00")`,
  retaining embedded NULs. `capa/features/extractors/viv/file.py` yields
  these segment names, including `PE_Header`. The pefile extractor instead
  truncates section names at the first NUL. The sample's `"   \x00    "`
  section therefore satisfies the Themida rule only under pefile semantics.
- **Implementation:** full x86/x64 PE analysis obtains section features from
  the loaded workspace segments. File-only analysis continues to use the
  independent pefile extractor. The same input can satisfy both upstream
  contracts because these are separate API paths.
- **Status:** resolved. A regression test checks embedded NULs, all-space
  names, and `PE_Header` through both public analysis modes.

### KD-010: function extents split or merged inside shared code

- **Class:** recovery / function extent
- **Status:** the documented examples are resolved. This does not claim exact
  function-boundary parity for arbitrary shared code.
- **Unwind boundaries:** the native backend stops fallthrough at independent
  PE unwind entries. Compatibility recovery follows the pinned reference's
  fallthrough across these entries and preserves the function view when its
  discovery finishes. This restores the loop match at `0x1400e1300` in
  `29a76e413ffe0f78b62926b8455082d6.exe_`. Later-discovered instructions must
  not expand the earlier function's matching scope. Chained unwind fragments
  remain excluded from the seed set.
- **Corrected attribution:** on current main, `3fdfb2d5...exe_` already has
  `0x4146a9` inside `0x41467e`, exactly as the pinned reference does. Its
  remaining `link function at runtime on Windows` extra was an import-loader
  discrepancy, not a split function. The nonzero `OriginalFirstThunk` RVA
  `0x11` names an empty table in the DOS header. Goblin's section-based lookup
  falls back to the IAT, while `PE.parseImportTable` honors the declared
  table and finds no imports. Code API bindings now respect its terminator,
  report the fallback mismatch as a loader diagnostic, and retain the valid
  IAT fallback when `OriginalFirstThunk` is zero. File import features retain
  their separate parser contract.
- **Regression coverage:** synthetic independent unwind starts and explicit
  shared tails; the real merged-extent sample; the header lookup table and
  its explicit-zero fallback variant in `loaded_image.rs`.

### KD-011: resource-hosted code recovery

- **Class:** loader / recovery
- **Status:** resolved for `0cd2b334aede270b14868db28211cde3.exe_`.
- **Behavior:** resource-directory sections are mapped, matching
  `viv_utils.getWorkspace`'s `loadresources = True`. Mapping preserves ordinary
  section permissions; it does not make non-executable resources executable.
- **Extent fix:** an instruction-budget stop used to discard the walk's
  already discovered call targets. Without those callees, subsequent
  no-return passes could not cut off the caller and it absorbed a large
  unpacked region. Budgeted walks now retain their callees and emit a
  diagnostic. Once the callees are analyzed, this sample's entry function
  contains the same 22 instructions as the reference, including the jump
  into resource-hosted code at `0x531cb3`, and excludes the unrelated range
  starting at `0x402fbe`.
- **Outcome:** `contain loop` and `packed with generic packer` are recovered
  without adding `contain pusha popa sequence`.
- **Regression coverage:** executable and non-executable resource mapping,
  call-target retention at the walk budget, and the real sample's entry
  extent and recovered callees.

### KD-012: recovery gaps incorrectly propagate no-return status

- **Class:** recovery / function extent
- **Status:** resolved for the documented caller-truncation cases. Ordinary
  undecodable leaves still follow the pinned `noret.py` rule; the broad
  relaxation previously measured and rejected has not been restored.
- **Conflicting decodings:** `70fd3347...exe_` calls `0x4031e8`, inside an
  existing instruction, and `749cf36a...elf_` has unresolved relocation calls
  targeting their own operands. The alternate streams stop on privileged or
  invalid bytes, whereas Vivisect retains the original instruction location's
  size and flags. Such conflicting starts no longer establish no-return
  status or remove caller continuations.
- **Pointer-jump extent:** `2f7f5fb5...elf_`'s `0x401138` is a plain pointer
  jump. It was treated as a jump table and inherited no-return status from
  code reached through adjacent pointers. Plain memory jumps now dereference
  one pointer and, like `codeblocks.py`'s `BR_DEREF` handling, do not include
  the pointed-to code in their function view. Indexed table arms still belong
  to their dispatching function.
- **Outcome:** `get OS version`, `calculate modulo 256 via x86 assembly`,
  and `generate random numbers using a Mersenne Twister` are restored.
  The pointer-jump fix also restores `parse credit card information` on
  `2f7f5fb5`. The fourth historically listed capability, `PEB access`, remains
  different after the caller is fully recovered; its corrected attribution
  is KD-014.
- **Historical extra matches:** restored flow in `749cf36a` initially exposed
  three more valid API detections under KD-004. Compatibility loading now
  follows the reference's import classification, while native loading
  retains the broader relocation bindings.
- **Regression coverage:** conflicting instruction streams, genuine
  undecodable leaves, import-thunk propagation, plain versus indexed memory
  jumps, and all three affected caller chains.

### KD-013 : AArch64 switch/jump-table dispatch is not resolved

- **Class:** recovery / function extent
- **Direction:** capa-x reports fewer matches
- **Affects:** `terminate process`
- **Samples:** `687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf_`
  : 1 of 1 diff on this sample, and the only J9 divergence across the 3-sample
  pinned AArch64 BinExport2 corpus
- **Root cause:** the function's dispatch is the standard AAPCS64
  `adrp`/`add`/`ldrsw`/`add`/`br` sequence (a PC-relative table load into an
  indirect branch). Ghidra resolves the arm count and every arm's target from
  a bounds check it recovers ahead of the `br` : a static analysis, not
  emulation, but one this port does not yet perform; capa-x's recovery
  stops at the `br` with no static `direct_target`, the same shape as
  KD-006's x86 switch case but reached by ISA-native structural analysis on
  the reference side instead of vivisect's emulated `analyzeJmp`. The call to
  the process-termination API lives in one of the unrecovered arms.
- **Upstream analogue:** the `xfail:` rows in the BinExport/idalib tables : a
  backend without the reference's jump-table resolution is given its own
  expectation rather than being expected to match it, the same posture KD-006
  documents for vivisect's switch-case emulation.
- **Status:** resolved for the documented dispatch by bounded static analysis
  in `capa-x/src/extract/recovery/switch.rs`. It validates the unsigned
  `cmp`/`b.hi` or `b.hs` guard, register relationships, table extent, signed
  offsets, and aligned executable targets before adding any edges. The
  index's upper bits must also be constrained when a W-register comparison
  feeds an X-register table index. Unsupported forms remain unresolved.
  A fresh before/after run on the three pinned AArch64 pairs recovered
  `terminate process`, changing 1 missing / 0 extra to 0 missing / 0 extra
  against 29 reference-matched rules. The formerly exempt feature rows at
  `function=0x105128,bb=0x105450` now pass without exceptions.

### KD-014: PEB match from an overlapping reference block

- **Class:** recovery / reference instruction ownership
- **Direction:** capa-x reports fewer matches
- **Affects:** `PEB access`
- **Sample:** `70fd3347786ed7a4a43910e6778ef296.exe_`
- **Root cause:** the reference function `0x407d58` owns an overlapping block
  beginning at `0x407e41`, inside the immediate operand of the real
  `push 0x407e75` at `0x407e3d`. Decoding from that interior byte produces
  `add byte [edi + edi * 8 + 0x30], ah`, supplying the rule's `offset(0x30)`.
  The block also contains FS accesses at `0x407e45` and `0x407e64`, so the
  basic-block rule combines the unrelated offset with those accesses.
  The correctly aligned stream instead has `fs: push [eax]` at `0x407e42`;
  its FS accesses have offset zero and do not read the PEB.
- **Evidence:** reproduced with the pinned capa 10 CLI, the pinned rules,
  and `reference/capa/sigs`. `VivisectFeatureExtractor` exposes the overlapping
  block under `0x407d58` while the workspace location at `0x407e41` still
  belongs to the five-byte push at `0x407e3d`. The full 31-instruction
  `0x407e2c` caller is now recovered and is not marked no-return.
- **Status:** resolved in compatibility mode. Discovery preserves the first
  instruction location, as `VivCodeFlowContext._cb_opcode` does. Function
  blocks advance by those location sizes, including for interior branch
  entries, and decode the resulting byte intervals independently, matching
  `generic/codeblocks.py` and `viv_utils.BasicBlock.instructions`.
  This reproduces the reference's match from conflicting boundaries.

### KD-015: XOR match in conflicting instruction streams

- **Class:** recovery / instruction boundaries
- **Direction:** capa-x reports fewer matches
- **Affects:** `encode data using XOR`
- **Sample:** `971e599e6e707349eccea2fd4c8e5f67.exe_`
- **Evidence:** the pinned reference matches block `0x42bee1` in function
  `0x42c6d9`. Its branch from `0x42bf01` enters the middle of the instruction
  at `0x42bedf`. The resulting overlapping block includes `insb` at
  `0x42bef3` and XOR at `0x42bef4`, supplying the loop/XOR evidence.
  The surrounding reference stream also includes `out`, `insd`, unrelated
  absolute memory accesses, and a far call. Recovery stops at privileged
  instructions and does not reconstruct this overlapping loop.
- **Upstream mechanism:** Vivisect's codeflow and code-block ownership allow
  alternate branch-entry decodings; capa extracts the instructions exposed
  by those blocks through `features/extractors/viv/extractor.py`.
- **Status:** resolved in compatibility mode using the location and block
  distinction described in KD-014. Compatibility codeflow continues through
  string I/O instructions. The pinned decoder's C6/C7 MOV and 8F POP aliases,
  which ignore ModRM extension bits, keep the path to this loop decodable.
  Candidate evaluation still rejects output instructions and decoder
  anomalies, including when another queued branch could reach a return.
  This prevents pointer discovery from treating data as code.

### KD-016: EVEX instructions unsupported by the reference decoder

- **Class:** feature extraction / reference decoder
- **Direction:** capa-x reports one additional match
- **Affects:** `decode data using Base64 via VBMI lookup table`
- **Sample:** `f53dfa294d6979145fbb34303cf73bb6.exe_`, function `0x1400083a0`.
- **Root cause:** the pinned Vivisect amd64 decoder interprets EVEX prefix
  `0x62` as legacy `bound`, producing conflicting instruction boundaries and
  missing vector mnemonics. A fresh trace decodes `0x1400083d9` as `bound`
  and later vector bytes as branches and `outsd`. This is not the same
  instruction stream decoded by iced-x86.
- **Upstream evidence:** the pinned rule itself explicitly comments that
  its SSE/AVX example is unsupported by Vivisect and comments out this exact
  sample/address in `rules/nursery/decode-data-using-base64-via-vbmi-lookup-table.yml`.
- **Status:** resolved in compatibility mode by interpreting opcode `0x62`
  through the pinned decoder's legacy BOUND operand layout, including in
  amd64 mode. Native decoding retains EVEX support. Previously included in
  KD-008 because instruction-address comparison reported unowned bytes.

### KD-017: ordinal-only OLE Automation imports

- **Class:** loader
- **Direction:** historically fewer API matches
- **Root cause:** the loader lacked the pinned Vivisect 1.3.2
  `PE/ordlookup/oleaut32.py` ordinal names. Ordinal-only calls therefore had
  no named API feature.
- **Resolution:** port the complete pinned table and normalize the DLL suffix
  case-insensitively. The table cites its source and adds no dependency.
- **Status:** resolved on the expanded corpus.

### KD-018: switch bases established before the local dispatch window

- **Class:** recovery / function extent
- **Direction:** historically fewer matches
- **Root cause:** `generic/switchcase.py` reads the live emulator's base
  register, while the static resolver previously required a nearby LEA.
- **Resolution:** prove constant register values through bounded predecessor
  traversal, including a base established before the guard and the optional
  MOVSXD form. Validate bounds, register relationships, and every table read.
- **Status:** the expanded corpus's rule-name misses are resolved. Arbitrary
  symbolic dispatch and full function-extent parity remain incomplete.

### KD-019: library recognition depends on function creation order

- **Class:** recovery / library-function scope
- **Direction:** historically both fewer and more matches
- **Root cause:** `viv_utils/flirt.py` runs each signature database when a
  function completes. Secondary public labels require an existing function;
  local labels may create functions at undefined executable addresses. Applying
  signatures to the final address-sorted function set changes which bodies
  capa excludes from capability matching.
- **Resolution:** record function completion and opcode-definition order,
  apply databases in that order with per-invocation caches, distinguish public
  and local labels, and discover local-label code before fallback function
  entries. Static indirect callees and no-return callees complete before their
  callers. PE entry-point flow precedes other loader roots.
- **Evidence:** `3265b2b0...exe_` retains the modulo-256 match in the nonlibrary
  function at `0x440bc9`; `03b236b2...dll_` now has identical match-address sets.
- **Status:** rule-name regressions are resolved. Local discovery is a bounded
  phase before fallback entries, not a complete reproduction of nested
  workspace callbacks. Remaining address differences require further work.

### KD-020: typed locations and candidate evaluation timing

- **Class:** recovery / candidate discovery
- **Direction:** historically both fewer and more matches
- **Root cause:** the reference follows each relocation before typing later
  slots, checks location types at every candidate instruction, marks strings
  and hotpatch padding as data, and ignores writes through unmapped taint
  addresses in safe-memory mode (`generic/relocations.py`,
  `generic/emucode.py`, `ms/hotpatch.py`, `impemu/emulator.py`).
- **Resolution:** preserve sequential relocation handling, merge typed-data
  ranges, reject paths entering typed data, and retain concrete callback stack
  arguments across unknown-address writes. Support the pinned bit-test
  operations used by trap-flag checks. Forwarded PE exports do not seed code.
- **Evidence:** `07f7846b...exe_` loses spurious library-derived detections;
  Practical Malware Analysis Lab 14-02 retains its file and pipe rules.
- **Status:** resolved for the expanded rule-name comparison; general emulator
  and workspace-location parity remains bounded as described in ADR 0007.

### KD-021: AMD64 Go runtime root

- **Class:** recovery / function discovery
- **Direction:** historically fewer matches
- **Root cause:** only the i386 Go startup sequence was implemented. The
  pinned `analysis/amd64/golang.py` locates runtime_main through a RIP-relative
  pointer in its startup sequence.
- **Resolution:** port the AMD64 mnemonic sequence, build-ID gate, and checked
  pointer read alongside the existing i386 path.
- **Status:** resolved for the expanded rule-name comparison.

### KD-022: INT1 decoding in the pinned i386 backend

- **Class:** recovery / decoder compatibility
- **Direction:** historically more matches
- **Root cause:** the pinned i386 decoder's platform-trap handling raises on
  operandless opcode F1. Continuing through it exposes code the reference
  never recovers.
- **Resolution:** compatibility decoding rejects this opcode for i386 PE and
  ELF input. AMD64 and native decoding retain their existing behavior.
- **Status:** resolved; removes the extra kernel HMAC rule.

### KD-023: static loop edges and ELF PLT thunk features

- **Class:** feature extraction
- **Direction:** historically both fewer and more match locations
- **Root cause:** `viv/function.py:extract_function_loop` uses static branch
  targets rather than emulator-resolved switch edges. `analysis/elf/elfplt.py`
  also marks multi-instruction CET PLT stubs as thunks, suppressing their jump
  API feature.
- **Resolution:** derive x86 loop edges from terminal instruction branches;
  retain ELF PLT section ranges and recognize import jumps following ENDBR.
- **Status:** these mechanisms are implemented and tested. They improve match
  locations but do not eliminate the remaining 55 differing samples.


### KD-024: function completion and evaluated callees

- **Class:** recovery / function extent
- **Upstream behavior:** `envi/codeflow.py:addCodeFlow` completes branch paths
  and callees before the function callback. `generic/codeblocks.py` captures
  the locations available at that point. Later discovery does not rebuild
  every previous function from the expanded instruction map.
- **Resolution:** preserve compatibility views at completion, finish switch
  arms before capturing them, and propagate compatibility no-return decisions
  as functions complete. Native recovery retains its graph-wide fixed point.
  Calling traces run before final no-return classification, and changed jump
  table edges refresh the affected function scopes. Late signatures cannot
  start inside an existing instruction, matching `generic/funcentries.py`.
- **Evaluated calls:** `impemu/monitor.py:AnalysisMonitor.apicall` also creates
  concrete runtime-resolved callees. The bounded calling trace now follows
  computed jumps into undecoded bytes and records executable callees. Import
  identities take precedence over raw IAT contents. Newly supported scalar
  and SSE operations follow `envi/archs/i386/emu.py`; unsupported operations
  still produce diagnostics. Vector values remain unknown.
- **Decoder boundary:** operand-size-prefixed relative branches retain their
  complete 32-bit target in compatibility mode. Typed data locations constrain
  codeflow, while pointer locations remain eligible for reclassification.
  WAIT, legacy NOP aliases, and SSE string-register behavior follow the pinned
  decoder and emulator.
- **Coverage:** synthetic tests exercise completion order, signature interiors,
  computed jumps, IAT identities, packed operations, and prefixed LOOP targets.
  `match_address_parity.rs` compares complete rule/address sets for eleven
  inputs with the immutable reference index. The initial PR gained 70 exact
  samples; the follow-up gains five more and preserves every previously exact
  sample. The remaining 50 differing inputs are listed in the current
  validation report.

### KD-025: extra function scopes expose pusha/popa matches

- **Class:** recovery / callback discovery and function ownership
- **Direction:** two extra rule-name matches
- **Sample:** `971e599e6e707349eccea2fd4c8e5f67.exe_`
- **Affects:** `contain anti-disasm techniques`
- **Evidence:** callback discovery before function finalization retains extra
  function scopes matching `contain pusha popa sequence`, crossing the parent
  rule's threshold. This sample already had address differences on main; the
  new rule-name match is a regression, not an accepted baseline change.
- **Upstream mechanism:** `WorkspaceEmulator.runFunction` checks no-return
  locations only after the entry opcode. A call at trace entry can therefore
  expose later concrete callees to `AnalysisMonitor.apicall`, even though the
  captured function blocks end at that call. The calling monitor also rejects
  the all-zero bad opcode before following more calls. Applying those rules
  restores the parent rule's threshold behavior.
- **Additional sample:** `648fc498110b11b4313a47a776e6ba40.exe_` gains
  `contain pusha popa sequence` at function `0x5fa068`. This was absent from
  the main baseline. A typed pointer at `0x5fa114` is partially overwritten by
  the instruction at `0x5fa113`. The reference location map keeps the pointer
  suffix at `0x5fa117`, which stops codeflow before a false pusha/popa sequence.
  Preserve exact pointer spans separately from merged data intervals to
  reproduce that boundary.
- **Status:** resolved for rule names. A permanent integration test compares
  both complete rule-name sets with the immutable reference. Synthetic tests
  cover trace-entry exceptions, bad opcodes, and pointer suffixes. Both samples
  still have match-address differences. Expected baselines remain unchanged.
