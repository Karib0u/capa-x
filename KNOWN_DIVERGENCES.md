# Known divergences vs Python capa

Every result difference between capa-x and the pinned Python capa
(`flare-capa` and Vivisect versions in [`PINNED.md`](PINNED.md)),
one entry per *class* of difference. Resolved entries retain their IDs and
historical causes so earlier measurements remain interpretable.

## Current measured remainder

The 2026-10-20 full-corpus run after callback recovery and removal of
compatibility sweeps has 18 rule-name differences across 10 of 200 samples,
down from 39 differences across 19 samples on main `1943f82`.
See `docs/BENCHMARKS.md` for the commands and validation. Historical sample
lists below retain earlier attributions; this table is the current remainder.

| Class | Missing | Extra | Samples |
|---|---:|---:|---|
| KD-004: reference ELF import handling | 0 | 6 | `749cf36a` |
| KD-008: reference instruction ownership | 0 | 8 | `1e9fc7f3`, `31600ad0`, `50d5ee1c`, `a563c50c`, `f53dfa29`, `f5903519` |
| KD-009: PE section names | 0 | 2 | `2826b762` |
| KD-014: overlapping PEB block | 1 | 0 | `70fd3347` |
| KD-015: conflicting XOR loop | 1 | 0 | `971e599e` |

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
- **Status:** accepted | tracked in the divergence record | resolved
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
- **Corrected attribution:** the six extras on `749cf36a...22c2.elf_` are
  KD-004's unresolved reference imports. The two historical extras on
  `e17e6a79...elf_` were caused by an absolute jump-table scan reading past
  an unsigned selector bound into adjacent tables. They are not evidence
  that a candidate evaluator accepts invalid function starts.
- **Status:** the documented pointer-classification misses are resolved by
  bounded candidate evaluation. Full workspace location and function-extent
  parity remain separate concerns. Unsupported evaluation paths retain
  diagnostics as described in ADR 0007.

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

### KD-008 — code the reference decodes but never wraps in a function

- **Class:** matching scope (reference-side), reached through recovery
- **Direction:** capa-x reports **more** matches
- **Affects:** `check for unmoving mouse cursor`, `connect to URL`,
  `contain loop` (×2 samples), `create
  directory`, `delete directory`, `delete registry key`, `decode data using
  Base64 via VBMI lookup table`, `enumerate files on Windows`, `enumerate files
  recursively` (10 extras)
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

**Additional evidence after static switch recovery (2026-10-20).**
On `f5903519`, the newly reached `GetCursorPos` calls at `0x14007b1ad`
and `0x14007b25e` satisfy `check for unmoving mouse cursor` in function
`0x140079a90`. `scripts/triage/attribute_shared_extras.py` attributes this
to code without reference function ownership: both call addresses are
unowned, and the reference extracts no cursor-position API feature from
that function. Both calls lie inside the same PE runtime-function interval,
`[0x140079a90, 0x14007bdd0)`, independently confirming that this is not
merging separate functions. Keep the match rather than discarding valid
switch arms to reproduce the reference's ownership gap.

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

### KD-010: function extents split or merged inside shared code

- **Class:** recovery / function extent
- **Status:** the documented examples are resolved. This does not claim exact
  function-boundary parity for arbitrary shared code.
- **Merged extent:** `29a76e413ffe0f78b62926b8455082d6.exe_` previously
  accumulated code from adjacent functions under `0x1400e1300`, producing
  `execute shellcode via indirect call`. Function views now stop fallthrough
  at another independent PE unwind entry. Explicit branches still reach
  shared tails, and chained unwind fragments remain excluded from the seed
  set. Ending at this boundary does not itself prove a function never returns.
  This intentionally follows linker evidence instead of reproducing the
  reference workspace's overlapping, partially shared extents.
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
- **Accepted extra matches:** restored flow in `749cf36a` exposes three more
  valid API detections already covered by KD-004. The reference cannot name
  those relocation imports; these are deliberate baseline changes rather
  than invented function-scope evidence.
- **Regression coverage:** conflicting instruction streams, genuine
  undecodable leaves, import-thunk propagation, plain versus indexed memory
  jumps, and all three affected caller chains.

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
- **Status:** accepted reference false positive. Previously attributed to
  KD-012; recovering the caller proves that no-return propagation is not its
  cause. Reproducing the match would invent a PEB access from conflicting
  instruction boundaries.

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
- **Status:** retained as a reference instruction-boundary difference,
  alongside KD-014. Removing raw call sweeps also removes this sample's
  unrelated extra `PEB access`; it does not manufacture the missing XOR loop.
