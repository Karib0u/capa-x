# Accuracy and performance

This page records the methodology behind the summary numbers in the project
README. The measurements are reproducible evidence for a pinned implementation,
ruleset, corpus, and host. They are not universal rankings.


## Allocation and architecture audit (2026-10-20)

Baseline: freshly fetched main `a203bd3`, release build on Apple M1 Max,
macOS 27.0.1, single analysis job, unchanged pinned rules and samples.
Measurements below were rerun for this audit. This is a shared workstation;
background compilation caused substantial wall-time outliers in some CLI
runs, so small end-to-end changes should not be treated as established wins.

### Implemented changes

- Scope matching borrows the feature map until the first successful rule
  needs to publish dependency features. The internal results-only entry point
  avoids returning a deep copy that scope drivers immediately discard. The
  public `match_scope` contract still returns an owned feature map.
- Completed instruction/block/thread feature sets move into their parents.
  New keys reuse their existing location trees; duplicate keys retain their
  original insertion positions and union their locations.
- Embedded-PE carving scans bytes once, deriving the only possible XOR key
  from each candidate's first byte. It previously scanned separately for all
  256 keys. Sorting successful hits by descending key and ascending offset
  preserves the reference's LIFO evidence order. Existing header bounds and
  the existing `MAX_OFFSET_PE_AFTER_MZ` limit remain unchanged.

No dependencies, rule syntax, extraction boundaries, or public result schemas
change. The matcher still clones on successful scopes, so this reduces
allocation churn without eliminating the large retained feature tree.

### Matching measurements

`scripts/bench_matching.rs` loads rules and extracts one sample once, then
runs the static matcher six times with `AnalysisOptions::SERIAL`. Run zero
warms the matcher; these are medians of runs 1 through 5. The timer includes
scope aggregation and matching, excluding extraction, rule loading, output
printing, and destruction of the returned capabilities. These measurements
isolate the allocation changes; the carving change is outside this timer.

| Sample prefix | Functions / blocks / instructions | Main | Updated | Time reduction |
|---|---:|---:|---:|---:|
| `03b236b2` | 672 / 13,046 / 55,344 | 194.36 ms | 152.48 ms | 21.5% |
| `112f9f0e` | 7,432 / 93,351 / 692,275 | 2,244.49 ms | 1,810.47 ms | 19.3% |

Alternating complete CLI runs (one warm-up per binary, three measured runs
per binary, jobs 1) illustrate why this is a phase-level claim:

| Sample prefix | Main wall median | Updated wall median | Main / updated peak RSS |
|---|---:|---:|---:|
| `03b236b2` | 1.568 s | 1.471 s | 795 / 795 MiB |
| `2826b762` | 1.107 s | 0.975 s | 680 / 680 MiB |
| `112f9f0e` | 11.110 s | 15.667 s | 1,850 / 1,852 MiB |

The last sample's updated wall times ranged from 9.786 to 16.689 s, while
main ranged from 11.087 to 11.191 s. Its matching phase still fell from a
2.427 s median to 2.009 s; the wall-time regression was in loading/recovery
while other processes were running. This run does not establish an overall
speedup, and peak RSS is effectively unchanged. Recheck complete runs on an
idle host before using these changes for end-to-end performance claims.

The instruction counts include each function's view, so shared instructions
can be counted more than once. This is the work actually sent to matching.

Build the harness against each revision's release library separately. Keep
the resulting executables before rebuilding the library:

```bash
cargo build --release -p capa-x
rustc --edition=2021 -O scripts/bench_matching.rs \
  --extern capa_x=target/release/libcapa_x.rlib \
  -L dependency=target/release/deps -o /tmp/bench-matching
/tmp/bench-matching tests/testfiles/03b236b23b1ec37c663527c1f53af3fe.dll_
/tmp/bench-matching tests/testfiles/112f9f0e8d349858a80dd8c14190e620.exe_
```

To reproduce the signature capacity inspection with the same Rust toolchain
used for the release build:

```bash
flirt_rlib=$(ls -t target/release/deps/liblancelot_flirt-*.rlib | head -n 1)
rustc --edition=2021 -O scripts/inspect_signature_allocations.rs \
  --extern lancelot_flirt="$flirt_rlib" \
  -L dependency=target/release/deps -o /tmp/inspect-signatures
/tmp/inspect-signatures capa-x/sigs/*.sig
```

For complete CLI runs, preserve the main binary before rebuilding, then run
`scripts/bench.py --samples scripts/corpus-bench.txt --jobs 1 --runs 3`
against each binary using `--capa-cli` and separate `--json` paths. Alternate
versions when comparing a small effect. Peak RSS measures the whole process;
it is not an allocation count or a measure of total allocation traffic.

### Implementation complexity versus impact

Complexity includes implementation and compatibility validation, not only
code size. Rewards for proposed work are hypotheses grounded in the audit;
they are not measured speedups or amounts of reclaimable memory.

| Optimization | Status | Complexity | Reward / impact | Main validation challenge |
|---|---|---|---|---|
| Borrow feature maps and move completed child scopes | Implemented | Low | Measured 19.3-21.5% less matching time on two samples; lower allocation churn | Preserve insertion order, location unions, dependency matches, and full evidence |
| Scan embedded PEs once across all XOR keys | Implemented | Low | Removes 256 separate byte scans; most useful on larger files | Preserve descending-key/ascending-offset order and header bounds |
| Compact and precompile bundled FLIRT signatures | Proposed | Medium-high | Largest identified cold PE memory opportunity: about 346 MiB of major parsed-buffer capacity; could also reduce initialization time | Preserve ambiguous-match ordering and custom-signature parsing; compact storage and precompilation can be separate steps |
| Use an ordered cursor for instruction coverage | Proposed | Medium | Targets a sampled recovery CPU hotspot by removing repeated B-tree predecessor searches | Preserve overlapping coverage, relocation-slot priority, and pointer-width skipping |
| Share decoded instructions and store their bytes inline | Proposed | High | Potentially substantial recovery memory and allocation reduction across overlapping function views | Preserve ownership snapshots, shared tails, and both decoder architectures |
| Add a batch CLI that reuses rules and signatures | Proposed | Low-medium | Strong reward for many small inputs: amortizes about 0.2 s of rule loading per process plus PE signature initialization | Keep per-sample metadata, errors, and output ordering isolated |
| Cache compiled rules across processes | Proposed | Medium-high | Targets about 0.2 s of repeated startup cost for independent CLI invocations | Correct invalidation for rule contents, parser versions, custom rules, and filters |
| Stream bounded batches of function features into matching | Proposed | High | Potentially substantial peak-memory reduction by releasing the complete feature tree earlier | Preserve the freeze seam, global metadata, layout, feature counts, and deterministic results |
| Intern repeated features or use small location storage | Proposed | Medium | Potentially lower allocation traffic in extraction and matching; benefit not yet quantified | Preserve feature equality, first-insertion order, and location-set behavior |

For the next small change, prioritize batch reuse for throughput or the
coverage cursor for large-sample recovery. For memory reduction, start by
prototyping compact signatures before changing the recovery and freeze models.

### Larger opportunities, ranked by workload

1. **Cold PE memory and startup: compact or precompile bundled signatures.**
   The baseline 3 KB packed PE uses about 659 MiB peak RSS, with about 0.6 s
   in loading/recovery, despite almost no analysis work. A direct probe of
   the pinned `lancelot_flirt::sig::parse` output found 711,752 signatures.
   Their vector capacities reserve 1,033,668 signature slots. Signature
   slots, pattern buffers, symbol vectors, and name strings alone account
   for approximately 346 MiB of requested capacity, excluding allocator
   overhead, tail bytes, and prefix indexes. Compact immutable arrays and a
   shared string table are the largest memory opportunity. Precompiling the
   bundled corpus could also remove runtime decompression and object
   construction. Keep runtime parsing and contextual errors for custom
   signatures, and preserve original ordering for ambiguous matches.
   `shrink_to_fit` is a smaller experiment, but cannot remove the parser's
   transient peak or the many independent allocations. No compact-storage
   speedup or memory reduction is claimed here.
2. **Large-sample recovery: avoid repeated ordered-map searches and owned
   instruction copies.** A 10-second native CPU sample on `112f9f0e` captured
   1,695 stacks. Of these, 191 were inside the import scan's coverage query,
   including 182 in B-tree range navigation. `fragment_starts` queries
   instruction coverage for each scanned address. An ordered coverage cursor
   can avoid repeated predecessor searches while preserving relocation-slot
   priority and pointer-width skipping. Separately, `build_function_view`
   copies decoded instructions, each of which owns a byte vector; tail-block
   composition clones those views again. An immutable instruction arena with
   address/index references and inline instruction bytes would reduce both
   allocation and cache pressure. Preserve function views captured at
   creation, overlapping instruction ownership, and shared-tail behavior.
   The profile samples only a window of one run, not whole-run percentages.
3. **Batch throughput: reuse rules and signatures across inputs.** Small ELF
   samples take about 0.21-0.24 s, almost all in rule loading. The library
   already accepts a reusable `MatchingRuleSet`, and bundled signatures
   already use `OnceLock`; a batch CLI can expose this amortization without a
   new analysis abstraction. For independent single-file processes, a
   versioned compiled-rule cache would need content-based invalidation for
   rule sources and parser semantics, including custom rules and errors.
4. **Large-sample retained memory: stream completed function features into
   matching.** The current API materializes the entire `Freeze` tree before
   matching and builds location sets at each nested scope. A bounded batch
   of per-function extraction/matching could release features earlier while
   retaining ordered results, feature counts, and layout metadata. Keep the
   freeze import/export seam available for parity tests. First measure live
   allocations by phase: peak RSS alone cannot distinguish signature storage,
   decoded-code copies, and the retained feature tree. Interning repeated
   mnemonic/characteristic strings and small location storage are secondary
   candidates after that measurement.

Adding more workers does not remove these costs. In the baseline ten-sample
run, extraction plus matching accounts for a median 1.3% of total time and
at most 27.7%. Those fractions describe these samples only. No change to
hashing, evidence order, or feature-set insertion order is proposed.


### Compatibility checks

- `cargo test -p capa-x --test features_parity`: all four tests pass.
- `cargo test --workspace`: 454 tests pass; six slow gates remain ignored.
- Full JSON from freshly run main and updated binaries agrees for all 29
  samples in the union of the smoke and benchmark corpora at jobs 1.
  Only invocation metadata is normalized; evidence order and duplicates
  remain observable.
- The full smoke differential against pinned Python capa 10.0.0 agrees on all
  23 samples and 731 reference-matched rules, with zero missing/extra rules.
  Rust results were recomputed with `--no-rust-cache`; all retained Python
  reference documents were checked to report version 10.0.0.
- `scripts/determinism.py --samples scripts/corpus-jobs.txt --jobs 1,2,4
  --repeat 2 --workers 3`: all 30 runs across five samples agree byte for byte.
- `cargo +1.98.1 clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --all -- --check`, `git diff --check`, `scripts/check_env.sh`,
  and all six Python harness tests pass. The explicit Clippy toolchain
  recognizes the repository's existing MSRV-preserving lint attributes.
- Regression tests cover all 256 carving keys, repeated candidates,
  key/offset output order, starting offsets, truncated headers, and the
  existing PE-header distance bound. Matcher tests compare full evidence
  against the exhaustive evaluator, including dependent and namespace rules;
  owned merge tests check empty locations, insertion order, and deduplication.

These performance measurements cover static PE/ELF workloads. Dynamic matching
uses the same borrowing optimization and passes its existing workspace tests,
but no dynamic throughput or memory claim is made. The larger representation
changes above remain proposals and need their own measurements and parity gates.

## Instruction-stream and switch compatibility (capa 10.0.0)

Measured on 2026-10-20 after updating to main `292b7c5`. The release binary
was rebuilt and every sample was analyzed with `--no-rust-cache`; the pinned
Python reference cache was retained. Fresh workspace traces independently
verified the four former divergences and the two candidate-classification
regressions found and fixed during development. Rules, signatures, and corpus
pins are unchanged.

| Corpus | Samples | Reference-matched rules | Missing | Extra | Identical rule sets |
|---|---:|---:|---:|---:|---:|
| Outer | 200 | 6,300 | 0 | 0 | 200/200 |
| Smoke | 23 | 731 | 0 | 0 | 23/23 |

Both corpora have 100.00% matched-rule agreement and zero analysis errors.
This measures rule names on the pinned binaries. It does not claim identical
instruction boundaries, match addresses, or complete JSON evidence for
arbitrary binaries. Freeze-driven tests separately cover matching and result
construction from shared features.

The implementation has no sample-address or rule-name exceptions:

- Preserve the first opcode location while decoding each function block's
  byte interval independently. Interior branch entries reproduce KD-014 and
  KD-015. Codeflow visits callees before caller continuations.
- Decode the pinned reference's BOUND and MOV/POP ModRM aliases in
  compatibility mode. Native decoding retains EVEX support.
- Apply candidate evaluation to consecutive switch-table entries. Definite
  rejection stops the table, including when a selector skips that entry.
  Fresh traces identify divide-by-zero anomalies as the cause of KD-008's
  missing arms, correcting its earlier ownership attribution.
- Reject decoder anomalies and output instructions across candidate paths.
  This protects the real XOR loop on `5dd0b130` and prevents data on
  `648fc498` from becoming a false pusha/popa match.

The outer expected file deliberately removes only the four prior differences.
The smoke baseline already contained zero differences and stays unchanged.
Native extraction retains its prior decoding and guarded-switch policy.

Reproduction:

```bash
cargo build --release
python3 scripts/difftest.py --mode full --samples scripts/corpus-outer.txt \
  --capa-cli target/release/capa-x --jobs 6 --no-rust-cache
python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt \
  --capa-cli target/release/capa-x --jobs 6 --no-rust-cache
cargo test -p capa-x --test features_parity
cargo test --workspace
cargo test --workspace -- --ignored
cargo +1.98.1 clippy --workspace --all-targets -- -D warnings
python3 -m unittest discover -s scripts -p 'test_*.py'
scripts/check_env.sh
```

Validation: 462 ordinary Rust tests and all six separately run slow acceptance
and robustness gates passed, for 468 Rust tests total. All four feature-parity
tests passed. Clippy passed on the installed 1.98.1
toolchain, which recognizes the repository's existing lint attributes.
All six Python harness tests and the pinned-environment check passed.

Determinism: 72 runs at jobs 1, 2, and 4, with two repetitions per job
count over 12 samples, match the single-job result byte for byte after the
harness's standard metadata normalization. The sample list combines
`corpus-jobs.txt`, the four former divergence samples, `5dd0b130`,
`648fc498`, and the overlapping relocation-call fixture `749cf36a`.
The generated list and reports are under `target/compatibility-*`.

```bash
python3 scripts/determinism.py --samples target/compatibility-determinism.txt \
  --capa-cli target/release/capa-x --jobs 1,2,4 --repeat 2 --workers 6
```

## Loader and import-call ownership compatibility (capa 10.0.0)

Measured on 2026-10-20 against freshly fetched main `d660eec`. Both sides
used newly built release binaries and fresh sample analysis with
`--no-rust-cache`; the pinned Python reference cache was retained. Rules,
signatures, and corpus pins are unchanged. This measures matched rule names
per sample, not exact evidence locations or full JSON equivalence.

| Outer corpus | Main | Updated |
|---|---:|---:|
| Samples / reference-matched rules | 200 / 6,300 | 200 / 6,300 |
| Missing / extra rules | 2 / 16 | 2 / 2 |
| Total divergences | 18 | 4 |
| Rule-level agreement | 99.71% | 99.94% |
| Identical matched-rule sets | 190/200 | 196/200 |
| Analysis errors | 0 | 0 |

Six samples improve and none regress. The 23-sample smoke corpus improves
from 22 identical samples and six extra rules to 23 identical samples and
zero differences against 731 reference-matched rules. Both expected files
are deliberately refreshed to lock in these improvements.

- Reference ELF import classification removes six extras on `749cf36a`.
  Native recovery retains the broader relocation bindings.
- Full PE workspace section names remove two extras on `2826b762`.
  File-only extraction retains the separate pefile naming contract.
- Import-call discovery order and function views captured at creation
  remove six extras on `1e9fc7f3`, `31600ad0`, `50d5ee1c`, and `a563c50c`.
  Respecting relocation pointer locations protects `6f99a2c8` from a
  premature import-call scan that otherwise hides a signature-created
  function. Regression tests cover that sample and the ownership boundaries.
- A separate file-only parity check exposed format features at the wrong
  scope on PE and ELF. The API now puts them at file scope for file-only
  extraction while full analysis retains global format features.

The four remaining differences are KD-008's switch-arm ownership extra,
KD-014/KD-015's overlapping-instruction misses, and KD-016's EVEX decoder
extra. The pinned Base64 rule explicitly disables its Vivisect example for
the last case. No sample-specific addresses or rule names are used in the
implementation to force agreement.

Validation:

- `cargo test --workspace`: 450 passed; six slow gates ignored.
- `cargo test --workspace -- --ignored`: all six acceptance and robustness
  gates passed, for 456 Rust tests in total.
- `cargo +1.98.1 clippy --workspace --all-targets -- -D warnings`: passed.
  The default installed Clippy rejects pre-existing
  `chunks_exact_to_as_chunks` lint attributes; the newer installed toolchain
  recognizes them without suppressing warnings.
- `python3 -m unittest discover -s scripts -p 'test_*.py'`: six passed.
- File-only feature and result comparison: all 23 smoke samples match,
  plus the embedded-NUL section sample `2826b762`.
- Determinism: 90 runs at jobs 1, 2, and 4, with two repetitions per job
  count over 15 samples, match single-job output byte for byte after the
  harness's metadata normalization. The sample list is the union of
  `corpus-jobs.txt`, main `d660eec`'s ten differing outer-corpus samples,
  and the `6f99a2c8` relocation regression sample.
- `cargo fmt --all -- --check`, `git diff --check`, and
  `scripts/check_env.sh`: passed.

Reproduction commands:

```bash
cargo build --release
python3 scripts/difftest.py --mode full --samples scripts/corpus-outer.txt \
  --capa-cli target/release/capa-x --jobs 6 --no-rust-cache
python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt \
  --capa-cli target/release/capa-x --jobs 6 --no-rust-cache
python3 scripts/difftest.py --mode file-features --samples scripts/corpus-smoke.txt \
  --capa-cli target/release/capa-x --jobs 6 --no-expected
```

## Callback recovery and compatibility seed policy (capa 10.0.0)

Measured on 2026-10-20 against main `1943f82`, using fresh release analyses
with `--no-rust-cache` and the verified capa 10.0.0 reference results.
Host: Apple M1 Max, macOS 27.0.1, arm64. Rules, signatures, and corpus pins
are unchanged. This measures matched rule
names per sample, not exact evidence addresses or full JSON equivalence.

| Outer corpus | Main | Updated recovery |
|---|---:|---:|
| Samples / reference-matched rules | 200 / 6,300 | 200 / 6,300 |
| Missing / extra rules | 12 / 27 | 2 / 16 |
| Total divergences | 39 | 18 |
| Rule-level agreement | 99.38% | 99.71% |
| Identical matched-rule sets | 181/200 | 190/200 |
| Analysis errors | 0 | 0 |

Eleven samples improve and no sample regresses. The smoke corpus improves
from 1 missing / 9 extra and 19/23 identical samples to 0 missing / 6 extra
and 22/23 identical samples. Both expected files are deliberately refreshed
to retain these improvements.

The changes address three causes:

- Callback arguments and the x86 LEA data-pointer monitor recover ten
  missing rules across `a70052c4`, `253309d8`, `c335a9d4`, and `49a34cfb`.
- Removing broad prologue and raw call sweeps from x86/x64 compatibility mode
  removes ten extras. The initial experiment lost `create pipe` on
  `74e0758e`; implementing the reference's `xadd` semantics recovers its
  relocation-backed root and eliminates that regression. Native mode keeps
  the broad scans, as does AArch64 recovery.
- Honoring the stored pointer for ELF relative relocations removes the
  `e5e8c139` loop extra. Native mode retains addend-based discovery.

The remaining 18 differences are mapped in `KNOWN_DIVERGENCES.md`: two
instruction-boundary misses (KD-014/KD-015), eight function-ownership extras
(KD-008), six reference ELF-import differences (KD-004), and two PE-section
name differences (KD-009). These results do not establish 100% compatibility.

Validation on the final source:

- `cargo test --workspace`: 445 passed.
- `cargo test --workspace -- --ignored`: all 6 slow robustness and acceptance
  gates passed, for 451 Rust tests in total.
- `python3 -m unittest discover -s scripts -p 'test_*.py'`: all 6 tests passed.
- `cargo test -p capa-x --test features_parity --test aarch64_features_parity`:
  all 6 fixture tests passed.
- `cargo +1.98.1 clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo fmt --all -- --check`, `git diff --check`, and `scripts/check_env.sh`:
  passed.
- Determinism: 66 runs at jobs 1, 2, and 4, with two repetitions over 11
  samples, matched single-job output byte for byte after the harness's
  normal metadata normalization. The samples are `corpus-jobs.txt` plus
  `a70052c4`, `253309d8`, `c335a9d4`, `49a34cfb`, `74e0758e`, and `e5e8c139`.
- AArch64 BinExport comparison: all 3 samples and 29 reference-matched rules
  agree. AArch64 retains its existing function-entry recovery policy.
- All 89 x86 and 83 x64 callback API definitions were checked against the
  installed Vivisect 1.3.2 tables, including argument positions and x86
  calling conventions.

Reproduce the final comparison and deliberate baseline refresh:

```bash
cargo build --release -p capa-x-cli
python3 scripts/difftest.py --mode full --samples scripts/corpus-outer.txt \
  --capa-cli target/release/capa-x --jobs 6 --no-rust-cache --write-expected
python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt \
  --capa-cli target/release/capa-x --jobs 6 --no-rust-cache --write-expected
```

## Pointer and unreferenced-function discovery (capa 10.0.0)

Measured on 2026-10-20 against main `69070db` and the KD-002/KD-003
implementation described in ADR 0007. Both release binaries were freshly
analyzed with `--no-rust-cache`, using the verified pinned capa 10.0.0
reference cache. This compares rule names, not exact evidence addresses.

| Outer corpus | Main | Candidate evaluation |
|---|---:|---:|
| Samples / reference-matched rules | 200 / 6,300 | 200 / 6,300 |
| Missing / extra rules | 51 / 32 | 12 / 27 |
| Total divergences | 83 | 39 |
| Rule-level agreement | 98.68% | 99.38% |
| Identical samples | 165/200 | 181/200 |
| Analysis errors | 0 | 0 |

Twenty samples improve by the per-sample difference count; no sample's
count increases, and no new rule-level difference is introduced. The smoke
corpus improves from 8 missing / 10 extra to
1 missing / 9 extra, with identical samples increasing from 16/23 to 19/23.
Both expected files are deliberately updated to preserve these gains.

Representative changes:

| Sample prefix | Diffs before / after | Evidence |
|---|---:|---|
| `112f9f0e` | 3 / 0 | Operand-reference candidates recover hook and keyboard capabilities |
| `294b8db1` | 4 / 0 | Pointer and emucode discovery expose missing Linux capabilities |
| `2f7f5fb5` | 1 / 0 | Recover AES through newly discovered code |
| `b5f0524e` | 3 / 0 | Accept pointer-only roots without registered entry signatures |
| `512a5575` | 3 / 0 | Recover RC4/modulo and io_uring without the API callback monitor |
| `49a34cfb` | 4 / 1 | Recover stackstrings, MD5, and credit-card parsing |
| `70fd3347` | 6 / 3 | Recover three missing rules; KD-014's overlapping PEB block remains |
| `e17e6a79` | 2 / 0 | Prevent unbounded indexed jumps from absorbing adjacent pointer tables |
| `a70052c4` | 7 / 7 | Live creation tracing attributes the remaining roots to KD-007 callbacks |

The ELF table correction is necessary alongside pointer discovery:
`i386Opcode.getBranches` labels only scale-four SIB operands as `BR_TABLE`.
The old fallback also scanned scale-eight operands until a non-code pointer,
swallowing adjacent tables and defining unrelated addresses as instructions.
Recognized guarded absolute tables now use the actual selector bound; other
scale-eight operands remain unresolved. This removes the two `e17e6a79`
extras previously attributed to pointer classification.

The candidate-source tests also distinguish RIP-relative LEA from absolute
x86 LEA. `i386ImmMemOper.getOperValue` returns no static value without an
emulator for the latter. Treating it as a `REF_PTR` incorrectly introduced
`check OS version` on `49a34cfb`: `lea ecx,[0x456850]` at `0x43979f`
created a speculative function whose call exposed `0x4397f0`. The pinned
workspace holds `0x456850` as a four-byte data location, never evaluates it
as an emucode candidate, and has no function at `0x4397f0`. Restricting LEA
candidate references to the decoder-supported RIP-relative form removes
that extra without losing the three recovered rules.

Validation of the final implementation:

- `cargo test --workspace`: 437 passed, 6 slow gates ignored.
- `cargo test -p capa-x --test features_parity`: 4 passed.
- `cargo +1.98.1 clippy --workspace --all-targets -- -D warnings`: passed.
  The default 1.96 toolchain rejects existing MSRV-preserving lint annotations.
- `cargo fmt --all -- --check`, `git diff --check`, `scripts/check_env.sh`,
  and all 6 Python script tests: passed.
- Determinism: 72 runs at jobs 1, 2, and 4, with two repetitions per job
  count over 12 samples, matched the single-job output byte for byte.
  The set comprises `corpus-jobs.txt` plus `b5f0524e`, `2f7f5fb5`,
  `294b8db1`, `6f99a2c8`, `e17e6a79`, `49a34cfb`, and `a70052c4`.

Reproduce the rule comparison and deliberate baseline refresh:

```bash
cargo build --release
python3 scripts/difftest.py --mode full --samples scripts/corpus-outer.txt \
  --capa-cli target/release/capa-x --jobs 6 --no-rust-cache
python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt \
  --capa-cli target/release/capa-x --jobs 6 --no-rust-cache
```

Add `--write-expected` only when deliberately recording the same change.

## Recovery gap verification (capa 10.0.0)

Measured on 2026-10-20 against latest main `b3835e1` and the recovery fixes
described in KD-010 through KD-012. Both release binaries were run over all
200 samples with `--no-rust-cache`; the reference cache was checked against
the pinned capa 10.0.0 version and rules, replacing stale 9.4.0 entries.
This is a rule-name comparison, not an exact-address or performance claim.

| Outer corpus | Main | With recovery fixes |
|---|---:|---:|
| Reference-matched rules | 6,300 | 6,300 |
| Missing / extra rules | 57 / 31 | 51 / 32 |
| Total divergences | 88 | 83 |
| Rule-level agreement | 98.60% | 98.68% |
| Identical samples | 162/200 | 165/200 |
| Analysis errors | 0 | 0 |

Only the six investigated samples change:

| Sample prefix | Diffs before / after | Reason |
|---|---:|---|
| `0cd2b334` | 2 / 0 | Recover resource-hosted code and preserve callees after a walk budget |
| `29a76e41` | 1 / 0 | Contain fallthrough at independent unwind starts |
| `2f7f5fb5` | 3 / 1 | Keep plain pointer-jump targets out of the caller's extent |
| `3fdfb2d5` | 1 / 0 | Honor the declared empty import lookup table |
| `70fd3347` | 7 / 6 | Restore caller continuation after a conflicting instruction start |
| `749cf36a` | 4 / 6 | Restore modulo detection and three valid API detections covered by KD-004 |

The last row deliberately increases the raw difference count: its one missing
rule is recovered, while the reference cannot name the three newly exposed
relocation imports. Those API detections are already accepted by KD-004.
The smoke corpus includes this sample, so its baseline changes from 9 missing
and 7 extra to 8 missing and 10 extra, with 16/23 samples still identical.
Both expected files are updated with this change; no other sample regresses.

`PEB access` on `70fd3347` remains a reference-only overlapping-block artifact,
not a remaining no-return gap. The pinned CLI and extractor were rerun with
the pinned signatures to verify the offset inside the push operand. KD-014
records that evidence. The caller itself now contains all 31 instructions.

Validation on the final implementation:

- `cargo test -p capa-x --test features_parity`: 4 passed.
- `cargo test --workspace`: 415 passed, 6 slow gates ignored.
- `cargo +1.98.1 clippy --workspace --all-targets -- -D warnings`: passed.
  The default 1.96 toolchain rejects pre-existing
  `clippy::chunks_exact_to_as_chunks` annotations as unknown lints.
- `cargo fmt --all -- --check`, `git diff --check`,
  `scripts/check_env.sh`, and all 6 Python script tests: passed.
- Determinism: 66 repeated runs at jobs 1, 2, and 4 over the five existing
  jobs-corpus samples plus the six samples above were byte-identical to
  the single-job baseline, including evidence ordering.

Reproduce the rule comparisons against each release binary:

```bash
python3 scripts/difftest.py --mode full --samples scripts/corpus-outer.txt \
  --capa-cli target/release/capa-x --jobs 6 --no-rust-cache
python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt \
  --capa-cli target/release/capa-x --jobs 6 --no-rust-cache
```

## capa 10.0.0 compatibility

Measured on commit `626f74e`, before static switch recovery, on 2026-10-20
against the capa and capa-rules v10.0.0 commits in
[`PINNED.md`](../PINNED.md), with the existing pinned sample corpus.
Reference results were generated afresh for this version, in a separate
`.cache/capa10/` directory. The historical release measurements below still
refer to capa 9.4.0.

| Check | Result |
|---|---:|
| Unmodified rules parsed | 1,054 |
| Native 200-sample rule-name comparison | 98.56%; 161/200 identical; 61 missing and 30 extra of 6,300 reference rules |
| Native smoke regression gate | No regressions; 16/23 identical, 16 known rule divergences |
| Freeze rule names and match addresses | 62/62 samples identical |
| Full JSON evidence from shared freezes | 62/62 samples identical |
| Native .NET rule names | 8/8 samples identical; 228/228 reference rules |
| AArch64 ELF against BinExport2 | 2/3 identical; 1 missing of 29 reference rules (`KD-013`) |
| Reproducible v10 freezes and v10 result-document schema | 10/10 fixtures; jobs 1 and 4 identical |

The native `full` mode compares rule names; the freeze modes also check
match addresses and JSON evidence. All 91 native divergences matched the
recorded baseline at that commit. Static switch recovery subsequently updates
two baseline rows as documented below. The combined main baseline and the
subsequent recovery fixes are measured in the preceding section.

The JSON comparison ignores invocation metadata, synthetic rule suffixes,
and ordering in location sets and spliced match/subscope evidence. Ordinary
And/Or/Some child order remains significant. The determinism check preserves
all evidence ordering, including the ordering ignored for Python parity.

The compatibility changes cover .NET backward-branch loops, CLR metadata row
one, global-only .NET format features, recursive rule optimization, numeric
zero versus `NO_ADDRESS` evidence, ELF import virtual addresses, signed hex
and operand counts in rules, count descriptions, and subscope metadata.
The .NET and AArch64 assertion tables now come from upstream's JSON fixture
manifests. Ten result-document fixtures were regenerated with capa 10.0.0.

An additional file-only extractor probe on the 23 smoke samples reports only
the existing format-placement difference: Python's `PefileFeatureExtractor`
and `ElfFeatureExtractor` emit `format` at file scope, while the full native
backend emits it globally, as Vivisect does. All other dumped file/global
features agree. The PE format-placement difference was also reproduced with
capa 9.4.0; this probe is distinct from the full native rule comparison.

Reproduction (after `scripts/setup_dev.sh` and `cargo build --release`):

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/difftest.py --mode json --samples scripts/corpus-freeze.txt \
  --capa-cli target/release/capa-x --cache-dir .cache/capa10/interop --jobs 6
python3 scripts/difftest.py --mode freeze --samples scripts/corpus-freeze.txt \
  --capa-cli target/release/capa-x --cache-dir .cache/capa10/interop --jobs 6
python3 scripts/difftest.py --profile dotnet --mode full \
  --samples scripts/corpus-dotnet.txt --capa-cli target/release/capa-x \
  --cache-dir .cache/capa10/dotnet --jobs 6
python3 scripts/difftest.py --profile aarch64-binexport --mode full \
  --samples scripts/corpus-aarch64.txt --capa-cli target/release/capa-x \
  --cache-dir .cache/capa10/aarch64 --jobs 3
python3 scripts/difftest.py --mode full --samples scripts/corpus-outer.txt \
  --capa-cli target/release/capa-x --cache-dir .cache/capa10/outer --jobs 6
```

## Static switch recovery verification (capa 9.4.0)

Measured on 2026-10-20 on a MacBook Pro M1 Max (10 CPUs), macOS 27.0.1
build 26A434, against capa and capa-rules 9.4.0, before integration with
capa 10. The before binary was built from `8309d6c`; the after binary
corresponds to `2c4b1b6`, which adds the bounded static switch resolver.
These results do not measure the combined capa 10 branch.
Both runs used `--no-rust-cache`. Python reference results use the harness's
normal pinned-reference cache.

| Corpus | Before | After |
|---|---|---|
| Outer, 200 samples / 6,263 reference-matched rules | 61 missing, 30 extra; 161 identical | 57 missing, 31 extra; 162 identical |
| AArch64 BinExport2, 3 samples / 29 reference-matched rules | 1 missing, 0 extra; 2 identical | 0 missing, 0 extra; 3 identical |

The outer run has no baseline regressions and no analysis failures.
Only two outer samples change: `276f691a` loses its three missing rules,
and `f5903519` gains `log keystrokes via Input Method Manager` plus
`check for unmoving mouse cursor`. The latter is an additional valid rule
match against code the reference leaves without function ownership, not a
merged-function artifact: both cursor calls are inside the same PE unwind
interval. See KD-008 for the addresses and attribution. These are the
deliberate changes recorded in `scripts/corpus-outer.expected.json`.
The smoke corpus remains at 9 missing / 7 extra and 16/23 identical samples,
with no baseline regressions.

Reproduction commands (substitute the saved before binary for the CLI path
to repeat the before side):

```bash
python3 scripts/difftest.py --mode full --samples scripts/corpus-outer.txt \
  --capa-cli target/release/capa-x --no-rust-cache --jobs 6
python3 scripts/difftest.py --profile aarch64-binexport --mode full \
  --capa-cli target/release/capa-x --no-rust-cache --jobs 3
python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt \
  --capa-cli target/release/capa-x --no-rust-cache --jobs 6
```

All ten switch regression tests, the x86 and AArch64 feature-parity suites,
and `cargo test --workspace` pass. The AArch64 fixture exceptions are
removed. The release-profile robustness test passes all 900 mutated ELF
samples with `--include-ignored`. Clippy passes with Rust 1.98.1 and
`--workspace --all-targets -- -D warnings`; builds and tests use Rust 1.96.0.
Determinism checks cover `scripts/corpus-jobs.txt` plus the three switch
samples: 24 runs at job counts 1, 2, and 4 are byte-identical to the
single-worker results.

```bash
cargo test -p capa-x --lib extract::recovery::switch
cargo test -p capa-x --test features_parity --test aarch64_features_parity
cargo test --workspace
cargo test --release -p capa-x --test aarch64_elf_fuzz -- --include-ignored
cargo +1.98.1 clippy --workspace --all-targets -- -D warnings
```

## Historical v1.0.0 accuracy (capa 9.4.0)

This release accuracy result was measured on the release tree against Python
capa 9.4.0 and the pinned capa-rules release over the 200-sample corpus in
`scripts/corpus-outer.txt`. The exact command, host, failures, and timeouts
are recorded in the release measurement log below.

| Metric | capa-x |
|---|---:|
| Rule-level agreement | **98.55%** |
| Reference-matched rules | 6,263 |
| Divergent rules | 91: 61 missing, 30 extra |
| Samples with identical rule sets | 161/200 (80.5%) |

Rule-level agreement is the headline because it measures individual rules
instead of treating a one-rule difference and a hundred-rule difference as the
same failed sample. Every measured difference is assigned to a root-cause
class in [`../KNOWN_DIVERGENCES.md`](../KNOWN_DIVERGENCES.md).

### Native backend accuracy

The x86/x64 PE/ELF/shellcode numbers above are the floor, not the scope.
One fresh run per native backend, all on the v1.0.0 release tree:

| Backend | Oracle | Metric | Result |
|---|---|---|---:|
| .NET / CLR (`-f dotnet`) | Python capa 9.4.0 + `dnfile` | Rule-level agreement | **100%** (0/225 rules, 8/8 samples identical) |
| Mach-O x86_64 + AArch64 (`-f macho`) | No Python oracle -- hand-built fixture corpus | Structure/feature fixture rows | **30/30** (`macho_features.rs`) |
| AArch64 PE | No Python oracle -- hand-built fixture corpus | Feature fixture rows | **15/15** (`aarch64_pe_features.rs`) |
| AArch64 ELF | Pinned Ghidra BinExport2 (no raw-AArch64 Python oracle) | Feature-presence table | **79/80** (1 upstream-documented gap) |
| AArch64 ELF | Pinned Ghidra BinExport2 | Rule-level agreement | **96.55%** (1/29 rules, 2/3 samples identical; the one divergence is `KD-013`) |

Mach-O and AArch64-PE have no Python-capa oracle at all -- pinned capa 9.4.0
accepts neither as raw input -- so their gate is a fixture table built from
`otool`/`nm`/`llvm-readobj` cross-checks and evidence addresses, not a
percentage. AArch64 ELF's rule-level number, unlike the PE/ELF/.NET numbers
above, compares against Ghidra's BinExport2 export rather than against
Python capa directly; see the [compatibility matrix](../README.md#compatibility-matrix)
for which class each backend belongs to.

### Cross-implementation coverage

The release gate compares capa-x directly with pinned Python capa 9.4.0 on
the full 200-sample corpus. The result document binding gate also validates
all 200 native result documents with Python capa's own schema parser and
compares their matched rule names with the CLI. No separate comparison with a
third-party Rust port is used as release evidence.

## Controlled runtime comparison

Measured on the v1.0.0 release tree using a MacBook Pro M1 Max (arm64, 10
logical CPUs) running macOS 26.6 (25G72). The input was
`tests/testfiles/Practical Malware Analysis Lab 18-03.exe_`, selected because
both tools produced valid JSON with the same user-visible capability rule set.

All tools used the pinned rules and the same FLIRT signature files. Each tool
received one warm-up run followed by five measured runs.

| Tool | Median | Peak RSS |
|---|---:|---:|
| capa-x | 0.959 s | 607 MiB |
| Python capa 9.4.0 | 3.007 s | Not recorded |

This is a result-equivalent check on one sample, not a universal speed claim.
The release-wide Rust scaling gate below is the performance evidence for
parallel analysis. The benchmark harness records Python wall time but not
Python peak RSS, so that cell is intentionally not reported.

## Parallel scaling

Ten PE and ELF samples from `scripts/corpus-bench.txt`, median of five warm
runs per job count on the same 10-core host, on the v1.0.0 release tree.

| Jobs | Total | Relative to `--jobs 1` |
|---:|---:|---:|
| 1 | 77.374 s | 1.00x |
| 2 | 59.009 s | 1.31x |
| 4 | 44.047 s | 1.76x |
| 10 (default) | 37.199 s | **2.08x** |

Per sample the median speedup is **2.03 times** and the worst is 1.52 times;
no sample is slower in parallel. The parallel extraction and matching seams
account for a median 8.6% of serial time and at most 71.3% on this corpus.
File loading and recovery stay serial by design and dominate the largest
sample, which is what limits end-to-end scaling there.

The performance acceptance bar asks for a median per-sample speedup of at least
1.5 times with no sample below 0.91 times, and this run meets it. The fresh
phase totals were rules 2.068 s, load and recovery 32.025 s, extraction
0.481 s, matching 42.415 s, result construction 0.032 s at `--jobs 1`; the
corresponding total at the default job count was 37.199 s.

## Reproduce the measurements

Set up the pinned development environment first:

```bash
scripts/setup_dev.sh
cargo build --release
```

Run the accuracy, determinism, and macro benchmark harnesses:

```bash
python3 scripts/difftest.py --mode full \
  --samples scripts/corpus-outer.txt --capa-cli target/release/capa-x \
  --no-rust-cache
python3 scripts/determinism.py \
  --samples scripts/corpus-jobs.txt --capa-cli target/release/capa-x
python3 scripts/bench.py \
  --samples scripts/corpus-bench.txt --capa-cli target/release/capa-x \
  --jobs 1,2,4,default --runs 5 --markdown
```

The controlled comparison uses `scripts/compare_bench.py`. Its `--capa-rs`
flag is required and expects a locally built binary of the third-party
[`capa` crate](https://crates.io/crates/capa) 0.5.2 (its `capa_cli` example);
that column is informational output of the harness only and is not release
evidence -- the published table above reports the capa-x and Python capa
columns:

```bash
python3 scripts/compare_bench.py \
  --samples scripts/corpus-bench-valid.txt \
  --capa-rs /path/to/capa_cli --runs 5
```

Use `--no-rust-cache` with the differential harness when the acceptance
question requires live runs rather than cached results. Record the host,
version, pins, sample list, warm-up count, run count, failures, and timeouts
with any published result.

## Boolean matching and recovery lookup (2026-10-20)

Fresh comparison of `8309d6c` against the local boolean-precheck and
smaller-set recovery-intersection changes. Host: Apple M1 Max, 10 logical
CPUs, macOS 27.0.1, arm64; Rust 1.96.0. Both binaries use release builds,
unchanged pinned rules and signatures, and `--jobs 1`. Each of the ten
samples in `scripts/corpus-bench.txt` received one warm-up and three measured
runs per binary. Builds and correctness checks ran outside the timed runs.

| Sample | Before wall | After wall | Speedup |
|---|---:|---:|---:|
| `Practical Malware Analysis Lab 01-02.exe_` | 0.876 s | 0.858 s | 1.02x |
| `03b236b23b1ec37c663527c1f53af3fe.dll_` | 4.854 s | 2.507 s | 1.94x |
| `112f9f0e8d349858a80dd8c14190e620.exe_` | 61.089 s | 21.370 s | 2.86x |

For the largest PE, load/recovery fell from 24.967 s to 6.164 s and matching
from 35.076 s to 14.343 s. These phases are measured separately; load/recovery
also includes loading and FLIRT, whose implementation was unchanged.

Across all ten samples, the sum of per-sample median wall times fell from
71.661 s to 29.359 s (2.44x), while the median per-sample speedup was 1.10x.
The packed `2826b762...exe_` sample was 4.6% slower overall (1.163 s to
1.216 s), despite slightly faster matching; its load/recovery phase increased.
There were no failed samples or timeouts. These results are a serial
before/after comparison, not a measurement of the J3 parallel-scaling gate.

The baseline executable was copied before editing the source. Commands:

```bash
cargo build --release -p capa-x-cli
mkdir -p /tmp/capa-x-first-two-optimizations
cp target/release/capa-x /tmp/capa-x-first-two-optimizations/capa-x-before
python3 scripts/bench.py --samples scripts/corpus-bench.txt \
  --capa-cli /tmp/capa-x-first-two-optimizations/capa-x-before \
  --jobs 1 --runs 3 --json /tmp/capa-x-first-two-optimizations/before.json
# Apply the source changes, run correctness checks, then rebuild.
cargo build --release -p capa-x-cli
python3 scripts/bench.py --samples scripts/corpus-bench.txt \
  --capa-cli target/release/capa-x \
  --jobs 1 --runs 3 --json /tmp/capa-x-first-two-optimizations/after.json
```

Validation on this patch:

- `cargo test -p capa-x --test features_parity`: 4 passed.
- `cargo test --workspace`: 381 passed, 6 slow tests ignored.
- `cargo fmt --all -- --check`: passed.
- Strict Clippy stopped on pre-existing `clippy::chunks_exact_to_as_chunks`
  annotations unknown to Clippy 0.1.96. Running
  `cargo clippy --workspace --all-targets -- -D warnings -A unknown-lints`
  passed.
- `python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt --capa-cli
  target/release/capa-x --jobs 6 --no-rust-cache`: no regressions across
  23 samples; the 7 differing samples stayed within the recorded baseline.
- `python3 scripts/determinism.py --samples scripts/corpus-jobs.txt --capa-cli
  target/release/capa-x --jobs 2,4 --repeat 2 --workers 2`: all 20 parallel
  runs across 5 samples matched the normalized single-threaded output.
- Direct old/new comparison at `--jobs 1`: all ten benchmark samples had
  identical complete result documents and `--dump-code-layout` output.
  The three committed static, .NET and dynamic freeze fixtures also had
  identical result documents. Only result metadata `timestamp` and `argv`
  were removed; evidence, locations, match multiplicity and list order were
  retained.

## Feature-indexed matching and shared signatures (2026-10-20)

This comparison starts from the already optimized working tree containing
boolean-only quick matching and smaller-set block-boundary intersection.
It measures only the additional rule index and embedded-signature cache.

The index selects positive features required by each rule, keeps a fallback
for rules that can match without them, and activates rule/namespace dependents
in the original topological order. Regex, substring, bytes and OS leaves use
conservative type buckets and retain their original evaluator. The signature
cache shares immutable bundled databases across calls; custom paths still
reload every time. No dependencies were added.

Fresh release measurements on the same host, `--jobs 1`, one warm-up and
three measured runs per binary and sample. Values are medians; RSS is peak
process memory in MiB. The initial full-corpus runs were sequential, with
all old-binary measurements preceding all new-binary measurements.

| Sample | Before wall s | After wall s | Before matching s | After matching s | Before MiB | After MiB |
|---|---:|---:|---:|---:|---:|---:|
| `Practical Malware Analysis Lab 01-02.exe_` | 0.996 | 0.958 | 0.007 | 0.002 | 658 | 665 |
| `Practical Malware Analysis Lab 10-03.sys_` | 1.235 | 1.208 | 0.007 | 0.002 | 660 | 663 |
| `bb38149ff4b5c95722b83f24ca27a42b.elf_` | 0.253 | 0.256 | 0.010 | 0.002 | 62 | 64 |
| `368239d36d221d8877a07ab6799e643a.elf_` | 0.240 | 0.242 | 0.008 | 0.003 | 62 | 64 |
| `055da8e6ccfe5a9380231ea04b850e18.elf_` | 0.257 | 0.280 | 0.007 | 0.002 | 61 | 63 |
| `79cde1aa711e321b4939805d27e160be.exe_` | 1.633 | 1.084 | 0.064 | 0.014 | 673 | 678 |
| `03b236b23b1ec37c663527c1f53af3fe.dll_` | 2.865 | 1.810 | 1.461 | 0.225 | 720 | 797 |
| `a198216798ca38f280dc413f8c57f2c2.exe_` | 1.029 | 1.026 | 0.063 | 0.013 | 661 | 671 |
| `2826b762b9c268601a44974ef469a671b441e798a6c3cbb40070450c6c030ba2.exe_` | 1.957 | 1.293 | 0.063 | 0.033 | 669 | 681 |
| `112f9f0e8d349858a80dd8c14190e620.exe_` | 22.569 | 18.828 | 15.166 | 5.201 | 1623 | 1924 |

Host timing varied materially: even the unchanged recovery work on the large
sample moved from 6.55 s to 13.20 s between these initial runs. Do not attribute
all wall-time changes in this table to the patch. Tiny ELF inputs also show
that index construction has a fixed cost and does not guarantee a total-time
improvement. An alternating comparison of the large sample follows below.

The alternating rerun used `112f9f0e8d349858a80dd8c14190e620.exe_`, one
warm-up per binary, then three observations per binary, reversing the order
on each round. Both versions ran with `--jobs 1`; no builds or tests ran
alongside these measurements.

| Large sample | Before | After | Speedup |
|---|---:|---:|---:|
| Total wall time | 28.133 s | 11.006 s | 2.56x |
| Rule matching | 19.374 s | 2.859 s | 6.78x |
| Peak process RSS | 1628 MiB | 1921 MiB | n/a |

The measured wall-time ranges were 28.007-30.054 s before and
10.337-11.544 s after. Shared signatures trade repeated parsing for
resident memory: the large sample's peak rose by about 293 MiB
(18%). The cache lasts until process exit, so this is an intentional
cost for repeated library/Python analyses, not a memory-reduction claim.

Reproduce the full-corpus measurements by saving the release binary before
applying the changes, then running this command against each binary:

```bash
python3 scripts/bench.py --samples scripts/corpus-bench.txt \
  --capa-cli /path/to/binary --jobs 1 --runs 3 --json /tmp/measurement.json
```

For same-process cache measurements, the standalone probe loads the tiny PE
five times, excluding file reading and rule matching from its timed interval.
It asserts identical extracted features and library names on every call and
prints a fingerprint for comparison between builds. Compile it against each
version's release library and run each executable three times, alternating
versions:

```bash
cargo build --release -p capa-x
rustc --edition=2021 -O scripts/bench_repeated_pe.rs \
  --extern capa_x=target/release/libcapa_x.rlib \
  -L dependency=target/release/deps -o /tmp/bench-repeated-pe
/tmp/bench-repeated-pe
```

Across three fresh launches per version, the first load's median was
0.977 s before and 0.749 s after. The median of the 12 subsequent calls was
765.59 ms before and 0.94 ms after. Every call in both builds
produced the same feature/library fingerprint. These are tiny-PE loader
measurements, not end-to-end analysis speedups; rule loading and matching
are excluded. Separate CLI processes cannot reuse this cache.

Validation:

- `cargo test -p capa-x --test features_parity`: 4 passed.
- `cargo test --workspace`: 385 passed, 6 slow tests ignored.
- The new matcher test compares complete evidence and feature insertion order
  with exhaustive evaluation for 500 statement trees across 257 feature maps,
  plus transitive and namespace dependencies and pre-existing match keys.
- Signature tests cover concurrent callers with different job counts, shared
  allocation, custom-file edits, malformed content and deletion.
- `cargo fmt --all -- --check`, standalone probe formatting and
  `git diff --check`: passed.
- `cargo clippy --workspace --all-targets -- -D warnings -A unknown-lints`:
  passed. The allowance is for existing `chunks_exact_to_as_chunks` annotations
  unknown to the installed Clippy, as in the preceding measurement.
- `python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt
  --capa-cli target/release/capa-x --jobs 6 --no-rust-cache`: no regressions
  across 23 samples; the 7 known differing samples stayed within baseline.
- `python3 scripts/determinism.py --samples scripts/corpus-jobs.txt --capa-cli
  target/release/capa-x --jobs 2,4 --repeat 2 --workers 2`: all 20 parallel runs
  across 5 samples matched single-threaded output.
- All ten benchmark samples and the three committed static, .NET and dynamic
  freeze fixtures produced identical complete result documents before/after.
  Only `meta.timestamp` and `meta.argv` were removed; evidence, match
  multiplicity, locations and list order were retained.

## Release measurement log

Every row below was measured on the `v1.0.0` release tree, with every sample
kept in the stated denominator, failures and timeouts recorded, and unmapped
divergences recorded separately. No result is carried forward from an earlier
note: each gate is re-measured on the tree that ships it.

| Gate | Release | Host | Command and corpus | Result | Failures and timeouts | Unmapped divergences | Notes |
|---|---|---|---|---|---|---|---|
| J1 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | `difftest.py --profile v2-static --mode full --samples corpus-outer.txt --no-rust-cache` | 6,263-rule denominator: 98.55% agreement, 91 divergences (61 missing, 30 extra), 161/200 identical samples | 0 failures, 0 timeouts | 0 | 39 differing samples; every divergence mapped, including `KD-013` |
| J2 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | `determinism.py --samples corpus-jobs.txt --jobs 2,4 --repeat 5 --workers 15` | 50/50 parallel runs byte-identical to `--jobs 1` across 5 samples | 0 failures | 0 | Jobs 1, 2, and 4 compared repeatedly |
| J3 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | `bench.py --samples corpus-bench.txt --jobs 1,2,4,default --runs 5` | 10/10 samples; median default-versus-1 speedup 2.03x; worst 1.52x; PASS | 0 failures | 0 | No sample below the 0.91x floor |
| J4 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | Same fresh J3 benchmark; phase totals recorded in `target/v3g-bench.json` | 77.374 s at `--jobs 1`, 37.199 s at default jobs; PASS | 0 failures | 0 | Rules 2.068 s, load and recovery 32.025 s, extraction 0.481 s, matching 42.415 s, result 0.032 s at jobs 1 |
| J5 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | `cargo test --workspace` (`dotnet_features_parity.rs`) | Green .NET backend fixture and parity tests | 0 failures | 0 | Included in the full workspace hardening run |
| J6 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | `difftest.py --profile dotnet --mode full --no-rust-cache` | 100.00% agreement, 0/225 rules, 8/8 samples identical | 0 failures, 0 timeouts | 0 | Pinned Python capa 9.4.0 and `dnfile` |
| J7 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | `cargo test -p capa-x --test macho_features` | 30/30 Mach-O fixture rows green | 0 failures | 0 | The profile corpus is intentionally empty; the authoritative gate is the fixture test |
| J8 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | `cargo test --workspace` (`aarch64_features_parity.rs`) | 79/80 AArch64 ELF feature-presence rows; 1 documented upstream gap | 0 failures | 0 | No raw-AArch64 Python oracle |
| J9 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | `difftest.py --profile aarch64-binexport --mode full --no-rust-cache` | 96.55% agreement, 1/29 rules, 2/3 samples identical | 0 failures, 0 timeouts | 0 | One mapped `KD-013` divergence |
| J10 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | `cargo test --workspace` (`macho_features.rs`, `aarch64_pe_features.rs`) | 30/30 Mach-O rows and 15/15 AArch64-PE rows green | 0 failures | 0 | Hand-built extension fixtures, no Python oracle |
| J11 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | `cargo test --workspace` plus `determinism.py` | 0 panics across 900 AArch64 mutants, 2,400 .NET mutants, malformed Mach-O and cross-product inputs; deterministic outputs | 0 failures | 0 | Includes malformed-input and repeated-output hardening |
| J12 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | `cargo doc --workspace --no-deps` | Local and CI-only documentation build completed | 0 build failures | 0 | Rustdoc emitted existing warnings; no crates.io or PyPI publication |
| J13 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | `cargo test --workspace` (`cross_product_matrix.rs`) | 4/4 tests green across 11 input shapes, repeated result documents, and job settings | 0 failures | 0 | API result and determinism invariants preserved |
| J14 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | `difftest.py --mode binding --samples corpus-outer.txt --no-rust-cache` | 200/200 result documents and matched rule names agree | 0 failures, 0 timeouts | 0 | Pinned capa `ResultDocument` validation |
| J15 | v1.0.0 | MacBook Pro M1 Max / macOS 26.6 (25G72) / arm64 / 10 CPUs | Local `maturin build --release` and isolated wheel smoke | Local `capa_x-1.0.0-cp38-abi3-macosx_11_0_arm64.whl` built, installed, imported, and scanned successfully | 0 local failures | 0 | Five-platform GitHub release matrix is verified after tag publication |
