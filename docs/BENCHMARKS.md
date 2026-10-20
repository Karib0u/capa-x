# Accuracy and performance

This page records the methodology behind the summary numbers in the project
README. The measurements are reproducible evidence for a pinned implementation,
ruleset, corpus, and host. They are not universal rankings.

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
two baseline rows as documented below; a full corpus measurement of the
combined capa 10 branch is pending.

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
