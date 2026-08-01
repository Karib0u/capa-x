# Accuracy and performance

This page records the methodology behind the summary numbers in the project
README. The measurements are reproducible evidence for a pinned implementation,
ruleset, corpus, and host. They are not universal rankings.

## Accuracy

The current accuracy result was measured on the release tree against Python
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
