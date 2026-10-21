# Benchmarks

The only place measurements live. Everything here was measured on 2026-10-21 against capa-x release build of `main` at `2d9862a` (plus comment-only changes), Python capa 10.0.0, and capa-rules v10.0.0. Results hold for this implementation, ruleset, corpus, and host. They are not universal claims. Re-run before quoting: commands are at the bottom.

## Accuracy

**x86/x64 PE, ELF, and shellcode vs Python capa 10.0.0.** 377 corpus inputs; the reference rejects one malformed ELF, leaving 376 comparable.

| Metric | Result |
|---|---:|
| Rule-name agreement | 100.00% |
| Reference rule/sample matches | 11,412 |
| Missing / extra rules | 0 / 0 |
| Samples with identical rule names | 376/376 |
| Samples with identical rule names and match addresses (`full-exact`) | 376/376 |

Evidence-tree identity and duplicate-match multiplicity are not compared.

**Other backends.**

| Backend | Oracle | Result |
|---|---|---|
| .NET / CLR | Python capa + `dnfile` | 8/8 samples identical (`full-exact`) |
| AArch64 ELF | Ghidra BinExport2 | 29/29 rules, 3/3 samples identical |
| Mach-O (x86_64, AArch64) | None (hand-built fixtures) | 30/30 fixture tests pass |
| AArch64 PE | None (hand-built fixtures) | 15/15 fixture tests pass |

## Performance

Host: MacBook Pro, Apple M1 Max, 10 logical CPUs, macOS 27.0.1. Median of 5 runs after one warm-up, wall time including process start-up and output.

### capa-x vs Python capa

`capa-x --jobs 1` against Python capa 10.0.0 (single-threaded), producing identical results on each sample. Speedups are per sample, not a corpus average.

| Sample | capa-x `--jobs 1` | Python capa | Speedup |
|---|---:|---:|---:|
| `Practical Malware Analysis Lab 18-03.exe_` | 0.835 s | 3.781 s | 4.5x |
| `055da8e6…elf_` (ELF64, 22 KB) | 0.215 s | 1.949 s | 9.1x |
| `a198216798…exe_` (PE32, 293 KB) | 0.867 s | 6.023 s | 6.9x |
| `79cde1aa…exe_` (PE32, 77 KB) | 0.921 s | 13.217 s | 14.4x |
| `03b236b2…dll_` (PE32+ DLL) | 2.236 s | 38.647 s | 17.3x |

Median speedup is 9.1x. capa-x pays a fixed start-up cost (about 1 s to load the rules and signatures), which dominates on small files.

### Parallel scaling

10 samples from `scripts/corpus-bench.txt`.

| Jobs | Total | Speedup |
|---:|---:|---:|
| 1 | 30.7 s | 1.00x |
| 2 | 27.2 s | 1.13x |
| 4 | 26.1 s | 1.18x |
| 10 (default) | 25.4 s | 1.21x |

Median per-sample speedup at the default job count is 1.85x (best 3.12x, a small ELF). The total barely moves because one 9.6 MB PE takes 22 s, of which about 20 s is load and recovery, which is serial by design.

Two results fall short of the project's own bar (median at least 1.5x with no sample below 0.91x, "gate J3"):

- `03b236b2…dll_` slows down with more jobs: 2.41 s at 1 job, 2.86 s at the default (0.84x).
- The largest PE reaches only 1.13x.

### Memory

Peak resident set size is about 660 MB for typical PE files, 63 MB for small ELF files, 770 MB for the PE32+ DLL, and 2.1 GB for the 9.6 MB PE. It does not change with job count.

### Phase times

Sum over the 10-sample corpus, in seconds.

| Phase | `--jobs 1` | `--jobs 2` | `--jobs 4` | default |
|---|---:|---:|---:|---:|
| rules | 2.62 | 1.71 | 1.22 | 1.00 |
| load and recovery | 25.07 | 23.08 | 23.05 | 22.92 |
| extraction | 0.49 | 0.34 | 0.20 | 0.12 |
| matching | 2.19 | 1.66 | 1.14 | 0.91 |
| result | 0.03 | 0.03 | 0.03 | 0.03 |
| total | 30.71 | 27.24 | 26.08 | 25.41 |

## Reproduce

```bash
scripts/setup_dev.sh && cargo build --release

# accuracy (rule names, then rule names plus addresses)
python3 scripts/difftest.py --mode full \
  --samples scripts/corpus-full-static.txt --capa-cli target/release/capa-x \
  --no-rust-cache --no-expected
python3 scripts/difftest.py --mode full-exact \
  --samples scripts/corpus-full-static.txt --capa-cli target/release/capa-x \
  --no-rust-cache --no-expected

# other backends
python3 scripts/difftest.py --mode full-exact --samples scripts/corpus-dotnet.txt \
  --capa-cli target/release/capa-x --no-rust-cache --no-expected
python3 scripts/difftest.py --profile aarch64-binexport --mode full \
  --samples scripts/corpus-aarch64.txt --capa-cli target/release/capa-x \
  --no-rust-cache --no-expected
cargo test --release -p capa-x --test macho_features --test aarch64_pe_features

# determinism across job counts
python3 scripts/determinism.py \
  --samples scripts/corpus-jobs.txt --capa-cli target/release/capa-x

# performance
python3 scripts/bench.py --samples scripts/corpus-bench.txt \
  --capa-cli target/release/capa-x --jobs 1,2,4,default --runs 5 --markdown
python3 scripts/bench.py --samples <samples.txt> --capa-cli target/release/capa-x \
  --jobs 1 --runs 5 --python .venv/bin/capa --markdown
```

Older reports, per-sample tables, and the divergence catalogue were removed from the tree; they remain in git history before the docs restructure.

## Optional native decompiler

Measured on 2026-10-21 with the release build on Apple M1 Max, 64 GiB RAM, macOS arm64, Rust 1.96.0. Each process reuses one session across seven compiled source fixtures, with no supplied prototypes. Raw outputs, process RSS, and executable/source hashes are in [tests/decompiler/measurements](../tests/decompiler/measurements/).

| Requests | Cold session setup | Highest function warm p95 | Peak RSS |
|---|---:|---:|---:|
| 700 | 52.482 ms | 3.104 ms | 36.250 MiB |
| 7,000 | 31.803 ms | 3.016 ms | 36.031 MiB |

Cold setup includes recovery and runtime recognition. The highest p95 is for the switch fixture, which also analyzes supporting callees. These local observations meet fixture regression targets of cold setup below 100 ms, warm p95 below 5 ms, peak RSS below 64 MiB, and less than 8 MiB growth between 700 and 7,000 requests. They do not establish limits for large corpus functions or prove leak freedom. Background machine activity and filesystem caches were not controlled.

Reproduce with:

```sh
cargo build --release -p capa-x --features decompiler --example decompiler_bench
/usr/bin/time -l target/release/examples/decompiler_bench 100
/usr/bin/time -l target/release/examples/decompiler_bench 1000
```

Use `/usr/bin/time -v` on Linux. See [the decompiler guide](decompiler.md) for scope, cooperative resource limits, and native-engine ownership.
