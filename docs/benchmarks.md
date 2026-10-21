# Benchmarks

The only place measurements live. Each is for a pinned implementation, ruleset,
corpus, and host, not a universal claim. Re-run before quoting: commands are at
the bottom.

## Accuracy

**x86/x64 PE, ELF, shellcode vs Python capa 10.0.0** (measured 2026-10-21,
capa-rules v10.0.0, 377 corpus inputs; the reference rejects one malformed ELF,
leaving 376 comparable).

| Metric | Result |
|---|---:|
| Rule-name agreement | 100% |
| Reference rule/sample matches | 11,412 |
| Missing / extra rules | 0 / 0 |
| Missing / extra match addresses | 0 / 0 |
| Samples with identical rule and match-address sets | 376/376 |

Evidence-tree identity and duplicate-match multiplicity are not compared.

**Other backends** (measured on v1.0.0, capa 9.4.0):

| Backend | Oracle | Result |
|---|---|---|
| .NET / CLR | Python capa + `dnfile` | 100% rule agreement, 8/8 samples identical |
| AArch64 ELF | Ghidra BinExport2 | 96.55% rule agreement (28/29 rules), 79/80 feature rows |
| Mach-O (x86_64, AArch64) | None (hand-built fixtures) | 30/30 fixture rows |
| AArch64 PE | None (hand-built fixtures) | 15/15 fixture rows |

## Performance

Host: MacBook Pro M1 Max, 10 logical CPUs, macOS 26.6, v1.0.0 release build.

**Single sample** (`Practical Malware Analysis Lab 18-03.exe_`, same rules and
signatures, 1 warm-up + 5 runs):

| Tool | Median |
|---|---:|
| capa-x | 0.959 s |
| Python capa 9.4.0 | 3.007 s |

**Parallel scaling** (10 samples from `scripts/corpus-bench.txt`, median of 5):

| Jobs | Total | Speedup |
|---:|---:|---:|
| 1 | 77.4 s | 1.00x |
| 2 | 59.0 s | 1.31x |
| 4 | 44.0 s | 1.76x |
| 10 (default) | 37.2 s | 2.08x |

Median per-sample speedup is 2.03x, worst 1.52x. File loading and recovery are
serial by design and dominate the largest sample.

## Reproduce

```bash
scripts/setup_dev.sh && cargo build --release

# accuracy
python3 scripts/difftest.py --mode full \
  --samples scripts/corpus-full-static.txt --capa-cli target/release/capa-x \
  --no-rust-cache --no-expected
python3 scripts/difftest.py --mode full-exact \
  --samples scripts/corpus-full-static.txt --capa-cli target/release/capa-x \
  --no-rust-cache --no-expected

# determinism across job counts
python3 scripts/determinism.py \
  --samples scripts/corpus-jobs.txt --capa-cli target/release/capa-x

# performance
python3 scripts/bench.py --samples scripts/corpus-bench.txt --markdown
```

Older reports, per-sample tables, and the divergence catalogue were removed
from the tree; they remain in git history before the docs restructure.
