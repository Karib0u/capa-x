# Compatibility

Python capa 10.0.0 is the behavioral reference
(see [`PINNED.md`](../PINNED.md)). capa-x is a native backend, not a
replacement for every capa input format. Each input below carries a different
kind of claim; do not read one row's evidence into another.

## Inputs

| Input | Status | Oracle |
|---|---|---|
| PE x86/x64 | Supported | Python capa 10.0.0 (Vivisect) |
| ELF x86/x64 | Supported | Python capa 10.0.0 (Vivisect) |
| Raw shellcode, 32/64-bit | Supported | Python capa 10.0.0 (`sc32`/`sc64`) |
| .NET / CLR managed PE | Supported | Python capa 10.0.0 (`dnfile`) |
| capa freeze files | Supported | Python capa 10.0.0 |
| ELF AArch64 | Supported | Pinned Ghidra BinExport2 fixtures (no raw-AArch64 Python oracle) |
| PE AArch64 | **Extension** | None |
| Mach-O x86_64 / arm64 / arm64e | **Extension** | None |
| IDA, Ghidra, Binary Ninja, BinExport | Non-goal | n/a |

Unsupported inputs are rejected with context, never silently accepted or
partially analyzed.

### Claim classes

| Class | Members | Evidence |
|---|---|---|
| Upstream parity | PE, ELF, shellcode, .NET | Direct comparison with Python capa ([report](validation/match-address-parity-2026-10-21.md)) |
| Cross-backend parity | AArch64 ELF | Feature- and rule-level comparison with Ghidra BinExport2 ([benchmarks](benchmarks.md)) |
| capa-x extension | Mach-O, AArch64 PE | Hand-built structural and feature fixtures; never claimed as upstream parity |
| Not measured | Evidence-tree identity, other ISAs, dynamic extractors | [known divergences](known-divergences.md) |

### Format notes

- **Mach-O** is not accepted by pinned capa at all. `-f macho` is therefore an
  extension, never selected by `-f auto` (which mirrors upstream's PE/ELF/freeze
  detection order) and must be requested explicitly. Thin and fat binaries are
  supported; `--arch` selects a slice, `auto` takes the first supported slice
  in fat-header order.
- **AArch64** decoding, recovery, and extraction (`disarm64`, no external
  disassembler) are shared by ELF, Mach-O, and PE. Only ELF has an oracle.
- **.NET**: a CLR PE is auto-detected and routed to the .NET backend. `-f pe`
  forces the native x86 path, `-f dotnet` forces .NET. Mixed-mode assemblies are
  analyzed for managed methods only, as in upstream, and carry the
  "mixed mode" characteristic feature.

## Accuracy

Measured 2026-10-21 against Python capa 10.0.0 and capa-rules v10.0.0 on the
377 native x86/x64 and shellcode inputs in the pinned testfiles corpus. The
reference rejects one malformed ELF, leaving 376 comparable inputs.

| Metric | Result |
|---|---:|
| Rule-name agreement | 100% |
| Reference rule/sample matches | 11,412 |
| Missing / extra rules | 0 / 0 |
| Missing / extra match addresses | 0 / 0 |
| Samples with identical rule and match-address sets | 376/376 |

This is corpus compatibility. Evidence-tree identity and duplicate-match
multiplicity are not established, and arbitrary binaries can still differ in
exact locations. Compatibility mode reproduces the reference's overlapping
instruction streams and legacy decoder behavior; native mode keeps its broader
decoding.

Reports: [match-address parity](validation/match-address-parity-2026-10-21.md),
[full-corpus baseline](validation/full-corpus-2026-10-20.md),
[reference results](../tests/reference-results/capa-10.0.0/README.md).

## Performance

Single-host measurements on a MacBook Pro M1 Max (macOS 26.6, 10 logical CPUs),
not universal claims.

| Measurement | Result |
|---|---|
| Result-equivalent sample, median of 5 runs | capa-x 0.959 s vs Python capa 9.4.0 3.007 s |
| 10-sample corpus, 1 job vs 10 jobs | 77.4 s vs 37.2 s (median per-sample speedup 2.03x) |

Methods and the dated log are in [benchmarks.md](benchmarks.md).

## Upstream tracking

capa-x follows upstream capa on a best-effort basis. Each supported version is
re-verified with the full differential suite before the pin moves.
