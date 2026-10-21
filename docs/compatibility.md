# Compatibility

Python capa 10.0.0 is the behavioral reference (see [`PINNED.md`](../PINNED.md)). capa-x is a native backend, not a replacement for every capa input format. Each input below carries a different kind of claim; do not read one row's evidence into another.

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
| External disassembler databases and BinExport | Non-goal | n/a |

Unsupported inputs are rejected with context, never silently accepted or partially analyzed.

### Claim classes

| Class | Members | Evidence |
|---|---|---|
| Upstream parity | PE, ELF, shellcode, .NET | Direct comparison with Python capa ([benchmarks](benchmarks.md)) |
| Cross-backend parity | AArch64 ELF | Feature- and rule-level comparison with Ghidra BinExport2 ([benchmarks](benchmarks.md)) |
| capa-x extension | Mach-O, AArch64 PE | Hand-built structural and feature fixtures; never claimed as upstream parity |
| Not covered | Evidence-tree identity, other ISAs, dynamic extractors | n/a |

### Format notes

- **Mach-O** is not accepted by pinned capa at all. `-f macho` is therefore an extension, never selected by `-f auto` (which mirrors upstream's PE/ELF/freeze detection order) and must be requested explicitly. Thin and fat binaries are supported; `--arch` selects a slice, `auto` takes the first supported slice in fat-header order.
- **AArch64** decoding, recovery, and extraction (`disarm64`, no external disassembler) are shared by ELF, Mach-O, and PE. Only ELF has an oracle.
- **.NET**: a CLR PE is auto-detected and routed to the .NET backend. `-f pe` forces the native x86 path, `-f dotnet` forces .NET. Mixed-mode assemblies are analyzed for managed methods only, as in upstream, and carry the "mixed mode" characteristic feature.

Measurements (accuracy, performance, reproduction) are in [benchmarks.md](benchmarks.md).

capa-x follows upstream capa on a best-effort basis; each supported version is re-verified with the full differential suite before the pin moves.
