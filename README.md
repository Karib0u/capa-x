<p align="center">
  <img src="capa-x-logo.png" width="200" alt="capa-x logo">
</p>

# capa-x

**Native Rust capability detection for executables, compatible with unmodified capa rules**

<p align="center">
  <a href="https://github.com/Karib0u/capa-x/actions/workflows/ci.yml"><img src="https://github.com/Karib0u/capa-x/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Karib0u/capa-x/releases/latest"><img src="https://img.shields.io/github/v/release/Karib0u/capa-x" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/capa-10.0.0-blue" alt="capa 10.0.0">
  <img src="https://img.shields.io/badge/license-Apache%202.0-green" alt="License">
</p>

[Releases](https://github.com/Karib0u/capa-x/releases) · [Documentation](docs/) · [Compatibility](docs/compatibility.md) · [Benchmarks](docs/benchmarks.md)

capa-x is an independent Rust implementation of the [Mandiant capa](https://github.com/mandiant/capa) static backend. It runs the unmodified capa rules with no Python and no external disassembler at analysis time, and produces deterministic output at every `--jobs` value.

Python capa 10.0.0 is the behavioral reference. On the pinned corpus, **376 of 376** comparable samples have identical rule and match-address sets ([benchmarks](docs/benchmarks.md)).

## Features

- **Inputs:** x86/x64 PE, ELF, .NET/CLR, raw shellcode, capa freeze files, AArch64 ELF and PE, and x86_64/AArch64 Mach-O.
- **Rules:** parses unmodified capa-rules; unknown constructs fail with context instead of being skipped.
- **Output:** human-readable text or capa's canonical JSON result document.
- **Fast:** parallel analysis with deterministic output ([benchmarks](docs/benchmarks.md)).
- **Bindings:** in-process Python extension, no subprocess.
- **Offline:** analysis performs no network access.

## Supported inputs

| Input | Status |
|---|---|
| PE x86/x64, ELF x86/x64, shellcode, .NET, freeze | Parity with Python capa 10.0.0 |
| ELF AArch64 | Validated against Ghidra BinExport2 fixtures |
| PE AArch64, Mach-O (`-f macho`) | capa-x extension, no Python oracle |
| IDA, Ghidra, Binary Ninja, BinExport | Non-goal |

Evidence and caveats for each row are in [docs/compatibility.md](docs/compatibility.md).

## Install

Download an archive from [GitHub Releases](https://github.com/Karib0u/capa-x/releases), unpack it, and run:

```bash
./capa-x sample.exe
```

Archives include the pinned rules. In a source checkout rules are read from `./rules`; otherwise place `rules/` beside the binary, pass `--rules`, or set `CAPA_RULES_DIR`. To download rules explicitly:

```bash
capa-x fetch-rules ./rules
```

## Usage

```bash
capa-x sample.exe                  # human-readable results
capa-x -j sample.exe               # canonical JSON
capa-x -f sc64 shellcode.bin       # raw shellcode (sc32 for 32-bit)
capa-x -f freeze sample.frz        # freeze file
capa-x -f macho sample             # Mach-O (explicit only)
capa-x --jobs 4 sample.exe         # explicit parallelism
```

CLR PEs are auto-detected; `-f dotnet` and `-f pe` force a backend. Run `capa-x --help` for architecture and OS overrides, tag filtering, signatures, verbosity, and output options.

## Build from source

Rust 1.87+ is required.

```bash
git clone https://github.com/Karib0u/capa-x.git
cd capa-x
git submodule update --init --depth 1 rules
cargo build --release
target/release/capa-x --version
```

## Python

```bash
pip install maturin
cd capa-x-python && maturin develop --release
```

```python
import capa_x

rules = capa_x.Rules.from_directory("rules")   # parse and validate once
result = capa_x.analyze("sample.exe", rules)   # same dict as `capa-x -j`
print(sorted(result["rules"]))
```

Details in [capa-x-python/README.md](capa-x-python/README.md).

## Limitations

- Exact instruction recovery and evidence locations can differ from Python capa on arbitrary binaries.
- Evidence-tree identity and duplicate-match multiplicity are not established.
- Dynamic analysis and other ISAs are out of scope.
- Targets capa 10.0.0 and tracks upstream on a best-effort basis. It is maintained by one person, so review and security response times are best-effort too.

## Documentation

- [Compatibility](docs/compatibility.md)
- [Benchmarks](docs/benchmarks.md)
- [Architecture](docs/architecture.md)
- [Development guide](docs/development.md) · [Contributing](CONTRIBUTING.md)
- [Pinned upstream versions](PINNED.md) · [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md)

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). capa-x is independent and not affiliated with or endorsed by Google LLC or Mandiant, Inc.
