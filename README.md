<p align="center">
  <img src="capa-x-logo.png" width="200" alt="capa-x logo">
</p>

# capa-x

capa-x is an independent native Rust implementation of the
[Mandiant capa](https://github.com/mandiant/capa) static backend. It runs
unmodified capa rules without requiring Python at analysis time. It is not
affiliated with or endorsed by Google LLC or Mandiant, Inc.

- Supports x86/x64 PE, ELF, .NET/CLR, raw shellcode, and capa freeze files,
  plus x86_64/AArch64 Mach-O (`-f macho`, a capa-x extension -- see below)
  and native AArch64 PE/ELF.
- Produces deterministic output at every `--jobs` value.
- Fails with context on unsupported inputs and unknown rule syntax.
- Targets capa 10.0.0 and its unmodified rule release. Compatibility checks
  and native extraction differences are recorded in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

Python capa is the behavioral reference. capa-x is a native backend, not a
complete replacement for every capa input format. Accepted backend differences
are documented in [KNOWN_DIVERGENCES.md](KNOWN_DIVERGENCES.md).

## Supported inputs

| Input | Status | Reference |
|---|---|---|
| PE x86/x64 | Supported | Python capa 10.0.0, Vivisect |
| PE AArch64 (`IMAGE_FILE_MACHINE_ARM64`) | Supported -- **capa-x extension** | No Python oracle; see below |
| ELF x86/x64 | Supported | Python capa 10.0.0, Vivisect |
| ELF AArch64 | Supported | No raw-AArch64 Python oracle; validated against Ghidra BinExport2 |
| .NET / CLR managed PE | Supported | Python capa 10.0.0, `dnfile` |
| Raw shellcode, 32/64-bit | Supported | Python capa 10.0.0, `sc32`/`sc64` |
| capa freeze files | Supported | Python capa 10.0.0 |
| Mach-O x86_64/arm64/arm64e (thin or fat, `-f macho`) | Supported -- **capa-x extension** | No Python oracle; see below |
| IDA, Ghidra, Binary Ninja, BinExport | Non-goal | Native inputs are the focus |

Unsupported inputs are never silently accepted or partially analyzed.

Pinned capa 10.0.0 does not accept Mach-O as raw input at all, so `-f macho`
is a documented capa-x extension rather than a parity claim: it is never
selected by `-f auto` (which mirrors upstream's own PE/ELF/freeze detection
order exactly) and must be requested explicitly. capa's feature semantics
still govern what a feature means; thin and fat (`--arch` selects a slice,
`auto` takes the first supported slice in fat-header order) x86_64, `arm64`,
and `arm64e` Mach-O are all supported.

Native AArch64 decoding, recovery, and feature extraction (`disarm64`-based,
no Ghidra/IDA/Binary Ninja/BinExport at runtime) cover ELF, Mach-O, and PE
alike -- the same decoder and recovery core, composed with each container
format's existing loader. Pinned capa 10.0.0 has no raw AArch64 input at all
(its own AArch64 support is BinExport2-only), so AArch64 PE and Mach-O carry
the same "capa-x extension, no Python oracle" caveat x86_64 Mach-O does;
AArch64 ELF is validated against the pinned Ghidra BinExport2 fixture corpus
instead, with the result recorded in the compatibility evidence.

A CLR PE is auto-detected and routed to the `.NET` backend ahead of the
native x86 extractor (`-f pe` overrides this and forces the x86 path, and
`-f dotnet` forces the `.NET` path). A mixed-mode assembly (managed +
unmanaged code in one binary) is analyzed for its managed methods only --
there is no cross-runtime call graph into the native portion, matching
upstream capa's own `dnfile` extractor. The file carries a "mixed mode"
characteristic feature and a mixed-mode assembly is otherwise detected and
analyzed the same as a fully managed one.

## Compatibility matrix

The table above lists every input by format; this one groups the same inputs
by *what kind of claim capa-x makes about them* -- collapsing the
distinction is how a port starts overclaiming.

| Class | Members | Oracle |
|---|---|---|
| Upstream-parity raw input | PE, ELF, shellcode (x86/x64), .NET/CLR | Python capa 10.0.0 direct comparison, recorded in `docs/BENCHMARKS.md` |
| Cross-backend parity | AArch64 ELF | No raw-AArch64 Python oracle; pinned Ghidra BinExport2 feature- and rule-level comparison, methodology in [docs/BENCHMARKS.md](docs/BENCHMARKS.md) |
| capa-x extension | Mach-O (x86_64, AArch64), AArch64 PE | No Python oracle at all -- pinned capa 10.0.0 has no raw Mach-O or AArch64 input; validated against a hand-built structural/feature fixture corpus (see [docs/BENCHMARKS.md](docs/BENCHMARKS.md)), never claimed as upstream parity |
| Measurement limits / non-goal | Exact binary evidence parity, other ISAs, live dynamic extractors | [`KNOWN_DIVERGENCES.md`](KNOWN_DIVERGENCES.md), including the current measured agreement and resolved historical causes |

## Install

Download an archive from
[GitHub Releases](https://github.com/Karib0u/capa-x/releases), unpack it,
and run:

```bash
./capa-x sample.exe
./capa-x -j sample.exe
```

Release archives include the pinned rules. In a source checkout, rules are
found in `./rules`. For another layout, place `rules/` beside the binary, pass
`--rules`, or set `CAPA_RULES_DIR`.

## Quick start

```bash
# Human-readable results
capa-x sample.exe

# Canonical JSON result document
capa-x -j sample.exe

# .NET / CLR managed PE (auto-detected; -f dotnet forces it)
capa-x sample.exe
capa-x -f dotnet sample.exe

# Raw shellcode
capa-x -f sc32 shellcode.bin
capa-x -f sc64 shellcode.bin

# Freeze input
capa-x -f freeze sample.frz

# Explicit parallelism
capa-x --jobs 4 sample.exe
```

Run `capa-x --help` for architecture and OS overrides, tag filtering, custom
signatures, verbosity, and output options.

Analysis performs no network access. Rules are downloaded only through the
explicit command:

```bash
capa-x fetch-rules ./rules
```

## Build from source

Rust 1.87 or newer is required.

```bash
git clone https://github.com/Karib0u/capa-x.git
cd capa-x
git submodule update --init --depth 1 rules
cargo build --release
target/release/capa-x --version
```

The large test corpus and Python reference submodules are needed only for
differential development. `scripts/setup_dev.sh` installs that environment.

## Python bindings

[`capa-x-python/`](capa-x-python/) is an in-process Python extension over this
same analysis code -- no subprocess, no Python at analysis time, nothing
reimplemented. Build it locally with [maturin](https://www.maturin.rs/):

```bash
pip install maturin
cd capa-x-python
maturin develop --release
```

```python
import capa_x

rules = capa_x.Rules.from_directory("rules")  # parse + validate once
result = capa_x.analyze("sample.exe", rules)   # load once, scan many
print(sorted(result["rules"].keys()))
```

`analyze()` returns upstream capa's own `ResultDocument` schema as a plain
`dict` -- the same shape `capa-x -j` prints, and the same shape
`capa.render.result_document.ResultDocument.model_validate_json` accepts
unmodified (see [`capa-x-python/README.md`](capa-x-python/README.md)). Prebuilt
wheels (linux x86_64/aarch64, macOS x86_64/arm64, Windows x86_64) are built
by [`release.yml`](.github/workflows/release.yml) on each tag; every push
gets a cheaper linux-only build plus the same schema-validation check.

## Accuracy and limitations

Measured on 2026-10-20 against Python capa 10.0.0 and capa-rules v10.0.0,
using all 377 native x86/x64 and shellcode inputs in the pinned testfiles
corpus. Original capa rejects one malformed ELF, leaving 376 comparable
inputs. Shared freeze tests separately check JSON evidence.

| Metric | Result |
|---|---:|
| Rule-name agreement | **99.72%** |
| Reference rule/sample matches | 11,412 |
| Divergent rules | 29 missing, 3 extra |
| Samples with identical rule sets | 358/376 (95.2%) |
| Samples with identical rule and match-address sets | 177/376 (47.1%) |

The earlier 200-sample regression corpus still has identical rule sets.
Expanding to every native input exposes differences outside that selection.
The [full validation report](docs/validation/full-corpus-2026-10-20.md)
records each case and the other backend checks. Complete
[original reference results](tests/reference-results/capa-10.0.0/README.md)
are preserved for future regression work. The newly found differences still
require root-cause investigation. Historical methods and performance
measurements are in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

On the v1.0.0 release, a controlled result-equivalent sample had medians of
0.959 seconds for capa-x and 3.007 seconds for Python capa 9.4.0 across five
measured runs. On the 10-sample parallel corpus, total runtime was 77.374 seconds with
one job and 37.199 seconds with the default 10 jobs, with a median per-sample
speedup of 2.03 times and a worst sample of 1.52 times. These are measurements
on a MacBook Pro M1 Max with macOS 26.6 and 10 logical CPUs, not universal
performance claims.

Previously resolved causes and measurement boundaries are catalogued in
[KNOWN_DIVERGENCES.md](KNOWN_DIVERGENCES.md). Compatibility mode reproduces
the reference's overlapping instruction streams and legacy decoder behavior;
native mode retains its broader decoding. Exact locations and evidence on
arbitrary binaries can still differ.
capa-x tracks upstream capa releases on a best-effort basis; it is currently
pinned to 10.0.0, and each supported upstream version is re-verified with the
full differential suite before the pin moves. This is maintained by one person,
so review and security response times are best-effort.

The differential suite compares capa-x against the pinned Python release.
The inventory covers all 377 native inputs; agreement metrics use the 376
comparable inputs. These results do not establish universal compatibility.

## Reproduce the evidence

```bash
scripts/setup_dev.sh
cargo build --release

cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

python3 scripts/difftest.py --mode full \
  --samples scripts/corpus-full-static.txt --capa-cli target/release/capa-x \
  --no-rust-cache --no-expected
python3 scripts/difftest.py --mode full-exact \
  --samples scripts/corpus-full-static.txt --capa-cli target/release/capa-x \
  --no-rust-cache --no-expected
python3 scripts/determinism.py \
  --samples scripts/corpus-jobs.txt --capa-cli target/release/capa-x
python3 scripts/bench.py \
  --samples scripts/corpus-bench.txt --markdown
```

## Documentation and community

- [Architecture](docs/ARCHITECTURE.md)
- [Design decisions](docs/decisions/)
- [Accuracy and performance methodology](docs/BENCHMARKS.md)
- [Known backend divergences](KNOWN_DIVERGENCES.md)
- [Pinned upstream versions](PINNED.md)
- [Release history](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

This is an independent implementation and is not affiliated with or endorsed
by Google LLC or Mandiant, Inc. See [NOTICE](NOTICE) for attribution and the
derivation record.

Licensed under the [Apache License 2.0](LICENSE).
