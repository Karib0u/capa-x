# Changelog

Notable changes to capa-x. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

Result differences against Python capa are not changelog entries - they are
tracked per class in [KNOWN_DIVERGENCES.md](KNOWN_DIVERGENCES.md).

## [Unreleased]

### Fixed

- `scripts/difftest.py` defaulted `--capa-cli` to `target/debug/capa`, which
  is not the binary's name. A run that omitted the flag could not find it, and
  on a tree that still held a stale artifact under the old name it would
  difftest that instead -- and since the harness caches capa-x's side by
  binary contents, the result would look clean and self-consistent while
  measuring the wrong build. The default is now `target/debug/capa-x`.

### Changed

- The slow acceptance and robustness gates
  (`capa-x/tests/cross_product_matrix.rs`, `aarch64_elf_fuzz.rs`,
  `dotnet_dnfile_fuzz.rs`) are `#[ignore]`d: ~383 s of a ~402 s suite, none of
  which an ordinary edit moves. `cargo test --workspace` is now ~20 s
  locally. CI runs the full set with `--include-ignored`, so coverage is
  unchanged.
- `scripts/corpus-outer.expected.json` records the 200-sample outer corpus
  baseline (98.55% rule-level agreement, 161/200 identical, 91 divergences,
  0 errors). Without it the outer loop had no baseline to resolve and exited
  nonzero on every run, so the pre-merge gate `AGENTS.md` documents could not
  pass; it now reports regressions against known diffs.

## [1.0.0]

First public release: a native Rust backend for unmodified upstream capa
rules, covering PE, ELF, raw shellcode, .NET/CLR, Mach-O, and capa freeze
input, with 98.55% rule-level agreement against pinned Python capa 9.4.0 on
the 200-sample evaluation corpus.

### Analysis backends

- **PE and ELF, x86/x64:** format loading, code recovery, FLIRT signature
  matching, and instruction/basic-block/function feature extraction, written
  against pinned Python capa and Vivisect as the behavioral specification.
- **Raw shellcode, 32- and 64-bit** (`-f sc32` / `-f sc64`).
- **capa freeze files** (`-f freeze`), read at the extraction seam that
  decouples backends from matching.
- **.NET / CLR** (`-f dotnet`): CLR metadata reader, name model, CIL decoder
  and basic blocks, and feature extraction. Auto-detected ahead of the native
  x86 path for a CLR PE (`-f pe` forces native x86; `-f dotnet` forces
  managed). Mixed-mode assemblies are analyzed for their managed methods
  only, matching upstream `dnfile`'s own scope. Vendors a patched fork of
  `dnfile` (`third_party/dnfile/`, whose `PATCH.md` documents 12 upstream
  defects found and fixed during the port, mostly signedness bugs in
  branch-target and exception-handler decoding). 100% rule-level agreement on
  all 8 pinned .NET samples.
- **Mach-O** (`-f macho`): thin and fat x86_64/`arm64`/`arm64e` images,
  including a from-scratch `LC_DYLD_CHAINED_FIXUPS` reader (`goblin` has
  none). A documented capa-x extension - pinned capa 9.4.0 has no raw Mach-O
  input, so it is never selected by `-f auto` and must be requested
  explicitly.
- **AArch64:** native decoding, recovery, and feature extraction
  (`disarm64`-based, no Ghidra/IDA/Binary Ninja/BinExport at runtime),
  composed with the existing ELF, Mach-O, and PE loaders. ELF is validated
  against the pinned Ghidra BinExport2 fixture corpus at 96.55% rule-level
  agreement (one divergence root-caused as `KD-013`); Mach-O and PE carry the
  same "capa-x extension, no Python oracle" caveat x86_64 Mach-O does and are
  validated against a hand-built fixture corpus.

### Interfaces

- `--jobs N`: bounded parallel analysis. Per-function feature extraction,
  per-function code-scope matching, and the initial rule-file parse are
  distributed across threads; loading, recovery, FLIRT classification,
  ruleset construction, file-scope aggregation and result construction stay
  serial. Defaults to the logical core count, capped by the number of work
  items. `--jobs 0` is rejected at argument-parsing time.
- **`--jobs N` output is byte-identical to `--jobs 1`**, which is the
  reference mode. Results are merged in address order, never completion
  order. Guarded by `capa-x/tests/jobs_determinism.rs` (rule loading,
  extraction, and the rendered result document, five repeats each) and by
  `scripts/determinism.py`, which CI runs on five samples at 1/2/4 jobs on
  every push.
- `--timing`: per-phase wall time (rule loading, file loading and recovery,
  feature extraction, matching, result construction, total) on stderr.
- `capa-x fetch-rules [DIR]`: clones the pinned capa-rules release. The only
  network access in the tool, and only when invoked by name - analysis never
  downloads anything.
- `capa-x --version` names the capa-rules release the build targets
  (`capa-x 1.0.0 (capa-rules v9.4.0)`), kept equal to `PINNED.md` by a test.
- `--rules` defaults to `./rules`, then to `rules/` beside the executable, so
  an unpacked release archive runs from any working directory.
- Library API: `capa_x::api::analyze` and `load_input`, with
  `capa_x::parallel::{AnalysisOptions, Jobs}` threaded through
  `load_rule_directory`, `enrich_static_features` and
  `find_static_capabilities` as an explicit parameter rather than a global.
- `capa-x-python`: a `pyo3` (`abi3-py38`) binding crate wrapping
  `capa_x::api::analyze` with no analysis logic of its own -
  `Rules.from_directory`, `analyze(...)`, a `CapaError` exception hierarchy,
  GIL release around the CPU-bound call, `.pyi`/`py.typed`, `fetch_rules`.
  Validated by parsing every result document with pinned capa's own
  `ResultDocument.model_validate_json` and comparing matched rule names
  against the CLI on the full 200-sample corpus: zero disagreements.
  `python-extension` is a local Cargo feature rather than unconditional
  ([ADR 0006](docs/decisions/0006-python-binding.md)), and this is the one
  crate in the workspace that cannot carry `#![forbid(unsafe_code)]`, as
  documented in its manifest.

### Distribution

- Release archives for Linux (`x86_64-unknown-linux-musl`, a static binary
  that runs regardless of the host glibc version), macOS (arm64 and x86_64),
  and Windows, each carrying the pinned capa-rules alongside the binary, so
  an unpacked archive runs with nothing further to download.
- `abi3-py38` Python wheels for linux x86_64/aarch64, macOS x86_64/arm64, and
  Windows x86_64, attached to the GitHub release. This release does not
  publish to crates.io or PyPI; crate docs are built locally and in CI only.
- Declared `rust-version = "1.87"`, measured by bisection rather than guessed
  and guarded by a CI job that builds and tests on exactly that toolchain, so
  the floor cannot rise by accident.

### Release evidence

- Every release gate was measured on the release tree against pinned Python
  capa 9.4.0 with the documented corpus denominators. The full evidence table
  is the release measurement log in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).
- A controlled result-equivalent sample measured 0.959 seconds median for
  capa-x and 3.007 seconds for Python capa.
- Every measured divergence from Python capa is root-caused and classified in
  [`KNOWN_DIVERGENCES.md`](KNOWN_DIVERGENCES.md) (13 classes).

### Decided

- No parallelism dependency. Both seams are a flat map over recovered
  functions, so scoped threads over an atomic cursor give the same load
  balancing as a work-stealing scheduler; reasoning and reopen criteria in
  [ADR 0002](docs/decisions/0002-parallelism.md).
- No Vivisect emulator port. Most remaining missing rules are emulator-bound;
  the decision and its reopen criteria are recorded in
  [`KNOWN_DIVERGENCES.md`](KNOWN_DIVERGENCES.md).
