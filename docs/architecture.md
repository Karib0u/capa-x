# Architecture

`capa-x` is a small Rust workspace with one analysis library and two thin
distribution surfaces. The library keeps input handling, feature extraction,
matching, and result construction together behind a stable API. The CLI and
Python binding supply that API with different ways to load inputs, rules, and
results.

## Workspace map

```text
capa-x/
├── capa-x/                 analysis library
│   ├── rules/              rule grammar, validation, and dependency graph
│   ├── extract/            file features, code recovery, and backend features
│   ├── freeze.rs           capa freeze-format reader and data model
│   ├── capabilities/       static and dynamic rule matching
│   ├── result_document/    canonical result document model
│   └── render/             text and JSON renderers
├── capa-x-cli/             command-line loading and presentation
├── capa-x-python/          PyO3 declarations around the library API
├── third_party/dnfile/     checked vendored CLR metadata and CIL parser
├── rules/                  pinned capa-rules submodule
├── reference/capa/         pinned Python capa behavioral reference
└── scripts/                differential tests, benchmarks, and maintenance
```

`capa-x-python` contains binding declarations only. It does not duplicate
analysis logic. The vendored `dnfile` fork is a path dependency of `capa-x`,
kept outside the workspace because its optional command-line targets are not
part of this project's build.

## The freeze-format seam

Extraction and matching communicate through `capa_x::freeze::Freeze`. A
backend converts bytes into a static or dynamic feature tree with ordered
addresses. The matching engine consumes that tree without knowing whether it
came from PE, ELF, shellcode, .NET, Mach-O, or a precomputed freeze file.

This boundary keeps two kinds of correctness independent:

- extractor tests can compare recovered features with an upstream or native
  oracle without involving rule evaluation;
- engine tests can validate rule parsing, statement evaluation, scopes, and
  evidence using freeze fixtures without loading a binary.

Ordering is part of the contract. Feature collections retain the order needed
by capa's short-circuiting string and regular-expression evaluation, while
address-keyed scopes are traversed in canonical address order.

## Data flow

```text
bytes or freeze file
        │
        ▼
load and identify format
        │
        ▼
recover code and extract file features
        │
        ▼
Freeze::Static or Freeze::Dynamic
        │
        ▼
match validated rules and collect evidence
        │
        ▼
build ResultDocument
        │
        ├── render text or JSON in capa-x-cli
        └── serialize through capa-x-python
```

The public library entry point is `capa_x::api::analyze`. It accepts input
bytes, a built `MatchingRuleSet`, and `AnalysisOptions`, then returns a
`ResultDocument`. `load_input` is also public for file-only and diagnostic
surfaces that need the freeze data before matching. Reading files and rules,
argument parsing, and presentation flags stay at the edges.

Bundled FLIRT signatures are parsed once per process and shared immutably
across analyses. The first caller's job count controls initialization;
subsequent calls reuse the same databases. This avoids repeated parsing for
library and Python callers, at the cost of retaining the databases until
process exit. Custom signature paths are loaded afresh on each call so edits,
removed files, and parse errors remain visible.

## Backend integration points

Each backend has the same broad responsibilities: validate its container,
recover code where applicable, emit capa-shaped features, and hand the result
to the shared freeze and matching layers.

- **PE and ELF x86/x64:** format loaders emit file features; the shared
  recovery code finds functions and basic blocks; the x86 decoder and feature
  modules emit instruction and operand features. FLIRT enrichment is an
  optional PE step before matching. Compatibility recovery evaluates
  undefined pointer and operand-reference targets with a bounded abstract
  interpreter over iced-x86, before late signature scans. It tracks private
  state without executing samples; unsupported paths retain diagnostics.
  Windows callback recovery reuses this state for typed API arguments.
  Import-call fragments run before entry signatures and preserve each
  callee's instruction view at creation, keeping later loose instructions
  separate from function ownership. The compatibility ELF loader binds only
  reference import relocation types; native loading retains broader bindings.
  Compatibility blocks distinguish opcode locations from the instruction
  streams extracted from their byte intervals, preserving overlapping
  reference blocks. Legacy BOUND and ModRM aliases follow the pinned decoder.
  Switch tables stop at definite candidate-evaluation failures in table order.
  Native recovery retains modern decoding and complete guarded switches.
  Full PE analysis uses workspace segment names, while file-only analysis
  uses pefile section names. File-only PE/ELF format features have file scope.
  x86/x64 compatibility recovery uses registered entry signatures rather than broad
  prologue and raw call scans; native recovery retains those fallbacks.
  See [ADR 0007](decisions/0007-candidate-evaluation.md).
- **Raw shellcode:** the shellcode loader supplies an explicitly selected
  architecture, then uses the shared recovery and x86 feature pipeline without
  a container loader.
- **.NET:** the CLR path validates the managed PE and uses the vendored
  `dnfile` fork for metadata and CIL. The .NET feature extractor emits the same
  static freeze structure consumed by the common matcher.
- **Mach-O:** the Mach-O loader validates thin and fat images and selects a
  slice. x86_64 uses the shared x86 path; AArch64 uses the AArch64 decoder and
  feature modules.
- **AArch64 ELF and PE:** format-specific loading and relocation handling feed
  the AArch64 recovery and feature modules. The result is still a normal
  static freeze tree.
- **Freeze input:** the freeze reader skips binary extraction entirely and
  enters at the shared matching stage.

Adding a backend therefore changes format dispatch and extraction modules. It
does not require a second rule engine, result schema, or renderer. Durable
dependency choices and parser boundaries are recorded in the ADRs under
[`decisions/`](decisions/).
