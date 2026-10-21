# Native function decompilation

Build the optional backend on macOS or Linux with a C++14 compiler and zlib
headers/library installed:

```sh
cargo build --release -p capa-x-cli --features decompiler
./target/release/capa-x sample.exe --decompile-function 0x140001000
./target/release/capa-x sample.exe --decompile-function 0x140001000 --json --timing
```

The initial scope is native x86-64 PE files and Windows x64 calling convention.
Addresses are hexadecimal virtual addresses, including the image base, not
file offsets or RVAs. One function is requested per call. The CLI emits C-like
text, or a dedicated JSON result with address, optional name, convention,
text, warnings and incomplete status. `--timing` adds measured initialization
and function timing to JSON. Without it, JSON is deterministic across job counts.
Rule files are unnecessary. Normal capability analysis never initializes this
backend. A binary built without the feature gives an actionable error for the
flag. `--jobs` continues to apply only to capability analysis.

The native library embeds compiled SLEIGH, processor and compiler specs.
There is no runtime JVM, Python, network access, external disassembler or
commercial engine. The build-time native SLEIGH compiler is built from the
same pinned source. See [PINNED.md](../PINNED.md) and the
[vendoring notes](../third_party/ghidra/README.md).

## Reusable API

```rust,ignore
use capa_x::decompiler::{DecompilerSession, ResourceLimits, ValueType};

let mut session = DecompilerSession::from_pe(&sample_bytes)?;
session.set_limits(ResourceLimits::default())?;
// Optional when the caller knows a fixed-argument prototype.
session.set_signature(0x140001000, ValueType::I32, &[ValueType::I32])?;
let first = session.decompile_function(0x140001000)?;
let second = session.decompile_function(0x140002000)?;
println!("{}", first.text);
```

A session owns one loaded image. `from_analysis(&analysis, &names,
CallingConvention::WindowsX64)` reuses existing recovery metadata and accepts
additional symbols. Specifications are initialized once per session; function
analysis is released after each request, including temporary inferred callee prototypes. The Rust result always includes
timings, even when the CLI omits them for deterministic JSON.

Sessions are neither Send nor Sync. Native calls are serialized process-wide
because Ghidra has shared registries. An unexpected native failure poisons the
session; create another session to continue. A work-limit or deadline error
aborts only its request and leaves the session usable. Rust-rejected invalid requests leave it
usable. Native warnings set `incomplete`; consumers should display them.
The adapter applies the prototype of every import from a Windows system DLL that
Ghidra's bundled Windows and C library data type archives describe (see
[Prototype pack](#prototype-pack)), and `from_pe` applies a compact subset of the bundled FLIRT signatures for
runtime names. Validated MSVC runtime matches and the PE DLL entry point get
known calling signatures. Validated security-cookie checks also receive an
explicit RAX-preservation effect, so their callers retain return values across
the check. An arbitrary caller-supplied name does not enable that effect.
See the [runtime-signature provenance](../capa-x/sigs/DECOMPILER.md). `from_pe` loads a PE whose import or delay import directory is malformed without imports and with an "import directory ignored" warning. `from_analysis` uses the caller's symbol map and
avoids the library-matching cost. PDB types are not loaded.

`set_signature` accepts explicit scalar/pointer prototypes for function entries
or IAT slots. For unknown direct callees, native analysis can infer prototypes
from at most 16 supporting functions and four call levels per request. These
share the request's time/work budget and instruction limit per analyzed function.
Only completed analysis without warnings or unresolved call prototypes supplies
an inferred signature. Recursive or unresolved callees remain unknown. Inference
has its own budget, separate from the selected function's, and each phase gets
the full limits. If enrichment hits a limit, the function is decompiled without
it and the result carries an "inference skipped" warning. Inferred signatures are
cached per session as a pure function of the image and explicit signatures, and a
cache hit charges the work of the original computation, so output and limits do
not depend on request order. Locks last only while a function is analyzed, and
`set_signature` and the other mutators drop the cache. Limits: 16 direct callees
per request, 16 analyzed functions below each, four call levels. An explicitly
requested unrecovered wrapper keeps the tail-call override it received.

Results using inferred callee prototypes carry a warning and are conservatively
marked incomplete. Calls still lacking prototypes retain the explicit unknown
callee warning. Recovery-provided direct tail calls and IAT jump thunks use
Ghidra's CALL_RETURN flow override; native SLEIGH still supplies the p-code.
For a requested entry absent from recovery, a bounded SLEIGH scan of at most
64 straight-line instructions also recognizes a direct tail jump to a supplied
executable function entry. It stops on any other control flow. This does not
replace general function or exception-handler discovery.

Read-only image sections retain constant/string semantics except for individual
eight-byte IAT slots. Typed string pointers allow Ghidra to render narrow and
UTF-16 literals. The adapter keeps small hand-built layouts of `LUID`,
`LUID_AND_ATTRIBUTES`, and `TOKEN_PRIVILEGES` for explicit `set_signature`
calls (sizes 8, 12 and 16, alignment 4, `ANYSIZE_ARRAY = 1`, following
[the SDK](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges)).
Imports get their full types from the prototype pack instead.

## Prototype pack

`capa-x-ghidra/data/winapi64.pack` (1.3 MB) holds 28,312 function prototypes and
8,052 named types exported from Ghidra 12.1.4's `windows_vs12_64.gdt` (Win32
headers, earlier archives win name clashes) and `generic_clib_64.gdt`. They are
encoded with Ghidra's own decompiler marshalling, so the embedded engine decodes
what Ghidra's decompiler would receive. Entries are zlib blocks sorted by key.
A lookup inflates one bounded block, and types are resolved on demand by a
`TypeFactory` subclass, the way Ghidra's decompiler asks its host. Nothing is
decoded at startup.

An import is typed when its module is a known Windows system DLL (`kernel32`,
`user32`, `ntdll`, `ws2_32`, `msvcrt`, `api-ms-win-*` and others, listed in
`system_import_function`) and its function name is in the pack. A same-named
export of an unrelated DLL stays untyped, as do names the archives lack, which
keep the unknown-callee warning. Ghidra itself matches by name only. The
module check is a deliberate stricter policy. Archive convention names such as
`__stdcall` map to the single Windows x64 model.

Eight archive entries (two callback typedef cycles and one unresolved enum)
cannot be rebuilt; their functions keep an unknown prototype instead of an
error. `capa-x-ghidra`'s `packed_archive_types_and_prototypes_decode` test decodes
the whole pack through the real engine and fails if that count grows. To
regenerate the pack, see `scripts/decompiler_types/README.md`. The archives are
derived from Microsoft SDK and OpenSSL headers by the Ghidra project
(Apache-2.0); the pack is a transformation of them.

Default limits are 5 seconds, 10,000 instructions and 2,000,000 work units.
The deadline is cooperative: a native operation between checkpoints can
overshoot it. This is not a hard wall-clock or memory sandbox. See the
[design decision](decompiler-design.md) for ownership,
resource policy and the scope of exception handling.

## Fixtures and reference comparison

```sh
scripts/build_decompiler_fixtures.sh
cargo test --release -p capa-x --features decompiler --test decompiler
GHIDRA_HOME=/path/to/ghidra_12.1.4_PUBLIC scripts/decompiler_reference.sh
cargo run --release -p capa-x --features decompiler --example decompiler_bench
```

The checked-in fixture DLL is built from `tests/decompiler/fixtures.c` with
MinGW GCC, without a CRT or timestamp. Rebuilding requires development-time
MinGW; normal tests use the checked-in DLL. Seven exports cover arithmetic,
branches, a sum-of-squares loop, a seven-case switch, volatile stack variables,
GetTickCount and non-returning ExitProcess. Tests check useful source logic,
repeatability, session ownership and malformed/limited requests. Source-logic
tests supply the known fixture signatures, including the two Windows imports.
Separate tests verify that unknown call prototypes are reported as incomplete.

`tests/decompiler/reference/*.c` is produced by the pinned Ghidra 12.1.4
headless release (the fixture output is identical to 11.4.2) and its default PE analyzer. The reference
script is exclusively a development tool. It is not part of the native build
or runtime. Its full analyzer supplies broader types and metadata than the
embedded adapter. Compare control flow, operations,
constants, arguments and effects rather than requiring identical variable names. The checked comparison found:

| Fixture | Source and reference logic preserved with supplied signatures |
|---|---|
| arithmetic | `x * 7 + y - 3` |
| branches | absolute value for negative input, clamp above 100, otherwise increment |
| loops | sum of squares from zero through `n - 1` |
| switches | seven cases, constants and forwarded arguments |
| stack_variables | two local stores and a dynamic index masked by one |
| imported_call | GetTickCount return value plus the incoming argument |
| nonreturn | ExitProcess receives the incoming exit code and has no fallthrough |

The ordinary CLI can reconstruct arithmetic and control flow without these
signatures. It reports incomplete call reconstruction where metadata is
missing. `nonreturn` also retains Ghidra's own no-return warning, so its
incomplete flag is conservatively set even with the supplied signature.

## Performance

Run the benchmark in a fresh release process. It reports cold session setup
including recovery and library matching, and 100 requests per function with
p50, p95 and maximum latency. Pass a repetition count to compare retention:

```sh
cargo build --release -p capa-x --features decompiler --example decompiler_bench
/usr/bin/time -l target/release/examples/decompiler_bench 100
/usr/bin/time -l target/release/examples/decompiler_bench 1000
```

On Linux use `/usr/bin/time -v` instead of `-l`. The resulting process maximum
RSS includes loading, recovery and all requests. Timings are observations of
the current binary, not cached acceptance numbers. Fixture-scale targets are
established from the measurements collected by the benchmark; large real functions can
hit limits and need separate evaluation.

See [fresh fixture measurements and regression targets](benchmarks.md#optional-native-decompiler).

## Validation

On the branch prepared for push, the default workspace suite passed 564 tests (six slow gates remained ignored), the optional native/adapter/CLI suites passed 18 tests, and all four feature-parity tests passed. The uncached native smoke differential run matched all 23 samples and all 731 reference-matched rules with zero missing or extra matches and no baseline regressions. The ten Python harness tests, source checksums, environment pins and formatting checks passed.

Strict Clippy currently reports existing unknown-lint attributes and a nonminimal Boolean expression in unchanged recovery code. Workspace Clippy and the optional targets with Rust 1.87 pass when only those categories are allowed:

```sh
cargo clippy --workspace --all-targets -- -D warnings -A unknown-lints -A clippy::nonminimal-bool
cargo +1.87.0 clippy --release -p capa-x -p capa-x-cli -p capa-x-ghidra \
  --all-targets --features capa-x/decompiler,capa-x-cli/decompiler,capa-x-ghidra/native \
  -- -D warnings -A unknown-lints -A clippy::nonminimal-bool
```

Linux and macOS CI exercise the optional feature; only macOS was run locally.
