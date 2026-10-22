# Native function decompilation

Build the optional backend on macOS or Linux with a C++14 compiler and zlib
headers/library installed:

```sh
cargo build --release -p capa-x-cli --features decompiler
./target/release/capa-x sample.exe --decompile-function 0x140001000
./target/release/capa-x sample.exe --decompile-function 0x140001000 --json --timing
```

The scope is native x86-64 and x86-32 PE files (managed images and other formats are rejected).
The x86-64 path uses the Windows x64 calling convention; the x86-32 path is described under
[x86-32](#x86-32).
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
CallingConvention::WindowsX64)` (`WindowsX86` for a 32-bit image) reuses existing recovery metadata and accepts
additional symbols. Specifications are initialized once per session; function
analysis is released after each request, including temporary inferred callee prototypes. The Rust result always includes
timings, even when the CLI omits them for deterministic JSON.

Sessions are neither Send nor Sync. Native calls are serialized process-wide
because Ghidra has shared registries. An unexpected native failure poisons the
session; create another session to continue. A work-limit or deadline error
aborts only its request and leaves the session usable. Rust-rejected invalid requests leave it
usable. Native warnings set `incomplete`; consumers should display them. `unknown_callees` says
whether the cause is a callee without a known prototype (arguments or return values may be
missing), which is by far the commonest one. `incomplete && !unknown_callees` is a harder
failure: a native error, a flow problem or a load diagnostic.
The adapter applies the prototype of every import from a Windows system DLL that
Ghidra's bundled Windows and C library data type archives describe (see
[Prototype pack](#prototype-pack)), and `from_pe` applies a compact subset of the bundled FLIRT signatures for
runtime names. Validated MSVC runtime matches and the PE DLL entry point get
known calling signatures. Runtime helpers with a modeled effect then get their
compiler-spec call fixup (see [Effect models](#effect-models)). An export name or an
arbitrary caller-supplied name does not enable one, and `from_analysis` applies none.
Functions that no other source names are then matched against Ghidra's Function ID
databases (see [Function ID names](#function-id-names)); a recognized name also
applies the packed prototype of that name, so `memset`, `strlen` and the other
libc functions are typed. See the [runtime-signature provenance](../capa-x/sigs/DECOMPILER.md). `from_pe` loads a PE whose import or delay import directory is malformed without imports and with an "import directory ignored" warning. `from_analysis` uses the caller's symbol map and
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
executable function entry. It stops on any other control flow. This is the
fallback for an analysis that lacks the wrapper; native recovery now finds them
(see Function discovery).

## Function discovery

`from_pe` uses the native recovery backend, which adds PE x64 sources the
Vivisect-compatible capability path does not use. Capa results are unchanged:
all of it is gated on `RecoveryBackend::Native`.

- **`.pdata`.** Every non-chained `RUNTIME_FUNCTION` begin is a start. Vivisect
  stops reading the table at the first entry it cannot read; native recovery
  keeps going. Entries bound a function exactly, so an address strictly inside
  one (a catch continuation, a switch arm or a chained fragment) is never a start.
- **Code named by data.** Image-relative (`u32`) and absolute (`u64`) values in
  initialized non-code sections (`.rdata`, `.xdata`, ...) that name undecoded
  code. MSVC leaf funclets (unwind cleanups, catch thunks) have no unwind entry
  and are reachable only this way. A value is accepted only if the target
  decodes, is not `int3`/`nop`, lies outside every unwind extent and follows a
  function-ending instruction (`ret`, unconditional or indirect `jmp`, `int3`,
  or a call to a no-return function) with only padding between them. Entries
  that sit back to back are admitted over successive rounds, once the one before
  them is decoded.
- **Tail jumps.** A direct unconditional `jmp` whose target is decoded code
  starting right after a function end and `int3` padding, outside unwind
  extents, makes the target a function. This generalizes the wrapper case to
  any target, and the existing tail-call override then keeps the jump a call.
  A `jmp [import]` stub that other code branches to is a function too. An
  unreferenced stub is not.
- Prologue patterns (three x64 byte patterns) and raw call sweeps already seed
  candidates in native recovery.

The Vivisect `/GS` cookie-tail split is skipped for native recovery: Ghidra keeps
the check in its caller.

Not done: a stack-balance check for the tail-jump rule (the padding and
function-end test stands in for it), Ghidra's function-start byte patterns
beyond the existing prologues, and `jmp [import]` stubs that nothing references
(Ghidra creates some, for example 176 in `kernel32` and 32 in a MinGW DLL).

Read-only image sections retain constant/string semantics except for individual
eight-byte IAT slots. Typed string pointers allow Ghidra to render narrow and
UTF-16 literals. The adapter keeps small hand-built layouts of `LUID`,
`LUID_AND_ATTRIBUTES`, and `TOKEN_PRIVILEGES` for explicit `set_signature`
calls (sizes 8, 12 and 16, alignment 4, `ANYSIZE_ARRAY = 1`, following
[the SDK](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges)).
Imports get their full types from the prototype pack instead.

## Function ID names

`from_pe` hashes every recovered function the way Ghidra's Function ID analyzer does
and looks it up in a pack built from Ghidra's Visual Studio databases
(`capa-x/sigs/fid-x64.pack`, about 9.9 MB, and `fid-x86.pack`, about 12.6 MB, embedded
only with the `decompiler` feature; provenance and validation in [`FID.md`](../capa-x/sigs/FID.md)). Lookup is
hash-bucketed and nothing is decoded until a hash matches. Matches are scored with
the callee and caller relations like Ghidra's `FidProgramSeeker`, and a name is
applied only when it is unambiguous. Exports, FLIRT names and the DLL entry keep
their names. Naming depends only on the image, never on request order.

An ambiguous match is left unnamed, but Ghidra labels each of its candidates `FID_conflict:`
and its call fixups list those labels. So when every candidate selects the same fixup
(`__SEH_prolog4` and `__SEH_prolog4_GS`), the fixup is applied anyway.

A function that is only `jmp [import slot]` is named after the import and typed like it (as
Ghidra does for thunks), and an export takes the archive prototype of its own name when the
archives know it (a proxy DLL's `GetFileVersionInfoA`). Decorated C++ export names never match.

## Effect models

Some runtime helpers break ordinary calling-convention rules: `__security_check_cookie`
preserves RAX and has no visible effect, and `__chkstk` moves the stack pointer. Ghidra
replaces calls to them with the p-code snippets of the `<callfixup>` entries in
`x86-64-win.cspec` (3 entries, 7 target names). `from_pe` does the same. The table in
`capa-x/src/decompiler/effects.rs` maps a recognized name, without leading underscores,
to a fixup: `security_check_cookie`; `alloca_probe` for `_alloca_probe`,
`_alloca_probe2`, `__chkstk`, `__chkstk2` and `___chkstk_ms`; `guard_dispatch_icall`.
Only names from FLIRT or Function ID select a model: an export is a claim by the image
itself, and `from_analysis` leaves effects to its caller.

Native `Session::set_call_fixup` applies a fixup by name and rejects unknown names. The
call disappears from the pseudocode, which gains Ghidra's
`replaced with injection` comment. That comment is informational: it does not set
`incomplete`, because it records a modeled effect, not a gap. Effects: callers keep RAX
across a cookie check, the dead cookie computation no longer shapes parameters
(`__GSHandlerCheckCommon` loses a spurious parameter and a void return), and a function
with a probed frame keeps a correct stack pointer instead of printing every local as an
`&stack0x...` address. `__GSHandlerCheck` itself needs no entry: it is ordinary code that
calls the cookie check. The older `set_preserves_rax` stays in the native API for a
helper that has a RAX effect but no fixup.

## Data and string symbols

Ghidra labels the data a function touches from its program database. The embedded engine
has none, so it printed globals as the engine's own placeholders (`uRam0000000140004098`)
and string pointers as bare constants. `Session::decompile` now derives labels from the
image bytes, per request, and uses Ghidra's conventions:

| Data | Name | Rule |
|---|---|---|
| Global read or written at a constant address | `DAT_<addr>` | size is the largest access seen |
| Address taken, not a string | `&DAT_<addr>` | |
| NUL-terminated printable ASCII, at least 4 characters | `s_<text>_<addr>` | typed `char[n]`, so the printer can show the literal |
| NUL-terminated UTF-16LE, ASCII range, at least 4 characters | `u_<text>_<addr>` | typed as a wide `char[n]` |
| 8-byte aligned cell holding an image address | `PTR_FUN_`, `PTR_DAT_`, `PTR_s_`/`PTR_u_<text>_<addr>` | by the pointee: code, data or a string |

The text is the first 32 characters after dropping trailing line breaks; every character
other than a letter, digit, `_`, `<` or `>` becomes `_` (so `usage: T1181-EWMI <payload>\n`
is `usage__T1181_EWMI_<payload>`); the address is lowercase hex padded to 8 digits. The
constants (32 characters, the kept set, the padding) were read from Ghidra 12.1.4's output
on the baseline and held-out selections (about 15 string labels, all consistent with the rule). The
minimum of 4 characters is this adapter's choice, not Ghidra's.

How it runs: the first analysis finds which data addresses the function uses (persistent
varnodes in mapped, non-executable memory, plus constant operands that land there). The
symbols are added to the global scope, the function is analyzed again, and they are
removed when the request ends. The symbols are not part of the supplied facts, carry
no locked type except the string arrays, and only skip an address that already has a real
symbol (an import, a function). The cost is a second analysis of each function that
touches data: median request time rose about 26% to 33% (8.1 to 10.3 ms and 4.7 to 6.3 ms
on the two measurement sets).

This also fixes a leak. The engine stores its `uRam...` placeholders in the global scope, so
the name of a global depended on which earlier request had typed it first (the same
address printed `uRam...` in one request and `xRam...` in another). The request's end now
removes every placeholder global, and a test requests the same functions in different
orders and sessions.

Limits: only addresses inside mapped sections are named, so memory the image does not
carry (the unpacked sections of a packed file, zero-filled tails beyond the raw data) keeps
placeholders; and a global that the analysis only discovers during callee-prototype inference
is named by the engine, not by this pass.

## x86-32

A PE32 image gets the x86-32 language: `x86.slaspec` (compiled at build time next to the x64 one),
`x86.pspec` and `x86win.cspec`. Everything that differs lives in one `Spec` in `native/bridge.cc`:
the specifications, the prototype pack, the pointer width (4 bytes: import slots, `ValueType::Pointer`,
data symbols for pointer cells), and the unmapped range used for import targets
(`0xf0000000` upward). Sessions of both languages coexist in one process.

- **Conventions.** `x86win.cspec` defaults to `__stdcall` with the stack purge unknown, so the engine
  infers it per function; `__cdecl`, `__fastcall` and `__thiscall` are defined too. Imports take the
  convention recorded in the pack. Output names it as Ghidra does (`__fastcall FUN_00414a70(...)`).
  The result's `calling_convention` is `windows_x86`.
- **Types.** `capa-x-ghidra/data/winapi32.pack` (1.3 MB; 28,186 functions, 8,006 types) comes from
  `windows_vs12_32.gdt` and `generic_clib.gdt` through the same export as the x64 pack
  (`scripts/decompiler_types/README.md`).
- **Library names.** `capa-x/sigs/fid-x86.pack` (12.6 MB) from the x86 Visual Studio databases;
  the matcher hashes 32-bit code (`fid::x86::describe_in`). See [`FID.md`](../capa-x/sigs/FID.md)
  for how closely it reproduces Ghidra's hashes.
- **Effect models.** `x86win.cspec` declares 10 call fixups with 27 target names (`__EH_prolog3`,
  `__SEH_prolog4`, `__alloca_probe`, `__RTC_CheckEsp`, `__security_check_cookie`, ...). A table in
  `capa-x/src/decompiler/effects.rs` maps recognized names to them, and a test compares both tables
  with the vendored specs.
- **Names.** Default function names are padded to the address width, as Ghidra prints them
  (`FUN_00404dd0`); data symbols use the same width (`DAT_0041b028`).
- **Discovery.** There is no `.pdata`, so function discovery relies on the capability path's sources
  plus the native additions that do not need it. See the x86-32 results.

Two robustness changes came with it and apply to both languages. A flow that leaves executable memory
is now Ghidra's own "bad instruction" warning (the rest of the function stays) instead of a failed
request, and a callee whose analysis cannot be translated costs only its own inferred prototype.

Not done for x86-32: Delphi and Borland register conventions (`x86delphi.cspec`, `x86borland.cspec`),
MinGW-specific runtime names (no FLIRT or Function ID data), `fwait` plus x87 forms beyond the
merge in the hasher, and AVX/VEX instructions in the Function ID masks.

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
`__stdcall` map to the single Windows x64 model. The x86-32 pack keeps each prototype's own
model, since `x86win.cspec` defines `__stdcall`, `__cdecl`, `__fastcall` and `__thiscall`.

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
