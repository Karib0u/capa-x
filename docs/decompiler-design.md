# Optional native Ghidra decompiler

Status: implemented for explicit x86-64 and x86-32 PE function requests.

The decompiler uses the pinned Ghidra C++ implementation and native SLEIGH
translation. iced-x86 recovery supplies discovery metadata only. This keeps
p-code semantics, data-flow recovery, structuring and C printing in Ghidra.
The result is a dedicated `Decompilation`, independent of capability results.
No decompiler is instantiated by normal capa analysis.

## Boundary and ownership

`capa-x-ghidra` is the only FFI crate. Its CXX declarations are the unsafe
boundary; the public Rust interface owns a native session and accepts copied
slices and strings. Both analysis and CLI retain `#![forbid(unsafe_code)]`.
CXX 1.0.180 is pinned to preserve Rust 1.87 compatibility. It is maintained,
MIT/Apache-2.0 licensed, generates ownership and exception glue, and contains
unsafe implementation code. CXX does not make upstream native parsing memory
safe. `cc` and `cxx-build` are build-only dependencies and do not parse samples.
Native allocation failures become errors where the C++ runtime throws;
process-wide allocator exhaustion is not a recoverable isolation boundary.

Ghidra is Apache-2.0, actively maintained, and handles untrusted instructions
in native C++. Vendored sources and specifications are pinned together, with
original notices and checksums. The optional build needs a C++14 compiler and
zlib headers/library. Native Linux and macOS builds are supported initially;
cross builds and Windows hosts fail with an explicit build error. The input
format is Windows PE regardless of host. Default builds do not compile C++
or include CXX, Ghidra or specifications.

Upstream `SleighArchitecture` has a static mutable translator map. The adapter
bypasses it and owns its translator. Specifications and instruction caches
remain alive for the session, while function analysis is cleared after every
request. Sessions are neither Send nor Sync. A process-wide C++ mutex also
serializes initialization, all native calls and destruction, protecting the
remaining global registries. Separate sessions can be created on separate
threads, but they do not execute concurrently. `--jobs` does not control the
decompiler. Do not remove this serialization without a new upstream audit.

## Adapter

`DecompilerSession::from_pe` validates the container, performs native recovery
once, matches a compact subset of the bundled FLIRT signatures, and supplies
PE exports and recognized runtime names. The 54-pattern, 6 KiB runtime subset
is generated conservatively from the pinned Mandiant database. Its immutable
cache is shared process-wide; startup time and memory are included in session
benchmarks. `from_analysis` accepts existing `Analysis` and a symbol-name map,
avoiding repeated recovery. All mapped section bytes,
permissions, recovered function entries, import slots and known non-returning
functions are copied into the session. Symbols become valid C identifiers;
the original selected name remains in the structured result. The embedded
`x86-64.pspec` initializes long-mode context and `x86-64-win.cspec` selects
Windows x64 argument registers, shadow space, stack rules and data sizes.
`CallingConvention::WindowsX64` selects the x86-64 language and `WindowsX86` the x86-32 one; a session
has the language of its image and `from_analysis` rejects a mismatch. In x86-32 the specs are `x86.slaspec`,
`x86.pspec` and `x86win.cspec`, whose default model is `__stdcall` with the stack purge inferred per
function. See [x86-32](decompiler.md#x86-32).

Imports are external-reference symbols at IAT addresses, pointing to function
symbols in a reserved unmapped address range. Only eight-byte import slots lose read-only constant-folding semantics; the
rest of each read-only section retains its constant and string context. Native p-code translation reads
the loaded image directly and rejects instruction flow outside executable
mappings. Explicit requests can register entries missed by discovery.

The adapter supplies Windows API prototypes and types from a packed Ghidra data
type archive export (see the prototype pack in decompiler.md) and
known prototypes for validated MSVC runtime matches and the DLL entry point.
Explicit `set_signature` calls can override the defaults. PDB types and
non-Windows archives are outside this milestone.

Native analysis of up to 16 supporting direct callees, bounded to four call
levels and the same request time/work budget, can recover forwarded arguments.
This is on-demand supporting analysis for one selected output function, not
whole-image decompilation. The instruction limit applies per analyzed function;
the aggregate work/deadline limit applies to all passes. Only completed,
warning-free analyses without unknown callee prototypes contribute inferred
signatures. Derived locks are released after each request. This avoids output
changing with request order or stale inference after an explicit override.

Direct branches to separately recovered functions and IAT jump thunks receive
Ghidra's CALL_RETURN override. Local branches and jumps back to the same entry
retain their original flow. No p-code is translated by iced-x86.

Inferred callee signatures, unknown prototypes, native warnings and loader
diagnostics are reported and conservatively set `incomplete`. Discovery
diagnostics stay on `Analysis`: native SLEIGH can resolve flow that the
independent recovery graph could not.
Raw machine code remains the authority when inferred logic is ambiguous.

## Limits and errors

Local defaults are 5 seconds, 10,000 instructions, and 2,000,000 native work
checkpoints. Work is charged for translation, p-code/varnode creation and
rule/action processing. User overrides have fixed upper bounds. Mapped bytes,
section counts, symbols, symbol lengths and output length are bounded too.
These constants are local policy, not copied upstream defaults.

Timeouts are cooperative, not hard wall-clock guarantees: an individual
upstream operation between checkpoints can overshoot the deadline. No
in-process C++ cancellation mechanism can safely kill a stuck thread.
Instruction and work caps bound the principal growth paths, but this backend
is not a sandbox for hostile native-engine exploits. A hard memory or
wall-clock isolation boundary would require a separate process, outside this
milestone's in-process requirement. Keep this limitation visible to callers.

Ghidra exceptions, standard exceptions and unknown exceptions are translated
before leaving C++. Native failures include the selected address in the Rust
error and poison the session. Dropping it releases its resources. Invalid
addresses and limits rejected by Rust leave the session usable. A successful
result may still carry `incomplete: true`; warnings are never silently lost.

## Validation

See [decompiler documentation](decompiler.md) for build/API examples,
fixture commands, reference comparison, measured performance and limitations.
The pinned Ghidra headless reference is development-only. It is never invoked
by the feature or CLI.
