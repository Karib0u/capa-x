# ADR 0007: Evaluate referenced function candidates in process

- Status: Accepted

## Context

The compatibility backend previously treated PE relocation targets with a
first-mnemonic whitelist and did not implement Vivisect's unreferenced-address
pass. KD-002 and KD-003 record missing functions and false starts caused by
these shortcuts. The pinned implementation uses
`vivisect/analysis/generic/emucode.py:watcher`, reached both by
`generic.emucode.analyze` and `VivWorkspace.isProbablyCode`.

## Decision

Use a bounded abstract interpreter over the existing iced-x86 decoder for
x86/x64 compatibility recovery. It tracks known register values, aliases,
effective addresses, and private memory writes. Calls invalidate return values
and caller-saved state; conditional branches explore both paths. It never
executes sample code, calls an external process, or loads a new dependency.

Acceptance follows the watcher's return/no-return and mnemonic-distribution
checks. Each address is visited at most once. Unknown operations or indirect
targets stop that path; if no supported path establishes code, recovery
reports an inconclusive diagnostic. Trace and candidate budgets likewise
produce diagnostics, never positive classifications.

Keep candidate selection separate from evaluation:

- Retain PE relocation source slots. A slot inside an instruction is an
  operand reference, not a defined data pointer.
- Scan undefined ELF locations for pointers, including unaligned locations.
  PE does not run the corresponding generic pointer-table passes.
- Collect named ELF addresses, immediate operands, and RIP-relative LEA
  operands for emucode. The pinned decoder does not expose a static value
  for an absolute x86 LEA without an emulator, so it does not create a
  candidate. The x86 calling-analysis monitor separately follows the pointer
  stored at a discrete LEA address, without promoting that address to code.
  Collect statically dereferenced pointer values for pointer classification.
- Respect existing instruction interiors, typed data, strings, and loader
  dead-data ranges, including embedded plaintext or single-byte-XOR PEs.
- Allow registered function signatures to bypass evaluation only for the
  pointer-classification path, matching `isProbablyCode`.
- Run emucode before signature fallbacks and late recovery passes. New
  operand references from those later passes do not restart emucode.
  Dereferenced pointers may still be followed.
- Recover concrete Windows API callback arguments using the `funcptr`
  positions in Vivisect 1.3.2's Windows API tables. Reuse the interpreter for
  x86 stack and Windows x64 register/stack values. Explicit callbacks can
  enter executable sections marked as dead data, as the upstream call
  monitor does; they cannot split existing instructions.
- Keep broad prologue and raw call sweeps for the native backend and
  AArch64, which has no Vivisect reference backend. Candidate, callback, and
  registered-signature recovery replace them in x86/x64 compatibility mode. Support `xadd` so relocation-backed functions do not
  depend on a raw call sweep to compensate for an unsupported operation.
- For x86/x64 ELF relative relocations, follow the reference's stored-pointer
  semantics instead of substituting a RELA addend.

Ordered candidate maps and path scheduling preserve reproducible results.
The native backend keeps its existing heuristic policy.

## Limits

This remains a bounded analyzer, not a complete Vivisect workspace emulator.
API callback positions are supported, but arbitrary API side effects,
dynamically resolved API identities, general symbolic switches, and all
vector/FPU operations are not. Unknown calls discard argument state while
preserving known imports in nonvolatile registers. Unknown input state stays
unknown. The supported instructions and limits are explicit in `emucode.rs`,
`callbacks.rs`, and `pointers.rs`.

The per-trace limits are 8,192 instructions and 256 queued paths. Discovery
examines at most 32 MiB of raw ELF pointer sources and evaluates at most
32,768 candidates per recovery pass. These are local resource limits,
not copied upstream semantics.
Callback traces use the same instruction and path bounds, and resolve at most
eight jump thunks per call. They retain already proven callback targets when
a later path reaches a limit, with a diagnostic. Paths visit each instruction
at most once; this is not exhaustive path-sensitive analysis.

Callback-created roots are documented in KD-007. Attributing every
function created during the emucode module to emucode itself is insufficient:
the module can consume references exposed by earlier callback analysis.
Measurements must trace the originating `makeFunction` call as well.

## Validation

Synthetic tests exercise computed targets, register aliases, path termination,
unsupported operations, distribution thresholds, known anomalies, instruction
interiors, relocated operands, typed data, API arguments, and pass ordering.
Pinned samples cover pointer-only ELF roots, callback chains, and shared PE
function boundaries. Corpus
comparisons and their deliberately updated baselines are recorded in
[`../BENCHMARKS.md`](../BENCHMARKS.md).
