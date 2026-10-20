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
  candidate. Collect statically dereferenced pointer values for pointer
  classification.
- Respect existing instruction interiors, typed data, strings, and loader
  dead-data ranges, including embedded plaintext or single-byte-XOR PEs.
- Allow registered function signatures to bypass evaluation only for the
  pointer-classification path, matching `isProbablyCode`.
- Run emucode before signature fallbacks and late recovery passes. New
  operand references from those later passes do not restart emucode.
  Dereferenced pointers may still be followed.

Ordered candidate maps and path scheduling preserve reproducible results.
The native backend keeps its existing heuristic policy.

## Limits

This is a candidate classifier, not a complete Vivisect workspace emulator.
It does not model API argument types, callback hooks, general symbolic
switches, or all vector/FPU operations. Unknown input state stays unknown.
The supported instruction subset and all limits are explicit in
`emucode.rs` and `pointers.rs`.

The per-trace limits are 8,192 instructions and 256 queued paths. Discovery
examines at most 32 MiB of raw ELF pointer sources and evaluates at most
32,768 candidates per recovery pass. These are local resource limits,
not copied upstream semantics.

Callback-created roots remain KD-007. In particular, attributing every
function created during the emucode module to emucode itself is insufficient:
the module can consume references exposed by earlier callback analysis.
Measurements must trace the originating `makeFunction` call as well.

## Validation

Synthetic tests exercise computed targets, register aliases, path termination,
unsupported operations, distribution thresholds, known anomalies, instruction
interiors, relocated operands, typed data, and pass ordering. Pinned samples
cover pointer-only ELF roots and shared PE function boundaries. Corpus
comparisons and their deliberately updated baselines are recorded in
[`../BENCHMARKS.md`](../BENCHMARKS.md).
