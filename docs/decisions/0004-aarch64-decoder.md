# ADR 0004: `disarm64` as the AArch64 instruction decoder

- Status: Accepted
- Scope: AArch64 instruction decoding

## Context

The AArch64 backend needs an instruction decoder behind an architecture-
neutral boundary. It must decode fixed-width A64 instructions into typed
operands and branch targets without unsafe code and without panicking on any
input, valid or not. This ADR compares `disarm64` and `yaxpeax-arm` and
records why the FFI-based options `capstone` and `bad64` are rejected.

## Rejected without a spike: `capstone`, `bad64`

Both fail the project's first dependency question ("does it use unsafe code
internally, and can this project accept that transitive risk") before any
decoding accuracy is worth measuring:

- **`capstone`** (crates.io, 0.14.0, MIT) binds the C `libcapstone` library
  via `unsafe extern "C"` FFI, and requires a C toolchain and the capstone
  shared/static library to build. That is exactly the risk category
  the binding crate's declarations-only exception is limited to one crate;
  accepting it here would put unsafe, FFI-linked code directly
  in the analysis path `#![forbid(unsafe_code)]` protects, for every
  platform this project ships a binary on.
- **`bad64`** (crates.io, 0.12.0, Apache-2.0) binds Vector35's Binary Ninja
  disassembler, which is proprietary and not freely redistributable —
  disqualifying independent of the FFI/unsafe question, since it would make
  a from-source build of capa-x depend on a commercial SDK this project
  cannot assume every contributor or CI runner has.

## Method

Both `disarm64` 0.2.0 and `yaxpeax-arm` 0.4.0 were added as dependencies of a
throwaway spike binary (not committed to this repository; built with the
pinned MSRV, `cargo +1.87.0 build`, using each crate's default/`full`
feature set) and run against:

1. every 4-byte-aligned word across the executable `PT_LOAD` segments of the
   three pinned AArch64 ELF samples (`tests/testfiles/aarch64/`) —
   84,839 words, including non-instruction bytes (literal pools, padding,
   embedded jump tables) alongside real code, since both crates see the same
   bytes and that is what a real recovery pass will hand them too;
2. 2,000,000 pseudo-random 32-bit words (deterministic xorshift64 seed);
3. 258 degenerate words: `0x00000000`, `0xFFFFFFFF`, and every byte value
   repeated across all four bytes.

Each decode call was wrapped in `std::panic::catch_unwind`. For every word,
both crates' validity verdict (decodable / not) was compared.

## Results

| Corpus | words | disarm64 ok/unknown/panic | yaxpeax-arm ok/unknown/panic | validity disagreements |
|---|---:|---|---|---:|
| 3 pinned samples (combined) | 84,839 | 71,776 / 13,063 / **0** | 70,410 / 14,429 / **0** | 1,660 (2.0%) |
| pseudo-random fuzz | 2,000,000 | 933,639 / 1,066,361 / **0** | 729,097 / 1,270,903 / **0** | 300,036 (15.0%) |
| degenerate words | 258 | 117 / 141 / **0** | 91 / 167 / **0** | 40 (15.5%) |

**Zero panics from either crate**, across all ~2.09 million decode attempts
combined (real code, fuzz, and degenerate input) — both satisfy the no-panic
requirement as measured here.

On the samples that matter — real AArch64 code — `disarm64` recognizes
1,366 more words than `yaxpeax-arm` (71,776 vs 70,410 out of 84,839, i.e.
84.6% vs 83.0%), and the validity disagreements are concentrated there: of
the 1,660 disagreements on real code, `disarm64` decodes and `yaxpeax-arm`
reports unknown in the large majority of cases (spot-checked a sample of 20;
none went the other way). On the fuzz/degenerate corpora, `disarm64` also
recognizes more words, which is expected of a garbage input stream and not a
recall signal — it says nothing about which crate's real-code opcode
coverage is better, only that `disarm64`'s decode space is somewhat larger.

Neither crate's own repository shows an unsafe block outside test/build
tooling; `disarm64` is `#![no_std]`. Both are actively maintained:
`kromych/disarm64` (45 GitHub stars, MIT license, last push 2026-07-02) and
`iximeow/yaxpeax-arm` (43 GitHub stars, 0BSD, last push 2026-07-28, two days
before this ADR). `yaxpeax-arm` has far higher crates.io download counts
(304,790 vs 42,818 total) as part of the broader yaxpeax multi-architecture
decoder family; `disarm64` is purpose-built for AArch64 only, generates its
decode tables from a machine-readable ISA grammar rather than hand-written
match arms, and claims 250+ MiB/s decode throughput.

## Decision

Adopt **`disarm64`** as the AArch64 instruction decoder.

- It recognizes more real AArch64 code in this project's own pinned corpus,
  which is the number that turns into fewer missing mnemonic/operand
  features once the backend wires it up.
- Its `#![no_std]`, single-purpose surface fits behind the decoder
  boundary more directly than `yaxpeax-arm`'s generic `Arch`/`Decoder`
  trait machinery, which this project has no other use for. The project
  defines its own minimal interface rather than adopting an
  upstream multi-architecture abstraction.
- `Unlicense OR MIT` is compatible with this project's Apache-2.0
  distribution.
- Zero panics across ~2.09M decode attempts, satisfying question 2.

`yaxpeax-arm` remains a credible fallback, not a rejected option: it is
better-adopted, equally panic-free here, and covers SVE/SME encodings
`disarm64`'s `full` feature does not (`disarm64`'s `full` feature excludes
those; `yaxpeax-arm`'s test suite exercises them explicitly). If the
implementation finds a specific `disarm64` coverage gap against the pinned corpus that
matters for a real rule, revisit this decision rather than work around it —
SVE/SME are server/HPC vector extensions vanishingly unlikely to appear in
the malware corpora this project analyzes, so this is not expected to bite,
but the option is not closed off.

The dependency policy asks what behavior belongs in a wrapper so replacement
remains possible. The decoder boundary is exactly that wrapper:
`disarm64`'s `Insn`/`Opcode` types stay behind it, never exposed through
`capa-x`'s public API, so swapping to `yaxpeax-arm` later stays internal.

## Consequences

- The AArch64 backend adds `disarm64` (and `disarm64_defn`, its table-generation
  dependency) to `capa-x/Cargo.toml`, pinned per `PINNED.md` convention,
  with the one-line justification this ADR provides.
- `capstone`/`bad64` are not evaluated again; a future contributor proposing
  either should point here first.
- The decoder boundary (D.1) must not leak `disarm64`'s own types past its
  module — this ADR's "replacement remains possible" claim depends on that
  containment holding, and D.1's own acceptance checklist should verify it.
- This ADR's spike is not committed (per ADR 0001's precedent) and used no
  fixture beyond what's already pinned in `tests/testfiles/aarch64/`; no new
  corpus obligation follows from it.

## References

- [disarm64 0.2.0](https://crates.io/crates/disarm64/0.2.0)
- [disarm64 repository](https://github.com/kromych/disarm64)
- [yaxpeax-arm 0.4.0](https://crates.io/crates/yaxpeax-arm/0.4.0)
- [yaxpeax-arm repository](https://github.com/iximeow/yaxpeax-arm)
- [capstone-rs 0.14.0](https://crates.io/crates/capstone/0.14.0) (rejected, FFI)
- [bad64 0.12.0](https://crates.io/crates/bad64/0.12.0) (rejected, FFI + proprietary)
- The dependency policy and decoder acceptance checks
