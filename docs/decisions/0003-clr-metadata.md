# ADR 0003: `dnfile` (Rust crate) for CLR metadata/CIL, pending a coded-index patch

- Status: Accepted, conditionally — see Decision
- Scope: checked CLR metadata and CIL

## Context

The managed backend needs a checked CLR metadata and CIL model: PE/CLR header
parsing, the `#~`/`#Strings`/`#Blob`/`#GUID`/`#US` streams, the full
metadata table set, coded-index resolution, and method-body (CIL) decoding
0.5.1 as the candidate to weigh against an in-tree parser. The audit runs it
over `tests/testfiles/dotnet/` plus a mutated-metadata corpus and disqualifies
it on any panic. This ADR records that audit.

Naming note: the dependency's name could be read as the well-known Python
`dnfile` library capa itself already depends on. It is not — there is a
same-named, independent **Rust** crate, [`dnfile`
0.5.1](https://crates.io/crates/dnfile/0.5.1) (`marirs/dnfile-rs`, not
affiliated with the Python project beyond the name and the file format both
parse), and that is what this ADR evaluates. `marirs` also publishes
`capa-rs`, the third-party Rust capa port this project's README benchmarks
against — worth naming since it means this crate has already seen use
parsing real-world .NET malware in an adjacent project, not just synthetic
test files.

## Method

`dnfile` 0.5.1 (default features — the `cli` feature and its `clap`/
`prettytable-rs`/`serde_json` dependencies were left out; only the library
is a candidate here) was added to a throwaway spike binary (not committed;
built at the pinned MSRV, `cargo +1.87.0 build`) and run against:

1. all 8 pinned `.NET` samples in `tests/testfiles/dotnet/`, calling
   `DnPe::parse` → `.net()` → `.functions()` on each, unmodified;
2. a mutated-metadata corpus: 496 mutants (62 per sample), each the
   original file with one of four corruptions applied at a
   pseudo-randomly chosen offset (deterministic xorshift64 seed) — a
   single bit flip, a zeroed run of up to 64 bytes, truncation to a random
   shorter length, or a run of up to 8 bytes overwritten with random data.
   The byte-level, offset-blind mutation strategy was chosen over
   structure-aware mutation (e.g. "corrupt only the `#~` stream's row
   counts") because it needs no advance knowledge of `dnfile`'s internal
   layout assumptions, and because a corrupted PE/CLR header, stream
   directory, or table row all reach the same question: does the crate
   return `Err`, or does it panic?

Every parse attempt (clean and mutant) ran inside `std::panic::catch_unwind`.

## Results

Clean parse: 7 of 8 pinned samples parse successfully; the eighth
(`e8ea789b860e8354b3ef5058bea7ea98.exe_`) returns a contextual `Err` rather
than a panic — an acceptable outcome (a real parse failure the crate
reports, not a crash), though its exact cause isn't diagnosed by this ADR
and is worth a note for whoever implements B.1.

Mutation fuzz: of 496 mutants, 298 parsed without error, 195 were correctly
rejected with `Err`, and **3 panicked**:

```
1c444ebeba24dcba8628b7dfe5fec7c6.exe_ (mutant): index out of bounds: the len is 5 but the index is 5
dd9098ff91717f4906afe9dafdfa2f52.exe_ (mutant): index out of bounds: the len is 3 but the index is 3
dd9098ff91717f4906afe9dafdfa2f52.exe_ (mutant): index out of bounds: the len is 5 but the index is 6
```

All three are the same defect: `src/stream/meta_data_tables/mdtables/
codedindex.rs`'s `CodedIndex::get_table_name` implementations index a fixed
`table_names` array with a tag value decoded from untrusted input --
```rust
fn get_table_name(&self, index: usize) -> Result<&'static str> {
    Ok(self.table_names[index])   // should be self.table_names.get(index).ok_or(...)
}
```
-- despite the method's own signature already committing to a `Result`. The
same pattern (`self.table_names[index]` instead of `.get(index)`) appears in
**all 14** of the file's `impl CodedIndex for ...` blocks
(`ResolutionScope`, `TypeDefOrRef`, `MemberRefParent`, `HasConstant`,
`HasCustomAttribute`, `CustomAttributeType`, `HasFieldMarshall`,
`HasDeclSecurity`, `HasSemantics`, `MethodDefOrRef`, `MemberForwarded`,
`Implementation`, `TypeOrMethodDef`, and one more) -- this ADR's mutants
happened to trigger only 2 of the 14, but the defect is systemic and
mechanical, not scattered: a coded index's low tag bits select which table
its target row belongs to, and every one of these 14 implementations trusts
that tag to be in range without checking, when the file bytes it comes from
are exactly the untrusted input a malformed-metadata corpus is supposed to
stress.

No unsafe code was found anywhere under `src/` outside the two `[[bin]]`
targets (`dndump`/`dnstrings`, gated behind the `cli` feature and not a
dependency of the library this ADR is scoped to) -- those two use
`unsafe extern "C"` for terminal-width detection, irrelevant to a library
consumer. Default-feature dependencies are `byteorder`, `goblin` (already a
`capa-x` dependency), `scroll`, `serde`, `thiserror`,
pins v1, a minor incompatibility, not a blocking one, since both major
versions coexist in one dependency graph without conflict), and `uuid`
(no default features) -- no FFI, no C build dependency. License is
Apache-2.0, matching this project's own. `rust-version = "1.85"` is below
the pinned 1.87 MSRV floor. ~11,500 total lines under `src/` (including the
two excluded bin files), matching the roadmap's "~10k LOC" estimate.
GitHub activity: 2 stars, last push 2026-05-29 -- low adoption, as the
roadmap's own framing anticipated, though co-authored by the same maintainer
as `capa-rs`.

## Decision

**Conditionally accept `dnfile` 0.5.1** for the managed backend, gated on fixing the
`codedindex.rs` unchecked-indexing defect before it enters this project's
dependency tree -- either:

(a) a small upstream PR to `marirs/dnfile-rs` changing all 14
    `get_table_name` implementations from `Ok(self.table_names[index])` to
    a bounds-checked lookup returning the crate's own
    `Error::UndefinedMetaDataTableIndex`/similar variant (the error type
    already has a shape for exactly this failure), pinned to a release
    once merged; or
(b) if upstream is slow, vendor a patched fork pinned by commit in
    `PINNED.md`, with the patch limited to those 14 sites -- a minimal,
    mechanical, easily-reviewed diff -- and a tracking note to drop the
    fork once upstream releases the fix.

As-is, `dnfile` 0.5.1 fails the project bar ("any panic is
disqualifying") and must not be added to `capa-x/Cargo.toml` until one of
the above lands. This is not a rejection of the crate: outside this one
systemic pattern, it parsed 7/8 pinned samples cleanly, correctly rejected
the 8th and 40% of mutants with a proper `Err`, carries no unsafe code, no
FFI, and a compatible license -- and re-implementing ECMA-335's metadata
tables, coded indices, and CIL decoding in-tree from scratch (the
roadmap-named alternative) is a substantially larger undertaking than
patching 14 array accesses in a crate that already gets the other ~11,500
lines of that format right.

## Consequences

- The dependency question is answered: use `dnfile`, once patched. The
  managed backend should
  not begin implementation until the patch is upstream or vendored -- using
  the unpatched crate and hoping the fuzz/malformed-corpus gate (B.5.4)
  catches it later just relocates this ADR's finding to a later, more
  expensive phase.
- Whoever lands the patch should also file it upstream regardless of
  whether this project vendors a fork in the meantime -- the same bug will
  bite any other consumer feeding `dnfile` untrusted `.NET` binaries.
- `capa-x`'s own no-unwrap/no-unchecked-indexing rule (AGENTS.md) applies
  to code this project writes, not to a vetted dependency's internals --
  but "vetted" here specifically means the coded-index patch landed. Record
  the dependency (once patched) with the same one-line justification this
  ADR provides, per the dependency policy.
- Re-run this audit's mutation fuzz against the patched version before the
  acceptance, rather than trusting the patch fixed every reachable instance
  without re-measuring.

## References

- [dnfile 0.5.1](https://crates.io/crates/dnfile/0.5.1)
- [dnfile-rs repository](https://github.com/marirs/dnfile-rs)
- [codedindex.rs, the file containing the defect](https://github.com/marirs/dnfile-rs/blob/main/src/stream/meta_data_tables/mdtables/codedindex.rs)
- The dependency policy and managed-backend acceptance checks
