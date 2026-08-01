# ADR 0005: `goblin`'s Mach-O support is enough for checked loading, with a thin validation wrapper

- Status: Accepted
- Scope: checked Mach-O loading

## Context

The project needs a checked Mach-O loader: thin and fat binaries in both
byte orders, 64-bit x86_64 headers and load commands, segment mapping,
sections, symbols, dylib/bind/rebase resolution, and — the part this ADR
exists to answer — validated offsets, sizes, alignments, command counts,
overlaps, and integer arithmetic before allocation or slicing. `goblin`
0.10.7 is already a `capa-x` dependency for PE and ELF loading. This ADR
answers the dependency question: is its Mach-O support enough for checked
loading, or only suitable as a header parser? The audit uses the malformed
fixture set in `capa-x/tests/fixtures/macho/malformed/`.

## Method

A throwaway spike binary (not committed, per ADR 0001's precedent) called
`goblin::mach::Mach::parse` on all 8 clean fixtures and all 5 malformed
fixtures from `capa-x/tests/fixtures/macho/`. For every successfully
parsed `MachO` (thin or, for fat binaries, each contained slice), it also
exercised the operations a real loader needs beyond the top-level parse:
`.symbols().count()`, `.exports()`, `.imports()`, `.relocations()` — since
"checked loading" means the whole path a feature extractor walks, not just
whether the initial header parse succeeds. Every call ran inside
`std::panic::catch_unwind`.

## Results

**Zero panics** across all 8 clean and 5 malformed fixtures, on both the
top-level parse and the deeper symbol/export/import/relocation walks.

| Fixture | Result |
|---|---|
| all 8 clean fixtures | parsed correctly; segment/symbol/export counts match expectations (e.g. 5 segments, 7 symbols, 2 exports for the executables; fat binaries correctly yield both contained slices) |
| `truncated-load-commands` | `Err`: "Buffer is too short for 16 load commands" |
| `filesize-gt-vmsize` | `Err`: "type is too big (69632) for 8544" |
| `slice-offset-past-eof` | `Err`: "Malformed entity: Object is too small" |
| `bad-ncmds` (doubled `ncmds`, `sizeofcmds` unchanged) | **accepted without error** — parses as if nothing were wrong, segment count unchanged from the clean fixture |
| `overlapping-segments` (`__DATA_CONST.fileoff` moved inside `__TEXT`'s range) | **accepted without error** — both segments parse with their now-overlapping file ranges intact, no cross-segment check |

Three of the five malformed fixtures are caught. `goblin` bounds-checks
individual reads against the buffer (that's what rejects the truncated and
slice-offset-past-eof cases, and the oversized single load-command type in
`filesize-gt-vmsize`), but it does **not** cross-validate `ncmds` against
what the file actually contains beyond a single pass, and it does **not**
check that segments' file ranges are mutually exclusive. Neither omission
causes a panic or an out-of-bounds read here — `goblin` never trusts
`ncmds` or a segment's `fileoff`/`filesize` further than a single bounds
check against the whole buffer — but both are real structural invariants a
"checked" loader should be able to reject, and `goblin` silently accepts
both.

`goblin` is already vetted as a `capa-x` dependency (PE and ELF loading
run through it today), so this ADR does not re-evaluate license,
maintenance, or unsafe-code posture — only whether its Mach-O module
specifically meets C.1's bar.

## Decision

**Use `goblin`'s Mach-O module**, with a thin validation layer in `capa-x`'s
own Mach-O loader -- not a different crate, and not a
from-scratch parser. Specifically, C.1 must add, before trusting a parsed
`MachO`'s segments:

1. a check that `ncmds` load commands actually fit within `sizeofcmds`
   (equivalently: that iterating `ncmds` commands from the header never
   reads past `header_size + sizeofcmds`) — `goblin` does not do this
   itself, as `bad-ncmds` demonstrates;
2. a pairwise check that no two `LC_SEGMENT_64` commands' `[fileoff,
   fileoff + filesize)` ranges overlap — `goblin` does not do this either,
   as `overlapping-segments` demonstrates.

Both are cheap (O(n) and O(n²) over a segment count that is never large)
and match the roadmap's own C.1 wording ("validate offsets, sizes,
alignments, command counts, overlaps... before allocation or slicing") —
this ADR is what makes "overlaps" and "command counts" concrete rather than
aspirational.

Everything else C.1 asks for — 64-bit header/load-command parsing, fat/thin
dispatch in both byte orders, segment/section/symbol access, dylib and
bind/rebase resolution surfaces — `goblin` already provides without
crashing on the malformed inputs this ADR tested, and no other Mach-O crate
needs evaluating: `goblin` is already in the dependency tree for PE/ELF, so
adopting it for Mach-O too adds no new crate, no new license, no new
maintenance surface — only the two validation checks above, which live in
`capa-x`, not in a dependency.

## Consequences

- The loader gets a concrete, evidence-based checklist item: the
  two validation checks above, each traceable to a named fixture in
  `capa-x/tests/fixtures/macho/malformed/` that demonstrates why it's
  needed. C.1's own malformed-fixture acceptance criterion ("every
  malformed fixture returns a contextual error") should re-run this ADR's
  spike as a real test once the loader exists, confirming `bad-ncmds` and
  `overlapping-segments` now reject too.
- No dependency ADR is needed for a Mach-O-specific crate; `goblin`'s
  existing pin in `capa-x/Cargo.toml` covers this.
- If the implementation finds a third class of structural invariant
  `goblin` doesn't check (not found by this ADR's five fixtures, but the
  set isn't exhaustive), add it to `capa-x`'s validation layer the same
  way — the pattern this ADR establishes, not a one-time list.

## References

- [goblin 0.10.7](https://crates.io/crates/goblin/0.10.7) (already pinned in `capa-x/Cargo.toml`)
- [`goblin::mach` module source](https://github.com/m4b/goblin/blob/main/src/mach/mod.rs)
- `capa-x/tests/fixtures/macho/` (this ADR's fixture corpus)
- The dependency policy and Mach-O loader acceptance checks
