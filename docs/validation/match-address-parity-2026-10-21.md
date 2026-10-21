# Complete native match-address parity, 2026-10-21

Fresh release analyses produce **376/376 identical rule and match-address
sets (100%)** across all comparable native x86/x64 PE, ELF, and shellcode
inputs in the pinned testfiles corpus. There are zero missing or extra rules
and zero missing or extra addresses.

| Metric | Result |
|---|---:|
| Raw corpus inputs | 377 |
| Comparable inputs | 376 |
| Reference rule/sample matches | 11,412 |
| Identical rule-name sets | 376/376 (100%) |
| Identical rule and match-address sets | 376/376 (100%) |
| Missing / extra rule names | 0 / 0 |
| Missing / extra addresses | 0 / 0 |
| Reference-side rejections | 1 |

The reference rejects the malformed ELF
`c2b2d7cea94179e6c2b6913205e37c45b67ccc0156d8f266548f7f1f95144285.elf_`
with exit 13. It remains in the raw denominator and in the
[complete per-sample report](match-address-parity-details-2026-10-21.md).
Consequently, the harness returns nonzero for the full corpus even though
every comparable result is exact. No failed input is treated as an empty
result or silently excluded from the report.

This establishes equality of rule/address sets on this pinned corpus.
Evidence-tree identity, duplicate-match multiplicity, other backend profiles,
and arbitrary binaries are separate questions. Historical measurements in
the [previous checkpoint](match-address-checkpoint-2026-10-20.md) remain
unchanged.

## Changes

- Preserve pointer retyping, orphaned suffixes, overlapping opcode deletion,
  and the reference's block installation order. Keep FLIRT visibility on a
  monotonic discovery sequence after locations are deleted.
- Stop string recognition and relocation traversal at previously typed
  locations. Record relocation and immediate references that bound adjacent
  jump tables.
- Defer image-relative switches until calling emulation reaches them, and
  follow unresolved scale-four tables as the pinned emulator does.
- Preserve PE entry/export/handler ordering, immediate-only delayed callback
  release, ELF register thunks, and dynamic-library hook return behavior.
- Align LOCK and redundant REX prefixes, legacy vector instruction lengths,
  undefined x87 aliases, vector emulation, bounds faults, and unresolved
  no-return edges with the pinned implementation.

Synthetic tests cover instruction boundaries, pointer suffix deletion,
signature visibility after deletion, strings, typed relocations, ELF thunks,
emulator faults and returns, PE root ordering, and unresolved jumps.
There are no sample-specific matching exceptions or new dependencies.
Pinned submodules, rules, samples, archived reference results, and expected
baselines are unchanged.

## Reproduction

Use the versions and setup in [PINNED.md](../../PINNED.md) and
[CONTRIBUTING.md](../../CONTRIBUTING.md):

```sh
scripts/check_env.sh
cargo build --release -p capa-x-cli
mkdir -p target/parity
cp target/release/capa-x target/parity/final-cli
python3 scripts/difftest.py --mode full-exact \
  --samples scripts/corpus-full-static.txt \
  --capa-cli target/parity/final-cli \
  --no-rust-cache --no-expected --jobs 6 \
  --report target/parity/full-exact.md
python3 scripts/difftest.py --mode full \
  --samples scripts/corpus-full-static.txt \
  --capa-cli target/parity/final-cli \
  --no-rust-cache --no-expected --jobs 6 \
  --report target/parity/full-rules.md
```

Both full-corpus commands retain the single reference rejection. Rust output
is regenerated from immutable release binaries. Six harness workers analyze
independent samples; each analysis uses the serial semantic baseline.
The pinned Python reference cache is reused without changing its outputs.
Host-specific path prefixes in the checked-in report are normalized to
repository-relative paths. Concurrent validation makes the reported durations
unsuitable for performance comparisons.

## Validation

- `cargo fmt --all -- --check` and `git diff --check`.
- `cargo +1.98.1 clippy --workspace --all-targets --target-dir target/clippy -- -D warnings`.
- `cargo test -p capa-x --test features_parity`: all four tests pass.
- `python3 -m unittest discover -s scripts -p 'test_*.py'`: all ten tests pass.
- `scripts/check_env.sh`: pinned reference version and submodule gitlinks pass.
- Fresh smoke differential: 23/23 identical, zero baseline regressions.
- Fresh full rule differential: 376/376 comparable inputs exact, covering
  11,412 reference rule/sample matches.
- Fresh full exact differential: 376/376 comparable inputs exact.
- Fresh outer differential: 200/200 identical, 6,300 reference rule/sample
  matches, zero baseline regressions.
- `cargo test --workspace -- --include-ignored`: all 568 tests pass,
  including the acceptance and robustness gates; none ignored.
- `python3 scripts/determinism.py --samples scripts/corpus-jobs.txt
  --capa-cli target/parity/final-cli --jobs 1,2,4 --repeat 2 --workers 2`:
  all 30 comparisons across five samples are byte-identical after
  invocation-metadata normalization.

The system Rust 1.96 Clippy does not recognize an existing repository lint
allowance, `clippy::chunks_exact_to_as_chunks`. Clippy validation uses the
installed Rust 1.98.1 toolchain, as at the previous checkpoint.
