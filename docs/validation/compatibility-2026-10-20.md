# Native corpus compatibility, 2026-10-20

Starting from main `2a5dc74`, the compatibility changes eliminate all 32
rule-name differences in the expanded native corpus. Every comparable input
now matches the pinned Python reference's rule-name set.

| Metric | Before | After |
|---|---:|---:|
| Rule-name agreement | 99.72% | 100% |
| Reference rule/sample matches | 11,412 | 11,412 |
| Missing / extra rules | 29 / 3 | 0 / 0 |
| Identical rule-name sets | 358/376 | 376/376 |
| Identical rule and match-address sets | 177/376 | 251/376 |

One of the 377 inputs is a malformed ELF rejected by the reference with exit
13. It remains in the corpus and reports as a reference error, rather than
being counted as an empty or successful result. The harness therefore prints
376/377 identical for names and 251/377 for exact sets. The table uses the 376
comparable inputs. No rule or sample exclusions were added.

## Changes

- Resolve ordinal-only OLE Automation APIs using the pinned ordinal table.
- Recover guarded x64 switches whose base register is established earlier,
  and recognize the AMD64 Go runtime entry sequence.
- Preserve sequential relocation discovery, typed strings and hotpatch
  padding, candidate trace location checks, and callback stack arguments.
- Match FLIRT function completion order and public/local label semantics;
  recover undefined local-label code before fallback function entries.
- Follow static indirect callees and no-return callees before caller
  completion, and avoid treating forwarded exports as code.
- Match the pinned i386 INT1 decoder boundary, static loop-edge extraction,
  and ELF CET PLT thunk suppression.

The pinned rules, samples, reference source, and archived reference outputs
remain unchanged. There are no new dependencies or external runtime tools.
Synthetic regression tests cover the changed mechanisms. See
[KNOWN_DIVERGENCES.md](../../KNOWN_DIVERGENCES.md), KD-017 through KD-023, for
upstream source references and remaining limitations.

## Reproduction

Use the versions in [PINNED.md](../../PINNED.md). Build once and retain an
immutable executable while the harness runs:

```sh
cargo build --release -p capa-x-cli
cp target/release/capa-x target/compatibility-final-capa-x
python3 scripts/difftest.py --mode full \
  --samples scripts/corpus-full-static.txt \
  --capa-cli target/compatibility-final-capa-x --no-rust-cache --jobs 6
python3 scripts/difftest.py --mode full-exact \
  --samples scripts/corpus-full-static.txt \
  --capa-cli target/compatibility-final-capa-x --jobs 6
```

Harness jobs parallelize samples. Analysis uses its serial default. Reference
JSON comes from the verified pinned outputs; the name comparison reruns Rust
without its output cache. Full-exact compares sets of `(rule, address)` pairs,
not evidence-tree identity or duplicate match multiplicity.

Detailed results:

- [All native rule-name comparisons](compatibility-rule-names-2026-10-20.md).
- [All native match-address comparisons](compatibility-match-addresses-2026-10-20.md).

## Validation

- `cargo fmt --all -- --check`
- `cargo +1.98.1 clippy --workspace --all-targets -- -D warnings`
- `cargo test -p capa-x --test features_parity`: 4 passed.
- `cargo test --workspace`: 478 passed, 6 ignored; includes 357 library tests and the new local-symbol regression.
- `python3 -m unittest discover -s scripts -p 'test_*.py'`: 10 passed.
- `scripts/check_env.sh`: runtime and submodule pins match.
- Smoke differential corpus: 23/23 identical, 731 reference rule/sample matches.
- `scripts/determinism.py`, `scripts/corpus-jobs.txt`, jobs 1/2/4, two
  repetitions: all 30 runs byte-identical after invocation-metadata normalization.

The slow `--include-ignored` run was stopped when this work was split into a
PR. The complete ignored gates and outer loop remain required before merge.

## Follow-up boundary

Exact agreement work is deferred to a separate session. There are 125
comparable samples with at least one match-address difference. Function
creation timing, shared block ownership, and incomplete abstract evaluation
remain relevant limits; the report records concrete differences without
assigning every remaining case an unverified root cause. Nested FLIRT
workspace callbacks are not fully reproduced by the current bounded local
symbol discovery phase.

This result establishes rule-name parity on this pinned native corpus. It
does not establish universal binary compatibility, identical evidence trees,
or new parity claims for .NET, AArch64, Mach-O, or dynamic inputs. Their earlier
measurements remain in the [expanded validation](full-corpus-2026-10-20.md).
