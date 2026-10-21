# Match-address parity checkpoint, 2026-10-20

Fresh full-corpus runs improve exact rule/address agreement from 326/376
on PR commit `c5a4ee9` to **357/376 (94.9%)**. All 376 comparable inputs
retain identical rule-name sets. Every current missing or extra rule/address
pair was already a discrepancy on that preceding commit: there are **zero
new address discrepancies**, and all 326 previously exact samples remain exact.

| Metric | Preceding PR commit | Checkpoint |
|---|---:|---:|
| Comparable native inputs | 376 | 376 |
| Identical rule-name sets | 376/376 | 376/376 |
| Reference rule/sample matches | 11,412 | 11,412 |
| Missing / extra rule names | 0 / 0 | 0 / 0 |
| Identical rule and match-address sets | 326/376 (86.7%) | 357/376 (94.9%) |
| Missing / extra addresses | 338 / 645 | 20 / 30 |
| Samples with address differences | 50 | 19 |
| Newly introduced missing / extra addresses | n/a | 0 / 0 |

The requested 100% exact-parity target is still unmet. The PR remains a draft.
The corpus has 377 inputs; the pinned reference rejects the malformed ELF
`c2b2d7cea94179e6c2b6913205e37c45b67ccc0156d8f266548f7f1f95144285.elf_`
with exit 13. The detailed report retains that error and the raw denominator
of 377. These measurements cover rule/address sets, not evidence-tree identity
or duplicate-match multiplicity.

## Changes

- Complete calling, pointer, and FLIRT discovery in reference order, including
  local signature functions, active functions, and deferred loose-code roots.
- Preserve partial registers and call state; evaluate arithmetic flags,
  conditional moves, accumulator extension, and safe-memory reads according
  to the pinned emulator. Keep candidate budgets and contextual diagnostics.
- Align instruction boundaries and flow for legacy LES/LDS, moffs, HLT,
  architecture-specific traps, far jumps, and unsupported SIMD encodings.
- Recover large absolute switch tables and image-relative dispatch with
  intervening image-base reloads. Stop at inconclusive compatibility targets.
- Apply ELF relative relocations from stored words and analyze PLT fragments
  before entry points. Preserve hotpatch, pointer, and short-string locations.
- Match no-return code-reference removal and restoration; exclude x64 stack
  adjustments from number/offset features.

A separate string-boundary change was withheld because it introduced one
extra address. No sample-specific matching exceptions, dependencies, pinned
submodules, rules, corpus files, archived reference outputs, or expected
baselines were added or changed.

Synthetic tests cover decoder boundaries, callback ordering, emulator state,
switch recovery, ELF relocation, API references, and resource limits. The
existing corpus integration tests continue to pass.

## Reproduction

Use the environment in [PINNED.md](../../PINNED.md):

```sh
cargo build --release --workspace
cp target/release/capa-x target/parity/checkpoint-capa-x
python3 scripts/difftest.py --mode full-exact \
  --samples scripts/corpus-full-static.txt \
  --capa-cli target/parity/checkpoint-capa-x \
  --no-rust-cache --no-expected --jobs 6 \
  --report target/checkpoint-exact.md
```

The command returns nonzero for the 19 remaining address-different samples
and the malformed reference input. Rust output was regenerated from an
immutable release binary, with serial analysis and six independent harness
workers. The pinned reference archive is unchanged. A second fresh dump of
all matched rule/address sets confirmed the same totals and compared each
missing/extra set with the preceding commit's measured sets. No current
missing or extra set contains a newly introduced pair.

[Every sample and remaining address difference](match-address-checkpoint-details-2026-10-20.md)
is recorded in the detailed report. Host-specific paths in that report are
normalized to repository-relative paths. The
[preceding report](match-address-followup-2026-10-20.md) remains historical.

## Validation

- `cargo fmt --all -- --check` and `git diff --check`: passed.
- `cargo +1.98.1 clippy --workspace --all-targets --target-dir target/clippy -- -D warnings`: passed.
- `cargo test --workspace`: 549 passed, 6 ignored, including all four feature-parity tests.
- `python3 -m unittest discover -s scripts -p 'test_*.py'`: 10 passed.
- `scripts/check_env.sh`: passed.
- `python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt --capa-cli target/parity/checkpoint-capa-x --no-rust-cache --jobs 6`: 23/23 identical, zero baseline regressions.
- Full exact comparison: 357/376 comparable inputs exact; 20 missing and 30 extra addresses; zero new discrepancies relative to `c5a4ee9`.

- `python3 scripts/determinism.py --samples scripts/corpus-jobs.txt --capa-cli target/parity/checkpoint-capa-x --jobs 1,2,4 --repeat 2 --workers 2`: all 30 comparisons across five samples byte-identical after invocation-metadata normalization.

Ignored acceptance gates and the outer regression gate remain required
before merge or release.
