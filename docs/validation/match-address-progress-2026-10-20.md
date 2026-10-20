# Match-address parity progress, 2026-10-20

The worktree was fast-forwarded to main `a667d54` before these changes.
A fresh baseline reproduced 251 identical rule/address sets. The updated
implementation improves that to 321, retaining every previously identical
sample. The 100% target is not met, and two rule-name regressions remain.

| Metric | Main baseline | Updated implementation |
|---|---:|---:|
| Comparable native inputs | 376 | 376 |
| Identical rule-name sets | 376/376 (100%) | 374/376 (99.5%) |
| Reference rule/sample matches | 11,412 | 11,412 |
| Missing / extra rule names | 0 / 0 | 0 / 2 |
| Identical rule and match-address sets | 251/376 (66.8%) | 321/376 (85.4%) |
| Samples with rule or address differences | 125 | 55 |

The corpus contains 377 inputs. The pinned reference rejects one malformed
ELF with exit 13, leaving 376 comparable inputs. The sample remains in the
corpus and appears as an error in the detailed reports. The harness counts
that error in its denominator and prints 321/377; the table above uses only
comparable inputs. No rules, samples, expected baselines, or archived
reference outputs were changed.

## Changes

- Capture compatibility function scopes when discovery completes. Finish
  switch arms and recursive callees before capturing their scopes, follow
  reference fallthrough across PE unwind roots, and propagate no-return
  decisions incrementally. Native recovery retains its boundary and fixed
  point behavior.
- Match discovery order for callback traces, pointer candidates, ELF pointer
  arrays, and SEH3 scope-table functions. Distinguish typed data barriers from
  pointer locations that can become code, and classify rejected string
  candidates before later function discovery.
- Preserve jump-table arm order and incremental references. Validate arms
  against the known graph, respect table boundaries, and refresh affected
  function scopes when a later dispatch splits adjacent tables.
- Resolve import identities before raw IAT contents, reject import slots as
  code, and recognize no-return CET PLT thunks. Trace concrete callees through
  computed jumps with bounded execution.
- Match compatibility decoding of prefixed relative branches, legacy NOP
  aliases, WAIT, and unsupported PadLock opcodes. Add scalar and packed
  instruction evaluation while keeping unknown vector values and diagnostics
  for unsupported operations.
- Follow the most recently recorded overlapping instruction locations and
  captured block ownership, including MSVC security-cookie feature filtering.

There are no new dependencies or external runtime tools. Six samples have a
permanent integration test comparing all rule/address sets to the immutable
reference index, alongside synthetic tests for the changed mechanisms.
See KD-010, KD-024, and KD-025 in
[KNOWN_DIVERGENCES.md](../../KNOWN_DIVERGENCES.md).

## Remaining work

The 55 differing samples remain listed in the exact comparison report.
`971e599e6e707349eccea2fd4c8e5f67.exe_` now also has an extra
`contain anti-disasm techniques` rule match. Callback discovery retains too
many function scopes matching `contain pusha popa sequence`, crossing the
parent rule's threshold. `648fc498110b11b4313a47a776e6ba40.exe_` also gains
`contain pusha popa sequence` at `0x5fa068`; the discovery step responsible
for that extra scope still needs isolation. Both regressions must be fixed
before merge. Expected baselines were not relaxed to accept them.

The reported exact comparison checks sets of `(rule, address)` pairs.
Evidence-tree identity and duplicate-match multiplicity are separate goals.

## Reproduction

Use the pinned environment described in [PINNED.md](../../PINNED.md):

```sh
cargo build --release
cp target/release/capa-x target/match-address-capa-x
python3 scripts/difftest.py --mode full-exact \
  --samples scripts/corpus-full-static.txt \
  --capa-cli target/match-address-capa-x --no-rust-cache --no-expected --jobs 6
python3 scripts/difftest.py --mode full \
  --samples scripts/corpus-full-static.txt \
  --capa-cli target/match-address-capa-x --no-rust-cache --no-expected --jobs 6
```

Both comparisons return nonzero: exact comparison reports the remaining
differences, while rule-name comparison reports the two extra rules and the
malformed reference input. These are measurements, not passing acceptance
checks. The measurement used a newly built immutable binary and fresh Rust
results. Reference JSON came from the checksum-verified pinned archive.
Harness jobs parallelize samples; analysis uses its serial default.

- [All match-address comparisons](match-address-details-2026-10-20.md).
- [All rule-name comparisons](match-address-rule-names-2026-10-20.md).
- [Previous compatibility work](compatibility-2026-10-20.md).

## Validation

- `cargo fmt --all -- --check` and `git diff --check`: passed.
- `cargo +1.98.1 clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo test --workspace`: 502 passed, 6 ignored, including the six-sample
  full rule/address integration test.
- `cargo test -p capa-x --test features_parity`: 4 passed.
- `python3 -m unittest discover -s scripts -p 'test_*.py'`: 10 passed.
- `scripts/check_env.sh`: pinned environment and submodules verified.
- `python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt
  --capa-cli target/parity/pr-capa-x --no-rust-cache --jobs 6`: 23/23 identical,
  no baseline regressions.
- `python3 scripts/determinism.py --samples scripts/corpus-jobs.txt
  --capa-cli target/parity/pr-capa-x --jobs 1,2,4 --repeat 2 --workers 2`:
  all 30 runs over five samples byte-identical after invocation-metadata
  normalization.

The final release rebuild is byte-identical to the immutable binary used for
these corpus and determinism runs.

The ignored acceptance gates and outer regression gate remain required
before merge or release.
