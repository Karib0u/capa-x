# Match-address parity follow-up, 2026-10-20

A fresh run of PR commit `de55bab` reproduced 321/376 exact rule/address
sets and two extra rule names. This follow-up restores 100% rule-name
agreement and increases exact rule/address agreement to 326/376 (86.7%).
Every previously exact sample remains exact. The requested 100% exact
target is still not met: 50 comparable samples have address differences.

| Metric | Preceding PR commit | Follow-up |
|---|---:|---:|
| Comparable native inputs | 376 | 376 |
| Identical rule-name sets | 374/376 (99.5%) | 376/376 (100%) |
| Reference rule/sample matches | 11,412 | 11,412 |
| Missing / extra rule names | 0 / 2 | 0 / 0 |
| Identical rule and match-address sets | 321/376 (85.4%) | 326/376 (86.7%) |
| Samples with rule or address differences | 55 | 50 |

The corpus contains 377 inputs. The pinned reference rejects
`c2b2d7cea94179e6c2b6913205e37c45b67ccc0156d8f266548f7f1f95144285.elf_`
with exit 13. It remains in the
corpus and appears as an error in the detailed reports, whose raw denominator
is 377. No rules, samples, expected baselines, or archived reference outputs
were changed. These metrics measure matched rule/address sets, not code
coverage, evidence-tree identity, or duplicate-match multiplicity.

## Changes

- Recover guarded x64 switch selectors loaded with MOVSXD or MOVZX. Apply
  the reference compatibility policy when the high selector bits cannot be
  proven. Native recovery still requires a proven bounded index.
- Recognize compatibility RVA dispatch through MOV/ADD/JMP when the image
  base is statically proven but an adjacent guard is absent. Scan targets
  in table order, with reference and candidate boundaries and an explicit
  resource-limit diagnostic.
- Preserve typed pointer suffixes after code overwrites the beginning of a
  pointer. This prevents the false pusha/popa sequence in `648fc...exe_`.
- Apply the calling emulator's no-return check at instruction sites, including
  its entry-opcode exception, and stop on its all-zero bad opcode. This
  removes the extra anti-disassembly rule in `971e...exe_` without extending
  the captured blocks past a no-return call.
- Support the SAL alias and opaque scalar SIMD multiplication in candidate
  evaluation. Unknown vector values remain unknown.

The exact integration test now covers eleven samples, including the five
newly exact inputs:

- `276f691a3df25481f59d79781799e35f.exe_`
- `82bf6347acf15e5d883715dc289d8a2b.exe_`
- `a6594d9550d56ddeaac8b3140821e698eefb7163ba29f0119c2ef19beb6040b0.exe_`
- `ad4229879180e267f431ac6666b6a0a2.exe_`
- `f59035192098e44b86c4648a0de4078edbe80352260276f4755d15d354f5fc58.exe_`

A separate integration test protects both restored rule-name sets while
explicitly retaining their address differences. Synthetic regressions cover
extended selectors, absent switch guards, table limits, pointer suffixes,
calling traces, and instruction evaluation. No dependencies were added.

## Reproduction

Use the pinned environment described in [PINNED.md](../../PINNED.md):

```sh
cargo build --release
cp target/release/capa-x target/parity/final-capa-x
python3 scripts/difftest.py --mode full-exact \
  --samples scripts/corpus-full-static.txt \
  --capa-cli target/parity/final-capa-x --no-rust-cache --no-expected --jobs 6
python3 scripts/difftest.py --mode full \
  --samples scripts/corpus-full-static.txt \
  --capa-cli target/parity/final-capa-x --no-rust-cache --no-expected --jobs 6
```

Both commands return nonzero. Exact comparison reports the remaining address
differences and the malformed reference input. Rule-name comparison reports
only that malformed input. Reference results come from the checksum-verified
pinned archive; Rust results were regenerated with a newly built immutable
binary. Harness jobs parallelize samples; analysis uses its serial default.

- [All exact comparisons](match-address-followup-details-2026-10-20.md).
- [All rule-name comparisons](match-address-followup-rule-names-2026-10-20.md).
- [Preceding PR measurement](match-address-progress-2026-10-20.md).

## Validation

- `cargo fmt --all -- --check` and `git diff --check`: passed.
- `cargo +1.98.1 clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo test --workspace`: 511 passed, 6 ignored.
- `cargo test -p capa-x --test features_parity`: 4 passed.
- `python3 -m unittest discover -s scripts -p 'test_*.py'`: 10 passed.
- `scripts/check_env.sh`: pinned environment and submodules verified.
- `python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt
  --capa-cli target/parity/final-capa-x --no-rust-cache --jobs 6`: 23/23
  identical, no baseline regressions.
- The full-corpus commands above: 326/376 exact rule/address sets and
  376/376 exact rule-name sets. Their nonzero exit status is explained above.
- `python3 scripts/determinism.py --samples scripts/corpus-jobs.txt
  --capa-cli target/parity/final-capa-x --jobs 1,2,4 --repeat 2 --workers 2`:
  all 30 comparisons over five samples byte-identical after invocation
  metadata normalization.

The final release rebuild is byte-identical to the immutable binary used
for the corpus and determinism runs. Detailed report paths are normalized
to repository-relative paths; results are unchanged.

The ignored acceptance gates and outer regression gate remain required
before merge or release. The PR remains a draft.
