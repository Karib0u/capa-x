# capa-x agent instructions

The pinned Python capa source in `reference/capa/` is the behavioral
specification. `PINNED.md` is the source of truth for every upstream version.
The project must parse unmodified capa-rules and preserve deterministic
results.

## Hard rules

- Never silently skip an unknown rule construct, field, or input structure.
- Return contextual errors for untrusted sample, rule, and freeze input. Do
  not use `unwrap`, `expect`, or unchecked indexing in those paths.
- Never modify `rules/`, `tests/testfiles/`, or `reference/capa/` directly.
- Do not invoke Python or an external disassembler at runtime.
- Keep `#![forbid(unsafe_code)]` on analysis crates.
- Justify new dependencies and document constants copied from upstream.

## Feedback loops

| Loop | Command | When | Cost |
|---|---|---|---|
| Inner | `cargo test -p capa-x --test features_parity` | Every change | ~7 s |
| Mid | `python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt --capa-cli target/release/capa-x --jobs 6` | Every commit | ~40 s |
| Outer | The mid command with `scripts/corpus-outer.txt` | Before merge or release | ~5 min |

Use the cheapest loop that can observe the change. `cargo test --workspace`
(~20 s) is the broader local check; the slow acceptance and robustness gates
are `#[ignore]`d and belong to CI, which runs them with `--include-ignored`.
Run them locally with the same flag before merge, not on every edit.

`--jobs 1` is the semantic baseline. Any byte difference across job counts is
a bug. Never carry a measurement forward from a note or cached report.

Both difftest corpora carry a per-sample baseline (`<corpus>.expected.json`),
so a run reports regressions against known diffs rather than the raw presence
of a diff. Re-record with `--write-expected` only for a deliberate change, in
the same commit, with the reason stated.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup, complete checks, and the
pull request checklist.
