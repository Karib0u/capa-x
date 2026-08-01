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

| Loop | Command | When |
|---|---|---|
| Inner | `cargo test -p capa-x --test features_parity` | Every change |
| Mid | `python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt --capa-cli target/release/capa-x --jobs 6` | Every commit |
| Outer | The mid command with `scripts/corpus-outer.txt` | Before merge or release |

`--jobs 1` is the semantic baseline. Any byte difference across job counts is
a bug. Never carry a measurement forward from a note or cached report.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup, complete checks, and the
pull request checklist.
