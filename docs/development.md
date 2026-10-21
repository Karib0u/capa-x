# Development

## Setup

Build and run: Rust 1.87+ and the rules submodule.

```bash
git clone https://github.com/Karib0u/capa-x.git
cd capa-x
git submodule update --init --depth 1 rules
cargo build
```

Parity work also needs `uv`, Python, the test corpus, and the pinned reference.
The script initializes submodules, installs the reference into `.venv`, and
checks every pin against [`PINNED.md`](../PINNED.md):

```bash
scripts/setup_dev.sh
cargo build --release
```

## Feedback loops

Use the cheapest loop that can observe the change.

| Loop | Command | When | Cost |
|---|---|---|---|
| Inner | `cargo test -p capa-x --test features_parity` | Every change | ~7 s |
| Mid | `python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt --capa-cli target/release/capa-x --jobs 6` | Every commit | ~40 s |
| Outer | Mid command with `scripts/corpus-outer.txt` | Before merge or release | ~5 min |

- **Inner** is the transcribed upstream feature contract.
- **Mid** is the smoke regression guard.
- **Outer** measures rule-level agreement and extra rules across the corpus.

Costs are for a 10-core M1 Max after a code change; treat them as orders of
magnitude. Results are cached under `.cache/` (Python reference by sample hash,
capa-x by binary contents), so a rebuild invalidates only the capa-x side. The
reference side is slow to regenerate (minutes to hours): use `--no-rust-cache`
to distrust a capa-x result instead of clearing the cache.

`--jobs 1` is the semantic baseline. Any byte difference at another job count
is a bug.

Both corpora have a per-sample baseline (`<corpus>.expected.json`), so the exit
status reports regressions against known diffs. Re-record with
`--write-expected` only for a deliberate change, in the same commit, with the
reason stated.

## Checks

Before pushing:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 -m unittest discover -s scripts -p 'test_*.py'
```

`cargo test --workspace` takes ~20 s. The slow acceptance and fuzz gates are
`#[ignore]`d (about 383 s of a ~402 s suite); CI runs them on all three
platforms with `--include-ignored`.

Before merge or release:

```bash
cargo test --workspace -- --include-ignored
scripts/check_env.sh
python3 scripts/difftest.py --mode full --samples scripts/corpus-outer.txt \
  --capa-cli target/release/capa-x --jobs 6
```

Other harnesses:

```bash
python3 scripts/difftest.py --mode <freeze|json|file-features|full> \
  --samples scripts/corpus-smoke.txt --capa-cli target/release/capa-x
python3 scripts/determinism.py --samples scripts/corpus-jobs.txt \
  --capa-cli target/release/capa-x
python3 scripts/bench.py --samples scripts/corpus-bench.txt --markdown
```

## Reproducing the published evidence

```bash
python3 scripts/difftest.py --mode full \
  --samples scripts/corpus-full-static.txt --capa-cli target/release/capa-x \
  --no-rust-cache --no-expected
python3 scripts/difftest.py --mode full-exact \
  --samples scripts/corpus-full-static.txt --capa-cli target/release/capa-x \
  --no-rust-cache --no-expected
```

Never carry a measurement forward from prose or a cached report; rerun it on
the commit under evaluation.

## Rules of the codebase

- Never modify `rules/`, `tests/testfiles/`, or `reference/capa/`. They are
  pinned submodules; bump them only through `PINNED.md` and the gitlink.
- Never silently skip an unknown rule construct, field, or input structure:
  return a contextual error and a nonzero exit.
- No `unwrap`, `expect`, or unchecked indexing on untrusted sample, rule, or
  freeze input.
- Keep `#![forbid(unsafe_code)]` on analysis crates. The binding crate is
  declarations only; its exception is documented in its manifest.
- No Python or external disassembler at runtime.
- Constants copied from Python (limits, byte caps, windows) name the upstream
  source file in a nearby comment.
- Justify new dependencies in one sentence: maintenance, malformed-input,
  panic, allocation, unsafe, and license properties.
- Output stays deterministic across job counts.
