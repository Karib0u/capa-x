# Contributing

Thank you for helping improve capa-x. Changes should be small, evidence-backed,
and compatible with unmodified upstream capa-rules.

## Before starting

Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the workspace and the
freeze-format seam. Read the relevant ADR under [`docs/decisions/`](docs/decisions/)
when a change crosses a parser, decoder, dependency, or API boundary. Read the
pinned Python implementation in `reference/capa/` before changing capa
behavior. Python capa is the behavioral reference wherever it implements the
same input and backend.

`PINNED.md` is the source of truth for the capa, capa-rules, and test corpus
versions. Do not copy measurements from prose, notes, or cached reports. Run
the measurement again on the commit being evaluated.

## Development setup

Building and running the binary requires Rust 1.87 or newer and the rules
submodule:

```bash
git clone https://github.com/Karib0u/capa-x.git
cd capa-x
git submodule update --init --depth 1 rules
cargo build
```

Parity development also requires `uv`, Python, the test corpus, and the pinned
reference source:

```bash
scripts/setup_dev.sh
cargo build --release
```

The setup script initializes the required submodules, installs the pinned
Python reference in `.venv`, and verifies every pin against `PINNED.md`.

## Development loops

Use the cheapest loop that can observe the change:

| Loop | Command | When | Cost |
|---|---|---|---|
| Inner | `cargo test -p capa-x --test features_parity` | Every change | ~7 s |
| Mid | `python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt --capa-cli target/release/capa-x --jobs 6` | Every commit | ~40 s |
| Outer | The mid command with `scripts/corpus-outer.txt` | Before merge or release | ~5 min |

The inner loop is the transcribed upstream feature contract. The mid loop is
the smoke regression guard. The outer loop measures rule-level agreement and
the extra-rule count across the full corpus.

The difftest costs above are what you pay *after a code change*, on a 10-core
M1 Max; treat them as an order of magnitude, not a benchmark. Both sides are
cached under `.cache/`: the Python reference by sample hash, capa-x's own
output by binary contents. So a rebuilt binary invalidates only the capa-x
side (mid ~40 s, outer ~5 min), and re-running either loop without rebuilding
is 1-2 s. `.cache/` is disposable, but deleting it costs a one-time
re-analysis of the corpus under the pinned Python reference, which is slow
(minutes to hours) -- prefer `--no-rust-cache` when you want to distrust a
capa-x result, rather than clearing the whole cache.

`--jobs 1` is the semantic baseline for analysis output. Harness-level jobs
only parallelize independent samples. Any byte difference between analysis
with `--jobs 1` and another job count is a bug.

### Before pushing

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`cargo test --workspace` is about 20 seconds. The slow acceptance and
robustness gates are `#[ignore]`d so this stays an inner loop: the
cross-product matrix and the two byte-flip fuzz suites are ~383 s of a ~402 s
suite between them, and an ordinary edit does not move them. CI runs the full
set with `--include-ignored` on all three platforms, so pushing without having
run them locally is expected, not a shortcut.

### Before merge or release

Run what CI cannot run cheaply on every push, plus the ignored gates:

```bash
cargo test --workspace -- --include-ignored
scripts/check_env.sh
python3 scripts/difftest.py --mode full --samples scripts/corpus-outer.txt \
  --capa-cli target/release/capa-x --jobs 6
```

Both difftest corpora have a recorded per-sample baseline
(`<corpus>.expected.json`), so the exit status reports *regressions* against
known diffs rather than the raw presence of any diff. A deliberate change to
what matches is re-recorded with `--write-expected`, in the same commit, with
the reason in the pull request.

Use the differential harness for behavioral changes:

```bash
python3 scripts/difftest.py --mode <freeze|json|file-features|full> \
  --samples scripts/corpus-smoke.txt --capa-cli target/release/capa-x
python3 scripts/determinism.py --samples scripts/corpus-jobs.txt \
  --capa-cli target/release/capa-x
python3 scripts/bench.py --samples scripts/corpus-bench.txt --markdown
```

## Change rules

- Never modify `rules/`, `tests/testfiles/`, or `reference/capa/` directly.
  They are pinned upstream submodules. Version bumps happen only through
  `PINNED.md` and the corresponding gitlink update.
- Never silently skip an unknown rule construct, field, or input structure.
  Return a contextual error and a nonzero exit status.
- Do not panic on untrusted sample, rule, or freeze input. Parsing paths return
  `Result` and do not use `unwrap`, `expect`, or unchecked indexing.
- Keep `#![forbid(unsafe_code)]` intact on analysis crates. The binding crate
  is declarations only and its exception is documented in its manifest.
- Do not invoke Python or an external disassembler at runtime.
- Add tests with behavior changes and preserve deterministic output.
- Explain any new dependency in one sentence, including its maintenance,
  malformed-input, panic, allocation, unsafe-code, and license properties.
- Constants copied from Python, such as length limits, byte caps, and window
  sizes, must name the upstream source file in a nearby comment.

## Pull requests

Keep one pull request focused on one coherent task when practical. Include:

- the problem and the pinned upstream behavior;
- the implementation decision;
- tests added or changed;
- exact commands run;
- differential results for behavior changes;
- benchmark methods and before/after values for performance claims;
- any deliberate trade and the durable documentation that records it.

Use relative links within the repository. Keep public claims in the README,
accepted design choices in the ADRs, and reproducible measurements in
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

## Reporting problems

Use a normal issue for reproducible bugs, unsupported behavior, and accuracy
differences that do not create a security impact. Report vulnerabilities
privately using [`SECURITY.md`](SECURITY.md).
