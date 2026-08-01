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

| Loop | Command | When |
|---|---|---|
| Inner | `cargo test -p capa-x --test features_parity` | Every change |
| Mid | `python3 scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt --capa-cli target/release/capa-x --jobs 6` | Every commit |
| Outer | The mid command with `scripts/corpus-outer.txt` | Before merge or release |

The inner loop is the transcribed upstream feature contract. The mid loop is
the smoke regression guard. The outer loop measures rule-level agreement and
the extra-rule count across the full corpus.

`--jobs 1` is the semantic baseline for analysis output. Harness-level jobs
only parallelize independent samples. Any byte difference between analysis
with `--jobs 1` and another job count is a bug.

Before submitting a pull request, run:

```bash
cargo build && cargo test
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
scripts/check_env.sh
```

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
