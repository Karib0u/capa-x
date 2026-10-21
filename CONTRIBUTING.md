# Contributing

Changes should be small, evidence-backed, and compatible with unmodified upstream capa-rules.

## Before you start

- [Architecture](docs/architecture.md) when touching a parser, decoder, dependency, or API boundary.
- The pinned Python source in `reference/capa/` defines behavior. Read it; do not recall it. Versions live in [`PINNED.md`](PINNED.md).
- [Development guide](docs/development.md) for setup, feedback loops, checks, and codebase rules.

## Pull requests

One focused change per PR. Include:

- the problem and the pinned upstream behavior;
- the decision, and tests added or changed;
- exact commands run, with differential results for behavior changes;
- benchmark method and before/after values for performance claims.

Use relative links. Public claims belong in the README and measurements in [`docs/benchmarks.md`](docs/benchmarks.md).

## Issues

Open a normal issue for reproducible bugs, unsupported behavior, and accuracy differences. Report vulnerabilities privately per [`SECURITY.md`](SECURITY.md).
