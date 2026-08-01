# ADR 0006: `pyo3` for the Python binding, `extension-module` gated behind a local feature

- Status: Accepted
- Scope: Python binding and packaging

## Context

The project needs an in-process Python extension module: `capa-x`'s analysis
reachable through the C ABI, with no subprocess and load-once-scan-many
semantics. The implementation uses `pyo3`, `abi3-py38`, `extension-module`,
and `maturin`. This ADR records the one place implementation
measurement forced a documented departure from that literal shape, plus the
version pin.

## Decision

`pyo3` `0.22.6` (`abi3-py38`), added only to the `capa-x-python` crate.
`capa-x` is its only other dependency, exactly as scoped -- never
`capa-x-cli`. Wheels are built by `maturin` (pinned separately in
`capa-x-python/pyproject.toml`'s `build-system.requires`, since that's a
Python-side pin `PINNED.md`'s table doesn't cover).

## The `extension-module` departure

The brief's dependency line reads `pyo3 (abi3-py38, extension-module)`. That
is correct for the *wheel* maturin builds, but adding it unconditionally to
`capa-x-python/Cargo.toml` breaks a hard rule one layer up: "cargo build...
must stay green" (`AGENTS.md` Commands). Measured on this repo's dev host
(macOS, Apple clang/ld64):

```
$ cargo build -p capa-x-python
   ...
   ld: symbol(s) not found for architecture arm64
   "_PyErr_Occurred", "_PyObject_SetAttr", "_Py_IncRef", ... (30+ CPython C
   API symbols)
   clang: error: linker command failed with exit code 1
```

`extension-module` deliberately leaves every CPython C API symbol
undefined in the compiled `cdylib` -- they're resolved by the *hosting*
Python process at `dlopen` time, never by this crate's own link step, which
is exactly what lets one wheel's `.so` load under any CPython that
satisfies its `abi3` floor. `maturin` (and, separately, `pip`/`cibuildwheel`
invoking it) passes the macOS linker `-undefined dynamic_lookup` to make an
extension-module cdylib link despite that; nothing else in this repo passes
that flag, so a plain `cargo build -p capa-x-python` fails outright, on every
macOS checkout, with no maturin involved. Linux's ELF linker tolerates
undefined symbols in a shared object by default and would not have shown
this; macOS's does not, and this is measured on the host actually used for
development here.

`cargo test` would fail for a second, independent reason even with the
linker satisfied: a test harness is an *executable*, not a `cdylib`, and an
executable cannot carry undefined symbols on any of the three platforms.
`capa-x-python/Cargo.toml`'s `[lib] test = false` / `doctest = false` opts the
crate out of `cargo test`'s lib-unittest target entirely -- not a lint
suppression, a structural fact: this crate is declarations only (type
conversion, error mapping, GIL handling; the binding is the one workspace
exception), so it carries no `#[test]` needing a live interpreter in
the first place. Its correctness is proven by the `pytest` suite under
`capa-x-python/tests/`, run against the real `.so` after `maturin develop`,
which is also where the brief's own GIL-release proof
("running `analyze` from two Python threads and showing they overlap")
has to live -- `cargo test` cannot host that either.

**Fix:** `extension-module` moves to a local Cargo feature
(`python-extension = ["pyo3/extension-module"]`), off by default. Plain
`cargo build`/`cargo test --workspace` link `capa-x-python` in `pyo3`'s
ordinary (embedding) mode -- against a real, discovered `libpython`, same as
any other program embedding a Python interpreter -- which is measured to
link cleanly on this host. `capa-x-python/pyproject.toml`'s
`[tool.maturin] features = ["python-extension"]` is what turns the real ABI3
extension-module build back on for the artifact that actually ships;
`cibuildwheel`/`maturin build` never invoke plain `cargo build` for this
crate, so the wheel's ABI is unaffected by this change -- only the
workspace's default `cargo build`/`test` invocation is.

This is the same shape as three other documented departures already in this
repo (A.2's rule-parsing parallel seam, A.1.5's scoped-thread pool instead
of a dependency, A.3.4's skipped ThreadSanitizer job): the brief said one
thing, a measurement said the literal reading doesn't hold, and the fix is
recorded here rather than silently diverging from the brief's text.

## Why not the alternatives

- **Ship a `.cargo/config.toml` with `-undefined dynamic_lookup` rustflags
  for the Apple targets instead.** Considered first. It fixes macOS but
  does nothing for the second failure mode (`cargo test`'s executable
  harness) on any platform, and it also does nothing for Windows, which
  needs a real import library at link time that only `maturin`/the Python
  installation's `python3.dll` supplies -- the feature gate fixes the
  problem at its source for all three platforms at once, and the
  rustflags workaround would still be needed *in addition* to `test = false`
  even if adopted.
- **Do not gate; document that `cargo build -p capa-x-python` requires
  `maturin` and is a known exception.** Rejected: `AGENTS.md`'s command
  table has no "except this one crate" clause, and a silent workspace-wide
  build failure on a bare checkout is precisely the failure mode the
  "boring dependencies" and "no exceptions" framing in `AGENTS.md` exists to
  prevent.
- **`pythonize`/`serde-pyobject` to convert `result_document::ResultDocument`
  to a Python object directly via `serde::Serialize`.** Not added. `capa-x`
  already serializes `ResultDocument` to a JSON string for `capa-x -j`; the binding
  reuses that exact path and converts the string via Python's own `json`
  module (`json.loads`) inside the extension. Zero new dependencies, and the
  object graph handed back to Python is built by CPython's own JSON decoder
  -- not a second, independently-maintained serializer that could disagree
  with it on edge cases (surrogate pairs, large integers, float formatting).

## Consequences

- `capa-x-python/Cargo.toml` carries a `python-extension` feature that must be
  passed explicitly by anything that wants the real wheel ABI; forgetting it
  produces a crate that builds and passes `cargo check` but is not
  importable as a Python extension. `capa-x-python/pyproject.toml` is the one
  place that matters, and it is committed with the feature already set.
- `maturin`'s own version is pinned in `capa-x-python/pyproject.toml`'s
  `build-system.requires` (`maturin>=1.7,<2.0`), not `PINNED.md` --
  `PINNED.md` is upstream-version tracking (capa, capa-rules, capa-testfiles,
  dnfile); `maturin` is this repo's own build tooling, closer in kind to the
  Rust toolchain pin than to an upstream behavioral spec.
