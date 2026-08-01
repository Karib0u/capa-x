//! An in-process Python extension over `capa-x`'s own analysis code --
//! Python calls through the C ABI, no subprocess, no Python at analysis
//! time, nothing reimplemented.
//!
//! This crate is declarations only: type conversion (`analyze`), error
//! mapping (`error`), and GIL handling. No parsing, decoding, matching, or
//! analysis logic -- all of that stays in `capa-x`, which keeps
//! `#![forbid(unsafe_code)]`. This is the one crate in the workspace that
//! cannot carry that lint itself, because pyo3's `#[pymodule]`/`#[pyclass]`
//! macros expand to `unsafe`; see [ADR 0006](../../docs/decisions/0006-python-binding.md)
//! and the crate manifest. There is no hand-written `unsafe` anywhere in this
//! crate.
//!
//! Two properties define the binding:
//!
//! - **the result document is the interface** -- `analyze` returns parsed
//!   Python data shaped exactly like upstream's `ResultDocument` pydantic
//!   model (J14), not a capa-x-specific object model;
//! - **a loaded ruleset is reusable** -- `Rules.from_directory` parses and
//!   validates once; the returned handle backs any number of `analyze`
//!   calls, including concurrently from multiple Python threads (the GIL is
//!   released for the CPU-bound part of `analyze`; see that function).

// pyo3 0.22's `create_exception!` macro expands to a `cfg(feature =
// "gil-refs")` check that Rust's `unexpected_cfgs` lint flags as unknown,
// because this crate (correctly) never declares a `gil-refs` feature of its
// own -- the check is pyo3-internal plumbing, not something a consumer
// crate controls. Upstream: https://github.com/PyO3/pyo3/issues/4394.
#![allow(unexpected_cfgs)]
// `#[pyfunction]`/`#[pymethods]` always generate a `PyErr -> PyErr`
// `.map_err(Into::into)` in their `Result`-returning wrapper, even when the
// function's own error type is already `PyErr` (true of every function in
// this crate, by design -- see `error.rs`). Clippy attributes the resulting
// no-op conversion to the function's closing brace, not to any line this
// crate controls. Same well-known pyo3+clippy interaction as the
// `unexpected_cfgs` allow above.
#![allow(clippy::useless_conversion)]

mod analyze;
mod error;
mod rules;

use pyo3::prelude::*;

#[pymodule]
fn _capa_x(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", capa_x::version())?;
    m.add("RULES_PIN", capa_x::RULES_PIN)?;

    m.add("CapaError", m.py().get_type_bound::<error::CapaError>())?;
    m.add(
        "InvalidRuleError",
        m.py().get_type_bound::<error::InvalidRuleError>(),
    )?;
    m.add(
        "UnsupportedFormatError",
        m.py().get_type_bound::<error::UnsupportedFormatError>(),
    )?;
    m.add(
        "InvalidSignatureError",
        m.py().get_type_bound::<error::InvalidSignatureError>(),
    )?;
    m.add(
        "CorruptFileError",
        m.py().get_type_bound::<error::CorruptFileError>(),
    )?;

    m.add_class::<rules::Rules>()?;
    m.add_function(wrap_pyfunction!(rules::fetch_rules, m)?)?;
    m.add_function(wrap_pyfunction!(analyze::analyze, m)?)?;
    Ok(())
}
