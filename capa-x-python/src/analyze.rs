//! `analyze()`: one call into [`capa_x::api::analyze`]. The binding must not
//! produce a result the CLI would not produce from the same bytes, the same
//! ruleset, and the same options.

use std::path::PathBuf;

use capa_x::api;
use capa_x::parallel::{AnalysisOptions, Jobs, ZeroJobs};
use capa_x::rd::{ARCH_AUTO, OS_AUTO};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyByteArrayMethods, PyBytes, PyBytesMethods};
use pyo3::PyRef;

use crate::error::{analysis_error, CapaError, UnsupportedFormatError};
use crate::rules::{rules_paths, ruleset, Rules};

/// bytes/bytearray are raw sample content; anything else is read through
/// `os.fspath` (str, `pathlib.Path`, or any other `os.PathLike`) as a file
/// to read. Deliberately not "try `PathBuf::extract` first": `os.fspath()`
/// on a `bytes` argument returns the bytes unchanged (that's the annotated
/// contract on `os.PathLike`), so a bytes-vs-path dispatch that started
/// from the path extraction would treat raw sample bytes as a filesystem
/// path made of those same bytes.
fn read_input(data_or_path: &Bound<'_, PyAny>) -> PyResult<(Vec<u8>, String)> {
    if let Ok(b) = data_or_path.downcast::<PyBytes>() {
        return Ok((b.as_bytes().to_vec(), String::new()));
    }
    if let Ok(b) = data_or_path.downcast::<PyByteArray>() {
        return Ok((b.to_vec(), String::new()));
    }
    let path: PathBuf = data_or_path.extract().map_err(|_| {
        PyTypeError::new_err("data_or_path must be bytes, bytearray, str, or os.PathLike")
    })?;
    let bytes = std::fs::read(&path)?;
    Ok((bytes, path.to_string_lossy().into_owned()))
}

fn parse_format(format: Option<&str>) -> PyResult<api::Format> {
    match format {
        None | Some("auto") => Ok(api::Format::Auto),
        Some("pe") => Ok(api::Format::Pe),
        Some("elf") => Ok(api::Format::Elf),
        Some("sc32") => Ok(api::Format::Sc32),
        Some("sc64") => Ok(api::Format::Sc64),
        Some("freeze") => Ok(api::Format::Freeze),
        Some("dotnet") => Ok(api::Format::Dotnet),
        Some("macho") => Ok(api::Format::Macho),
        Some(other) => Err(UnsupportedFormatError::new_err(format!(
            "unknown format {other:?}; expected one of: auto, pe, elf, sc32, sc64, freeze, \
             dotnet, macho"
        ))),
    }
}

fn parse_jobs(jobs: Option<usize>) -> PyResult<Jobs> {
    match jobs {
        None => Ok(Jobs::available()),
        Some(n) => Jobs::new(n).map_err(|ZeroJobs| {
            CapaError::new_err("jobs must be at least 1 (1 is the single-threaded reference mode)")
        }),
    }
}

/// Runs the whole PE/ELF/shellcode/.NET/Mach-O/freeze pipeline on
/// `data_or_path` and returns upstream's `ResultDocument` schema as a
/// Python `dict`.
///
/// `jobs=1` is byte-for-byte the same document `capa-x --jobs 1` prints with
/// `-j` -- same seam, same options struct, same
/// [`capa_x::api::analyze`] call the CLI itself makes.
#[pyfunction]
#[pyo3(signature = (data_or_path, rules, *, jobs=None, format=None, os=None, arch=None, file_only=false))]
#[allow(clippy::too_many_arguments)]
pub fn analyze(
    py: Python<'_>,
    data_or_path: &Bound<'_, PyAny>,
    rules: PyRef<'_, Rules>,
    jobs: Option<usize>,
    format: Option<String>,
    os: Option<String>,
    arch: Option<String>,
    file_only: bool,
) -> PyResult<PyObject> {
    let (bytes, sample_path) = read_input(data_or_path)?;
    let jobs = parse_jobs(jobs)?;
    let format = parse_format(format.as_deref())?;

    let options = AnalysisOptions {
        jobs,
        format,
        os: os.filter(|s| s != OS_AUTO),
        arch: arch.filter(|s| s != ARCH_AUTO),
        file_only,
        signatures_path: None,
    };
    let paths = rules_paths(&rules);
    let rules = ruleset(&rules);

    // The CPU-bound work -- rule matching and, unless `file_only`, code
    // recovery and feature extraction -- runs with the GIL released.
    // `capa_x::parallel`'s scoped-thread workers never touch a
    // Python object, so this is safe by construction, same as the roadmap's
    // "Errors and the GIL" task requires.
    let json = py.allow_threads(move || -> Result<String, PyErr> {
        let input = api::Input {
            bytes: &bytes,
            sample_path,
            rules_paths: paths,
            // `Some(vec![])`, not `None`: upstream's `ResultDocument.meta.
            // argv` is a required `list[str]`, not `Optional` (J14 caught
            // this -- `None` serializes to JSON `null`, which fails
            // `model_validate_json` with "Field required"). A binding call
            // has no real argv to report, but "empty" is a valid `list[str]`
            // where "absent" is not.
            argv: Some(Vec::new()),
        };
        let doc = api::analyze(&input, &rules, &options).map_err(analysis_error)?;
        serde_json::to_string(&doc)
            .map_err(|e| CapaError::new_err(format!("serializing result document: {e}")))
    })?;

    // Parsed via Python's own `json` module rather than a second Rust JSON
    // -> PyObject converter (ADR 0006): the object graph handed back to
    // Python is built by CPython's own decoder, not a crate that could
    // disagree with it on an edge case.
    let json_module = PyModule::import_bound(py, "json")?;
    let value = json_module.call_method1("loads", (json,))?;
    Ok(value.unbind())
}
