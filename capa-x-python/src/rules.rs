//! `Rules.from_directory`: parse once, reuse across scans.

use std::path::PathBuf;
use std::sync::Arc;

use capa_x::capabilities::MatchingRuleSet;
use capa_x::parallel::{AnalysisOptions, Jobs};
use capa_x::rules::load_rule_directory;
use pyo3::prelude::*;

use crate::error::rule_error;

/// An already-parsed, already-validated rule set. Cheap to clone (an
/// `Arc`): [`crate::analyze::analyze`] takes a `&Rules` and clones the
/// handle before releasing the GIL, so one `Rules` instance can back many
/// concurrent `analyze()` calls without re-parsing anything.
#[pyclass(name = "Rules", module = "capa_x", frozen)]
pub struct Rules {
    pub(crate) ruleset: Arc<MatchingRuleSet>,
    /// The directory this was loaded from, echoed into
    /// `meta.analysis.rules` the same way the CLI's own canonicalized `-r`
    /// path is -- see [`api::Input::rules_paths`].
    pub(crate) source_path: String,
}

#[pymethods]
impl Rules {
    /// Parses every rule file under `path`, builds the matching rule set
    /// (dependency ordering, subscope extraction, scope indexing -- see
    /// [`MatchingRuleSet::new`]), and returns a reusable handle.
    ///
    /// Raises [`crate::error::InvalidRuleError`] on an unparseable rule file
    /// or an invalid rule set (duplicate name, missing dependency, cycle) --
    /// this project's "never silently skip" rule applies to the binding
    /// exactly as it does to the CLI: no rule ever just vanishes.
    #[staticmethod]
    fn from_directory(py: Python<'_>, path: PathBuf) -> PyResult<Rules> {
        let source_path = path.to_string_lossy().into_owned();
        py.allow_threads(move || {
            // Rule *parsing* parallelizes over available cores (the same
            // seam the CLI uses;
            // validation/subscope-extraction/topological ordering inside
            // `MatchingRuleSet::new` stay serial, same as the CLI.
            let options = AnalysisOptions::with_jobs(Jobs::available());
            let rules = load_rule_directory(&path, &options).map_err(rule_error)?;
            let ruleset = MatchingRuleSet::new(rules).map_err(rule_error)?;
            Ok(Rules {
                ruleset: Arc::new(ruleset),
                source_path,
            })
        })
    }

    fn __repr__(&self) -> String {
        format!("Rules.from_directory({:?})", self.source_path)
    }
}

/// `capa-x fetch-rules`, exposed for the binding: clones the pinned
/// capa-rules release. Never runs at import time or as a side effect of
/// [`Rules::from_directory`] never downloads rules. Pulling network access
/// into `from_directory` would make loading rules a silent, sometimes-
/// networked operation.
#[pyfunction]
#[pyo3(signature = (directory, r#ref=None))]
pub fn fetch_rules(py: Python<'_>, directory: PathBuf, r#ref: Option<String>) -> PyResult<()> {
    py.allow_threads(move || {
        const RULES_REPO: &str = "https://github.com/mandiant/capa-rules.git";
        let reference = r#ref.as_deref().unwrap_or(capa_x::RULES_PIN);

        if directory.exists() {
            return Err(crate::error::CapaError::new_err(format!(
                "{} already exists; remove it or pass another directory",
                directory.display()
            )));
        }

        let status = std::process::Command::new("git")
            .args(["clone", "--depth", "1", "--branch", reference, RULES_REPO])
            .arg(&directory)
            .status()
            .map_err(|e| {
                crate::error::CapaError::new_err(format!(
                    "running git: {e}\nfetch_rules needs git on PATH; alternatively \
                     download the rules from {RULES_REPO} yourself."
                ))
            })?;
        if !status.success() {
            return Err(crate::error::CapaError::new_err(format!(
                "git clone failed ({status})"
            )));
        }
        Ok(())
    })
}

/// So `analyze()` (in `analyze.rs`) doesn't need to know about
/// `capa_x::api::Input`'s `rules_paths` field shape directly.
pub(crate) fn rules_paths(rules: &Rules) -> Vec<String> {
    vec![rules.source_path.clone()]
}

pub(crate) fn ruleset(rules: &Rules) -> Arc<MatchingRuleSet> {
    Arc::clone(&rules.ruleset)
}
