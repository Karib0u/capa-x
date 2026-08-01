//! Every `capa-x` error variant reaches Python as a typed exception under
//! one `CapaError` base, preserving the original message as `str(exc)`. A
//! hard error must never become `None`, an empty result, or a warning.
//!
//! `capa-x`'s own error types stay on the Rust side of the ABI -- Python
//! only ever sees a message string and an exception class, never one of
//! `capa-x`'s internal error enums. The result document is the interface, not
//! capa-x's internal types.

use capa_x::api::AnalysisError;
use capa_x::rules::RuleError;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::PyErr;

create_exception!(
    capa_x,
    CapaError,
    PyException,
    "Base class for every exception this module raises."
);
create_exception!(
    capa_x,
    InvalidRuleError,
    CapaError,
    "A rule file failed to parse, or the loaded rule set is invalid \
     (duplicate name, missing dependency, or a dependency cycle)."
);
create_exception!(
    capa_x,
    UnsupportedFormatError,
    CapaError,
    "The input format could not be auto-detected, or an explicit `format=` \
     value is not one capa-x recognizes."
);
create_exception!(
    capa_x,
    InvalidSignatureError,
    CapaError,
    "A FLIRT signature file failed to parse."
);
create_exception!(
    capa_x,
    CorruptFileError,
    CapaError,
    "The input bytes could not be parsed or analyzed as the selected (or \
     detected) format."
);

/// `RuleError` covers both `Rules.from_directory`'s parse step and the
/// `MatchingRuleSet::new` build step that follows it -- both raise the same
/// exception class, since both mean the same thing to a caller: the rule
/// set, not the sample, is the problem.
pub fn rule_error(e: RuleError) -> PyErr {
    InvalidRuleError::new_err(e.to_string())
}

/// Mirrors `capa_x::api::AnalysisError::exit_code`'s classification, but
/// as exception classes instead of process exit codes -- same source of
/// truth, a different ABI.
pub fn analysis_error(e: AnalysisError) -> PyErr {
    let message = e.to_string();
    match e {
        AnalysisError::UnknownFormat => UnsupportedFormatError::new_err(message),
        AnalysisError::Signature(_) => InvalidSignatureError::new_err(message),
        _ => CorruptFileError::new_err(message),
    }
}
