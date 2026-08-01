//! Error types, ported from `capa.rules.InvalidRule` / `InvalidRuleWithPath` /
//! `InvalidRuleSet`.

/// A rule failed to parse or validate. Carries an optional file path so
/// callers get the same context Python's `InvalidRuleWithPath` provides.
///
/// Per the project's hard rule ("never silently skip"), every unparseable
/// rule or unknown syntax/field must surface as one of these, never be
/// dropped silently.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("invalid rule: {0}")]
    Invalid(String),

    #[error("invalid rule: {path}: {message}")]
    InvalidWithPath { path: String, message: String },

    #[error("invalid rule set: {0}")]
    InvalidRuleSet(String),

    #[error("invalid rule: {0}")]
    Yaml(String),
}

impl RuleError {
    pub fn invalid(msg: impl Into<String>) -> RuleError {
        RuleError::Invalid(msg.into())
    }

    /// attach a file path to an existing error, as `Rule::from_yaml_file` does
    /// in Python by re-raising as `InvalidRuleWithPath`.
    pub fn with_path(self, path: impl Into<String>) -> RuleError {
        let message = match self {
            RuleError::Invalid(m) | RuleError::Yaml(m) => m,
            RuleError::InvalidWithPath { message, .. } => message,
            RuleError::InvalidRuleSet(m) => m,
        };
        RuleError::InvalidWithPath {
            path: path.into(),
            message,
        }
    }
}
