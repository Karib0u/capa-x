//! Rule parsing: YAML capa rules -> typed model. Ported from
//! `capa/rules/__init__.py` (v9.4.0, see PINNED.md). No matching or
//! evaluation here -- that lives in `capabilities` and `engine`.

mod error;
mod grammar;
mod graph;
mod meta;
mod scope;

pub use error::RuleError;
pub use scope::{
    is_subscope_compatible, Scope, Scopes, DYNAMIC_SCOPES, DYNAMIC_SCOPE_ORDER, STATIC_SCOPES,
    STATIC_SCOPE_ORDER,
};

use crate::features::Feature;

/// A single node in a rule's logic tree: a structural statement or a feature
/// leaf, plus its optional human-readable description.
///
/// Ported from `capa.engine.Statement` + its subclasses, and the
/// `description=` kwarg every one of them accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub stmt: Statement,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    /// `N or more:` / `optional:` (== `Some{count: 0, ..}`)
    Some {
        count: u32,
        children: Vec<Node>,
    },
    /// `count(<feature>): N` / `N or more` / `N or fewer` / `(min, max)`.
    /// `min` defaults to 0 (capa/engine.py: `Range.__init__` normalizes
    /// `min=None` to 0); `max: None` means unbounded.
    Range {
        feature: Feature,
        min: u32,
        max: Option<u32>,
    },
    /// `function:` / `basic block:` / `instruction:` / `process:` / `thread:`
    /// / `span of calls:` / `call:` -- a placeholder the matching engine must
    /// preprocess away (extract into its own rule) before evaluation, exactly
    /// as upstream's `Rule.extract_subscope_rules` does.
    Subscope {
        scope: Scope,
        body: Box<Node>,
    },
    Leaf(Feature),
}

/// Ported from `capa/render/result_document.py::RuleMetadata` (the subset of
/// meta fields rule parsing cares about) plus a verbatim copy of the whole `meta:`
/// mapping, so no custom or future meta key is ever lost even though this
/// struct doesn't model it individually.
#[derive(Debug, Clone)]
pub struct RuleMeta {
    pub name: String,
    pub namespace: Option<String>,
    pub authors: Vec<String>,
    pub description: String,
    pub lib: bool,
    /// kept as opaque strings; parsing into tactic/technique/subtechnique/id
    /// (`AttackSpec`/`MBCSpec`) is a rendering concern.
    pub attack: Vec<String>,
    pub mbc: Vec<String>,
    pub references: Vec<String>,
    pub examples: Vec<String>,
    /// the complete, original `meta:` mapping, verbatim.
    pub raw: serde_yaml::Mapping,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub namespace: Option<String>,
    pub meta: RuleMeta,
    pub scopes: Scopes,
    pub body: Node,
    pub is_lib: bool,
    /// the raw rule YAML text, preserved for the result document.
    pub source: String,
}

impl Rule {
    pub fn from_yaml(s: &str) -> Result<Rule, RuleError> {
        meta::rule_from_yaml(s)
    }

    pub fn from_yaml_file(path: &std::path::Path) -> Result<Rule, RuleError> {
        let bytes = std::fs::read(path)
            .map_err(|e| RuleError::invalid(format!("could not read {}: {e}", path.display())))?;
        let text = String::from_utf8(bytes)
            .map_err(|e| RuleError::invalid(format!("{}: not valid utf-8: {e}", path.display())))?;
        Rule::from_yaml(&text).map_err(|e| e.with_path(path.display().to_string()))
    }

    /// port of `Rule.get_dependencies`
    pub fn dependencies(
        &self,
        namespaces: &std::collections::HashMap<String, Vec<String>>,
    ) -> std::collections::HashSet<String> {
        graph::get_dependencies(&self.body, namespaces)
    }

    pub fn is_subscope_rule(&self) -> bool {
        self.meta
            .raw
            .get(serde_yaml::Value::String("capa/subscope-rule".to_string()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }
}

pub use graph::{index_rules_by_namespace, RuleSet};

/// mirrors `capa.rules.collect_rule_file_paths`'s directory walk: every
/// `.yml` file under `dir`, recursively, skipping anything under a `.git`
/// path segment (also incidentally skips a checked-out capa-rules repo's own
/// `.github/` CI config, which isn't rule content).
pub fn collect_rule_file_paths(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.to_string_lossy().contains(".git") {
            continue;
        }
        if path.is_dir() {
            collect_rule_file_paths(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("yml") {
            out.push(path);
        }
    }
}

/// parse every rule under `dir` (see `collect_rule_file_paths`). Returns the
/// first parse error encountered (in sorted path order), if any -- matching
/// this project's "never silently skip" rule: an unparseable rule fails the
/// whole load rather than vanishing from the set.
///
/// `options.jobs` parallelises the *per-file* parse, and nothing else. Each
/// file is read and parsed into an owned [`Rule`] independently; the returned
/// vector stays in sorted-path order, so `MatchingRuleSet::new`'s validation,
/// subscope extraction and topological ordering see exactly the input they saw
/// serially. Those steps remain serial, as does everything downstream of them
/// (the same parallel rule-loading seam used by the CLI).
///
/// This seam is not in A.2's list, which names per-function extraction and
/// matching. It is here because the measurement said so: on the benchmark
/// corpus, parsing 1,042 rule files is a fixed ~0.2 s that dominates the
/// runtime of every small and medium sample, so leaving it serial would have
/// capped the end-to-end speedup below A.4's gate no matter how well the
/// per-function seams scaled. The same "lowest-indexed error wins" rule keeps
/// the reported parse error identical to the serial one.
pub fn load_rule_directory(
    dir: &std::path::Path,
    options: &crate::parallel::AnalysisOptions,
) -> Result<Vec<Rule>, RuleError> {
    let mut paths = Vec::new();
    collect_rule_file_paths(dir, &mut paths);
    paths.sort();

    crate::parallel::try_map(options.jobs, &paths, |path| Rule::from_yaml_file(path))
}
