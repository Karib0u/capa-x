//! The "matching" rule set: subscope extraction, COM feature expansion,
//! and per-scope topological grouping. Ported from the relevant parts of
//! `capa/rules/__init__.py::RuleSet` (`_extract_subscope_rules`,
//! `_get_rules_for_scope`, `get_rules_and_dependencies`,
//! `topologically_order_rules`, `rules_by_scope`) -- the matching-time
//! sibling of `rules::RuleSet` (name-level validation only).
//!
//! Built *from* an already-validated `rules::RuleSet`: that validation
//! (unique names, resolvable `match:`/namespace dependencies, cycle-free)
//! doesn't need subscope extraction to be correct, because `rules::graph`'s
//! dependency walker already recurses directly into `Subscope` bodies (see
//! that module's doc comment) -- so it's safe to layer this on top rather
//! than re-deriving uniqueness/acyclicity here.

mod dynamic_analysis;
mod ruleset;
mod static_analysis;

pub use dynamic_analysis::{find_dynamic_capabilities, DynamicCapabilities};
pub use ruleset::MatchingRuleSet;
pub use static_analysis::{find_static_capabilities, CapabilityError, StaticCapabilities};
