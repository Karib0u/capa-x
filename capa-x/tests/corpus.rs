//! Every rule in the pinned `rules/` submodule must parse and
//! validates, and the whole corpus forms a valid dependency graph (no
//! unresolved `match:` references, no cycles, a stable topological order).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use capa_x::capabilities::MatchingRuleSet;
use capa_x::rules::{collect_rule_file_paths, Rule, RuleSet};

/// pinned count for `rules/` @ v9.4.0 (PINNED.md). Update deliberately,
/// alongside a PINNED.md version bump, if this ever changes.
const PINNED_RULE_COUNT: usize = 1042;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capa-x has a parent directory")
        .to_path_buf()
}

#[test]
fn corpus_parses_and_validates() {
    let rules_dir = workspace_root().join("rules");
    let mut paths = Vec::new();
    collect_rule_file_paths(&rules_dir, &mut paths);
    paths.sort();

    assert_eq!(
        paths.len(),
        PINNED_RULE_COUNT,
        "pinned capa-rules file count changed ({} found, expected {}) -- if this is a deliberate \
         PINNED.md version bump, update PINNED_RULE_COUNT to match",
        paths.len(),
        PINNED_RULE_COUNT
    );

    let mut errors: Vec<String> = Vec::new();
    let mut rules = Vec::new();
    for path in &paths {
        match Rule::from_yaml_file(path) {
            Ok(rule) => rules.push(rule),
            Err(e) => errors.push(format!("{}: {e}", path.display())),
        }
    }

    assert!(
        errors.is_empty(),
        "{} rule(s) failed to parse/validate:\n{}",
        errors.len(),
        errors.join("\n")
    );

    let rule_count = rules.len();
    let rule_set =
        RuleSet::new(rules).expect("the full pinned corpus must form a valid dependency graph");
    assert_eq!(rule_set.len(), rule_count);
    assert_eq!(
        rule_set.eval_order.len(),
        rule_count,
        "eval order must cover every rule exactly once"
    );

    // eval order must be a valid topological order: every rule's dependencies
    // appear before it.
    let position: std::collections::HashMap<&str, usize> = rule_set
        .eval_order
        .iter()
        .map(|s| s.as_str())
        .zip(0..)
        .collect();
    for (i, name) in rule_set.eval_order.iter().enumerate() {
        let rule = rule_set
            .get(name)
            .expect("eval_order only contains known rule names");
        for dep in rule.dependencies(&rule_set.by_namespace_prefix) {
            let dep_pos = position
                .get(dep.as_str())
                .unwrap_or_else(|| panic!("unresolved dependency \"{dep}\" from rule \"{name}\""));
            assert!(
                *dep_pos < i,
                "rule \"{name}\" evaluated before its dependency \"{dep}\""
            );
        }
    }
}

/// The full pinned corpus must also build as a *matching*
/// rule set -- subscope extraction and COM feature expansion (both deferred
/// from rule-parse time to here, see capabilities/ruleset.rs and com.rs)
/// succeed for every rule, including the two real capa-rules that use
/// `com/class`/`com/interface` (host-interaction/hardware/
/// enumerate-devices-by-category.yml, host-interaction/wmi/
/// connect-to-wmi-namespace-via-wbemlocator.yml).
#[test]
fn corpus_builds_as_a_matching_ruleset() {
    let rules_dir = workspace_root().join("rules");
    let mut paths = Vec::new();
    collect_rule_file_paths(&rules_dir, &mut paths);
    paths.sort();

    let rules: Vec<Rule> = paths
        .iter()
        .map(|p| Rule::from_yaml_file(p).expect("corpus_parses_and_validates covers parse errors"))
        .collect();
    let rule_count = rules.len();

    let matching = MatchingRuleSet::new(rules)
        .expect("the full pinned corpus must build as a matching rule set");

    // every original (non-subscope) rule is reachable through some scope's
    // dependency-closure bucket.
    use capa_x::rules::Scope;
    let mut seen = std::collections::HashSet::new();
    for scope in [
        Scope::File,
        Scope::Function,
        Scope::BasicBlock,
        Scope::Instruction,
        Scope::Process,
        Scope::Thread,
        Scope::SpanOfCalls,
        Scope::Call,
    ] {
        for rule in matching.rules_for_scope(scope) {
            if !rule.is_subscope_rule() {
                seen.insert(rule.name.clone());
            }
        }
    }
    assert_eq!(
        seen.len(),
        rule_count,
        "every original corpus rule should be scheduled at some scope"
    );
}
