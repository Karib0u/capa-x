//! Rule dependency graph: `match:` resolution, namespace indexing, and
//! topological ordering. Ported from `capa/rules/__init__.py`:
//! `Rule.get_dependencies`, `index_rules_by_namespace`,
//! `ensure_rules_are_unique`, `ensure_rule_dependencies_are_met`,
//! `topologically_order_rules`, and the (non-matching, non-optimizer) parts
//! of `RuleSet.__init__`.
//!
//! Two things upstream does here are deliberately **not** ported, since they
//! only matter once rules are actually being matched, not while validating
//! them:
//!
//! - `Rule.extract_subscope_rules` / `RuleSet._extract_subscope_rules`:
//!   mutates a rule's tree, replacing each `Subscope` node with a `match:`
//!   reference to a newly synthesized lib rule, so the flattened per-scope
//!   matcher (`RuleSet._match`) can evaluate scopes independently. Since this
//!   port's `get_dependencies` recurses directly into `Subscope` bodies
//!   (mirroring upstream's own `Statement.get_children()`), the *validation*
//!   this module cares about -- unresolved `match:` references, cycles,
//!   topological order -- comes out identical whether or not subscopes have
//!   been extracted into separate rules first.
//! - `capa.optimizer.optimize_rules`: reorders `And`/`Or`/`Some` children by
//!   estimated evaluation cost. Pure performance tuning for the matcher, has
//!   no bearing on parsing or validation.
//!
//! Also note: upstream's `RuleSet._get_rules_for_scope` includes **every**
//! rule reachable from any non-subscope rule, `lib` or not -- see the
//! comment above it referencing capa issue #398 ("we want to include
//! general 'lib' rules here - even if they are not dependencies of other
//! rules"). So despite the obvious temptation to handle lib-rule
//! pruning, `RuleSet::new` here includes every parsed rule unconditionally,
//! matching upstream's actual (unpruned) behavior per this project's
//! source-of-truth hierarchy (Python wins on disagreement with the brief).

use std::collections::{HashMap, HashSet};

use crate::features::Feature;
use crate::rules::{Node, Rule, RuleError, Statement};

/// port of `Rule.get_dependencies`
pub fn get_dependencies(body: &Node, namespaces: &HashMap<String, Vec<String>>) -> HashSet<String> {
    let mut deps = HashSet::new();
    walk(&body.stmt, namespaces, &mut deps);
    deps
}

fn register(value: &str, namespaces: &HashMap<String, Vec<String>>, deps: &mut HashSet<String>) {
    // give precedence to namespaces over rule names, exactly as upstream does
    // (a `match:` value could name either).
    match namespaces.get(value) {
        Some(names) => deps.extend(names.iter().cloned()),
        None => {
            deps.insert(value.to_string());
        }
    }
}

fn walk(stmt: &Statement, namespaces: &HashMap<String, Vec<String>>, deps: &mut HashSet<String>) {
    match stmt {
        Statement::Leaf(Feature::MatchedRule(value)) => register(value, namespaces, deps),
        Statement::Leaf(_) => {}
        Statement::And(children) | Statement::Or(children) => {
            for c in children {
                walk(&c.stmt, namespaces, deps);
            }
        }
        Statement::Some { children, .. } => {
            for c in children {
                walk(&c.stmt, namespaces, deps);
            }
        }
        Statement::Not(child) => walk(&child.stmt, namespaces, deps),
        Statement::Subscope { body, .. } => walk(&body.stmt, namespaces, deps),
        Statement::Range { feature, .. } => {
            // `count(match(foo)): N` -- Range wraps the feature directly, so
            // this is the one place a dependency can hide behind a `Range`
            // rather than a `Leaf`.
            if let Feature::MatchedRule(value) = feature {
                register(value, namespaces, deps);
            }
        }
    }
}

/// port of `index_rules_by_namespace`
pub fn index_rules_by_namespace(rules: &[Rule]) -> HashMap<String, Vec<String>> {
    let mut namespaces: HashMap<String, Vec<String>> = HashMap::new();
    for rule in rules {
        let Some(ns) = &rule.namespace else {
            continue;
        };
        let mut current = ns.as_str();
        while !current.is_empty() {
            namespaces
                .entry(current.to_string())
                .or_default()
                .push(rule.name.clone());
            match current.rfind('/') {
                Some(idx) => current = &current[..idx],
                None => break,
            }
        }
    }
    namespaces
}

/// port of `ensure_rules_are_unique`
fn ensure_rules_are_unique(rules: &[Rule]) -> Result<(), RuleError> {
    let mut seen = HashSet::new();
    for rule in rules {
        if !seen.insert(rule.name.as_str()) {
            return Err(RuleError::invalid(format!(
                "duplicate rule name: {}",
                rule.name
            )));
        }
    }
    Ok(())
}

/// port of `ensure_rule_dependencies_are_met`
fn ensure_rule_dependencies_are_met(
    rules: &[Rule],
    namespaces: &HashMap<String, Vec<String>>,
) -> Result<(), RuleError> {
    let by_name: HashSet<&str> = rules.iter().map(|r| r.name.as_str()).collect();
    for rule in rules {
        let mut deps: Vec<String> = get_dependencies(&rule.body, namespaces)
            .into_iter()
            .collect();
        deps.sort();
        for dep in deps {
            if !by_name.contains(dep.as_str()) {
                return Err(RuleError::invalid(format!(
                    "rule \"{}\" depends on missing rule \"{dep}\"",
                    rule.name
                )));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    Visiting,
    Done,
}

/// port of `topologically_order_rules`, with cycle detection added: upstream
/// has no visited-in-progress marker, so a true cycle would recurse forever
/// (eventually a Python `RecursionError`). This project's "no panics on
/// untrusted input" rule means we detect and report the cycle instead.
fn topologically_order_rules(
    rules: &[Rule],
    namespaces: &HashMap<String, Vec<String>>,
) -> Result<Vec<String>, RuleError> {
    let by_name: HashMap<&str, &Rule> = rules.iter().map(|r| (r.name.as_str(), r)).collect();
    let mut marks: HashMap<String, Mark> = HashMap::new();
    let mut order: Vec<String> = Vec::with_capacity(rules.len());

    for rule in rules {
        visit(&rule.name, &by_name, namespaces, &mut marks, &mut order)?;
    }

    Ok(order)
}

fn visit(
    name: &str,
    by_name: &HashMap<&str, &Rule>,
    namespaces: &HashMap<String, Vec<String>>,
    marks: &mut HashMap<String, Mark>,
    order: &mut Vec<String>,
) -> Result<(), RuleError> {
    match marks.get(name) {
        Some(Mark::Done) => return Ok(()),
        Some(Mark::Visiting) => {
            return Err(RuleError::invalid(format!(
                "rule \"{name}\" has a circular dependency"
            )))
        }
        None => {}
    }
    let Some(rule) = by_name.get(name) else {
        // dependencies are checked up-front by `ensure_rule_dependencies_are_met`,
        // so this should be unreachable in `RuleSet::new`'s own call path; kept
        // as a clean error (not a panic) for any other caller.
        return Err(RuleError::invalid(format!(
            "rule \"{name}\" depends on missing rule"
        )));
    };

    marks.insert(name.to_string(), Mark::Visiting);

    let mut deps: Vec<String> = get_dependencies(&rule.body, namespaces)
        .into_iter()
        .collect();
    deps.sort();
    for dep in deps {
        visit(&dep, by_name, namespaces, marks, order)?;
    }

    marks.insert(name.to_string(), Mark::Done);
    order.push(name.to_string());
    Ok(())
}

/// port of the validation/ordering (non-matching) portion of `RuleSet.__init__`.
#[derive(Debug)]
pub struct RuleSet {
    pub rules: HashMap<String, Rule>,
    pub by_namespace_prefix: HashMap<String, Vec<String>>,
    /// dependency-first topological order of rule names.
    pub eval_order: Vec<String>,
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>) -> Result<RuleSet, RuleError> {
        ensure_rules_are_unique(&rules)?;

        if rules.is_empty() {
            return Err(RuleError::InvalidRuleSet("no rules selected".to_string()));
        }

        let by_namespace_prefix = index_rules_by_namespace(&rules);
        ensure_rule_dependencies_are_met(&rules, &by_namespace_prefix)?;
        let eval_order = topologically_order_rules(&rules, &by_namespace_prefix)?;

        let rules = rules.into_iter().map(|r| (r.name.clone(), r)).collect();
        Ok(RuleSet {
            rules,
            by_namespace_prefix,
            eval_order,
        })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn get(&self, name: &str) -> Option<&Rule> {
        self.rules.get(name)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn rule(name: &str, namespace: Option<&str>, match_target: &str) -> Rule {
        let ns_line = namespace
            .map(|n| format!("    namespace: {n}\n"))
            .unwrap_or_default();
        let doc = format!(
            "rule:\n  meta:\n    name: {name}\n{ns_line}    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - match: {match_target}\n"
        );
        Rule::from_yaml(&doc).unwrap_or_else(|e| panic!("test rule {name} failed to parse: {e}"))
    }

    fn leaf_rule(name: &str, namespace: Option<&str>) -> Rule {
        let ns_line = namespace
            .map(|n| format!("    namespace: {n}\n"))
            .unwrap_or_default();
        let doc = format!(
            "rule:\n  meta:\n    name: {name}\n{ns_line}    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - api: CreateFileA\n"
        );
        Rule::from_yaml(&doc).unwrap_or_else(|e| panic!("test rule {name} failed to parse: {e}"))
    }

    #[test]
    fn topological_order_puts_dependencies_first() {
        let a = leaf_rule("a", None);
        let b = rule("b", None, "a");
        let c = rule("c", None, "b");
        let set = RuleSet::new(vec![c, a, b]).expect("valid dependency graph");
        let pos = |n: &str| {
            set.eval_order
                .iter()
                .position(|x| x == n)
                .expect("rule present in eval_order")
        };
        assert!(pos("a") < pos("b"));
        assert!(pos("b") < pos("c"));
    }

    #[test]
    fn missing_dependency_is_an_error() {
        let a = rule("a", None, "does not exist");
        let err = RuleSet::new(vec![a]).unwrap_err();
        assert!(
            err.to_string().contains("missing rule"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn circular_dependency_is_an_error_not_a_stack_overflow() {
        let a = rule("a", None, "b");
        let b = rule("b", None, "a");
        let err = RuleSet::new(vec![a, b]).unwrap_err();
        assert!(
            err.to_string().contains("circular dependency"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn duplicate_rule_name_is_an_error() {
        let a1 = leaf_rule("dup", None);
        let a2 = leaf_rule("dup", None);
        let err = RuleSet::new(vec![a1, a2]).unwrap_err();
        assert!(
            err.to_string().contains("duplicate rule name"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn namespace_match_takes_precedence_over_rule_name() {
        // "match: ns/a" should resolve to every rule under namespace "ns/a",
        // not to a (nonexistent) rule literally named "ns/a".
        let m1 = leaf_rule("m1", Some("ns/a"));
        let m2 = leaf_rule("m2", Some("ns/a"));
        let dependent = rule("dependent", None, "ns/a");
        let set =
            RuleSet::new(vec![m1, m2, dependent]).expect("namespace-based dependency must resolve");
        let pos = |n: &str| {
            set.eval_order
                .iter()
                .position(|x| x == n)
                .expect("rule present in eval_order")
        };
        assert!(pos("m1") < pos("dependent"));
        assert!(pos("m2") < pos("dependent"));
    }

    #[test]
    fn index_rules_by_namespace_covers_every_prefix() {
        let rules = vec![leaf_rule("r", Some("a/b/c"))];
        let namespaces = index_rules_by_namespace(&rules);
        assert_eq!(namespaces.get("a/b/c").map(|v| v.len()), Some(1));
        assert_eq!(namespaces.get("a/b").map(|v| v.len()), Some(1));
        assert_eq!(namespaces.get("a").map(|v| v.len()), Some(1));
        assert!(!namespaces.contains_key("b"));
        assert!(!namespaces.contains_key("c"));
    }
}
