use std::collections::{BTreeSet, HashMap, HashSet};

use crate::address::Address;
use crate::engine::{self, EngineError, FeatureSet, MatchResults};
use crate::features::Feature;
use crate::rules::{Node, Rule, RuleError, RuleMeta, Scope, Scopes, Statement};

/// `capa/rules/__init__.py::RuleSet.rules_by_scope`'s scope tuple order
/// (order is cosmetic here; each rule ends up in exactly one bucket per its
/// own declared `Scopes`, though a rule can be a *dependency* -- and so
/// appear in `rules` -- across scopes it isn't itself matched at).
const ALL_SCOPES: [Scope; 8] = [
    Scope::Call,
    Scope::SpanOfCalls,
    Scope::Thread,
    Scope::Process,
    Scope::Instruction,
    Scope::BasicBlock,
    Scope::Function,
    Scope::File,
];

/// The matching rule set.
pub struct MatchingRuleSet {
    /// every rule (original + synthetic subscope-derived lib rules), by name.
    rules: HashMap<String, Rule>,
    /// dependency-first topological order, per scope, restricted to rules
    /// needed for that scope: `RuleSet._get_rules_for_scope`.
    rules_by_scope: HashMap<Scope, Vec<String>>,
    /// namespace prefix -> rule names: `RuleSet.rules_by_namespace`. Public
    /// since `capabilities::dynamic`'s span-of-calls matcher needs it to
    /// compute `rule.dependencies(namespaces)` for its suppression logic.
    pub by_namespace_prefix: HashMap<String, Vec<String>>,
}

impl MatchingRuleSet {
    pub fn new(rules: Vec<Rule>) -> Result<MatchingRuleSet, RuleError> {
        // Validates uniqueness/dependencies/acyclicity; see module doc for
        // why this doesn't need subscope extraction to have happened first.
        // We don't need its output, only the validation side effect.
        crate::rules::RuleSet::new(rules.clone())?;

        let expanded = expand_and_extract(rules)?;

        let by_namespace_prefix = crate::rules::index_rules_by_namespace(&expanded);
        let by_name: HashMap<String, &Rule> =
            expanded.iter().map(|r| (r.name.clone(), r)).collect();

        let mut rules_by_scope = HashMap::new();
        for scope in ALL_SCOPES {
            rules_by_scope.insert(
                scope,
                rules_for_scope(&expanded, &by_name, &by_namespace_prefix, scope),
            );
        }

        let rules = expanded.into_iter().map(|r| (r.name.clone(), r)).collect();
        Ok(MatchingRuleSet {
            rules,
            rules_by_scope,
            by_namespace_prefix,
        })
    }

    pub fn get(&self, name: &str) -> Option<&Rule> {
        self.rules.get(name)
    }

    /// dependency-first ordered rules matched at the given scope --
    /// `RuleSet.rules_by_scope[scope]` / the `{scope}_rules` properties.
    pub fn rules_for_scope(&self, scope: Scope) -> impl Iterator<Item = &Rule> {
        self.rules_by_scope
            .get(&scope)
            .into_iter()
            .flatten()
            .filter_map(|name| self.rules.get(name))
    }

    /// port of `capa.engine.match(rules_by_scope[scope], features, addr)`.
    ///
    /// Upstream's `RuleSet.match` calls a feature-indexed `_match` that's
    /// provably equivalent to (and asserted against, via its `paranoid`
    /// flag) the plain `capa.engine.match` over the same topologically
    /// ordered rule list -- it exists purely to skip evaluating rules that
    /// can't possibly match, for speed. This port takes correctness over
    /// speed and uses the simple, always-correct form directly: evaluate every rule for this scope in dependency
    /// order, and feed each match back into `features` (via
    /// `index_rule_matches`) before considering the next rule, so later
    /// rules can depend on earlier ones via `match:`.
    pub fn match_scope(
        &self,
        scope: Scope,
        features: &FeatureSet,
        addr: Address,
    ) -> Result<(FeatureSet, MatchResults), EngineError> {
        let mut features = features.clone();
        let mut results: MatchResults = HashMap::new();

        for rule in self.rules_for_scope(scope) {
            let quick = engine::evaluate(&rule.body, &features, true)?;
            if !quick.success {
                continue;
            }
            // re-evaluate without short-circuiting to collect the full
            // Result tree (matches capa.engine.match's two-pass approach).
            let full = engine::evaluate(&rule.body, &features, false)?;
            debug_assert!(full.success);

            let locations: BTreeSet<Address> = [addr].into_iter().collect();
            engine::index_rule_matches(&mut features, rule, &locations);
            results
                .entry(rule.name.clone())
                .or_default()
                .push((addr, full));
        }

        Ok((features, results))
    }
}

/// port of `RuleSet._get_rules_for_scope`.
fn rules_for_scope(
    rules: &[Rule],
    by_name: &HashMap<String, &Rule>,
    namespaces: &HashMap<String, Vec<String>>,
    scope: Scope,
) -> Vec<String> {
    let mut scope_rule_names: HashSet<String> = HashSet::new();
    for rule in rules {
        if rule.is_subscope_rule() {
            continue;
        }
        transitive_closure(by_name, namespaces, &rule.name, &mut scope_rule_names);
    }

    topo_sort_subset(&scope_rule_names, by_name, namespaces)
        .into_iter()
        .filter(|name| by_name.get(name).is_some_and(|r| r.scopes.contains(scope)))
        .collect()
}

/// port of `get_rules_and_dependencies`, folded into a single accumulating
/// walk. No cycle re-detection: `MatchingRuleSet::new` already validated the
/// full rule set acyclic (via `rules::RuleSet::new`) before this runs, and
/// subscope extraction only ever adds new leaves (`match:` -> synthetic
/// rule) whose own bodies are drawn from the (already acyclic) parent, so no
/// new cycle can be introduced here.
fn transitive_closure(
    by_name: &HashMap<String, &Rule>,
    namespaces: &HashMap<String, Vec<String>>,
    start: &str,
    out: &mut HashSet<String>,
) {
    if !out.insert(start.to_string()) {
        return;
    }
    let Some(rule) = by_name.get(start) else {
        return;
    };
    let mut deps: Vec<String> = rule.dependencies(namespaces).into_iter().collect();
    deps.sort_unstable();
    for dep in deps {
        transitive_closure(by_name, namespaces, &dep, out);
    }
}

/// port of `topologically_order_rules`, restricted to a subset of rules
/// (`RuleSet._get_rules_for_scope` topologically orders just the scope's
/// dependency closure, not the whole rule set).
fn topo_sort_subset(
    names: &HashSet<String>,
    by_name: &HashMap<String, &Rule>,
    namespaces: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    fn visit(
        name: &str,
        by_name: &HashMap<String, &Rule>,
        namespaces: &HashMap<String, Vec<String>>,
        seen: &mut HashSet<String>,
        order: &mut Vec<String>,
    ) {
        if !seen.insert(name.to_string()) {
            return;
        }
        if let Some(rule) = by_name.get(name) {
            let mut deps: Vec<String> = rule.dependencies(namespaces).into_iter().collect();
            deps.sort_unstable();
            for dep in deps {
                visit(&dep, by_name, namespaces, seen, order);
            }
        }
        order.push(name.to_string());
    }

    let mut sorted_names: Vec<&String> = names.iter().collect();
    sorted_names.sort_unstable();

    let mut seen = HashSet::new();
    let mut order = Vec::with_capacity(names.len());
    for name in sorted_names {
        visit(name, by_name, namespaces, &mut seen, &mut order);
    }
    order
}

/// port of `RuleSet._extract_subscope_rules` (the stack-based driver) over
/// `Rule.extract_subscope_rules`/`_extract_subscope_rules_rec`, plus COM
/// feature expansion (rule parsing defers `Com` leaves to here; see
/// `com.rs`). Each rule's body is walked once to expand any `Com` leaves,
/// then once more to lift `Subscope` children out into synthetic `lib: true`
/// rules (replacing them in place with a `match:` reference) -- mirroring
/// the two upstream passes (`translate_com_feature` at rule-parse time,
/// `_extract_subscope_rules` at RuleSet-build time), just reordered since
/// this port does both lazily, here.
fn expand_and_extract(rules: Vec<Rule>) -> Result<Vec<Rule>, RuleError> {
    let mut stack = rules;
    let mut done = Vec::with_capacity(stack.len());
    while let Some(mut rule) = stack.pop() {
        let expanded_stmt = expand_com(rule.body.stmt)?;

        let mut counter = 0u64;
        let mut extracted: Vec<(String, Scope, Node)> = Vec::new();
        let new_stmt = extract_children(expanded_stmt, &rule.name, &mut counter, &mut extracted);
        rule.body = Node {
            stmt: new_stmt,
            description: rule.body.description.clone(),
        };

        for (name, scope, body) in extracted {
            stack.push(subscope_rule(name, scope, body, &rule.name));
        }
        done.push(rule);
    }

    // port of `RuleSet.__init__`'s `rules = capa.optimizer.optimize_rules(rules)`
    // step, applied to the fully expanded set (parent rules + synthetic
    // subscope rules), same as upstream.
    for rule in &mut done {
        optimize_node(&mut rule.body);
    }

    Ok(done)
}

/// port of `capa/optimizer.py`: `get_node_cost`.
fn feature_cost(f: &Feature) -> u32 {
    match f {
        // "we assume these are the most restrictive features: authors
        // commonly use them at the start of rules to restrict the category
        // of samples to inspect."
        Feature::Os(_) | Feature::Arch(_) | Feature::Format(_) => 0,
        // "substring and regex features require a full scan of each string
        // which we anticipate is more expensive than a hash lookup feature."
        Feature::String(crate::features::StringFeature::Substring(_))
        | Feature::String(crate::features::StringFeature::Regex(_))
        | Feature::Bytes(_) => 2,
        // "this should be all hash-lookup features. we give this an
        // arbitrary weight of 1."
        _ => 1,
    }
}

/// port of `get_node_cost`, over our unified `Node`/`Statement` types.
fn node_cost(node: &Node) -> u32 {
    match &node.stmt {
        Statement::Leaf(f) => feature_cost(f),
        Statement::Not(child) => 1 + node_cost(child),
        Statement::Range { feature, .. } => 1 + feature_cost(feature),
        Statement::And(children) | Statement::Or(children) => {
            1 + children.iter().map(node_cost).sum::<u32>()
        }
        Statement::Some { children, .. } => 1 + children.iter().map(node_cost).sum::<u32>(),
        // never reached in practice: `Subscope` nodes are always lifted out
        // by `extract_children` before this runs, same as upstream (whose
        // `get_node_cost` also has no `Subscope`/`ceng.Subscope` case).
        Statement::Subscope { body, .. } => 1 + node_cost(body),
    }
}

/// port of `capa/optimizer.py`: `optimize_statement`. Sorts (stably) the
/// *immediate* children of an And/Or/Some by ascending cost, then stops --
/// it does **not** recurse into those children to also optimize any nested
/// And/Or/Some. Only `Not`/`Range` (which wrap a single child, nothing to
/// sort) recurse, looking for a compound statement further down to
/// optimize. This shallow-recursion behavior is upstream's actual behavior
/// (`optimize_statement` returns immediately after sorting an And/Or/Some,
/// never calling itself on the now-reordered children) -- verified against
/// real `capa -j` output (difftest): a compound statement nested two
/// levels inside another And/Or/Some keeps its original declaration order.
fn optimize_node(node: &mut Node) {
    match &mut node.stmt {
        Statement::And(children) | Statement::Or(children) => {
            children.sort_by_key(node_cost);
        }
        Statement::Some { children, .. } => {
            children.sort_by_key(node_cost);
        }
        Statement::Not(child) => optimize_node(child),
        Statement::Subscope { body, .. } => optimize_node(body),
        Statement::Range { .. } | Statement::Leaf(_) => {}
    }
}

/// port of `translate_com_feature`'s call site inside `parse_feature`,
/// walking the whole tree since rule parsing leaves `Com` leaves in place
/// wherever they
/// occur (rather than only at the point a rule is parsed).
fn expand_com(stmt: Statement) -> Result<Statement, RuleError> {
    Ok(match stmt {
        Statement::Leaf(Feature::Com(kind, name)) => {
            crate::com::translate_com_feature(&name, kind)?
        }
        Statement::Leaf(f) => Statement::Leaf(f),
        Statement::And(children) => Statement::And(expand_com_children(children)?),
        Statement::Or(children) => Statement::Or(expand_com_children(children)?),
        Statement::Some { count, children } => Statement::Some {
            count,
            children: expand_com_children(children)?,
        },
        Statement::Not(child) => Statement::Not(Box::new(expand_com_node(*child)?)),
        Statement::Subscope { scope, body } => Statement::Subscope {
            scope,
            body: Box::new(expand_com_node(*body)?),
        },
        // `Range` wraps a bare `Feature`, and the rule grammar never
        // produces a `com/...` feature there (`count(com/class(...))` isn't
        // a recognized `count()` term -- see grammar.rs's `build_count`).
        Statement::Range { feature, min, max } => Statement::Range { feature, min, max },
    })
}

fn expand_com_node(node: Node) -> Result<Node, RuleError> {
    Ok(Node {
        stmt: expand_com(node.stmt)?,
        description: node.description,
    })
}

fn expand_com_children(children: Vec<Node>) -> Result<Vec<Node>, RuleError> {
    children.into_iter().map(expand_com_node).collect()
}

/// port of `Rule._extract_subscope_rules_rec`: replace every `Subscope`
/// *child* of `stmt` with a `match:` leaf referencing a newly synthesized
/// rule (collected into `extracted`), then recurse into the (now-updated)
/// children looking for further, deeper subscopes. Mirrors upstream's gap
/// verbatim: a `Subscope` that is itself the *root* of a rule body is never
/// replaced (nothing calls `replace_child` on a tree root) -- confirmed
/// empirically absent from the pinned capa-rules corpus, and `engine.rs`
/// surfaces a clean `EngineError::UnextractedSubscope` rather than panicking
/// if one is ever evaluated directly.
fn extract_children(
    stmt: Statement,
    rule_name: &str,
    counter: &mut u64,
    extracted: &mut Vec<(String, Scope, Node)>,
) -> Statement {
    match stmt {
        Statement::And(children) => {
            Statement::And(extract_child_list(children, rule_name, counter, extracted))
        }
        Statement::Or(children) => {
            Statement::Or(extract_child_list(children, rule_name, counter, extracted))
        }
        Statement::Some { count, children } => Statement::Some {
            count,
            children: extract_child_list(children, rule_name, counter, extracted),
        },
        Statement::Not(child) => Statement::Not(Box::new(extract_single_child(
            *child, rule_name, counter, extracted,
        ))),
        Statement::Subscope { scope, body } => Statement::Subscope {
            scope,
            body: Box::new(extract_single_child(*body, rule_name, counter, extracted)),
        },
        Statement::Range { .. } | Statement::Leaf(_) => stmt,
    }
}

fn extract_child_list(
    children: Vec<Node>,
    rule_name: &str,
    counter: &mut u64,
    extracted: &mut Vec<(String, Scope, Node)>,
) -> Vec<Node> {
    children
        .into_iter()
        .map(|c| extract_single_child(c, rule_name, counter, extracted))
        .collect()
}

fn extract_single_child(
    node: Node,
    rule_name: &str,
    counter: &mut u64,
    extracted: &mut Vec<(String, Scope, Node)>,
) -> Node {
    if let Statement::Subscope { scope, body } = node.stmt {
        *counter += 1;
        // upstream uses a random uuid4 hex suffix ("ideally, this won't ever
        // be rendered to a user"); a per-rule counter is just as unique
        // (rule names are already validated unique) and deterministic.
        let name = format!("{rule_name}/{counter}");
        extracted.push((name.clone(), scope, *body));
        // upstream's replacement is a bare `MatchedRule(name)` with no
        // `description=` -- so any description on the subscope entry itself
        // is dropped here, matching that (minor) upstream quirk.
        Node {
            stmt: Statement::Leaf(Feature::MatchedRule(name)),
            description: None,
        }
    } else {
        Node {
            stmt: extract_children(node.stmt, rule_name, counter, extracted),
            description: node.description,
        }
    }
}

/// port of the synthetic `Rule(...)` construction inside
/// `_extract_subscope_rules_rec`.
fn subscope_rule(name: String, scope: Scope, body: Node, parent: &str) -> Rule {
    let scopes = if matches!(
        scope,
        Scope::Process | Scope::Thread | Scope::SpanOfCalls | Scope::Call
    ) {
        Scopes {
            static_: None,
            dynamic: Some(scope),
        }
    } else {
        Scopes {
            static_: Some(scope),
            dynamic: None,
        }
    };

    let mut raw = serde_yaml::Mapping::new();
    raw.insert(
        serde_yaml::Value::String("name".to_string()),
        serde_yaml::Value::String(name.clone()),
    );
    raw.insert(
        serde_yaml::Value::String("lib".to_string()),
        serde_yaml::Value::Bool(true),
    );
    raw.insert(
        serde_yaml::Value::String("capa/subscope-rule".to_string()),
        serde_yaml::Value::Bool(true),
    );
    raw.insert(
        serde_yaml::Value::String("capa/parent".to_string()),
        serde_yaml::Value::String(parent.to_string()),
    );

    Rule {
        name: name.clone(),
        namespace: None,
        meta: RuleMeta {
            name,
            namespace: None,
            authors: Vec::new(),
            description: String::new(),
            lib: true,
            attack: Vec::new(),
            mbc: Vec::new(),
            references: Vec::new(),
            examples: Vec::new(),
            raw,
        },
        scopes,
        body,
        is_lib: true,
        source: String::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn rule(yaml: &str) -> Rule {
        Rule::from_yaml(yaml).unwrap_or_else(|e| panic!("test rule failed to parse: {e}"))
    }

    #[test]
    fn subscope_gets_extracted_into_a_hidden_lib_rule() {
        let r = rule(
            "rule:\n  meta:\n    name: has bb\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - and:\n      - basic block:\n        - api: CreateFileA\n      - api: WriteFile\n",
        );
        let set = MatchingRuleSet::new(vec![r]).expect("valid ruleset");

        let function_rules: Vec<&Rule> = set.rules_for_scope(Scope::Function).collect();
        assert_eq!(function_rules.len(), 1);
        assert_eq!(function_rules[0].name, "has bb");

        let bb_rules: Vec<&Rule> = set.rules_for_scope(Scope::BasicBlock).collect();
        assert_eq!(bb_rules.len(), 1);
        assert!(bb_rules[0].is_subscope_rule());
        assert!(bb_rules[0].is_lib);

        // the parent rule's `and:` now references the synthetic rule by name
        // instead of embedding the subscope directly.
        let Statement::And(children) = &set.get("has bb").unwrap().body.stmt else {
            panic!("expected And")
        };
        assert!(children.iter().any(|c| matches!(
            &c.stmt,
            Statement::Leaf(Feature::MatchedRule(n)) if n == &bb_rules[0].name
        )));
    }

    #[test]
    fn dependency_order_holds_across_scopes() {
        let a = rule(
            "rule:\n  meta:\n    name: a\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - api: CreateFileA\n",
        );
        let b = rule(
            "rule:\n  meta:\n    name: b\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - match: a\n",
        );
        let set = MatchingRuleSet::new(vec![b, a]).expect("valid ruleset");
        let names: Vec<&str> = set
            .rules_for_scope(Scope::Function)
            .map(|r| r.name.as_str())
            .collect();
        let pos_a = names.iter().position(|n| *n == "a").unwrap();
        let pos_b = names.iter().position(|n| *n == "b").unwrap();
        assert!(pos_a < pos_b);
    }

    #[test]
    fn com_feature_is_expanded_before_matching() {
        let r = rule(
            "rule:\n  meta:\n    name: uses com\n    authors: [t]\n    scopes:\n      static: file\n      dynamic: unsupported\n  features:\n    - com/class: ClusAppWiz\n",
        );
        let set = MatchingRuleSet::new(vec![r]).expect("valid ruleset");
        let got = &set.get("uses com").unwrap().body.stmt;
        assert!(matches!(got, Statement::Or(children) if children.len() == 2));
    }

    #[test]
    fn unknown_com_name_fails_ruleset_construction() {
        let r = rule(
            "rule:\n  meta:\n    name: bad com\n    authors: [t]\n    scopes:\n      static: file\n      dynamic: unsupported\n  features:\n    - com/class: ThisDoesNotExist\n",
        );
        assert!(MatchingRuleSet::new(vec![r]).is_err());
    }
}
