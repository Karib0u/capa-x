use std::collections::{BTreeSet, HashMap, HashSet};

use crate::address::Address;
use crate::engine::{self, EngineError, FeatureSet, MatchResults};
use crate::features::{Feature, NumberValue, StringFeature};
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
    indexes: HashMap<Scope, RuleFeatureIndex>,
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

        let indexes = rules_by_scope
            .iter()
            .map(|(&scope, names)| {
                let index = RuleFeatureIndex::new(
                    names.iter().filter_map(|name| by_name.get(name).copied()),
                );
                (scope, index)
            })
            .collect();
        let rules = expanded.into_iter().map(|r| (r.name.clone(), r)).collect();
        Ok(MatchingRuleSet {
            rules,
            rules_by_scope,
            indexes,
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

    /// Feature-indexed equivalent of `capa.engine.match`. Candidates retain
    /// dependency-first order, and new rule/namespace matches activate later
    /// candidates before the next evaluation. Evidence still comes from the
    /// unchanged full evaluator.
    pub fn match_scope(
        &self,
        scope: Scope,
        features: &FeatureSet,
        addr: Address,
    ) -> Result<(FeatureSet, MatchResults), EngineError> {
        let mut features = features.clone();
        let mut results: MatchResults = HashMap::new();

        let Some(index) = self.indexes.get(&scope) else {
            return Ok((features, results));
        };
        let mut candidates = index.candidates(&features);
        while let Some(position) = candidates.pop_first() {
            let Some(rule) = self
                .rules_by_scope
                .get(&scope)
                .and_then(|names| names.get(position))
                .and_then(|name| self.rules.get(name))
            else {
                continue;
            };
            if !engine::evaluate_boolean(&rule.body, &features)? {
                continue;
            }
            // re-evaluate without short-circuiting to collect the full
            // Result tree (matches capa.engine.match's two-pass approach).
            let full = engine::evaluate(&rule.body, &features, false)?;
            debug_assert!(full.success);

            let locations: BTreeSet<Address> = [addr].into_iter().collect();
            let previous_len = features.len();
            engine::index_rule_matches(&mut features, rule, &locations);
            for feature in features.keys().skip(previous_len) {
                if let Some(dependents) = index.exact.get(feature) {
                    candidates.extend(dependents.iter().copied().filter(|&i| i > position));
                }
            }
            results
                .entry(rule.name.clone())
                .or_default()
                .push((addr, full));
        }

        Ok((features, results))
    }
}

/// Conservative positive-feature index, following
/// `capa/rules/__init__.py::RuleSet._index_rules_by_feature`.
/// Each rule is registered under a set of alternatives, at least one of
/// which must be present for the rule to match. Scanning leaves use coarse
/// type buckets; the evaluator checks their actual regex/prefix/OS semantics.
#[derive(Default)]
struct RuleFeatureIndex {
    exact: HashMap<Feature, Vec<usize>>,
    strings: Vec<usize>,
    bytes: Vec<usize>,
    os: Vec<usize>,
    always: Vec<usize>,
}

impl RuleFeatureIndex {
    fn new<'a>(rules: impl Iterator<Item = &'a Rule>) -> Self {
        let mut index = Self::default();
        for (position, rule) in rules.enumerate() {
            let Some((_, alternatives)) = required_features(&rule.body) else {
                index.always.push(position);
                continue;
            };
            for feature in alternatives {
                let bucket = match feature {
                    Feature::String(StringFeature::Substring(_) | StringFeature::Regex(_)) => {
                        &mut index.strings
                    }
                    Feature::Bytes(_) => &mut index.bytes,
                    Feature::Os(_) => &mut index.os,
                    _ => index.exact.entry(feature).or_default(),
                };
                if bucket.last() != Some(&position) {
                    bucket.push(position);
                }
            }
        }
        index
    }

    fn candidates(&self, features: &FeatureSet) -> BTreeSet<usize> {
        let mut candidates: BTreeSet<_> = self.always.iter().copied().collect();
        let (mut strings, mut bytes, mut os) = (false, false, false);
        for feature in features.keys() {
            if let Some(positions) = self.exact.get(feature) {
                candidates.extend(positions);
            }
            match feature {
                Feature::String(_) => strings = true,
                Feature::Bytes(_) => bytes = true,
                Feature::Os(_) => os = true,
                _ => {}
            }
        }
        for (present, positions) in [
            (strings, &self.strings),
            (bytes, &self.bytes),
            (os, &self.os),
        ] {
            if present {
                candidates.extend(positions);
            }
        }
        candidates
    }
}

// CompiledRegex hashes and compares only its immutable source, not its cache.
#[allow(clippy::mutable_key_type)]
fn required_features(node: &Node) -> Option<(u8, HashSet<Feature>)> {
    match &node.stmt {
        // These can succeed without any positive feature. Keep a fallback
        // rather than imposing upstream's indexability assertions on rules.
        Statement::Not(_)
        | Statement::Some { count: 0, .. }
        | Statement::Range { min: 0, .. }
        | Statement::Subscope { .. } => None,
        Statement::Leaf(feature) | Statement::Range { feature, .. } => Some((
            index_score(feature),
            [feature.clone()].into_iter().collect(),
        )),
        Statement::And(children) => children
            .iter()
            .filter_map(required_features)
            .max_by_key(|(score, features)| (*score, std::cmp::Reverse(features.len()))),
        Statement::Or(children) | Statement::Some { children, .. } => {
            let mut alternatives = HashSet::new();
            let mut score = u8::MAX;
            for child in children {
                let (child_score, features) = required_features(child)?;
                score = score.min(child_score);
                alternatives.extend(features);
            }
            Some((score, alternatives))
        }
    }
}

/// Selectivity scores from pinned `capa/rules/__init__.py::_score_feature`.
/// They only choose an AND anchor; they never decide a match. Match references
/// use upstream's default score rather than recursively scoring dependencies.
fn index_score(feature: &Feature) -> u8 {
    match feature {
        Feature::MatchedRule(_) | Feature::String(StringFeature::Plain(_)) => 9,
        Feature::Api(_) => 8,
        Feature::Export(_) => 7,
        Feature::Number(value) | Feature::OperandNumber(_, value) => match value {
            NumberValue::Int(v)
                if (-0x8000..=0x8000).contains(v)
                    || (0xffff_ff00..=0xffff_ffff).contains(v)
                    || (0xffff_ffff_ffff_ff00..=0xffff_ffff_ffff_ffff).contains(v) =>
            {
                3
            }
            _ => 7,
        },
        Feature::Class(_)
        | Feature::Namespace(_)
        | Feature::Property { .. }
        | Feature::Import(_)
        | Feature::Section(_)
        | Feature::FunctionName(_) => 5,
        Feature::Characteristic(_) | Feature::Offset(_) | Feature::OperandOffset(_, _) => 4,
        Feature::Mnemonic(_) => 2,
        Feature::BasicBlock => 1,
        Feature::Os(_)
        | Feature::Arch(_)
        | Feature::Format(_)
        | Feature::Bytes(_)
        | Feature::String(StringFeature::Substring(_) | StringFeature::Regex(_))
        | Feature::Com(_, _) => 0,
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

/// `capa/optimizer.py optimize_statement`: stably sort immediate children
/// by cost, then recurse in upstream traversal order.
fn optimize_node(node: &mut Node) {
    match &mut node.stmt {
        Statement::And(children) | Statement::Or(children) | Statement::Some { children, .. } => {
            children.sort_by_key(node_cost);
            for child in children {
                optimize_node(child);
            }
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

    fn node(stmt: Statement) -> Node {
        Node {
            stmt,
            description: Some("index parity".into()),
        }
    }

    fn named_rule(name: &str, body: Node) -> Rule {
        let mut r = rule(&format!(
            "rule:\n  meta:\n    name: {name}\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - api: seed\n"
        ));
        r.body = body;
        r
    }

    // Keep a separate, exhaustive oracle using the original evidence evaluator.
    fn assert_linear_parity(set: &MatchingRuleSet, input: &FeatureSet) {
        let addr = Address::Absolute(0x1000);
        let mut expected_features = input.clone();
        let mut expected = std::collections::BTreeMap::new();
        for rule in set.rules_for_scope(Scope::Function) {
            if engine::evaluate(&rule.body, &expected_features, true)
                .unwrap()
                .success
            {
                let full = engine::evaluate(&rule.body, &expected_features, false).unwrap();
                engine::index_rule_matches(&mut expected_features, rule, &[addr].into());
                expected.insert(rule.name.clone(), vec![(addr, full)]);
            }
        }
        let (features, results) = set.match_scope(Scope::Function, input, addr).unwrap();
        assert_eq!(format!("{features:?}"), format!("{expected_features:?}"));
        let results: std::collections::BTreeMap<_, _> = results.into_iter().collect();
        assert_eq!(format!("{results:?}"), format!("{expected:?}"));
    }

    #[test]
    fn indexed_matching_preserves_nested_logic_counts_and_scanning_evidence() {
        let regex_rule = rule(
            "rule:\n  meta:\n    name: regex\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - string: /hello.*/\n"
        );
        let Statement::Leaf(regex) = regex_rule.body.stmt else {
            panic!("regex leaf")
        };
        let leaves = vec![
            Feature::Api("seed".into()),
            Feature::String(StringFeature::Plain("hello".into())),
            Feature::String(StringFeature::Substring("ell".into())),
            regex.clone(),
            Feature::Bytes(vec![1, 2]),
            Feature::Os("windows".into()),
            Feature::Os("any".into()),
            Feature::Number(NumberValue::Int(6)),
        ];
        let mut nodes = Vec::new();
        for feature in &leaves {
            let leaf = node(Statement::Leaf(feature.clone()));
            nodes.push(leaf.clone());
            nodes.push(node(Statement::Not(Box::new(leaf.clone()))));
            nodes.push(node(Statement::Not(Box::new(node(Statement::Not(
                Box::new(leaf.clone()),
            ))))));
            for min in 0..=2 {
                nodes.push(node(Statement::Range {
                    feature: feature.clone(),
                    min,
                    max: Some(2),
                }));
            }
            for other in &leaves {
                let children = vec![leaf.clone(), node(Statement::Leaf(other.clone()))];
                nodes.push(node(Statement::And(children.clone())));
                nodes.push(node(Statement::Or(children.clone())));
                for count in 0..=3 {
                    nodes.push(node(Statement::Some {
                        count,
                        children: children.clone(),
                    }));
                }
                let optional = node(Statement::Some {
                    count: 0,
                    children: vec![leaf.clone()],
                });
                nodes.push(node(Statement::Or(vec![
                    optional,
                    node(Statement::Not(Box::new(children[1].clone()))),
                ])));
            }
        }
        nodes.extend([
            node(Statement::And(vec![])),
            node(Statement::Or(vec![])),
            node(Statement::Some {
                count: 0,
                children: vec![],
            }),
            node(Statement::Some {
                count: 1,
                children: vec![],
            }),
        ]);
        let set = MatchingRuleSet::new(
            nodes
                .into_iter()
                .enumerate()
                .map(|(i, body)| named_rule(&format!("rule-{i}"), body))
                .collect(),
        )
        .unwrap();
        let extracted = [
            Feature::Api("seed".into()),
            Feature::String(StringFeature::Plain("hello".into())),
            Feature::String(StringFeature::Substring("hello world".into())),
            regex,
            Feature::Bytes(vec![1, 2, 3]),
            Feature::Os("any".into()),
            Feature::Os("linux".into()),
            Feature::Number(NumberValue::Float(6.0)),
        ];
        for mask in 0..(1 << extracted.len()) {
            let mut input = FeatureSet::new();
            for (i, feature) in extracted.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    input.insert(
                        feature.clone(),
                        [Address::Absolute(1), Address::Absolute(2)].into(),
                    );
                }
            }
            assert_linear_parity(&set, &input);
        }
        // Presence and a positive count differ when a key has no locations.
        let input = leaves
            .into_iter()
            .map(|feature| (feature, BTreeSet::new()))
            .collect();
        assert_linear_parity(&set, &input);
    }

    #[test]
    fn indexed_matches_activate_transitive_and_namespace_dependents() {
        let mut seed = named_rule("z-seed", node(Statement::Leaf(Feature::Api("seed".into()))));
        seed.namespace = Some("network/http".into());
        let namespace = named_rule(
            "b-namespace",
            node(Statement::Leaf(Feature::MatchedRule("network".into()))),
        );
        let dependent = named_rule(
            "a-dependent",
            node(Statement::Leaf(Feature::MatchedRule("b-namespace".into()))),
        );
        let negative = named_rule(
            "negative",
            node(Statement::Not(Box::new(node(Statement::Leaf(
                Feature::MatchedRule("z-seed".into()),
            ))))),
        );
        let absent = named_rule(
            "absent",
            node(Statement::Leaf(Feature::Api("absent".into()))),
        );
        let set = MatchingRuleSet::new(vec![dependent, namespace, negative, seed, absent]).unwrap();
        let input: FeatureSet =
            [(Feature::Api("seed".into()), [Address::Absolute(1)].into())].into();
        assert_linear_parity(&set, &input);
        assert_linear_parity(&set, &FeatureSet::new());
        // Pre-existing match keys must work even though insertion adds no key.
        let mut existing = input.clone();
        existing.insert(Feature::MatchedRule("network".into()), BTreeSet::new());
        existing.insert(Feature::MatchedRule("z-seed".into()), BTreeSet::new());
        assert_linear_parity(&set, &existing);
        let candidates = set
            .indexes
            .get(&Scope::Function)
            .unwrap()
            .candidates(&input);
        assert!(candidates.len() < set.rules_for_scope(Scope::Function).count());
        let (_, results) = set
            .match_scope(Scope::Function, &input, Address::Absolute(1))
            .unwrap();
        assert!(results.contains_key("a-dependent"));
        assert!(!results.contains_key("absent"));
        assert!(!results.contains_key("negative"));
    }

    #[test]
    fn optimizer_recurses_into_and_or_and_some_children() {
        for statement in ["and", "or", "1 or more"] {
            let r = rule(&format!(
                "rule:\n  meta:\n    name: nested\n    authors: [t]\n    scopes:\n      static: file\n      dynamic: unsupported\n  features:\n    - {statement}:\n      - or:\n        - string: /expensive/\n        - os: windows\n      - string: other\n"
            ));
            let set = MatchingRuleSet::new(vec![r]).expect("valid ruleset");
            let root = &set.get("nested").unwrap().body.stmt;
            let children = match root {
                Statement::And(children)
                | Statement::Or(children)
                | Statement::Some { children, .. } => children,
                _ => panic!("expected compound root"),
            };
            let nested = children
                .iter()
                .find_map(|child| match &child.stmt {
                    Statement::Or(children) => Some(children),
                    _ => None,
                })
                .expect("nested or");
            assert!(matches!(&nested[0].stmt, Statement::Leaf(Feature::Os(os)) if os == "windows"));
        }
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
