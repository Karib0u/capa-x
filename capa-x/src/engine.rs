//! Statement evaluation, ported from `capa/engine.py` and the per-feature
//! `evaluate()` overrides in `capa/features/common.py` (String/Substring/
//! Regex/Bytes/OS). Port faithfully -- rendering depends on the shape
//! of the `Result`/`MatchResult` tree, not just the boolean outcome.

use std::collections::{BTreeSet, HashMap};

use indexmap::IndexMap;

use crate::address::Address;
use crate::features::{ComKind, Feature, StringFeature};
use crate::rules::{Node, Rule, Scope, Statement};

/// capa/engine.py: `FeatureSet = dict[Feature, set[Address]]`.
///
/// Must iterate in *insertion* order, matching Python dict semantics: the
/// `Bytes`/`Substring`/`Regex` leaf `evaluate()` overrides below scan this
/// map and short-circuit on the first qualifying entry *in iteration order*
/// (capa/features/common.py). A plain `HashMap` has unspecified iteration
/// order, so it could pick a different "first match" (same success/failure,
/// but potentially different `locations`) than Python. `IndexMap` preserves
/// first-insertion order across repeated `.entry().or_default()` updates,
/// same as a Python dict.
pub type FeatureSet = IndexMap<Feature, BTreeSet<Address>>;

/// insert `addr` into `fs[feature]`, creating the entry (at the end of
/// iteration order) if this is the first time `feature` is seen. Mirrors
/// `features[feature].add(addr)` / `FeatureSet: collections.defaultdict(set)`.
pub fn insert(fs: &mut FeatureSet, feature: Feature, addr: Address) {
    fs.entry(feature).or_default().insert(addr);
}

/// mirrors `features[feature].update(locations)`.
pub fn insert_many(
    fs: &mut FeatureSet,
    feature: Feature,
    locations: impl IntoIterator<Item = Address>,
) {
    fs.entry(feature).or_default().extend(locations);
}

/// merge `other`'s entries into `fs`, preserving `fs`'s existing insertion
/// positions and appending any new keys from `other` at the end -- mirrors
/// how `capabilities/*.py` merges a child scope's `FeatureSet` into its
/// parent's (e.g. `for feature, vas in child.features.items(): parent[feature].update(vas)`).
pub fn merge(fs: &mut FeatureSet, other: &FeatureSet) {
    for (feature, locs) in other {
        fs.entry(feature.clone())
            .or_default()
            .extend(locs.iter().copied());
    }
}

/// capa/engine.py: `MatchResults = Mapping[str, list[tuple[Address, Result]]]`.
pub type MatchResults = HashMap<String, Vec<(Address, MatchResult)>>;

/// port of `get_rule_namespaces`: yields `namespace` and each of its
/// ancestor prefixes, e.g. `"a/b/c"` -> `"a/b/c"`, `"a/b"`, `"a"`.
pub fn rule_namespaces(namespace: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(namespace), |ns| ns.rfind('/').map(|i| &ns[..i]))
}

/// port of `index_rule_matches`: record that `rule` matched at `locations`,
/// both under its own name and every ancestor namespace prefix, so that
/// enclosing/dependent rules can reference it via `match: <rule-or-namespace>`.
pub fn index_rule_matches(fs: &mut FeatureSet, rule: &Rule, locations: &BTreeSet<Address>) {
    insert_many(
        fs,
        Feature::MatchedRule(rule.name.clone()),
        locations.iter().copied(),
    );
    if let Some(namespace) = &rule.namespace {
        for prefix in rule_namespaces(namespace) {
            insert_many(
                fs,
                Feature::MatchedRule(prefix.to_string()),
                locations.iter().copied(),
            );
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// capa/engine.py: `Subscope.evaluate` raises `ValueError("cannot
    /// evaluate a subscope directly!")`. Reachable only if a rule tree is
    /// evaluated before subscope extraction (a driver bug, not malformed
    /// user input), but per this project's "no panics" rule this is a clean
    /// error rather than a panic.
    #[error("cannot evaluate a `{}` subscope directly -- subscopes must be extracted into their own rule before matching", .0.as_str())]
    UnextractedSubscope(Scope),
    /// capa/rules/__init__.py: `translate_com_feature` expands `com/class`/
    /// `com/interface` leaves into an `Or` of GUID string/bytes checks at
    /// RuleSet-build time; a raw `Com` leaf reaching `evaluate()` means that
    /// expansion was skipped.
    #[error("cannot evaluate a `com/{0:?}` feature directly -- COM features must be expanded before matching")]
    UnexpandedCom(ComKind),
}

/// mirrors `capa.engine.Statement`/`Feature` as the thing a `Result` node
/// refers to: either a structural statement kind, or the matched feature
/// leaf. `Range` and `Leaf` carry their `Feature` since (unlike And/Or/Not/
/// Some) there's no child `Node` to look back at for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchedNode {
    And,
    Or,
    Not,
    Some {
        count: u32,
    },
    Range {
        feature: Feature,
        min: u32,
        max: Option<u32>,
    },
    Leaf(Feature),
}

/// mirrors `capa.features.common.Result`.
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub success: bool,
    pub node: MatchedNode,
    pub description: Option<String>,
    /// capa/engine.py: only `Leaf` (via `Feature.evaluate`) and `Range`
    /// populate this; structural statements (And/Or/Not/Some) always
    /// construct their `Result` without a `locations=` kwarg, so it's the
    /// empty set even on success -- match locations live on the leaves.
    pub locations: BTreeSet<Address>,
    pub children: Vec<MatchResult>,
    /// capa/features/common.py: `_MatchedSubstring`/`_MatchedRegex.matches`
    /// -- populated only for a `Substring`/`Regex` leaf, mapping each
    /// distinct *matched string value* (not the query) to the locations of
    /// the `String` feature(s) that carried it. Every other node kind
    /// (structural statements, exact-match leaves, `Range`) leaves this
    /// empty, matching upstream's `Match.captures` (`capa/render/
    /// result_document.py`), which is only ever non-empty for those two
    /// statement types. Rendering (vverbose's per-capture location list)
    /// and the result-document schema both need this.
    pub captures: std::collections::BTreeMap<String, BTreeSet<Address>>,
}

impl MatchResult {
    /// mirrors `bool(result)` (`Result.__bool__`).
    pub fn is_match(&self) -> bool {
        self.success
    }
}

fn leaf(
    node: MatchedNode,
    success: bool,
    description: Option<String>,
    locations: BTreeSet<Address>,
) -> MatchResult {
    MatchResult {
        success,
        node,
        description,
        locations,
        children: Vec::new(),
        captures: std::collections::BTreeMap::new(),
    }
}

/// port of `Statement.evaluate` (And/Or/Not/Some/Range/Subscope) and
/// `Feature.evaluate` (the base exact-match impl, plus the String/Substring/
/// Regex/Bytes/OS overrides), dispatched over our unified `Node`/`Statement`/
/// `Feature` types.
pub fn evaluate(
    node: &Node,
    fs: &FeatureSet,
    short_circuit: bool,
) -> Result<MatchResult, EngineError> {
    let description = node.description.clone();
    match &node.stmt {
        Statement::And(children) => eval_and(children, fs, short_circuit, description),
        Statement::Or(children) => eval_or(children, fs, short_circuit, description),
        Statement::Not(child) => eval_not(child, fs, short_circuit, description),
        Statement::Some { count, children } => {
            eval_some(*count, children, fs, short_circuit, description)
        }
        Statement::Range { feature, min, max } => {
            Ok(eval_range(feature, *min, *max, fs, description))
        }
        Statement::Subscope { scope, .. } => Err(EngineError::UnextractedSubscope(*scope)),
        Statement::Leaf(feature) => eval_leaf(feature, fs, short_circuit, description),
    }
}

fn eval_and(
    children: &[Node],
    fs: &FeatureSet,
    short_circuit: bool,
    description: Option<String>,
) -> Result<MatchResult, EngineError> {
    if short_circuit {
        let mut results = Vec::with_capacity(children.len());
        for c in children {
            let r = evaluate(c, fs, short_circuit)?;
            let ok = r.success;
            results.push(r);
            if !ok {
                return Ok(MatchResult {
                    success: false,
                    node: MatchedNode::And,
                    description,
                    locations: BTreeSet::new(),
                    children: results,
                    captures: std::collections::BTreeMap::new(),
                });
            }
        }
        Ok(MatchResult {
            success: true,
            node: MatchedNode::And,
            description,
            locations: BTreeSet::new(),
            children: results,
            captures: std::collections::BTreeMap::new(),
        })
    } else {
        let results = eval_all(children, fs, short_circuit)?;
        let success = results.iter().all(|r| r.success);
        Ok(MatchResult {
            success,
            node: MatchedNode::And,
            description,
            locations: BTreeSet::new(),
            children: results,
            captures: std::collections::BTreeMap::new(),
        })
    }
}

fn eval_or(
    children: &[Node],
    fs: &FeatureSet,
    short_circuit: bool,
    description: Option<String>,
) -> Result<MatchResult, EngineError> {
    if short_circuit {
        let mut results = Vec::with_capacity(children.len());
        for c in children {
            let r = evaluate(c, fs, short_circuit)?;
            let ok = r.success;
            results.push(r);
            if ok {
                return Ok(MatchResult {
                    success: true,
                    node: MatchedNode::Or,
                    description,
                    locations: BTreeSet::new(),
                    children: results,
                    captures: std::collections::BTreeMap::new(),
                });
            }
        }
        Ok(MatchResult {
            success: false,
            node: MatchedNode::Or,
            description,
            locations: BTreeSet::new(),
            children: results,
            captures: std::collections::BTreeMap::new(),
        })
    } else {
        let results = eval_all(children, fs, short_circuit)?;
        let success = results.iter().any(|r| r.success);
        Ok(MatchResult {
            success,
            node: MatchedNode::Or,
            description,
            locations: BTreeSet::new(),
            children: results,
            captures: std::collections::BTreeMap::new(),
        })
    }
}

fn eval_not(
    child: &Node,
    fs: &FeatureSet,
    short_circuit: bool,
    description: Option<String>,
) -> Result<MatchResult, EngineError> {
    let r = evaluate(child, fs, short_circuit)?;
    let success = !r.success;
    Ok(MatchResult {
        success,
        node: MatchedNode::Not,
        description,
        locations: BTreeSet::new(),
        children: vec![r],
        captures: std::collections::BTreeMap::new(),
    })
}

fn eval_some(
    count: u32,
    children: &[Node],
    fs: &FeatureSet,
    short_circuit: bool,
    description: Option<String>,
) -> Result<MatchResult, EngineError> {
    if short_circuit {
        let mut results = Vec::with_capacity(children.len());
        let mut satisfied = 0u32;
        for c in children {
            let r = evaluate(c, fs, short_circuit)?;
            if r.success {
                satisfied += 1;
            }
            results.push(r);
            if satisfied >= count {
                return Ok(MatchResult {
                    success: true,
                    node: MatchedNode::Some { count },
                    description,
                    locations: BTreeSet::new(),
                    children: results,
                    captures: std::collections::BTreeMap::new(),
                });
            }
        }
        Ok(MatchResult {
            success: false,
            node: MatchedNode::Some { count },
            description,
            locations: BTreeSet::new(),
            children: results,
            captures: std::collections::BTreeMap::new(),
        })
    } else {
        let results = eval_all(children, fs, short_circuit)?;
        let satisfied = results.iter().filter(|r| r.success).count() as u32;
        Ok(MatchResult {
            success: satisfied >= count,
            node: MatchedNode::Some { count },
            description,
            locations: BTreeSet::new(),
            children: results,
            captures: std::collections::BTreeMap::new(),
        })
    }
}

fn eval_all(
    children: &[Node],
    fs: &FeatureSet,
    short_circuit: bool,
) -> Result<Vec<MatchResult>, EngineError> {
    children
        .iter()
        .map(|c| evaluate(c, fs, short_circuit))
        .collect()
}

/// port of `Range.evaluate`. `max: None` means unbounded (Python defaults it
/// to `(1<<64)-1`; a location count can never approach `u32::MAX`, so we
/// just skip the upper-bound check instead of materializing that constant).
fn eval_range(
    feature: &Feature,
    min: u32,
    max: Option<u32>,
    fs: &FeatureSet,
    description: Option<String>,
) -> MatchResult {
    let matched = fs.get(feature);
    let count = matched.map_or(0, |s| s.len() as u32);

    if min == 0 && count == 0 {
        return leaf(
            MatchedNode::Range {
                feature: feature.clone(),
                min,
                max,
            },
            true,
            description,
            BTreeSet::new(),
        );
    }

    let success = count >= min && max.is_none_or(|mx| count <= mx);
    let locations = matched.cloned().unwrap_or_default();
    leaf(
        MatchedNode::Range {
            feature: feature.clone(),
            min,
            max,
        },
        success,
        description,
        locations,
    )
}

fn eval_leaf(
    feature: &Feature,
    fs: &FeatureSet,
    short_circuit: bool,
    description: Option<String>,
) -> Result<MatchResult, EngineError> {
    match feature {
        Feature::String(StringFeature::Substring(needle)) => Ok(eval_string_scan(
            feature,
            needle,
            StringMatch::Substring,
            fs,
            short_circuit,
            description,
        )),
        Feature::String(StringFeature::Regex(re)) => Ok(eval_string_scan(
            feature,
            re.raw.as_str(),
            StringMatch::Regex(re),
            fs,
            short_circuit,
            description,
        )),
        Feature::Bytes(needle) => Ok(eval_bytes(feature, needle, fs, description)),
        Feature::Os(query) => Ok(eval_os(feature, query, fs, description)),
        Feature::Com(kind, _) => Err(EngineError::UnexpandedCom(*kind)),
        _ => Ok(eval_exact(feature, fs, description)),
    }
}

/// port of the base `Feature.evaluate`: exact hash lookup. Covers every leaf
/// kind without a bespoke `evaluate()` override in `features/common.py`:
/// plain `String`, `Number`, `Offset`, `Mnemonic`, `Api`, `Export`, `Import`,
/// `Section`, `FunctionName`, `Class`, `Namespace`, `Property`, `Arch`,
/// `Format`, `MatchedRule`, `Characteristic`, `BasicBlock`, `OperandNumber`,
/// `OperandOffset`.
fn eval_exact(feature: &Feature, fs: &FeatureSet, description: Option<String>) -> MatchResult {
    match fs.get(feature) {
        Some(locations) => leaf(
            MatchedNode::Leaf(feature.clone()),
            true,
            description,
            locations.clone(),
        ),
        None => leaf(
            MatchedNode::Leaf(feature.clone()),
            false,
            description,
            BTreeSet::new(),
        ),
    }
}

enum StringMatch<'a> {
    Substring,
    Regex(&'a crate::features::CompiledRegex),
}

impl StringMatch<'_> {
    fn matches(&self, needle: &str, haystack: &str) -> bool {
        match self {
            StringMatch::Substring => haystack.contains(needle),
            StringMatch::Regex(re) => re.is_match(haystack),
        }
    }
}

/// port of `Substring.evaluate` / `Regex.evaluate`: scan every `String`-family
/// feature actually present in the set (plain `String`, and -- matching
/// Python's `isinstance(feature, (String,))`, which a `Substring`/`Regex`
/// instance also satisfies -- any `Substring`/`Regex` feature that somehow
/// ended up as *data* rather than a rule query) for a match, short-circuiting
/// on the first hit when `short_circuit` is set.
fn eval_string_scan(
    query: &Feature,
    needle: &str,
    matcher: StringMatch,
    fs: &FeatureSet,
    short_circuit: bool,
    description: Option<String>,
) -> MatchResult {
    let mut any = false;
    let mut locations = BTreeSet::new();
    let mut captures: std::collections::BTreeMap<String, BTreeSet<Address>> =
        std::collections::BTreeMap::new();
    for (feature, locs) in fs {
        let Feature::String(sf) = feature else {
            continue;
        };
        let haystack = match sf {
            StringFeature::Plain(s) | StringFeature::Substring(s) => s.as_str(),
            StringFeature::Regex(re) => re.raw.as_str(),
        };
        if matcher.matches(needle, haystack) {
            any = true;
            locations.extend(locs.iter().copied());
            captures
                .entry(haystack.to_string())
                .or_default()
                .extend(locs.iter().copied());
            if short_circuit {
                break;
            }
        }
    }
    MatchResult {
        success: any,
        node: MatchedNode::Leaf(query.clone()),
        description,
        locations,
        children: Vec::new(),
        captures,
    }
}

/// port of `Bytes.evaluate`: returns the *first* (in iteration order) `Bytes`
/// feature whose value starts with the query bytes -- note this ignores
/// `short_circuit` entirely, exactly like upstream (it always returns on the
/// first hit, never aggregates locations across multiple matching entries).
fn eval_bytes(
    query: &Feature,
    needle: &[u8],
    fs: &FeatureSet,
    description: Option<String>,
) -> MatchResult {
    for (feature, locs) in fs {
        if let Feature::Bytes(v) = feature {
            if v.starts_with(needle) {
                return leaf(
                    MatchedNode::Leaf(query.clone()),
                    true,
                    description,
                    locs.clone(),
                );
            }
        }
    }
    leaf(
        MatchedNode::Leaf(query.clone()),
        false,
        description,
        BTreeSet::new(),
    )
}

/// port of `OS.evaluate`: like `Bytes`, returns on the first hit regardless
/// of `short_circuit`, with `"any"` matching either side.
fn eval_os(
    query_feature: &Feature,
    query: &str,
    fs: &FeatureSet,
    description: Option<String>,
) -> MatchResult {
    for (feature, locs) in fs {
        if let Feature::Os(v) = feature {
            if query == "any" || v == "any" || query == v {
                return leaf(
                    MatchedNode::Leaf(query_feature.clone()),
                    true,
                    description,
                    locs.clone(),
                );
            }
        }
    }
    leaf(
        MatchedNode::Leaf(query_feature.clone()),
        false,
        description,
        BTreeSet::new(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::features::NumberValue;

    const ADDR1: Address = Address::Absolute(0x401001);
    const ADDR2: Address = Address::Absolute(0x401002);
    const ADDR3: Address = Address::Absolute(0x401003);
    const ADDR4: Address = Address::Absolute(0x401004);

    fn num(n: i128) -> Feature {
        Feature::Number(NumberValue::Int(n))
    }

    fn leaf_node(f: Feature) -> Node {
        Node {
            stmt: Statement::Leaf(f),
            description: None,
        }
    }

    fn and(children: Vec<Node>) -> Node {
        Node {
            stmt: Statement::And(children),
            description: None,
        }
    }
    fn or(children: Vec<Node>) -> Node {
        Node {
            stmt: Statement::Or(children),
            description: None,
        }
    }
    fn not(child: Node) -> Node {
        Node {
            stmt: Statement::Not(Box::new(child)),
            description: None,
        }
    }
    fn some(count: u32, children: Vec<Node>) -> Node {
        Node {
            stmt: Statement::Some { count, children },
            description: None,
        }
    }
    fn range(feature: Feature, min: u32, max: Option<u32>) -> Node {
        Node {
            stmt: Statement::Range { feature, min, max },
            description: None,
        }
    }

    fn fs(entries: Vec<(Feature, Vec<Address>)>) -> FeatureSet {
        let mut m = FeatureSet::new();
        for (f, locs) in entries {
            m.insert(f, locs.into_iter().collect());
        }
        m
    }

    fn ev(node: &Node, fs: &FeatureSet) -> bool {
        evaluate(node, fs, true).expect("no engine error").success
    }

    // --- ported 1:1 from tests/test_engine.py ---

    #[test]
    fn test_number() {
        assert!(!ev(&leaf_node(num(1)), &fs(vec![(num(0), vec![ADDR1])])));
        assert!(ev(&leaf_node(num(1)), &fs(vec![(num(1), vec![ADDR1])])));
        assert!(!ev(
            &leaf_node(num(1)),
            &fs(vec![(num(2), vec![ADDR1, ADDR2])])
        ));
    }

    #[test]
    fn test_and() {
        assert!(!ev(
            &and(vec![leaf_node(num(1))]),
            &fs(vec![(num(0), vec![ADDR1])])
        ));
        assert!(ev(
            &and(vec![leaf_node(num(1))]),
            &fs(vec![(num(1), vec![ADDR1])])
        ));
        assert!(!ev(
            &and(vec![leaf_node(num(1)), leaf_node(num(2))]),
            &fs(vec![(num(0), vec![ADDR1])])
        ));
        assert!(!ev(
            &and(vec![leaf_node(num(1)), leaf_node(num(2))]),
            &fs(vec![(num(1), vec![ADDR1])])
        ));
        assert!(!ev(
            &and(vec![leaf_node(num(1)), leaf_node(num(2))]),
            &fs(vec![(num(2), vec![ADDR1])])
        ));
        assert!(ev(
            &and(vec![leaf_node(num(1)), leaf_node(num(2))]),
            &fs(vec![(num(1), vec![ADDR1]), (num(2), vec![ADDR2])])
        ));
    }

    #[test]
    fn test_or() {
        assert!(!ev(
            &or(vec![leaf_node(num(1))]),
            &fs(vec![(num(0), vec![ADDR1])])
        ));
        assert!(ev(
            &or(vec![leaf_node(num(1))]),
            &fs(vec![(num(1), vec![ADDR1])])
        ));
        assert!(!ev(
            &or(vec![leaf_node(num(1)), leaf_node(num(2))]),
            &fs(vec![(num(0), vec![ADDR1])])
        ));
        assert!(ev(
            &or(vec![leaf_node(num(1)), leaf_node(num(2))]),
            &fs(vec![(num(1), vec![ADDR1])])
        ));
        assert!(ev(
            &or(vec![leaf_node(num(1)), leaf_node(num(2))]),
            &fs(vec![(num(2), vec![ADDR1])])
        ));
    }

    #[test]
    fn test_not() {
        assert!(ev(
            &not(leaf_node(num(1))),
            &fs(vec![(num(0), vec![ADDR1])])
        ));
        assert!(!ev(
            &not(leaf_node(num(1))),
            &fs(vec![(num(1), vec![ADDR1])])
        ));
    }

    #[test]
    fn test_some() {
        assert!(ev(
            &some(0, vec![leaf_node(num(1))]),
            &fs(vec![(num(0), vec![ADDR1])])
        ));
        assert!(!ev(
            &some(1, vec![leaf_node(num(1))]),
            &fs(vec![(num(0), vec![ADDR1])])
        ));

        let children = vec![leaf_node(num(1)), leaf_node(num(2)), leaf_node(num(3))];
        assert!(!ev(
            &some(2, children.clone()),
            &fs(vec![(num(0), vec![ADDR1])])
        ));
        assert!(!ev(
            &some(2, children.clone()),
            &fs(vec![(num(0), vec![ADDR1]), (num(1), vec![ADDR1])])
        ));
        assert!(ev(
            &some(2, children.clone()),
            &fs(vec![
                (num(0), vec![ADDR1]),
                (num(1), vec![ADDR1]),
                (num(2), vec![ADDR1])
            ])
        ));
        assert!(ev(
            &some(2, children),
            &fs(vec![
                (num(0), vec![ADDR1]),
                (num(1), vec![ADDR1]),
                (num(2), vec![ADDR1]),
                (num(3), vec![ADDR1]),
            ])
        ));
    }

    #[test]
    fn test_complex() {
        let features = fs(vec![
            (num(5), vec![ADDR1]),
            (num(6), vec![ADDR1]),
            (num(7), vec![ADDR1]),
            (num(8), vec![ADDR1]),
        ]);
        assert!(ev(
            &or(vec![
                and(vec![leaf_node(num(1)), leaf_node(num(2))]),
                or(vec![
                    leaf_node(num(3)),
                    some(
                        2,
                        vec![leaf_node(num(4)), leaf_node(num(5)), leaf_node(num(6))]
                    )
                ]),
            ]),
            &features
        ));
        assert!(!ev(
            &or(vec![
                and(vec![leaf_node(num(1)), leaf_node(num(2))]),
                or(vec![
                    leaf_node(num(3)),
                    some(2, vec![leaf_node(num(4)), leaf_node(num(5))])
                ]),
            ]),
            &features
        ));
    }

    #[test]
    fn test_range() {
        // unbounded range, no matching feature: min=0 and count=0 -> ok
        assert!(ev(&range(num(1), 0, None), &fs(vec![(num(2), vec![])])));
        // unbounded range with a matching feature always matches
        assert!(ev(&range(num(1), 0, None), &fs(vec![(num(1), vec![])])));
        assert!(ev(
            &range(num(1), 0, None),
            &fs(vec![(num(1), vec![ADDR1])])
        ));

        // unbounded max
        assert!(ev(
            &range(num(1), 1, None),
            &fs(vec![(num(1), vec![ADDR1])])
        ));
        assert!(!ev(
            &range(num(1), 2, None),
            &fs(vec![(num(1), vec![ADDR1])])
        ));
        assert!(ev(
            &range(num(1), 2, None),
            &fs(vec![(num(1), vec![ADDR1, ADDR2])])
        ));

        // unbounded min
        assert!(!ev(
            &range(num(1), 0, Some(0)),
            &fs(vec![(num(1), vec![ADDR1])])
        ));
        assert!(ev(
            &range(num(1), 0, Some(1)),
            &fs(vec![(num(1), vec![ADDR1])])
        ));
        assert!(ev(
            &range(num(1), 0, Some(2)),
            &fs(vec![(num(1), vec![ADDR1])])
        ));
        assert!(ev(
            &range(num(1), 0, Some(2)),
            &fs(vec![(num(1), vec![ADDR1, ADDR2])])
        ));
        assert!(!ev(
            &range(num(1), 0, Some(2)),
            &fs(vec![(num(1), vec![ADDR1, ADDR2, ADDR3])])
        ));

        // exact match via min==max
        assert!(!ev(&range(num(1), 1, Some(1)), &fs(vec![(num(1), vec![])])));
        assert!(ev(
            &range(num(1), 1, Some(1)),
            &fs(vec![(num(1), vec![ADDR1])])
        ));
        assert!(!ev(
            &range(num(1), 1, Some(1)),
            &fs(vec![(num(1), vec![ADDR1, ADDR2])])
        ));

        // bounded range
        assert!(!ev(&range(num(1), 1, Some(3)), &fs(vec![(num(1), vec![])])));
        assert!(ev(
            &range(num(1), 1, Some(3)),
            &fs(vec![(num(1), vec![ADDR1])])
        ));
        assert!(ev(
            &range(num(1), 1, Some(3)),
            &fs(vec![(num(1), vec![ADDR1, ADDR2])])
        ));
        assert!(ev(
            &range(num(1), 1, Some(3)),
            &fs(vec![(num(1), vec![ADDR1, ADDR2, ADDR3])])
        ));
        assert!(!ev(
            &range(num(1), 1, Some(3)),
            &fs(vec![(num(1), vec![ADDR1, ADDR2, ADDR3, ADDR4])])
        ));
    }

    #[test]
    fn test_short_circuit() {
        let features = fs(vec![(num(1), vec![ADDR1])]);
        let node = or(vec![leaf_node(num(1)), leaf_node(num(2))]);
        assert!(ev(&node, &features));

        assert_eq!(evaluate(&node, &features, true).unwrap().children.len(), 1);
        assert_eq!(evaluate(&node, &features, false).unwrap().children.len(), 2);
    }

    #[test]
    fn test_eval_order() {
        let node = or(vec![leaf_node(num(1)), leaf_node(num(2))]);

        assert!(ev(&node, &fs(vec![(num(1), vec![ADDR1])])));
        assert!(ev(&node, &fs(vec![(num(2), vec![ADDR1])])));

        assert_eq!(
            evaluate(&node, &fs(vec![(num(1), vec![ADDR1])]), true)
                .unwrap()
                .children
                .len(),
            1
        );
        assert_eq!(
            evaluate(&node, &fs(vec![(num(2), vec![ADDR1])]), true)
                .unwrap()
                .children
                .len(),
            2
        );
        assert_eq!(
            evaluate(
                &node,
                &fs(vec![(num(1), vec![ADDR1]), (num(2), vec![ADDR1])]),
                true
            )
            .unwrap()
            .children
            .len(),
            1
        );

        let r1 = evaluate(&node, &fs(vec![(num(1), vec![ADDR1])]), true).unwrap();
        assert_eq!(r1.children[0].node, MatchedNode::Leaf(num(1)));
        assert_ne!(r1.children[0].node, MatchedNode::Leaf(num(2)));

        let r2 = evaluate(&node, &fs(vec![(num(2), vec![ADDR1])]), true).unwrap();
        assert_eq!(r2.children[1].node, MatchedNode::Leaf(num(2)));
        assert_ne!(r2.children[1].node, MatchedNode::Leaf(num(1)));
    }

    // --- leaf-evaluate semantics ported from tests/test_match.py / features/common.py ---

    #[test]
    fn plain_string_is_exact_match_only() {
        let query = leaf_node(Feature::String(StringFeature::Plain("foo".into())));
        let features = fs(vec![(
            Feature::String(StringFeature::Plain("foobar".into())),
            vec![ADDR1],
        )]);
        // "foo" != "foobar": exact-match semantics, no substring search.
        assert!(!ev(&query, &features));
    }

    #[test]
    fn substring_scans_string_features() {
        let query = leaf_node(Feature::String(StringFeature::Substring("bar".into())));
        let features = fs(vec![(
            Feature::String(StringFeature::Plain("foobarbaz".into())),
            vec![ADDR1],
        )]);
        let r = evaluate(&query, &features, true).unwrap();
        assert!(r.success);
        assert_eq!(r.locations, [ADDR1].into_iter().collect());
    }

    #[test]
    fn substring_captures_group_locations_by_matched_string_value() {
        // mirrors `_MatchedSubstring.matches`: keyed by the *full* string
        // value that contained the substring, not the query itself, so two
        // different literal strings that both match end up as two entries.
        let query = leaf_node(Feature::String(StringFeature::Substring("bar".into())));
        let features = fs(vec![
            (
                Feature::String(StringFeature::Plain("foobarbaz".into())),
                vec![ADDR1],
            ),
            (
                Feature::String(StringFeature::Plain("barbar".into())),
                vec![ADDR2],
            ),
        ]);
        let r = evaluate(&query, &features, false).unwrap();
        assert!(r.success);
        assert_eq!(r.captures.len(), 2);
        assert_eq!(
            r.captures.get("foobarbaz"),
            Some(&[ADDR1].into_iter().collect())
        );
        assert_eq!(
            r.captures.get("barbar"),
            Some(&[ADDR2].into_iter().collect())
        );

        let no_match = leaf_node(Feature::String(StringFeature::Substring("zzz".into())));
        let empty = evaluate(&no_match, &features, false).unwrap();
        assert!(!empty.success);
        assert!(empty.captures.is_empty());
    }

    #[test]
    fn substring_short_circuit_returns_only_first_match_locations() {
        let query = leaf_node(Feature::String(StringFeature::Substring("bar".into())));
        let features = fs(vec![
            (
                Feature::String(StringFeature::Plain("barA".into())),
                vec![ADDR1],
            ),
            (
                Feature::String(StringFeature::Plain("barB".into())),
                vec![ADDR2],
            ),
        ]);
        let short = evaluate(&query, &features, true).unwrap();
        assert_eq!(short.locations, [ADDR1].into_iter().collect());

        let full = evaluate(&query, &features, false).unwrap();
        assert_eq!(full.locations, [ADDR1, ADDR2].into_iter().collect());
    }

    #[test]
    fn regex_case_insensitive() {
        let re = crate::features::CompiledRegex::compile("/^foo.*bar$/i").unwrap();
        let query = leaf_node(Feature::String(StringFeature::Regex(re)));
        let features = fs(vec![(
            Feature::String(StringFeature::Plain("FOO 123 BAR".into())),
            vec![ADDR1],
        )]);
        assert!(ev(&query, &features));
    }

    #[test]
    fn bytes_prefix_match_ignores_short_circuit_flag() {
        let query = leaf_node(Feature::Bytes(vec![0x01, 0x02]));
        let features = fs(vec![(Feature::Bytes(vec![0x01, 0x02, 0x03]), vec![ADDR1])]);
        assert!(ev(&query, &features));
        assert!(evaluate(&query, &features, false).unwrap().success);
    }

    #[test]
    fn os_any_matches_either_side() {
        let features = fs(vec![(Feature::Os("any".into()), vec![ADDR1])]);
        assert!(ev(&leaf_node(Feature::Os("windows".into())), &features));

        let features2 = fs(vec![(Feature::Os("windows".into()), vec![ADDR1])]);
        assert!(ev(&leaf_node(Feature::Os("any".into())), &features2));
        assert!(!ev(&leaf_node(Feature::Os("linux".into())), &features2));
    }

    #[test]
    fn unextracted_subscope_is_a_clean_error_not_a_panic() {
        let node = Node {
            stmt: Statement::Subscope {
                scope: Scope::BasicBlock,
                body: Box::new(leaf_node(num(1))),
            },
            description: None,
        };
        assert!(matches!(
            evaluate(&node, &FeatureSet::new(), true),
            Err(EngineError::UnextractedSubscope(Scope::BasicBlock))
        ));
    }

    #[test]
    fn whole_valued_float_number_matches_int_query() {
        // .NET floating-point immediates extract as `Number(f64)`; a rule's
        // integer literal must still match (see NumberValue's doc comment).
        let query = leaf_node(num(6));
        let features = fs(vec![(
            Feature::Number(NumberValue::Float(6.0)),
            vec![ADDR1],
        )]);
        assert!(ev(&query, &features));
    }
}
