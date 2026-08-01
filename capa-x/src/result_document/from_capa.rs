//! Builds a [`super::ResultDocument`] from the matching engine's output. Ported
//! from `capa/render/result_document.py` (`Match.from_capa`,
//! `RuleMetadata.from_capa`, `ResultDocument.from_capa`,
//! `AttackSpec`/`MBCSpec.from_str`) and `capa/loader.py`
//! (`collect_metadata`, `compute_static_layout`, `compute_dynamic_layout`).
//!
//! Result building is freeze-driven, so
//! wherever upstream calls into a `FeatureExtractor`
//! (`get_functions`/`get_processes`/etc.), this reads directly from the
//! already-parsed `freeze::StaticFeatures`/`DynamicFeatures` tree instead --
//! same data, no extractor abstraction needed.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::address::Address;
use crate::capabilities::MatchingRuleSet;
use crate::engine::{self, MatchResults};
use crate::features::Feature;
use crate::freeze::{DynamicFeatures, StaticFeatures};
use crate::rules::{Rule, Scope};

use super::address::RdAddress;
use super::feature::RdFeature;
use super::meta::{BasicBlockLayout, CallLayout, FunctionFeatureCount, FunctionLayout};
use super::meta::{
    DynamicAnalysis, DynamicFeatureCounts, DynamicLayout, LibraryFunction, Metadata,
    ProcessFeatureCount, ProcessLayout, Sample, StaticAnalysis, StaticFeatureCounts, StaticLayout,
    ThreadLayout,
};
use super::tree::{
    AttackSpec, MBCSpec, MaecMetadata, Match, Node, RdScopes, ResultDocument, RuleMatches,
    RuleMetadata, Statement,
};

#[derive(Debug, thiserror::Error)]
pub enum FromCapaError {
    #[error("rendering feature: {0}")]
    Feature(String),
    #[error("match tree inconsistency: rule {rule:?} has no recorded match at {addr}")]
    MissingRuleMatch { rule: String, addr: String },
    #[error("subscope rule {0:?} has neither a static nor a dynamic scope")]
    SubscopeRuleMissingScope(String),
}

/// per-function/per-process feature counts, computed by the matching
/// drivers (`capabilities::static_`/`dynamic`) alongside their matches --
/// see those modules' `find_static_capabilities`/`find_dynamic_capabilities`.
#[derive(Debug, Clone, Default)]
pub struct StaticCounts {
    pub file_feature_count: u64,
    pub function_feature_counts: Vec<(Address, u64)>,
}

#[derive(Debug, Clone, Default)]
pub struct DynamicCounts {
    pub file_feature_count: u64,
    pub process_feature_counts: Vec<(Address, u64)>,
}

fn yaml_str(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    match map.get(serde_yaml::Value::String(key.to_string())) {
        Some(serde_yaml::Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn yaml_bool(map: &serde_yaml::Mapping, key: &str) -> bool {
    matches!(
        map.get(serde_yaml::Value::String(key.to_string())),
        Some(serde_yaml::Value::Bool(true))
    )
}

/// port of `RuleMetadata.from_capa`.
pub fn rule_metadata(rule: &Rule) -> RuleMetadata {
    let raw = &rule.meta.raw;
    RuleMetadata {
        name: rule.name.clone(),
        namespace: rule.namespace.clone(),
        authors: rule.meta.authors.clone(),
        scopes: RdScopes {
            static_: rule.scopes.static_.map(|s| s.as_str().to_string()),
            dynamic: rule.scopes.dynamic.map(|s| s.as_str().to_string()),
        },
        attack: rule
            .meta
            .attack
            .iter()
            .map(|s| AttackSpec::from_str(s))
            .collect(),
        mbc: rule.meta.mbc.iter().map(|s| MBCSpec::from_str(s)).collect(),
        references: rule.meta.references.clone(),
        examples: rule.meta.examples.clone(),
        description: rule.meta.description.clone(),
        lib: rule.meta.lib,
        is_subscope_rule: yaml_bool(raw, "capa/subscope"),
        maec: MaecMetadata {
            analysis_conclusion: yaml_str(raw, "maec/analysis-conclusion"),
            analysis_conclusion_ov: yaml_str(raw, "maec/analysis-conclusion-ov"),
            malware_family: yaml_str(raw, "maec/malware-family"),
            malware_category: yaml_str(raw, "maec/malware-category"),
            malware_category_ov: yaml_str(raw, "maec/malware-category-ov"),
        },
    }
}

/// port of `node_from_capa`/`statement_from_capa`, specialized for our
/// `engine::MatchedNode` (`Subscope` is deliberately absent -- see
/// `splice_match_reference`'s doc comment for where it actually comes from).
fn node_from_matched(
    node: &engine::MatchedNode,
    description: Option<String>,
) -> Result<Node, FromCapaError> {
    use engine::MatchedNode;
    Ok(match node {
        MatchedNode::And => Node::Statement {
            statement: Statement::And { description },
        },
        MatchedNode::Or => Node::Statement {
            statement: Statement::Or { description },
        },
        MatchedNode::Not => Node::Statement {
            statement: Statement::Not { description },
        },
        MatchedNode::Some { count: 0 } => Node::Statement {
            statement: Statement::Optional { description },
        },
        MatchedNode::Some { count } => Node::Statement {
            statement: Statement::Some {
                description,
                count: *count as u64,
            },
        },
        MatchedNode::Range { feature, min, max } => Node::Statement {
            statement: Statement::Range {
                description,
                min: *min as u64,
                // upstream materializes "unbounded" as `(1<<64)-1` (`Range.max`'s
                // default), which is exactly `u64::MAX`.
                max: max.map(|m| m as u64).unwrap_or(u64::MAX),
                // the counted feature's own description isn't tracked
                // separately from the `Range` statement's (see rules::Node
                // -- our grammar attaches `= description` to the enclosing
                // node, not a nested per-feature slot), so this is always
                // `None`; a real capa-rules `count(...)` clause with an
                // inline feature description is not known to occur.
                child: RdFeature::from_engine(feature, None).map_err(FromCapaError::Feature)?,
            },
        },
        MatchedNode::Leaf(feature) => Node::Feature {
            feature: RdFeature::from_engine(feature, description)
                .map_err(FromCapaError::Feature)?,
        },
    })
}

/// `dict(capabilities[rule_name])`: last-address-wins map from match address
/// to that rule's `Result` at the address, for `match:`/namespace splicing.
fn rule_match_index<'a>(
    capabilities: &'a MatchResults,
    rule_name: &str,
) -> HashMap<Address, &'a engine::MatchResult> {
    let mut out = HashMap::new();
    if let Some(matches) = capabilities.get(rule_name) {
        for (addr, result) in matches {
            out.insert(*addr, result);
        }
    }
    out
}

/// port of the `matches_in_thread = sorted(...); most_recent_match = ...`
/// span-of-calls fallback: the match (if any) at the highest call id no
/// greater than `id`, within the same thread.
fn most_recent_in_thread<'a>(
    rule_matches: &HashMap<Address, &'a engine::MatchResult>,
    ppid: u32,
    pid: u32,
    tid: u32,
    id: u64,
) -> Option<&'a engine::MatchResult> {
    rule_matches
        .iter()
        .filter_map(|(addr, m)| match addr {
            Address::Call {
                ppid: p2,
                pid: pi2,
                tid: t2,
                id: id2,
            } if *p2 == ppid && *pi2 == pid && *t2 == tid && *id2 <= id => Some((*id2, *m)),
            _ => None,
        })
        .max_by_key(|(id2, _)| *id2)
        .map(|(_, m)| m)
}

/// port of `Match.from_capa`.
pub fn build_match(
    ruleset: &MatchingRuleSet,
    capabilities: &MatchResults,
    result: &engine::MatchResult,
) -> Result<Match, FromCapaError> {
    let success = result.success;
    let mut node = node_from_matched(&result.node, result.description.clone())?;
    let mut children: Vec<Match> = result
        .children
        .iter()
        .map(|c| build_match(ruleset, capabilities, c))
        .collect::<Result<_, _>>()?;

    let is_feature = matches!(node, Node::Feature { .. });
    let is_range = matches!(
        &node,
        Node::Statement {
            statement: Statement::Range { .. }
        }
    );
    let locations: Vec<RdAddress> = if (is_feature || is_range) && success {
        result.locations.iter().map(RdAddress::from).collect()
    } else {
        Vec::new()
    };

    let captures: BTreeMap<String, Vec<RdAddress>> = result
        .captures
        .iter()
        .map(|(k, locs)| (k.clone(), locs.iter().map(RdAddress::from).collect()))
        .collect();

    // splice in the referenced rule's (or namespace's) own match tree, on a
    // successful `match:` leaf -- see `Match.from_capa`'s long comment.
    if success {
        if let Node::Feature {
            feature: RdFeature::Match { match_: name, .. },
        } = &node
        {
            let name = name.clone();
            if let Some(rule) = ruleset.get(&name) {
                let rule_matches = rule_match_index(capabilities, &name);

                if rule.is_subscope_rule() {
                    let scope = rule
                        .scopes
                        .static_
                        .or(rule.scopes.dynamic)
                        .ok_or_else(|| FromCapaError::SubscopeRuleMissingScope(name.clone()))?;
                    node = Node::Statement {
                        statement: Statement::Subscope {
                            description: None,
                            scope: scope.as_str().to_string(),
                        },
                    };
                }

                for location in &result.locations {
                    match location {
                        Address::Call { ppid, pid, tid, id } => {
                            if let Some(m) = rule_matches.get(location) {
                                children.push(build_match(ruleset, capabilities, m)?);
                            } else if let Some(m) =
                                most_recent_in_thread(&rule_matches, *ppid, *pid, *tid, *id)
                            {
                                children.push(build_match(ruleset, capabilities, m)?);
                            }
                        }
                        _ => {
                            let m = rule_matches.get(location).ok_or_else(|| {
                                FromCapaError::MissingRuleMatch {
                                    rule: name.clone(),
                                    addr: location.canonical_key(),
                                }
                            })?;
                            children.push(build_match(ruleset, capabilities, m)?);
                        }
                    }
                }
            } else {
                for rule_name in ruleset.by_namespace_prefix.get(&name).into_iter().flatten() {
                    if !capabilities.contains_key(rule_name) {
                        continue;
                    }
                    let rule_matches = rule_match_index(capabilities, rule_name);
                    for location in &result.locations {
                        match location {
                            Address::Call { ppid, pid, tid, id } => {
                                if let Some(m) = rule_matches.get(location) {
                                    children.push(build_match(ruleset, capabilities, m)?);
                                } else if let Some(m) =
                                    most_recent_in_thread(&rule_matches, *ppid, *pid, *tid, *id)
                                {
                                    children.push(build_match(ruleset, capabilities, m)?);
                                }
                            }
                            _ => {
                                if let Some(m) = rule_matches.get(location) {
                                    children.push(build_match(ruleset, capabilities, m)?);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(Match {
        success,
        node,
        children,
        locations,
        captures,
    })
}

/// port of `ResultDocument.from_capa`.
pub fn build_result_document(
    ruleset: &MatchingRuleSet,
    capabilities: &MatchResults,
    meta: Metadata,
) -> Result<ResultDocument, FromCapaError> {
    let mut rules = BTreeMap::new();
    for (rule_name, matches) in capabilities {
        let Some(rule) = ruleset.get(rule_name) else {
            continue;
        };
        if rule.is_subscope_rule() {
            continue;
        }

        let mut rendered_matches = Vec::with_capacity(matches.len());
        for (addr, result) in matches {
            let m = build_match(ruleset, capabilities, result)?;
            rendered_matches.push((RdAddress::from(addr), m));
        }

        rules.insert(
            rule_name.clone(),
            RuleMatches {
                meta: rule_metadata(rule),
                source: rule.source.clone(),
                matches: rendered_matches,
            },
        );
    }

    Ok(ResultDocument { meta, rules })
}

/// port of `compute_static_layout`.
pub fn compute_static_layout(
    ruleset: &MatchingRuleSet,
    freeze: &StaticFeatures,
    capabilities: &MatchResults,
) -> StaticLayout {
    let mut bbs_by_function: Vec<(Address, Vec<Address>)> = Vec::new();
    for (fn_addr, func) in &freeze.functions {
        bbs_by_function.push((*fn_addr, func.basic_blocks.keys().copied().collect()));
    }

    let mut matched_bbs: HashSet<Address> = HashSet::new();
    for (rule_name, matches) in capabilities {
        let Some(rule) = ruleset.get(rule_name) else {
            continue;
        };
        if rule.scopes.contains(Scope::BasicBlock) {
            matched_bbs.extend(matches.iter().map(|(addr, _)| *addr));
        }
    }

    let functions = bbs_by_function
        .into_iter()
        .filter_map(|(fn_addr, bbs)| {
            let matched: Vec<Address> = bbs
                .into_iter()
                .filter(|b| matched_bbs.contains(b))
                .collect();
            if matched.is_empty() {
                return None;
            }
            Some(FunctionLayout {
                address: RdAddress::from(fn_addr),
                matched_basic_blocks: matched
                    .into_iter()
                    .map(|b| BasicBlockLayout {
                        address: RdAddress::from(b),
                    })
                    .collect(),
            })
        })
        .collect();

    StaticLayout { functions }
}

fn collect_matched_calls(result: &engine::MatchResult, out: &mut BTreeSet<Address>) {
    for loc in &result.locations {
        if matches!(loc, Address::Call { .. }) {
            out.insert(*loc);
        }
    }
    for child in &result.children {
        collect_matched_calls(child, out);
    }
}

/// port of `compute_dynamic_layout` (the `rules` parameter upstream takes is
/// unused there too).
pub fn compute_dynamic_layout(
    freeze: &DynamicFeatures,
    capabilities: &MatchResults,
) -> DynamicLayout {
    let mut matched_calls: BTreeSet<Address> = BTreeSet::new();
    for matches in capabilities.values() {
        for (_, result) in matches {
            collect_matched_calls(result, &mut matched_calls);
        }
    }

    let mut processes = Vec::new();
    for (process_addr, process) in &freeze.processes {
        let mut threads = Vec::new();
        for (thread_addr, thread) in &process.threads {
            let mut calls = Vec::new();
            for (call_addr, call) in &thread.calls {
                if matched_calls.contains(call_addr) {
                    calls.push(CallLayout {
                        address: RdAddress::from(*call_addr),
                        name: call.name.clone(),
                    });
                }
            }
            if !calls.is_empty() {
                threads.push(ThreadLayout {
                    address: RdAddress::from(*thread_addr),
                    matched_calls: calls,
                });
            }
        }
        if !threads.is_empty() {
            processes.push(ProcessLayout {
                address: RdAddress::from(*process_addr),
                name: process.name.clone(),
                matched_threads: threads,
            });
        }
    }

    DynamicLayout { processes }
}

/// the "auto" sentinel accepted by `--os`; kept in sync with
/// `capa/main.py`'s `OS_AUTO`.
pub const OS_AUTO: &str = "auto";
/// capa-x-specific: `--arch` has no upstream equivalent (`main.py` never
/// registers an `--arch` flag); "auto"
/// mirrors `OS_AUTO`'s convention.
pub const ARCH_AUTO: &str = "auto";

fn global_str(global_features: &[Feature], variant: fn(&Feature) -> Option<&str>) -> Option<&str> {
    global_features.iter().find_map(|f| variant(f))
}

fn as_format(f: &Feature) -> Option<&str> {
    match f {
        Feature::Format(v) => Some(v.as_str()),
        _ => None,
    }
}
fn as_arch(f: &Feature) -> Option<&str> {
    match f {
        Feature::Arch(v) => Some(v.as_str()),
        _ => None,
    }
}
fn as_os(f: &Feature) -> Option<&str> {
    match f {
        Feature::Os(v) => Some(v.as_str()),
        _ => None,
    }
}

/// inputs shared by `build_static_metadata`/`build_dynamic_metadata`; see
/// `capa.loader.collect_metadata`.
pub struct MetaInputs {
    pub argv: Option<Vec<String>>,
    pub version: String,
    pub timestamp: String,
    pub sample: Sample,
    /// the input-format flag as understood by the CLI (`"freeze"` for
    /// capa-x today); used as `format`'s fallback when no `Format`
    /// global feature is present, exactly like upstream's `input_format`
    /// fallback in `collect_metadata`.
    pub input_format_fallback: String,
    /// `--os` value; `OS_AUTO` ("auto") if not overridden.
    pub os_override: String,
    /// `--arch` value; `ARCH_AUTO` ("auto") if not overridden.
    pub arch_override: String,
    pub rules_paths: Vec<String>,
}

/// port of `collect_metadata` + `get_sample_analysis`, static flavor.
pub fn build_static_metadata(
    inputs: MetaInputs,
    freeze: &StaticFeatures,
    counts: StaticCounts,
    library_functions: Vec<LibraryFunction>,
    layout: StaticLayout,
) -> Metadata {
    let format = global_str(&freeze.global_features, as_format)
        .map(str::to_string)
        .unwrap_or(inputs.input_format_fallback);
    let arch = global_str(&freeze.global_features, as_arch)
        .map(str::to_string)
        .unwrap_or_else(|| {
            if inputs.arch_override == ARCH_AUTO {
                "unknown".to_string()
            } else {
                inputs.arch_override.clone()
            }
        });
    let os = global_str(&freeze.global_features, as_os)
        .map(str::to_string)
        .unwrap_or_else(|| {
            if inputs.os_override == OS_AUTO {
                "unknown".to_string()
            } else {
                inputs.os_override.clone()
            }
        });

    Metadata::Static {
        timestamp: inputs.timestamp,
        version: inputs.version,
        argv: inputs.argv,
        sample: inputs.sample,
        analysis: StaticAnalysis {
            format,
            arch,
            os,
            extractor: "NullStaticFeatureExtractor".to_string(),
            rules: inputs.rules_paths,
            base_address: RdAddress::from(freeze.base_address),
            layout,
            feature_counts: StaticFeatureCounts {
                file: counts.file_feature_count,
                functions: counts
                    .function_feature_counts
                    .into_iter()
                    .map(|(addr, count)| FunctionFeatureCount {
                        address: RdAddress::from(addr),
                        count,
                    })
                    .collect(),
            },
            library_functions,
        },
    }
}

/// port of `collect_metadata` + `get_sample_analysis`, dynamic flavor.
pub fn build_dynamic_metadata(
    inputs: MetaInputs,
    freeze: &DynamicFeatures,
    counts: DynamicCounts,
    layout: DynamicLayout,
) -> Metadata {
    let format = global_str(&freeze.global_features, as_format)
        .map(str::to_string)
        .unwrap_or(inputs.input_format_fallback);
    let arch = global_str(&freeze.global_features, as_arch)
        .map(str::to_string)
        .unwrap_or_else(|| {
            if inputs.arch_override == ARCH_AUTO {
                "unknown".to_string()
            } else {
                inputs.arch_override.clone()
            }
        });
    let os = global_str(&freeze.global_features, as_os)
        .map(str::to_string)
        .unwrap_or_else(|| {
            if inputs.os_override == OS_AUTO {
                "unknown".to_string()
            } else {
                inputs.os_override.clone()
            }
        });

    Metadata::Dynamic {
        timestamp: inputs.timestamp,
        version: inputs.version,
        argv: inputs.argv,
        sample: inputs.sample,
        analysis: DynamicAnalysis {
            format,
            arch,
            os,
            extractor: "NullDynamicFeatureExtractor".to_string(),
            rules: inputs.rules_paths,
            layout,
            feature_counts: DynamicFeatureCounts {
                file: counts.file_feature_count,
                processes: counts
                    .process_feature_counts
                    .into_iter()
                    .map(|(addr, count)| ProcessFeatureCount {
                        address: RdAddress::from(addr),
                        count,
                    })
                    .collect(),
            },
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::capabilities::find_static_capabilities;
    use crate::parallel::AnalysisOptions;
    use crate::rules::Rule;

    fn rule(yaml: &str) -> Rule {
        Rule::from_yaml(yaml).unwrap_or_else(|e| panic!("test rule failed to parse: {e}"))
    }

    fn load_fixture(name: &str) -> StaticFeatures {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/freeze")
            .join(name);
        let s = std::fs::read_to_string(path).expect("fixture present");
        match crate::freeze::loads(&s).expect("valid freeze json") {
            crate::freeze::Freeze::Static(sf) => sf,
            crate::freeze::Freeze::Dynamic(_) => panic!("expected static flavor"),
        }
    }

    #[test]
    fn match_reference_splices_in_the_referenced_rules_subtree() {
        let fn_rule = rule(
            "rule:\n  meta:\n    name: has api\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - api: CreateFileA\n",
        );
        let file_rule = rule(
            "rule:\n  meta:\n    name: file sees fn match\n    authors: [t]\n    scopes:\n      static: file\n      dynamic: unsupported\n  features:\n    - match: has api\n",
        );
        let ruleset = MatchingRuleSet::new(vec![fn_rule, file_rule]).unwrap();

        let fn_addr = Address::Absolute(0x2000);
        let mut functions = std::collections::BTreeMap::new();
        functions.insert(
            fn_addr,
            crate::freeze::FunctionFeatures {
                features: vec![(fn_addr, Feature::Api("CreateFileA".into()))],
                basic_blocks: Default::default(),
            },
        );
        let freeze = StaticFeatures {
            base_address: Address::Absolute(0),
            sample_hashes: crate::freeze::SampleHashes {
                md5: String::new(),
                sha1: String::new(),
                sha256: String::new(),
            },
            global_features: vec![],
            file_features: vec![],
            functions,
        };

        let caps = find_static_capabilities(&ruleset, &freeze, &AnalysisOptions::SERIAL).unwrap();
        let capabilities = &caps.matches;
        let inputs = MetaInputs {
            argv: None,
            version: "0.0.0".into(),
            timestamp: "t".into(),
            sample: Sample {
                md5: String::new(),
                sha1: String::new(),
                sha256: String::new(),
                path: String::new(),
            },
            input_format_fallback: "freeze".into(),
            os_override: OS_AUTO.into(),
            arch_override: ARCH_AUTO.into(),
            rules_paths: vec![],
        };
        let layout = compute_static_layout(&ruleset, &freeze, capabilities);
        let meta = build_static_metadata(inputs, &freeze, StaticCounts::default(), vec![], layout);

        let doc = build_result_document(&ruleset, capabilities, meta).unwrap();

        let file_match = &doc.rules["file sees fn match"].matches[0].1;
        assert!(file_match.success);
        // the top node is the `match: has api` feature leaf itself...
        let Node::Feature {
            feature: RdFeature::Match { match_, .. },
        } = &file_match.node
        else {
            panic!("expected a match feature node");
        };
        assert_eq!(match_, "has api");
        // ...and its child is the spliced-in subtree of "has api" itself
        // (an `api: CreateFileA` feature node), not an empty leaf.
        assert_eq!(file_match.children.len(), 1);
        let Node::Feature {
            feature: RdFeature::Api { api, .. },
        } = &file_match.children[0].node
        else {
            panic!("expected an api feature node spliced in from the referenced rule");
        };
        assert_eq!(api, "CreateFileA");
    }

    #[test]
    fn subscope_match_is_rendered_as_a_subscope_statement_not_a_match_feature() {
        let r = rule(
            "rule:\n  meta:\n    name: has bb with api\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - and:\n      - basic block:\n        - api: CreateFileA\n      - api: WriteFile\n",
        );
        let ruleset = MatchingRuleSet::new(vec![r]).unwrap();

        let bb_addr = Address::Absolute(0x3000);
        let insn_addr = Address::Absolute(0x3001);
        let mut basic_blocks = std::collections::BTreeMap::new();
        basic_blocks.insert(
            bb_addr,
            crate::freeze::BasicBlockFeatures {
                features: vec![],
                instructions: [(
                    insn_addr,
                    crate::freeze::InstructionFeatures {
                        features: vec![(insn_addr, Feature::Api("CreateFileA".into()))],
                    },
                )]
                .into_iter()
                .collect(),
            },
        );
        let fn_addr = Address::Absolute(0x3000);
        let mut functions = std::collections::BTreeMap::new();
        functions.insert(
            fn_addr,
            crate::freeze::FunctionFeatures {
                features: vec![(fn_addr, Feature::Api("WriteFile".into()))],
                basic_blocks,
            },
        );
        let freeze = StaticFeatures {
            base_address: Address::Absolute(0),
            sample_hashes: crate::freeze::SampleHashes {
                md5: String::new(),
                sha1: String::new(),
                sha256: String::new(),
            },
            global_features: vec![],
            file_features: vec![],
            functions,
        };

        let caps = find_static_capabilities(&ruleset, &freeze, &AnalysisOptions::SERIAL).unwrap();
        let capabilities = &caps.matches;
        let inputs = MetaInputs {
            argv: None,
            version: "0.0.0".into(),
            timestamp: "t".into(),
            sample: Sample {
                md5: String::new(),
                sha1: String::new(),
                sha256: String::new(),
                path: String::new(),
            },
            input_format_fallback: "freeze".into(),
            os_override: OS_AUTO.into(),
            arch_override: ARCH_AUTO.into(),
            rules_paths: vec![],
        };
        let layout = compute_static_layout(&ruleset, &freeze, capabilities);
        assert_eq!(layout.functions.len(), 1);
        assert_eq!(layout.functions[0].matched_basic_blocks.len(), 1);

        let meta = build_static_metadata(inputs, &freeze, StaticCounts::default(), vec![], layout);
        let doc = build_result_document(&ruleset, capabilities, meta).unwrap();

        // only the parent rule appears in the document -- the synthetic
        // `capa/subscope-rule` basic-block rule is excluded entirely.
        assert_eq!(doc.rules.len(), 1);
        let m = &doc.rules["has bb with api"].matches[0].1;
        assert!(m.success);

        // find the `and:`'s children and confirm one of them got rewritten
        // into a `subscope` statement (`basic block:`), not left as a
        // `match:` feature leaf referencing the hidden synthetic rule.
        let Node::Statement {
            statement: Statement::And { .. },
        } = &m.node
        else {
            panic!("expected top-level and:")
        };
        let has_subscope = m.children.iter().any(|c| {
            matches!(
                &c.node,
                Node::Statement {
                    statement: Statement::Subscope { scope, .. }
                } if scope == "basic block"
            )
        });
        assert!(
            has_subscope,
            "expected a basic-block subscope statement among: {:?}",
            m.children.iter().map(|c| &c.node).collect::<Vec<_>>()
        );
    }

    #[test]
    fn namespace_match_splices_matching_rules_in_the_namespace() {
        let a = rule(
            "rule:\n  meta:\n    name: rule a\n    namespace: ns/x\n    authors: [t]\n    scopes:\n      static: file\n      dynamic: unsupported\n  features:\n    - characteristic: embedded pe\n",
        );
        let user = rule(
            "rule:\n  meta:\n    name: uses namespace\n    authors: [t]\n    scopes:\n      static: file\n      dynamic: unsupported\n  features:\n    - match: ns/x\n",
        );
        let ruleset = MatchingRuleSet::new(vec![a, user]).unwrap();

        let freeze = StaticFeatures {
            base_address: Address::Absolute(0),
            sample_hashes: crate::freeze::SampleHashes {
                md5: String::new(),
                sha1: String::new(),
                sha256: String::new(),
            },
            global_features: vec![],
            file_features: vec![(
                Address::Absolute(0x1000),
                Feature::Characteristic("embedded pe".into()),
            )],
            functions: Default::default(),
        };

        let caps = find_static_capabilities(&ruleset, &freeze, &AnalysisOptions::SERIAL).unwrap();
        let capabilities = &caps.matches;
        let inputs = MetaInputs {
            argv: None,
            version: "0.0.0".into(),
            timestamp: "t".into(),
            sample: Sample {
                md5: String::new(),
                sha1: String::new(),
                sha256: String::new(),
                path: String::new(),
            },
            input_format_fallback: "freeze".into(),
            os_override: OS_AUTO.into(),
            arch_override: ARCH_AUTO.into(),
            rules_paths: vec![],
        };
        let layout = compute_static_layout(&ruleset, &freeze, capabilities);
        let meta = build_static_metadata(inputs, &freeze, StaticCounts::default(), vec![], layout);
        let doc = build_result_document(&ruleset, capabilities, meta).unwrap();

        let m = &doc.rules["uses namespace"].matches[0].1;
        assert!(m.success);
        assert_eq!(m.children.len(), 1);
        let Node::Feature {
            feature: RdFeature::Characteristic { characteristic, .. },
        } = &m.children[0].node
        else {
            panic!("expected the namespace's rule subtree spliced in");
        };
        assert_eq!(characteristic, "embedded pe");
    }

    #[test]
    fn static_metadata_pulls_format_arch_os_from_global_features() {
        let freeze = load_fixture("pma01-01-dll.frz.json");
        let placeholder = rule(
            "rule:\n  meta:\n    name: placeholder\n    authors: [t]\n    scopes:\n      static: file\n      dynamic: unsupported\n  features:\n    - characteristic: mixed mode\n",
        );
        let ruleset = MatchingRuleSet::new(vec![placeholder]).unwrap();
        let caps = find_static_capabilities(&ruleset, &freeze, &AnalysisOptions::SERIAL).unwrap();
        let capabilities = &caps.matches;
        let inputs = MetaInputs {
            argv: Some(vec!["capa".into(), "sample.dll".into()]),
            version: "0.0.0".into(),
            timestamp: "t".into(),
            sample: Sample {
                md5: freeze.sample_hashes.md5.clone(),
                sha1: freeze.sample_hashes.sha1.clone(),
                sha256: freeze.sample_hashes.sha256.clone(),
                path: "sample.dll".into(),
            },
            input_format_fallback: "freeze".into(),
            os_override: OS_AUTO.into(),
            arch_override: ARCH_AUTO.into(),
            rules_paths: vec!["/rules".into()],
        };
        let layout = compute_static_layout(&ruleset, &freeze, capabilities);
        let meta = build_static_metadata(inputs, &freeze, StaticCounts::default(), vec![], layout);
        let Metadata::Static { analysis, .. } = &meta else {
            panic!("expected static metadata")
        };
        assert_eq!(analysis.format, "pe");
        assert_eq!(analysis.os, "windows");
        assert_ne!(analysis.arch, "unknown");
        assert_eq!(analysis.extractor, "NullStaticFeatureExtractor");
    }
}
