//! Static-flavor matching driver, ported from `capa/capabilities/static.py`
//! and the `find_file_capabilities` half of `capa/capabilities/common.py`.
//! Bottom-up: instruction -> basic block -> function -> file.
//!
//! Freeze-driven by design, so this reads directly from
//! `freeze::StaticFeatures`'s already-nested, address-sorted tree
//! (mirroring how upstream reads from a `NullStaticFeatureExtractor`) rather
//! than an `extractor.get_functions()`-style API.

use std::collections::{BTreeSet, HashMap};

use crate::address::Address;
use crate::capabilities::MatchingRuleSet;
use crate::engine::{self, EngineError, FeatureSet, MatchResults};
use crate::features::Feature;
use crate::freeze::{BasicBlockFeatures, FunctionFeatures, StaticFeatures};
use crate::parallel::{self, AnalysisOptions};
use crate::rules::Scope;

/// An [`EngineError`] plus the scope it came from.
///
/// The address matters more than it looks: with the per-function loop running
/// on worker threads, an error carries no stack the caller can read, so the
/// failing function has to be *in* the message or it is lost. `capa-x-cli` adds
/// the sample path on the way out, which completes the sample/function/phase
/// triple.
#[derive(Debug, thiserror::Error)]
pub enum CapabilityError {
    #[error("code-scope matching of function {address}: {source}")]
    Function {
        address: Address,
        #[source]
        source: EngineError,
    },
    #[error("file-scope matching: {source}")]
    File {
        #[source]
        source: EngineError,
    },
}

/// inserts `features`, in order, then `global_features` at `Address::NoAddress`
/// -- the `itertools.chain(extract_*_features(...), extract_global_features())`
/// pattern shared by every scope loop except `find_file_capabilities` (which
/// has its own truthiness-guarded variant below).
fn seed(fs: &mut FeatureSet, features: &[(Address, Feature)], global_features: &[Feature]) {
    for (addr, f) in features {
        engine::insert(fs, f.clone(), *addr);
    }
    for f in global_features {
        engine::insert(fs, f.clone(), Address::NoAddress);
    }
}

fn extend_matches(into: &mut MatchResults, from: MatchResults) {
    for (name, res) in from {
        into.entry(name).or_default().extend(res);
    }
}

/// port of `find_instruction_capabilities`.
pub fn find_instruction_capabilities(
    ruleset: &MatchingRuleSet,
    insn_addr: Address,
    insn_features: &[(Address, Feature)],
    global_features: &[Feature],
) -> Result<(FeatureSet, MatchResults), EngineError> {
    let mut features = FeatureSet::new();
    seed(&mut features, insn_features, global_features);

    let (_, matches) = ruleset.match_scope(Scope::Instruction, &features, insn_addr)?;
    promote_matches(ruleset, &mut features, &matches);

    Ok((features, matches))
}

/// port of `find_basic_block_capabilities`.
pub fn find_basic_block_capabilities(
    ruleset: &MatchingRuleSet,
    bb_addr: Address,
    bb: &BasicBlockFeatures,
    global_features: &[Feature],
) -> Result<(FeatureSet, MatchResults, MatchResults), EngineError> {
    let mut features = FeatureSet::new();
    let mut insn_matches: MatchResults = HashMap::new();

    for (insn_addr, insn) in &bb.instructions {
        let (insn_features, matches) =
            find_instruction_capabilities(ruleset, *insn_addr, &insn.features, global_features)?;
        engine::merge(&mut features, &insn_features);
        extend_matches(&mut insn_matches, matches);
    }

    seed(&mut features, &bb.features, global_features);

    let (_, bb_matches) = ruleset.match_scope(Scope::BasicBlock, &features, bb_addr)?;
    promote_matches(ruleset, &mut features, &bb_matches);

    Ok((features, bb_matches, insn_matches))
}

/// port of `find_code_capabilities` (function scope). Unlike bb/instruction,
/// upstream does *not* self-promote function matches back into
/// `function_features` here -- function-scope matches only need to be
/// visible to the enclosing FILE scope, which `find_static_capabilities`
/// handles separately via `function_and_lower_features`.
pub fn find_code_capabilities(
    ruleset: &MatchingRuleSet,
    fn_addr: Address,
    func: &FunctionFeatures,
    global_features: &[Feature],
) -> Result<(MatchResults, MatchResults, MatchResults, usize), EngineError> {
    let mut function_features = FeatureSet::new();
    let mut bb_matches: MatchResults = HashMap::new();
    let mut insn_matches: MatchResults = HashMap::new();

    for (bb_addr, bb) in &func.basic_blocks {
        let (bb_features, this_bb_matches, this_insn_matches) =
            find_basic_block_capabilities(ruleset, *bb_addr, bb, global_features)?;
        engine::merge(&mut function_features, &bb_features);
        extend_matches(&mut bb_matches, this_bb_matches);
        extend_matches(&mut insn_matches, this_insn_matches);
    }

    seed(&mut function_features, &func.features, global_features);

    // capa/capabilities/static.py: `code_capabilities.feature_count =
    // len(function_features)` -- the distinct-feature count *before* the
    // function-scope match below (which never self-promotes back into
    // `function_features`; see this fn's doc comment), feeding
    // `rdoc.FunctionFeatureCount` in the result document.
    let feature_count = function_features.len();

    let (_, function_matches) =
        ruleset.match_scope(Scope::Function, &function_features, fn_addr)?;

    Ok((function_matches, bb_matches, insn_matches, feature_count))
}

/// port of `find_file_capabilities` (capa/capabilities/common.py), the half
/// shared with the dynamic driver, specialized here for a `StaticFeatures`'
/// `file_features`/`global_features` and a caller-supplied promoted
/// `function_and_lower_features` set.
pub fn find_file_capabilities(
    ruleset: &MatchingRuleSet,
    file_features_list: &[(Address, Feature)],
    global_features: &[Feature],
    function_and_lower_features: &FeatureSet,
) -> Result<(MatchResults, usize), EngineError> {
    let mut file_features = FeatureSet::new();
    for (addr, f) in file_features_list {
        guarded_insert(&mut file_features, f.clone(), *addr);
    }
    for f in global_features {
        guarded_insert(&mut file_features, f.clone(), Address::NoAddress);
    }
    engine::merge(&mut file_features, function_and_lower_features);

    // capa/capabilities/common.py: `FileCapabilities.feature_count = len(file_features)`.
    let feature_count = file_features.len();

    let (_, matches) = ruleset.match_scope(Scope::File, &file_features, Address::NoAddress)?;
    Ok((matches, feature_count))
}

/// port of the `if va: ... else: ...` guard in `find_file_capabilities`: a
/// file feature at a falsy address (in practice, absolute/relative/file/dn
/// token address `0`) is recorded with an *empty* location set instead of
/// `{addr}`. See `Address::is_truthy`'s doc comment.
fn guarded_insert(fs: &mut FeatureSet, feature: Feature, addr: Address) {
    if addr.is_truthy() {
        engine::insert(fs, feature, addr);
    } else {
        fs.entry(feature).or_default();
    }
}

/// port of the `for rule_name, res in matches.items(): ... index_rule_matches(...)`
/// step that follows every `ruleset.match(...)` call in `capabilities/static.py`
/// *except* at function scope (see `find_code_capabilities`'s doc comment) --
/// self-promotes each matched rule's `match(name)`/namespace features back
/// into this scope's own `features`, so that when `features` is merged up
/// into the enclosing scope, the match is visible there too.
fn promote_matches(ruleset: &MatchingRuleSet, features: &mut FeatureSet, matches: &MatchResults) {
    for (rule_name, res) in matches {
        let Some(rule) = ruleset.get(rule_name) else {
            continue;
        };
        for (addr, _) in res {
            let locations: BTreeSet<Address> = [*addr].into_iter().collect();
            engine::index_rule_matches(features, rule, &locations);
        }
    }
}

/// port of `Capabilities` (`capa/capabilities/common.py`), static flavor:
/// matches plus the feature-count bookkeeping the result document's
/// `meta.analysis.feature_counts` needs. `library_functions` is always empty
/// here -- freeze-driven input has no FLIRT/signature backend, and
/// `NullStaticFeatureExtractor.is_library_function` (which upstream's own
/// freeze-input path also uses) never overrides the base extractor's
/// `False` default, so no function is ever skipped as a library function
/// either (matching upstream's freeze-driven behavior exactly, not just
/// approximating it).
#[derive(Debug, Clone, Default)]
pub struct StaticCapabilities {
    pub matches: MatchResults,
    pub file_feature_count: usize,
    /// one entry per non-library function, in `freeze.functions`' (address)
    /// iteration order -- `rdoc.StaticFeatureCounts.functions`.
    pub function_feature_counts: Vec<(Address, usize)>,
}

/// port of `find_static_capabilities`.
///
/// The per-function loop is the second parallel seam (`options.jobs`; the
/// first is [`crate::extract::flirt::enrich_static_features`]). Code-scope
/// matching reads an immutable ruleset and an immutable freeze, and each
/// function's matches are merged only after every worker has finished, in
/// address order -- so the merge, the short-circuit evidence it carries, and
/// the resulting document are identical to the serial run. File scope stays
/// serial: it is a single match over the aggregate.
pub fn find_static_capabilities(
    ruleset: &MatchingRuleSet,
    freeze: &StaticFeatures,
    options: &AnalysisOptions,
) -> Result<StaticCapabilities, CapabilityError> {
    let mut all_function_matches: MatchResults = HashMap::new();
    let mut all_bb_matches: MatchResults = HashMap::new();
    let mut all_insn_matches: MatchResults = HashMap::new();
    let mut function_feature_counts: Vec<(Address, usize)> = Vec::new();

    // Materialized so the workers can index it; `freeze.functions` is a
    // BTreeMap, so this is already in address order and the join below is the
    // same sequence the serial loop walked.
    let functions: Vec<(&Address, &FunctionFeatures)> = freeze.functions.iter().collect();
    let per_function = parallel::try_map(options.jobs, &functions, |(fn_addr, func)| {
        find_code_capabilities(ruleset, **fn_addr, func, &freeze.global_features).map_err(
            |source| CapabilityError::Function {
                address: **fn_addr,
                source,
            },
        )
    })?;

    for ((fn_addr, _), (function_matches, bb_matches, insn_matches, feature_count)) in
        functions.iter().zip(per_function)
    {
        function_feature_counts.push((**fn_addr, feature_count));
        extend_matches(&mut all_function_matches, function_matches);
        extend_matches(&mut all_bb_matches, bb_matches);
        extend_matches(&mut all_insn_matches, insn_matches);
    }

    // capa/capabilities/static.py: `function_and_lower_features`, the
    // promoted match/namespace features from every function/bb/insn match,
    // folded into a single FeatureSet for the FILE-scope match below.
    let mut function_and_lower_features = FeatureSet::new();
    for (rule_name, results) in all_insn_matches
        .iter()
        .chain(all_bb_matches.iter())
        .chain(all_function_matches.iter())
    {
        let Some(rule) = ruleset.get(rule_name) else {
            continue;
        };
        let locations: BTreeSet<Address> = results.iter().map(|(addr, _)| *addr).collect();
        engine::index_rule_matches(&mut function_and_lower_features, rule, &locations);
    }

    let (file_matches, file_feature_count) = find_file_capabilities(
        ruleset,
        &freeze.file_features,
        &freeze.global_features,
        &function_and_lower_features,
    )
    .map_err(|source| CapabilityError::File { source })?;

    let mut matches = MatchResults::new();
    extend_matches(&mut matches, all_insn_matches);
    extend_matches(&mut matches, all_bb_matches);
    extend_matches(&mut matches, all_function_matches);
    extend_matches(&mut matches, file_matches);
    Ok(StaticCapabilities {
        matches,
        file_feature_count,
        function_feature_counts,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
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
    fn end_to_end_against_a_freeze_fixture() {
        // a file-scope rule on a global feature actually present in the
        // trimmed pma01-01-dll fixture (a PE, i386, windows sample),
        // exercised through the full driver rather than hand-built features.
        let freeze = load_fixture("pma01-01-dll.frz.json");
        let r = rule(
            "rule:\n  meta:\n    name: is a windows pe\n    authors: [t]\n    scopes:\n      static: file\n      dynamic: unsupported\n  features:\n    - and:\n      - os: windows\n      - format: pe\n",
        );
        let ruleset = MatchingRuleSet::new(vec![r]).unwrap();
        let capabilities =
            find_static_capabilities(&ruleset, &freeze, &AnalysisOptions::SERIAL).unwrap();
        assert!(capabilities.matches.contains_key("is a windows pe"));
    }

    #[test]
    fn instruction_scope_match_promotes_into_basic_block() {
        // an instruction-scope rule matching "api: CreateFileA" should be
        // visible to a basic-block-scope rule that does `match:` on it,
        // proving the promote_matches self-feedback step works.
        let insn_rule = rule(
            "rule:\n  meta:\n    name: opens file\n    authors: [t]\n    scopes:\n      static: instruction\n      dynamic: unsupported\n  features:\n    - api: CreateFileA\n",
        );
        let bb_rule = rule(
            "rule:\n  meta:\n    name: bb sees insn match\n    authors: [t]\n    scopes:\n      static: basic block\n      dynamic: unsupported\n  features:\n    - match: opens file\n",
        );
        let ruleset = MatchingRuleSet::new(vec![insn_rule, bb_rule]).unwrap();

        let addr = Address::Absolute(0x1000);
        let bb = BasicBlockFeatures {
            features: vec![],
            instructions: [(
                addr,
                crate::freeze::InstructionFeatures {
                    features: vec![(addr, Feature::Api("CreateFileA".into()))],
                },
            )]
            .into_iter()
            .collect(),
        };

        let (_, bb_matches, insn_matches) =
            find_basic_block_capabilities(&ruleset, addr, &bb, &[]).unwrap();
        assert!(insn_matches.contains_key("opens file"));
        assert!(bb_matches.contains_key("bb sees insn match"));
    }

    #[test]
    fn file_scope_sees_function_scope_matches() {
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
            FunctionFeatures {
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

        let capabilities =
            find_static_capabilities(&ruleset, &freeze, &AnalysisOptions::SERIAL).unwrap();
        assert!(capabilities.matches.contains_key("has api"));
        assert!(capabilities.matches.contains_key("file sees fn match"));
        assert_eq!(capabilities.function_feature_counts.len(), 1);
        assert_eq!(capabilities.function_feature_counts[0].0, fn_addr);
        assert!(capabilities.function_feature_counts[0].1 > 0);
    }

    #[test]
    fn subscope_rule_matches_are_not_in_final_results_by_name_collision() {
        // sanity: a function-scoped rule with an embedded `basic block:`
        // subscope should match via the driver end-to-end, exercising
        // MatchingRuleSet's subscope extraction + the static driver together.
        // note: the subscope entry must be wrapped (e.g. in `and:`) rather
        // than being the rule's sole top-level statement -- a *root-level*
        // bare subscope is never extracted, matching an upstream gap (see
        // ruleset.rs's `extract_children` doc comment); real capa-rules
        // never do this (verified empirically against the pinned corpus).
        let r = rule(
            "rule:\n  meta:\n    name: has bb with api\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - and:\n      - basic block:\n        - api: CreateFileA\n",
        );
        let ruleset = MatchingRuleSet::new(vec![r]).unwrap();

        let bb_addr = Address::Absolute(0x3000);
        let insn_addr = Address::Absolute(0x3001);
        let mut basic_blocks = std::collections::BTreeMap::new();
        basic_blocks.insert(
            bb_addr,
            BasicBlockFeatures {
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
        let (function_matches, _, _, _) = find_code_capabilities(
            &ruleset,
            fn_addr,
            &FunctionFeatures {
                features: vec![],
                basic_blocks,
            },
            &[],
        )
        .unwrap();
        assert!(function_matches.contains_key("has bb with api"));
    }
}
