//! Dynamic-flavor matching driver, ported from `capa/capabilities/dynamic.py`
//! and the `find_file_capabilities` half of `capa/capabilities/common.py`.
//! Bottom-up: call -> span of calls -> thread -> process -> file.
//!
//! Freeze-driven by design, reading directly from `freeze::DynamicFeatures`'s
//! already-nested, address-sorted tree -- whether that tree was parsed from a
//! freeze file or produced in-process by the extractors.

use std::collections::{BTreeSet, HashMap, VecDeque};

use crate::address::Address;
use crate::capabilities::MatchingRuleSet;
use crate::engine::{self, EngineError, FeatureSet, MatchResults};
use crate::features::Feature;
use crate::freeze::{DynamicFeatures, ProcessFeatures, ThreadFeatures};
use crate::rules::Scope;

/// capa/capabilities/dynamic.py: SPAN_SIZE -- the number of calls that make
/// up a span of calls. Larger recognizes longer call chains at the cost of
/// more evaluation work per call.
const SPAN_SIZE: usize = 20;

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

/// port of `find_call_capabilities`.
pub fn find_call_capabilities(
    ruleset: &MatchingRuleSet,
    call_addr: Address,
    call_features: &[(Address, Feature)],
    global_features: &[Feature],
) -> Result<(FeatureSet, MatchResults), EngineError> {
    let mut features = FeatureSet::new();
    seed(&mut features, call_features, global_features);

    let (_, matches) = ruleset.match_scope(Scope::Call, &features, call_addr)?;
    promote_matches(ruleset, &mut features, &matches);

    Ok((features, matches))
}

/// port of `SpanOfCallsMatcher`: a sliding window (size `SPAN_SIZE`) over a
/// thread's calls, matching span-of-calls-scope rules against the union of
/// features seen in the trailing window, with match deduplication across
/// overlapping/adjacent spans.
struct SpanOfCallsMatcher<'a> {
    ruleset: &'a MatchingRuleSet,
    matches: MatchResults,
    /// the trailing window's per-call feature sets, oldest first.
    current_feature_sets: VecDeque<FeatureSet>,
    /// live union of `current_feature_sets`.
    current_features: FeatureSet,
    /// names of rules matched at the immediately preceding span, so
    /// contiguous runs of the same match only get recorded once.
    last_span_matches: std::collections::HashSet<String>,
}

impl<'a> SpanOfCallsMatcher<'a> {
    fn new(ruleset: &'a MatchingRuleSet) -> Self {
        SpanOfCallsMatcher {
            ruleset,
            matches: HashMap::new(),
            current_feature_sets: VecDeque::with_capacity(SPAN_SIZE),
            current_features: FeatureSet::new(),
            last_span_matches: std::collections::HashSet::new(),
        }
    }

    fn next(&mut self, call_addr: Address, call_features: &FeatureSet) -> Result<(), EngineError> {
        if self.current_feature_sets.len() == SPAN_SIZE {
            if let Some(overflowing) = self.current_feature_sets.pop_front() {
                for (feature, locs) in &overflowing {
                    // global features (arch/os/format) are seeded into every
                    // call's own feature set as a lone NO_ADDRESS location;
                    // leave them permanently in the window rather than
                    // repeatedly removing/re-adding them as calls slide by.
                    if locs.len() == 1 && locs.contains(&Address::NoAddress) {
                        continue;
                    }
                    if let Some(current) = self.current_features.get_mut(feature) {
                        for loc in locs {
                            current.remove(loc);
                        }
                        if current.is_empty() {
                            self.current_features.shift_remove(feature);
                        }
                    }
                }
            }
        }

        self.current_feature_sets.push_back(call_features.clone());
        for (feature, locs) in call_features {
            self.current_features
                .entry(feature.clone())
                .or_default()
                .extend(locs.iter().copied());
        }

        let (_, matches) =
            self.ruleset
                .match_scope(Scope::SpanOfCalls, &self.current_features, call_addr)?;

        let newly_encountered: Vec<&String> = matches
            .keys()
            .filter(|name| !self.last_span_matches.contains(*name))
            .collect();

        let mut suppressed_rules = self.last_span_matches.clone();
        for new_rule in newly_encountered {
            if let Some(rule) = self.ruleset.get(new_rule) {
                for dep in rule.dependencies(&self.ruleset.by_namespace_prefix) {
                    suppressed_rules.remove(&dep);
                }
            }
        }

        for (rule_name, res) in &matches {
            if suppressed_rules.contains(rule_name) {
                continue;
            }
            self.matches
                .entry(rule_name.clone())
                .or_default()
                .extend(res.clone());
        }

        self.last_span_matches = matches.into_keys().collect();
        Ok(())
    }
}

/// port of `find_thread_capabilities`.
pub fn find_thread_capabilities(
    ruleset: &MatchingRuleSet,
    thread_addr: Address,
    thread: &ThreadFeatures,
    global_features: &[Feature],
) -> Result<(FeatureSet, MatchResults, MatchResults, MatchResults), EngineError> {
    let mut features = FeatureSet::new();
    let mut call_matches: MatchResults = HashMap::new();
    let mut span_matcher = SpanOfCallsMatcher::new(ruleset);

    for (call_addr, call) in &thread.calls {
        let (call_features, this_call_matches) =
            find_call_capabilities(ruleset, *call_addr, &call.features, global_features)?;
        engine::merge(&mut features, &call_features);
        extend_matches(&mut call_matches, this_call_matches);

        span_matcher.next(*call_addr, &call_features)?;
    }

    seed(&mut features, &thread.features, global_features);

    let (_, thread_matches) = ruleset.match_scope(Scope::Thread, &features, thread_addr)?;
    promote_matches(ruleset, &mut features, &thread_matches);

    Ok((features, thread_matches, span_matcher.matches, call_matches))
}

/// port of `find_process_capabilities`.
pub fn find_process_capabilities(
    ruleset: &MatchingRuleSet,
    process_addr: Address,
    process: &ProcessFeatures,
    global_features: &[Feature],
) -> Result<
    (
        MatchResults,
        MatchResults,
        MatchResults,
        MatchResults,
        usize,
    ),
    EngineError,
> {
    let mut process_features = FeatureSet::new();
    let mut thread_matches: MatchResults = HashMap::new();
    let mut span_matches: MatchResults = HashMap::new();
    let mut call_matches: MatchResults = HashMap::new();

    for (thread_addr, thread) in &process.threads {
        let (thread_features, this_thread_matches, this_span_matches, this_call_matches) =
            find_thread_capabilities(ruleset, *thread_addr, thread, global_features)?;
        engine::merge(&mut process_features, &thread_features);
        extend_matches(&mut thread_matches, this_thread_matches);
        extend_matches(&mut span_matches, this_span_matches);
        extend_matches(&mut call_matches, this_call_matches);
    }

    seed(&mut process_features, &process.features, global_features);

    // capa/capabilities/dynamic.py: `ProcessCapabilities.feature_count = len(process_features)`.
    let feature_count = process_features.len();

    let (_, process_matches) =
        ruleset.match_scope(Scope::Process, &process_features, process_addr)?;

    Ok((
        process_matches,
        thread_matches,
        span_matches,
        call_matches,
        feature_count,
    ))
}

/// port of the `if va: ... else: ...` guard in `find_file_capabilities`; see
/// `capabilities::static_`'s copy of this for the full explanation.
fn guarded_insert(fs: &mut FeatureSet, feature: Feature, addr: Address) {
    if addr.is_truthy() {
        engine::insert(fs, feature, addr);
    } else {
        fs.entry(feature).or_default();
    }
}

/// port of `find_file_capabilities` (capa/capabilities/common.py), shared
/// with the static driver.
pub fn find_file_capabilities(
    ruleset: &MatchingRuleSet,
    file_features_list: &[(Address, Feature)],
    global_features: &[Feature],
    process_and_lower_features: &FeatureSet,
) -> Result<(MatchResults, usize), EngineError> {
    let mut file_features = FeatureSet::new();
    for (addr, f) in file_features_list {
        guarded_insert(&mut file_features, f.clone(), *addr);
    }
    for f in global_features {
        guarded_insert(&mut file_features, f.clone(), Address::NoAddress);
    }
    engine::merge(&mut file_features, process_and_lower_features);

    let feature_count = file_features.len();

    let (_, matches) = ruleset.match_scope(Scope::File, &file_features, Address::NoAddress)?;
    Ok((matches, feature_count))
}

/// port of `Capabilities`, dynamic flavor: matches plus the feature-count
/// bookkeeping the result document's `meta.analysis.feature_counts` needs.
#[derive(Debug, Clone, Default)]
pub struct DynamicCapabilities {
    pub matches: MatchResults,
    pub file_feature_count: usize,
    /// one entry per process, in `freeze.processes`' (address) iteration order.
    pub process_feature_counts: Vec<(Address, usize)>,
}

/// port of `find_dynamic_capabilities`.
pub fn find_dynamic_capabilities(
    ruleset: &MatchingRuleSet,
    freeze: &DynamicFeatures,
) -> Result<DynamicCapabilities, EngineError> {
    let mut all_process_matches: MatchResults = HashMap::new();
    let mut all_thread_matches: MatchResults = HashMap::new();
    let mut all_span_matches: MatchResults = HashMap::new();
    let mut all_call_matches: MatchResults = HashMap::new();
    let mut process_feature_counts: Vec<(Address, usize)> = Vec::new();

    for (process_addr, process) in &freeze.processes {
        let (process_matches, thread_matches, span_matches, call_matches, feature_count) =
            find_process_capabilities(ruleset, *process_addr, process, &freeze.global_features)?;
        process_feature_counts.push((*process_addr, feature_count));
        extend_matches(&mut all_process_matches, process_matches);
        extend_matches(&mut all_thread_matches, thread_matches);
        extend_matches(&mut all_span_matches, span_matches);
        extend_matches(&mut all_call_matches, call_matches);
    }

    let mut process_and_lower_features = FeatureSet::new();
    for (rule_name, results) in all_call_matches
        .iter()
        .chain(all_span_matches.iter())
        .chain(all_thread_matches.iter())
        .chain(all_process_matches.iter())
    {
        let Some(rule) = ruleset.get(rule_name) else {
            continue;
        };
        let locations: BTreeSet<Address> = results.iter().map(|(addr, _)| *addr).collect();
        engine::index_rule_matches(&mut process_and_lower_features, rule, &locations);
    }

    let (file_matches, file_feature_count) = find_file_capabilities(
        ruleset,
        &freeze.file_features,
        &freeze.global_features,
        &process_and_lower_features,
    )?;

    let mut matches = MatchResults::new();
    extend_matches(&mut matches, all_call_matches);
    extend_matches(&mut matches, all_span_matches);
    extend_matches(&mut matches, all_thread_matches);
    extend_matches(&mut matches, all_process_matches);
    extend_matches(&mut matches, file_matches);
    Ok(DynamicCapabilities {
        matches,
        file_feature_count,
        process_feature_counts,
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

    fn call(pid: u32, tid: u32, id: u64) -> Address {
        Address::Call {
            ppid: 0,
            pid,
            tid,
            id,
        }
    }

    #[test]
    fn call_scope_match_promotes_into_thread() {
        let call_rule = rule(
            "rule:\n  meta:\n    name: calls createfile\n    authors: [t]\n    scopes:\n      static: unsupported\n      dynamic: call\n  features:\n    - api: CreateFileA\n",
        );
        let thread_rule = rule(
            "rule:\n  meta:\n    name: thread sees call match\n    authors: [t]\n    scopes:\n      static: unsupported\n      dynamic: thread\n  features:\n    - match: calls createfile\n",
        );
        let ruleset = MatchingRuleSet::new(vec![call_rule, thread_rule]).unwrap();

        let addr = call(1, 1, 0);
        let thread = ThreadFeatures {
            features: vec![],
            calls: [(
                addr,
                crate::freeze::CallFeatures {
                    name: "CreateFileA".into(),
                    features: vec![(addr, Feature::Api("CreateFileA".into()))],
                },
            )]
            .into_iter()
            .collect(),
        };

        let thread_addr = Address::Thread {
            ppid: 0,
            pid: 1,
            tid: 1,
        };
        let (_, thread_matches, _, call_matches) =
            find_thread_capabilities(&ruleset, thread_addr, &thread, &[]).unwrap();
        assert!(call_matches.contains_key("calls createfile"));
        assert!(thread_matches.contains_key("thread sees call match"));
    }

    #[test]
    fn span_of_calls_matches_across_a_window_of_calls() {
        // a span-scope rule requiring both CreateFileA and WriteFile: no
        // single call has both, but a span containing both calls should.
        let span_rule = rule(
            "rule:\n  meta:\n    name: open then write\n    authors: [t]\n    scopes:\n      static: unsupported\n      dynamic: span of calls\n  features:\n    - and:\n      - api: CreateFileA\n      - api: WriteFile\n",
        );
        let ruleset = MatchingRuleSet::new(vec![span_rule]).unwrap();

        let a1 = call(1, 1, 0);
        let a2 = call(1, 1, 1);
        let thread = ThreadFeatures {
            features: vec![],
            calls: [
                (
                    a1,
                    crate::freeze::CallFeatures {
                        name: "CreateFileA".into(),
                        features: vec![(a1, Feature::Api("CreateFileA".into()))],
                    },
                ),
                (
                    a2,
                    crate::freeze::CallFeatures {
                        name: "WriteFile".into(),
                        features: vec![(a2, Feature::Api("WriteFile".into()))],
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };

        let thread_addr = Address::Thread {
            ppid: 0,
            pid: 1,
            tid: 1,
        };
        let (_, _, span_matches, _) =
            find_thread_capabilities(&ruleset, thread_addr, &thread, &[]).unwrap();
        assert!(span_matches.contains_key("open then write"));
    }

    #[test]
    fn span_of_calls_suppresses_repeated_matches_across_contiguous_spans() {
        // three identical calls: the span should keep matching under the
        // hood (same rule every time), but only record it once, since
        // `last_span_matches` suppresses a rule that matched in the
        // immediately preceding span too.
        let span_rule = rule(
            "rule:\n  meta:\n    name: any create file\n    authors: [t]\n    scopes:\n      static: unsupported\n      dynamic: span of calls\n  features:\n    - api: CreateFileA\n",
        );
        let ruleset = MatchingRuleSet::new(vec![span_rule]).unwrap();

        let addrs = [call(1, 1, 0), call(1, 1, 1), call(1, 1, 2)];
        let calls = addrs
            .into_iter()
            .map(|a| {
                (
                    a,
                    crate::freeze::CallFeatures {
                        name: "CreateFileA".into(),
                        features: vec![(a, Feature::Api("CreateFileA".into()))],
                    },
                )
            })
            .collect();
        let thread = ThreadFeatures {
            features: vec![],
            calls,
        };

        let thread_addr = Address::Thread {
            ppid: 0,
            pid: 1,
            tid: 1,
        };
        let (_, _, span_matches, _) =
            find_thread_capabilities(&ruleset, thread_addr, &thread, &[]).unwrap();
        assert_eq!(
            span_matches.get("any create file").map(|v| v.len()),
            Some(1)
        );
    }

    #[test]
    fn file_scope_sees_process_scope_matches() {
        let process_rule = rule(
            "rule:\n  meta:\n    name: has proc feature\n    authors: [t]\n    scopes:\n      static: unsupported\n      dynamic: process\n  features:\n    - number: 1\n",
        );
        let file_rule = rule(
            "rule:\n  meta:\n    name: file sees proc match\n    authors: [t]\n    scopes:\n      static: unsupported\n      dynamic: file\n  features:\n    - match: has proc feature\n",
        );
        let ruleset = MatchingRuleSet::new(vec![process_rule, file_rule]).unwrap();

        let process_addr = Address::Process { ppid: 0, pid: 1 };
        let mut processes = std::collections::BTreeMap::new();
        processes.insert(
            process_addr,
            ProcessFeatures {
                name: "test.exe".into(),
                features: vec![(
                    process_addr,
                    Feature::Number(crate::features::NumberValue::Int(1)),
                )],
                threads: Default::default(),
            },
        );
        let freeze = DynamicFeatures {
            base_address: Address::NoAddress,
            sample_hashes: crate::freeze::SampleHashes {
                md5: String::new(),
                sha1: String::new(),
                sha256: String::new(),
            },
            global_features: vec![],
            file_features: vec![],
            processes,
        };

        let capabilities = find_dynamic_capabilities(&ruleset, &freeze).unwrap();
        assert!(capabilities.matches.contains_key("has proc feature"));
        assert!(capabilities.matches.contains_key("file sees proc match"));
        assert_eq!(capabilities.process_feature_counts.len(), 1);
        assert_eq!(capabilities.process_feature_counts[0].0, process_addr);
        assert!(capabilities.process_feature_counts[0].1 > 0);
    }
}
