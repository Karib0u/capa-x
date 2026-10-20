//! Exact rule and address regressions against the immutable capa 10.0.0 index.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::Path;

use capa_x::api::{analyze, Input};
use capa_x::capabilities::MatchingRuleSet;
use capa_x::parallel::AnalysisOptions;
use capa_x::result_document::RdAddress;
use capa_x::rules::{collect_rule_file_paths, Rule};
use flate2::read::GzDecoder;

#[test]
fn recovered_functions_match_all_reference_rule_addresses() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let expected: BTreeMap<String, BTreeMap<String, BTreeSet<RdAddress>>> =
        serde_json::from_reader(GzDecoder::new(
            File::open(root.join("tests/reference-results/capa-10.0.0/matches.json.gz")).unwrap(),
        ))
        .unwrap();
    let mut paths = Vec::new();
    collect_rule_file_paths(&root.join("rules"), &mut paths);
    paths.sort();
    let rules = MatchingRuleSet::new(
        paths
            .iter()
            .map(|path| Rule::from_yaml_file(path).unwrap())
            .collect(),
    )
    .unwrap();
    for sample in [
        // A computed memory jump exposes a recursive callee before importcalls.
        "0ce3bfa972ced61884ae7c1d77c7d4c45e17c7d767e669610cf2ef72b636b464.exe_",
        // Existing typed data must not create additional loop-bearing functions.
        "17264e3126a97c319a6a0c61e6da951e.dll_",
        // SSE instructions in a pointer-backed function candidate.
        "22d0a2e4c9c2163b2bf5f0e41a2e1762.exe_",
        // A prefixed LOOP keeps the complete 32-bit branch address.
        "2826b762b9c268601a44974ef469a671b441e798a6c3cbb40070450c6c030ba2.exe_",
        // Import-fragment extents must also constrain no-return propagation.
        "e5369ac309f1be6d77afeeb3edab0ed8.exe_",
        // A function falls through an unwind entry but keeps its creation extent.
        "e3a6fbbc9b315141da37e5abbae05bf20aa9f48d5f569c6353360f59a0315245.exe_",
    ] {
        let bytes = std::fs::read(root.join("tests/testfiles").join(sample)).unwrap();
        let input = Input {
            bytes: &bytes,
            sample_path: sample.into(),
            rules_paths: vec!["rules".into()],
            argv: Some(Vec::new()),
        };
        let result = analyze(&input, &rules, &AnalysisOptions::SERIAL).unwrap();
        let actual: BTreeMap<_, BTreeSet<_>> = result
            .rules
            .into_iter()
            .map(|(name, rule)| {
                (
                    name,
                    rule.matches
                        .into_iter()
                        .map(|(address, _)| address)
                        .collect(),
                )
            })
            .collect();
        assert_eq!(&actual, expected.get(sample).unwrap(), "{sample}");
    }
}
