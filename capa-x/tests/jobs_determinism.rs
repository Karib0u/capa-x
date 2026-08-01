//! `--jobs N` must be indistinguishable from `--jobs 1`.
//!
//! This is the library-level half of the determinism check: the parallel
//! seams in `extract::flirt::enrich_static_features` and
//! `capabilities::find_static_capabilities` are compared against the serial
//! reference on real samples, repeatedly, so a scheduling-dependent result
//! fails here rather than in a corpus run. The CLI-level half -- normalized
//! JSON from the shipped binary over a sample list -- is
//! `scripts/determinism.py`.
//!
//! The repeats are the point. A join that depends on completion order can
//! easily produce the right answer on a quiet machine and the wrong one under
//! load, so every comparison runs `REPEATS` times rather than once.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use capa_x::capabilities::{find_static_capabilities, MatchingRuleSet};
use capa_x::extract::elf::extract_elf;
use capa_x::extract::flirt::enrich_static_features;
use capa_x::extract::pe::extract_pe;
use capa_x::extract::recovery::{analyze, Analysis};
use capa_x::extract::{looks_like_elf, looks_like_pe};
use capa_x::freeze::StaticFeatures;
use capa_x::parallel::{AnalysisOptions, Jobs};
use capa_x::rules::{load_rule_directory, Rule};

/// One PE and one x86/x64 ELF, both large enough to have hundreds of
/// functions to distribute -- a two-function sample would take the serial
/// path in `parallel::try_map` and prove nothing. The AArch64 sample adds
/// The AArch64 parallel seam (`aarch64_features`/
/// `aarch64_basicblock_features`, dispatched from the same
/// `enrich_static_features` per-function loop as the x86 extractors) to
/// this gate -- J2/J11 for the new backend, not just the existing ones.
const SAMPLES: [&str; 3] = [
    "Practical Malware Analysis Lab 01-01.exe_",
    "055da8e6ccfe5a9380231ea04b850e18.elf_",
    "aarch64/687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf_",
];

const REPEATS: usize = 5;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capa-x has a parent directory")
        .to_path_buf()
}

fn job_counts() -> Vec<Jobs> {
    let mut counts = vec![
        Jobs::new(2).unwrap(),
        Jobs::new(4).unwrap(),
        Jobs::default(),
    ];
    counts.dedup();
    counts
}

fn analyze_sample(name: &str) -> (Vec<u8>, Analysis) {
    let path = workspace_root().join("tests/testfiles").join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let analysis = analyze(&bytes).unwrap_or_else(|e| panic!("recovering {}: {e}", path.display()));
    (bytes, analysis)
}

fn extract(bytes: &[u8], analysis: &Analysis, options: &AnalysisOptions) -> StaticFeatures {
    let mut features = if looks_like_pe(bytes) {
        extract_pe(bytes).expect("PE file features extract")
    } else if looks_like_elf(bytes) {
        extract_elf(bytes).expect("ELF file features extract")
    } else {
        panic!("sample is neither PE nor ELF");
    };
    // FLIRT is exercised elsewhere; an empty map here keeps every recovered
    // function in the parallel extraction path instead of excluding the
    // library ones.
    enrich_static_features(&mut features, analysis, &BTreeMap::new(), options);
    features
}

/// A structural fingerprint of the extracted tree. `StaticFeatures` is built
/// from `Vec`s and `BTreeMap`s, so `Debug` is a faithful, ordered rendering of
/// every feature and address in it -- including the *order* of the per-scope
/// feature vectors, which is what a bad parallel join would disturb.
fn fingerprint(features: &StaticFeatures) -> String {
    format!("{features:?}")
}

fn ruleset() -> MatchingRuleSet {
    let rules: Vec<Rule> =
        load_rule_directory(&workspace_root().join("rules"), &AnalysisOptions::SERIAL)
            .expect("pinned rules load");
    MatchingRuleSet::new(rules).expect("pinned rules build a matching set")
}

#[test]
fn rule_loading_is_independent_of_job_count() {
    // The parse is per file and the result stays in sorted-path order, so the
    // whole corpus must come back identical however it was distributed --
    // including rule *order*, which `MatchingRuleSet`'s topological ordering
    // and subscope naming both depend on.
    let dir = workspace_root().join("rules");
    let serial = load_rule_directory(&dir, &AnalysisOptions::SERIAL).expect("pinned rules load");
    let names: Vec<&str> = serial.iter().map(|rule| rule.name.as_str()).collect();

    for jobs in job_counts() {
        for repeat in 0..REPEATS {
            let parallel = load_rule_directory(&dir, &AnalysisOptions::with_jobs(jobs))
                .expect("pinned rules load");
            let parallel_names: Vec<&str> =
                parallel.iter().map(|rule| rule.name.as_str()).collect();
            assert_eq!(
                parallel_names,
                names,
                "rule order differs at --jobs {} (repeat {repeat})",
                jobs.get()
            );
        }
    }
}

#[test]
fn extraction_is_independent_of_job_count() {
    for name in SAMPLES {
        let (bytes, analysis) = analyze_sample(name);
        let serial = fingerprint(&extract(&bytes, &analysis, &AnalysisOptions::SERIAL));
        assert!(
            analysis.functions.len() > 8,
            "{name}: too few functions to distribute ({})",
            analysis.functions.len()
        );

        for jobs in job_counts() {
            for repeat in 0..REPEATS {
                let parallel = fingerprint(&extract(
                    &bytes,
                    &analysis,
                    &AnalysisOptions::with_jobs(jobs),
                ));
                assert!(
                    parallel == serial,
                    "{name}: extraction differs at --jobs {} (repeat {repeat})",
                    jobs.get()
                );
            }
        }
    }
}

#[test]
fn the_result_document_is_independent_of_job_count() {
    let ruleset = ruleset();

    for name in SAMPLES {
        let (bytes, analysis) = analyze_sample(name);
        let features = extract(&bytes, &analysis, &AnalysisOptions::SERIAL);

        let serial = render(&ruleset, &features, &AnalysisOptions::SERIAL);
        for jobs in job_counts() {
            for repeat in 0..REPEATS {
                let parallel = render(&ruleset, &features, &AnalysisOptions::with_jobs(jobs));
                assert!(
                    parallel == serial,
                    "{name}: result document differs at --jobs {} (repeat {repeat})",
                    jobs.get()
                );
            }
        }
    }
}

/// Matches, then serializes the result document -- the same bytes the CLI's
/// `-j` prints, which is what J2 actually gates on. Comparing the raw
/// `MatchResults` would compare a `HashMap`, whose iteration order is
/// unstable for reasons that have nothing to do with threads.
fn render(
    ruleset: &MatchingRuleSet,
    features: &StaticFeatures,
    options: &AnalysisOptions,
) -> String {
    use capa_x::rd::{self, MetaInputs, StaticCounts, ARCH_AUTO, OS_AUTO};

    let capabilities =
        find_static_capabilities(ruleset, features, options).expect("matching succeeds");
    let layout = rd::compute_static_layout(ruleset, features, &capabilities.matches);
    let inputs = MetaInputs {
        argv: None,
        version: "test".to_string(),
        // Fixed, so the only thing that can differ between two renderings is
        // the matching itself.
        timestamp: "2026-01-01T00:00:00.000000".to_string(),
        sample: rd::Sample {
            md5: features.sample_hashes.md5.clone(),
            sha1: features.sample_hashes.sha1.clone(),
            sha256: features.sample_hashes.sha256.clone(),
            path: "sample".to_string(),
        },
        input_format_fallback: "pe".to_string(),
        os_override: OS_AUTO.to_string(),
        arch_override: ARCH_AUTO.to_string(),
        rules_paths: vec!["rules".to_string()],
    };
    let counts = StaticCounts {
        file_feature_count: capabilities.file_feature_count as u64,
        function_feature_counts: capabilities
            .function_feature_counts
            .iter()
            .map(|(addr, count)| (*addr, *count as u64))
            .collect(),
    };
    let meta = rd::build_static_metadata(inputs, features, counts, Vec::new(), layout);
    let doc = rd::build_result_document(ruleset, &capabilities.matches, meta)
        .expect("result document builds");
    serde_json::to_string(&doc).expect("result document serializes")
}

/// A worker failure must fail the whole analysis, and say which function and
/// which phase -- there is no stack trace to read off a worker thread, so if
/// the address is not in the message it is gone.
///
/// The injected failure is a real one rather than a test hook: a rule whose
/// *only* top-level statement is a bare `basic block:` subscope is never
/// extracted into its own rule (see `capabilities::ruleset`'s
/// `extract_children`), so evaluating it at function scope raises
/// `EngineError::UnextractedSubscope` from inside the per-function loop.
#[test]
fn a_worker_error_fails_the_analysis_with_context() {
    use capa_x::address::Address;
    use capa_x::features::Feature;
    use capa_x::freeze::{BasicBlockFeatures, FunctionFeatures, InstructionFeatures};

    let rule = Rule::from_yaml(
        "rule:\n  meta:\n    name: unextractable\n    authors: [t]\n    scopes:\n      static: \
         function\n      dynamic: unsupported\n  features:\n    - basic block:\n      - api: \
         CreateFileA\n",
    )
    .expect("rule parses");
    let ruleset = MatchingRuleSet::new(vec![rule]).expect("ruleset builds");

    // Enough functions that the parallel path is taken and the failing one is
    // not simply the first thing any worker touches.
    let mut functions = BTreeMap::new();
    for index in 0..64u64 {
        let addr = Address::Absolute(0x1000 + index * 0x100);
        let insn = Address::Absolute(0x1000 + index * 0x100 + 1);
        functions.insert(
            addr,
            FunctionFeatures {
                features: vec![],
                basic_blocks: [(
                    addr,
                    BasicBlockFeatures {
                        features: vec![],
                        instructions: [(
                            insn,
                            InstructionFeatures {
                                features: vec![(insn, Feature::Api("CreateFileA".into()))],
                            },
                        )]
                        .into_iter()
                        .collect(),
                    },
                )]
                .into_iter()
                .collect(),
            },
        );
    }
    let features = StaticFeatures {
        base_address: Address::Absolute(0),
        sample_hashes: capa_x::freeze::SampleHashes {
            md5: String::new(),
            sha1: String::new(),
            sha256: String::new(),
        },
        global_features: vec![],
        file_features: vec![],
        functions,
    };

    for options in [
        AnalysisOptions::SERIAL,
        AnalysisOptions::with_jobs(Jobs::new(8).unwrap()),
    ] {
        let error = find_static_capabilities(&ruleset, &features, &options)
            .expect_err("an unextracted subscope must fail the analysis");
        let message = error.to_string();
        assert!(
            message.contains("code-scope matching of function"),
            "no phase in {message:?}"
        );
        // The lowest-addressed function is the lowest-indexed work item, so
        // the *same* function is named however many threads ran.
        assert!(
            message.contains("0x1000"),
            "no failing function address in {message:?}"
        );
        assert!(
            message.contains("subscope"),
            "the underlying cause was dropped from {message:?}"
        );
    }
}
