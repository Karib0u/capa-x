//! Smoke test: instruction/basic-block/function feature
//! extraction must never panic across the layout corpus (PE32/PE32+/
//! ELF32/ELF64, packed/unpacked), and every populated scope must carry the
//! features every instance of that scope always yields upstream (the
//! `BasicBlock` marker feature, exactly one `Mnemonic` feature per
//! instruction).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use std::collections::BTreeMap;

use capa_x::extract::flirt::enrich_static_features;
use capa_x::extract::recovery::analyze;
use capa_x::features::Feature;
use capa_x::freeze::StaticFeatures;
use capa_x::parallel::AnalysisOptions;

mod common;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn empty_static_features() -> StaticFeatures {
    use capa_x::address::Address;
    use capa_x::freeze::SampleHashes;
    StaticFeatures {
        base_address: Address::Absolute(0),
        sample_hashes: SampleHashes {
            md5: String::new(),
            sha1: String::new(),
            sha256: String::new(),
        },
        global_features: Vec::new(),
        file_features: Vec::new(),
        functions: Default::default(),
    }
}

#[test]
fn layout_corpus_extracts_code_features_without_panicking() {
    // FLIRT matching (Phase 2) is exercised by its own test module; this
    // smoke test isolates Phase 3/4/5 extraction, so it skips library
    // recognition entirely (an empty map -- every recovered function stays
    // in scope for extraction).
    let libraries = BTreeMap::new();

    for name in common::read_corpus_list(&root().join("scripts/corpus-layout.txt")) {
        let name = name.as_str();
        let bytes = std::fs::read(root().join("tests/testfiles").join(name))
            .unwrap_or_else(|error| panic!("reading {name}: {error}"));
        let analysis = analyze(&bytes).unwrap_or_else(|error| panic!("recovering {name}: {error}"));

        let mut features = empty_static_features();
        enrich_static_features(
            &mut features,
            &analysis,
            &libraries,
            &AnalysisOptions::SERIAL,
        );

        let mut saw_any_instruction = false;
        for function_features in features.functions.values() {
            for basic_block in function_features.basic_blocks.values() {
                assert!(
                    basic_block
                        .features
                        .iter()
                        .any(|(_, feature)| matches!(feature, Feature::BasicBlock)),
                    "{name}: basic block is missing its BasicBlock marker feature"
                );
                for instruction_features in basic_block.instructions.values() {
                    saw_any_instruction = true;
                    let mnemonics = instruction_features
                        .features
                        .iter()
                        .filter(|(_, feature)| matches!(feature, Feature::Mnemonic(_)))
                        .count();
                    assert_eq!(
                        mnemonics, 1,
                        "{name}: instruction must have exactly one Mnemonic feature"
                    );
                }
            }
        }
        assert!(
            saw_any_instruction,
            "{name}: no instructions were extracted"
        );
    }
}
