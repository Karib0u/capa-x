//! Recovery and index invariants across the layout corpus.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use capa_x::extract::recovery::{analyze, SeedKind};

mod common;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[test]
fn layout_corpus_recovers_every_deterministic_seed_without_empty_blocks() {
    for name in common::read_corpus_list(&root().join("scripts/corpus-layout.txt")) {
        let name = name.as_str();
        let bytes = std::fs::read(root().join("tests/testfiles").join(name))
            .unwrap_or_else(|error| panic!("reading {name}: {error}"));
        let analysis = analyze(&bytes).unwrap_or_else(|error| panic!("recovering {name}: {error}"));
        assert!(!analysis.functions.is_empty(), "{name}: no functions");

        for (address, kinds) in &analysis.seeds {
            let deterministic = kinds.iter().any(|kind| {
                !matches!(
                    kind,
                    SeedKind::CallTarget | SeedKind::FunctionSignature | SeedKind::Prologue
                )
            });
            if deterministic {
                assert!(
                    analysis.functions.contains_key(address),
                    "{name}: deterministic seed {address:#x} is missing"
                );
            }
        }
        for function in analysis.functions.values() {
            assert!(!function.blocks.is_empty(), "{name}: empty function");
            for block in &function.blocks {
                assert!(!block.insns.is_empty(), "{name}: empty block");
                assert_eq!(block.addr, block.insns[0].address);
                for insn in &block.insns {
                    assert!(analysis.instructions.contains_key(&insn.address));
                }
            }
        }
    }
}

#[test]
fn recovery_populates_code_data_and_call_indexes() {
    let name = "Practical Malware Analysis Lab 01-01.exe_";
    let bytes = std::fs::read(root().join("tests/testfiles").join(name)).expect("sample exists");
    let analysis = analyze(&bytes).expect("sample recovers");
    assert!(!analysis.code_xrefs.is_empty());
    assert!(!analysis.data_xrefs.is_empty());
    assert!(!analysis.callers.is_empty());
    assert!(!analysis.callees.is_empty());
}
