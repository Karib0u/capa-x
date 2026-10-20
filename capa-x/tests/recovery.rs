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

#[test]
fn recovery_gaps_do_not_cut_off_the_documented_callers() {
    for (name, function, recovered_instruction) in [
        ("70fd3347786ed7a4a43910e6778ef296.exe_", 0x407e2c, 0x407e74),
        (
            "749cf36adc5513c92c7acc836d20935e3c433f3c2d5641293e7a9c57c5ce22c2.elf_",
            0x200a4b0,
            0x200a4b0,
        ),
        ("2f7f5fb5de175e770d7eae87666f9831.elf_", 0x406e90, 0x406f13),
    ] {
        let bytes = std::fs::read(root().join("tests/testfiles").join(name)).unwrap();
        let analysis = analyze(&bytes).unwrap();
        assert!(
            !analysis.is_noreturn_va(function),
            "{name}: false no-return"
        );
        assert!(
            analysis.functions[&function]
                .blocks
                .iter()
                .flat_map(|block| &block.insns)
                .any(|insn| insn.address == recovered_instruction),
            "{name}: missing caller continuation"
        );
    }
}

#[test]
fn resource_code_recovers_without_absorbing_the_unpacked_region() {
    let bytes = std::fs::read(root().join("tests/testfiles/0cd2b334aede270b14868db28211cde3.exe_"))
        .unwrap();
    let analysis = analyze(&bytes).unwrap();
    let entry = &analysis.functions[&0x401000];
    let addresses: Vec<_> = entry
        .blocks
        .iter()
        .flat_map(|block| block.insns.iter().map(|insn| insn.address))
        .collect();
    assert!(addresses.contains(&0x531cb3));
    assert!(!addresses.contains(&0x402fbe));
    assert_eq!(addresses.len(), 22, "pinned reference entry extent");
    assert!(analysis.functions.contains_key(&0x531f50));
    assert!(analysis.functions.contains_key(&0x53413e));
}

#[test]
fn unwind_entries_do_not_merge_adjacent_function_scopes() {
    let bytes = std::fs::read(root().join("tests/testfiles/29a76e413ffe0f78b62926b8455082d6.exe_"))
        .unwrap();
    let analysis = analyze(&bytes).unwrap();
    let first = &analysis.functions[&0x1400e1300];
    assert!(first
        .blocks
        .iter()
        .flat_map(|block| &block.insns)
        .all(|insn| insn.address < 0x1400e1360));
    assert!(analysis.functions.contains_key(&0x1400e1360));
    assert!(!analysis.is_noreturn_va(0x1400e1300));
}
