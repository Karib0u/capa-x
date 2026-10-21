//! Recovery and index invariants across the layout corpus.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
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
            assert!(
                !function.blocks.is_empty(),
                "{name}: empty function {:#x}",
                function.addr
            );
            for block in &function.blocks {
                assert!(!block.insns.is_empty(), "{name}: empty block");
                assert_eq!(block.addr, block.insns[0].address);
                let (_, location) = analysis
                    .instructions
                    .range(..=block.addr)
                    .next_back()
                    .unwrap();
                assert!(block.addr < location.next_address);
                // A reference block can start inside an existing location.
                // Its extracted stream must cover contiguous mapped bytes,
                // but need not duplicate the location map's boundaries.
                for pair in block.insns.windows(2) {
                    assert_eq!(pair[0].next_address, pair[1].address);
                }
                for insn in &block.insns {
                    assert_eq!(
                        analysis.image.bytes_at(insn.address, insn.bytes.len()),
                        Some(insn.bytes.as_slice())
                    );
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
fn compatibility_preserves_reference_overlapping_block_streams() {
    for (sample, function, block, evidence) in [
        (
            "70fd3347786ed7a4a43910e6778ef296.exe_",
            0x407d58,
            0x407e41,
            0x407e45,
        ),
        (
            "971e599e6e707349eccea2fd4c8e5f67.exe_",
            0x42c6d9,
            0x42bee1,
            0x42bef4,
        ),
    ] {
        let bytes = std::fs::read(root().join("tests/testfiles").join(sample)).unwrap();
        let analysis = analyze(&bytes).unwrap();
        let block = analysis.functions[&function]
            .blocks
            .iter()
            .find(|candidate| candidate.addr == block)
            .unwrap();
        assert!(block.insns.iter().any(|insn| insn.address == evidence));
        if sample.starts_with("971e") {
            assert_eq!(block.insns.last().unwrap().direct_target, Some(block.addr));
        } else {
            assert_eq!(
                block.insns[0].x86_instruction().memory_displacement64(),
                0x30
            );
        }
    }
}

#[test]
fn compatibility_reproduces_decoder_and_switch_candidate_limits() {
    let samples = root().join("tests/testfiles");
    let evex = std::fs::read(samples.join("f53dfa294d6979145fbb34303cf73bb6.exe_")).unwrap();
    let analysis = analyze(&evex).unwrap();
    assert_eq!(
        analysis.instructions[&0x1400083d9]
            .x86_instruction()
            .mnemonic(),
        iced_x86::Mnemonic::Bound
    );
    let native = capa_x::extract::recovery::analyze_with_backend(
        &evex,
        capa_x::extract::recovery::RecoveryBackend::Native,
    )
    .unwrap();
    assert_ne!(
        native.instructions[&0x1400083d9]
            .x86_instruction()
            .mnemonic(),
        iced_x86::Mnemonic::Bound
    );

    let switch = std::fs::read(
        samples.join("f59035192098e44b86c4648a0de4078edbe80352260276f4755d15d354f5fc58.exe_"),
    )
    .unwrap();
    let analysis = analyze(&switch).unwrap();
    let addresses: BTreeSet<_> = analysis.functions[&0x140079a90]
        .blocks
        .iter()
        .flat_map(|block| block.insns.iter().map(|insn| insn.address))
        .collect();
    assert!(addresses.contains(&0x140079bd8));
    assert!(!addresses.contains(&0x14007b1ad));
    assert!(!addresses.contains(&0x14007b25e));
}

#[test]
fn candidate_anomalies_do_not_claim_data_as_instruction_locations() {
    for (sample, data) in [
        ("5dd0b130d5c3d40c69e3972f39fd7d62.exe_", 0x41bf5c),
        ("648fc498110b11b4313a47a776e6ba40.exe_", 0x56ce38),
    ] {
        let bytes = std::fs::read(root().join("tests/testfiles").join(sample)).unwrap();
        let analysis = analyze(&bytes).unwrap();
        assert!(!analysis.functions.contains_key(&data), "{sample}");
        assert!(!analysis.instructions.contains_key(&data), "{sample}");
    }
}

#[test]
fn callback_and_lea_discovery_recover_reference_function_roots() {
    for (sample, targets) in [
        (
            "a70052c45e907820187c7e6bcdc7ecca.exe_",
            &[0x4051a0, 0x405c40, 0x405e80, 0x406980][..],
        ),
        ("253309d8b3675d3cc61d4bf23aa15d4b.dll_", &[0x1000429f]),
        // This executable callback shares a dead-data section with imports.
        ("c335a9d41185a32ad918c5389ee54235.exe_", &[0x402820]),
        // The x86 LEA monitor follows a pointer slot at 0x6a6b3c; the
        // pointed-to function calls the RC4 implementation at 0x599940.
        (
            "49a34cfbeed733c24392c9217ef46bb6.exe_",
            &[0x599030, 0x599940],
        ),
        // A relocation points to this function. Its lock xadd must not force
        // recovery to depend on finding raw call opcodes in unrelated bytes.
        (
            "74e0758e469ab87f38cda7925d696ea41a122364891860e1ae30fc9ff2f68e7d.exe_",
            &[0x4037bc],
        ),
    ] {
        let bytes = std::fs::read(root().join("tests/testfiles").join(sample)).unwrap();
        let analysis = analyze(&bytes).unwrap();
        for target in targets {
            assert!(
                analysis.functions.contains_key(target),
                "{sample}: {target:#x}"
            );
        }
        if sample.starts_with("49a34") {
            assert!(!analysis.functions.contains_key(&0x6a6b3c));
        }
    }
}

#[test]
fn compatibility_uses_the_stored_relative_relocation_pointer() {
    use capa_x::extract::recovery::{analyze_with_backend, RecoveryBackend};

    let bytes = std::fs::read(
        root()
            .join("tests/testfiles")
            .join("e5e8c139772efe47f738f4788ae9b3dc97960b1c006bc6a406715cab69f27cfc.elf_"),
    )
    .unwrap();
    let compat = analyze(&bytes).unwrap();
    // R_X86_64_RELATIVE at 0x6c08 has addend 0x4b30, but the stored slot
    // is zero. Vivisect reads that slot instead of applying the addend.
    assert!(!compat.functions.contains_key(&0x2004b30));
    let native = analyze_with_backend(&bytes, RecoveryBackend::Native).unwrap();
    assert!(native.functions.contains_key(&0x2004b30));
}

#[test]
fn pointer_discovery_recovers_entries_without_signatures_and_preserves_shared_functions() {
    let bytes = std::fs::read(
        root()
            .join("tests/testfiles")
            .join("b5f0524e69b3a3cf636c7ac366ca57bf5e3a8fdc8a9f01caf196c611a7918a87.elf_"),
    )
    .unwrap();
    let analysis = analyze(&bytes).unwrap();
    // Pinned generic.pointers.analyze creates these prologue-less roots.
    // They expose the previously missing file and socket capabilities.
    for address in [0x80724b0, 0x807d2a0] {
        assert!(analysis.functions.contains_key(&address));
        assert!(analysis.seeds[&address].contains(&SeedKind::PointerTarget));
    }

    let bytes = std::fs::read(
        root()
            .join("tests/testfiles")
            .join("6f99a2c8944cb02ff28c6f9ced59b161.exe_"),
    )
    .unwrap();
    let analysis = analyze(&bytes).unwrap();
    // The relocation to 0x413420 is an instruction operand, not a data
    // pointer. Promoting it before emucode accepts it would let its callee
    // claim this shared function before the signature pass reaches it.
    assert!(analysis.functions.contains_key(&0x40d22a));
    assert!(!analysis.seeds[&0x413420].contains(&SeedKind::PointerTarget));
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
fn import_call_discovery_preserves_reference_function_ownership() {
    for (name, function, last_owned, loose_continuation) in [
        (
            "1e9fc7f32bd5522dd0222932eb9f1d8bd0a2e132c7b46cfcc622ad97831e6128.exe_",
            0x4028d2,
            0x40293b,
            0x402940,
        ),
        (
            "31600ad0d1a7ea615690df111ae36c73.exe_",
            0x401155,
            0x4011c2,
            0x4011c7,
        ),
        (
            "a563c50c5fa0fd541248acaf72cc4e7d.exe_",
            0x401490,
            0x4015c7,
            0x4015cc,
        ),
    ] {
        let bytes = std::fs::read(root().join("tests/testfiles").join(name)).unwrap();
        let analysis = analyze(&bytes).unwrap();
        let owned: BTreeSet<_> = analysis.functions[&function]
            .blocks
            .iter()
            .flat_map(|block| block.insns.iter().map(|insn| insn.address))
            .collect();
        assert!(
            owned.contains(&last_owned),
            "{name}: missing recursive call"
        );
        assert!(
            !owned.contains(&loose_continuation),
            "{name}: claimed instructions decoded after function creation"
        );
        assert!(
            analysis.instructions.contains_key(&loose_continuation),
            "{name}: loose code must still be decoded"
        );
        assert!(
            !analysis.is_noreturn_va(function),
            "{name}: false no-return"
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
fn native_unwind_boundaries_differ_from_reference_fallthrough() {
    let bytes = std::fs::read(root().join("tests/testfiles/29a76e413ffe0f78b62926b8455082d6.exe_"))
        .unwrap();
    let analysis = analyze(&bytes).unwrap();
    assert!(analysis.functions[&0x1400e1300]
        .blocks
        .iter()
        .flat_map(|block| &block.insns)
        .any(|insn| insn.address == 0x1400e1360));
    let analysis = capa_x::extract::recovery::analyze_with_backend(
        &bytes,
        capa_x::extract::recovery::RecoveryBackend::Native,
    )
    .unwrap();
    let first = &analysis.functions[&0x1400e1300];
    assert!(first
        .blocks
        .iter()
        .flat_map(|block| &block.insns)
        .all(|insn| insn.address < 0x1400e1360));
    assert!(analysis.functions.contains_key(&0x1400e1360));
    assert!(!analysis.is_noreturn_va(0x1400e1300));
}
