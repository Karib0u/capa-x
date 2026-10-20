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
