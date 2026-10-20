#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::extract::image::SHELLCODE_BASE;
use crate::extract::recovery::{analyze_shellcode, EdgeKind, SeedKind};
use std::collections::BTreeSet;

fn arm_code() -> Vec<u8> {
    let mut code = vec![0; 0x8c];
    // sub w8,w0,1; cmp w8,2; b.hi default; adrp x9,page;
    // add x9,x9,0x80; ldrsw x8,[x9,x8,lsl 2]; add x8,x8,x9; br x8
    for (i, word) in [
        0x5100_0408u32,
        0x7100_091f,
        0x5400_01c8,
        0x9000_0009,
        0x9102_0129,
        0xb8a8_7928,
        0x8b09_0108,
        0xd61f_0100,
    ]
    .into_iter()
    .enumerate()
    {
        code[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    for offset in [0x40, 0x44, 0x48] {
        code[offset..offset + 4].copy_from_slice(&0xd65f_03c0u32.to_le_bytes());
    }
    for (i, target) in [0x40i32, 0x44, 0x40].into_iter().enumerate() {
        code[0x80 + i * 4..0x84 + i * 4].copy_from_slice(&(target - 0x80).to_le_bytes());
    }
    code
}

fn x64_code(remap: bool) -> (Vec<u8>, u64) {
    let mut code = vec![
        0x89, 0xf8, // mov eax,edi
        0x83, 0xf8, 2, // cmp eax,2
        0x77, 0x39, // ja default (0x40)
        0x4c, 0x8d, 0x1d, 0xf2, 0xff, 0xff, 0xff, // lea r11,image base
    ];
    if remap {
        code.extend_from_slice(&[0x41, 0x0f, 0xb6, 0x84, 0x03, 0x8c, 0, 0, 0]);
    } else {
        code.extend_from_slice(&[0x48, 0x98]); // cdqe
    }
    code.extend_from_slice(&[0x41, 0x8b, 0x8c, 0x83, 0x80, 0, 0, 0]);
    code.extend_from_slice(&[0x49, 0x03, 0xcb]); // add rcx,r11
    let branch = SHELLCODE_BASE + code.len() as u64;
    code.extend_from_slice(&[0xff, 0xe1]); // jmp rcx
    code.resize(0x8f, 0xcc);
    for offset in [0x40, 0x44, 0x48] {
        code[offset] = 0xc3;
    }
    for (i, target) in [0x40u32, 0x44, 0x48].into_iter().enumerate() {
        code[0x80 + i * 4..0x84 + i * 4].copy_from_slice(&target.to_le_bytes());
    }
    code[0x8c..0x8f].copy_from_slice(&[2, 0, 2]);
    (code, branch)
}

fn resolved(code: &[u8], arch: Architecture, branch: u64) -> Option<Vec<u64>> {
    let analysis = analyze_shellcode(code, arch).unwrap();
    targets(&analysis, analysis.instructions.get(&branch)?)
}

#[test]
fn arm_signed_offsets_recover_sorted_unique_cfg_edges() {
    let analysis = analyze_shellcode(&arm_code(), Architecture::AArch64).unwrap();
    let function = analysis.functions.get(&SHELLCODE_BASE).unwrap();
    let dispatch = function
        .blocks
        .iter()
        .find(|b| {
            b.insns
                .last()
                .is_some_and(|i| i.address == SHELLCODE_BASE + 28)
        })
        .unwrap();
    assert_eq!(
        dispatch
            .succs
            .iter()
            .map(|e| (e.target, e.kind))
            .collect::<Vec<_>>(),
        vec![
            (SHELLCODE_BASE + 0x40, EdgeKind::JumpTable),
            (SHELLCODE_BASE + 0x44, EdgeKind::JumpTable)
        ]
    );
    assert!(function
        .blocks
        .iter()
        .any(|b| b.addr == SHELLCODE_BASE + 0x44));
}

#[test]
fn x64_direct_and_remapped_selectors_respect_the_guard() {
    for remap in [false, true] {
        let (code, branch) = x64_code(remap);
        let expected = if remap {
            vec![0x40, 0x48]
        } else {
            vec![0x40, 0x44, 0x48]
        };
        assert_eq!(
            resolved(&code, Architecture::X64, branch),
            Some(expected.into_iter().map(|v| SHELLCODE_BASE + v).collect())
        );
    }
}

#[test]
fn exclusive_bounds_do_not_read_an_extra_entry() {
    let (mut code, branch) = x64_code(false);
    code[5] = 0x73; // jae
    code[0x88..0x8c].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        resolved(&code, Architecture::X64, branch),
        Some(vec![SHELLCODE_BASE + 0x40, SHELLCODE_BASE + 0x44])
    );
    let mut code = arm_code();
    code[8..12].copy_from_slice(&0x5400_01c2u32.to_le_bytes()); // b.hs
    code[0x88..0x8c].copy_from_slice(&i32::MAX.to_le_bytes());
    assert_eq!(
        resolved(&code, Architecture::AArch64, SHELLCODE_BASE + 28),
        Some(vec![SHELLCODE_BASE + 0x40, SHELLCODE_BASE + 0x44])
    );
}

#[test]
fn x64_signed_offsets_can_point_before_the_table_base() {
    let (mut code, branch) = x64_code(false);
    code[10..14].copy_from_slice(&0x72i32.to_le_bytes()); // lea r11,base+0x80
    code[16..18].copy_from_slice(&[0x49, 0x63]); // movsxd rcx,dword [...]
    code[20..24].copy_from_slice(&0u32.to_le_bytes()); // table displacement
    for (i, offset) in [-64i32, -60, -56].into_iter().enumerate() {
        code[0x80 + i * 4..0x84 + i * 4].copy_from_slice(&offset.to_le_bytes());
    }
    assert_eq!(
        resolved(&code, Architecture::X64, branch),
        Some(vec![
            SHELLCODE_BASE + 0x40,
            SHELLCODE_BASE + 0x44,
            SHELLCODE_BASE + 0x48
        ])
    );
}

#[test]
fn arm_extended_w_index_does_not_need_a_zeroed_x_register() {
    for extend in [2u32, 6] {
        let mut code = arm_code();
        code[..4].copy_from_slice(&0xd503_201fu32.to_le_bytes()); // nop
        let load = (0xb8a8_7928u32 & !(7 << 13)) | (extend << 13);
        code[20..24].copy_from_slice(&load.to_le_bytes());
        assert_eq!(
            resolved(&code, Architecture::AArch64, SHELLCODE_BASE + 28),
            Some(vec![SHELLCODE_BASE + 0x40, SHELLCODE_BASE + 0x44])
        );
    }
}

#[test]
fn arm_rejects_signed_guard_register_mismatch_and_unbounded_high_bits() {
    for (offset, replacement) in [
        (8, 0x5400_01ccu32), // b.gt is not an unsigned range check
        (20, 0xb8aa_7928),   // load indexes x10, not the checked x8
        (16, 0x9102_0149),   // base ADD reads x10, not ADRP's x9
        (0, 0xd503_201f),    // nop leaves the high bits of x8 unbounded
        (4, 0x7110_011f),    // cmp w8,0x400 exceeds the case budget
    ] {
        let mut code = arm_code();
        code[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());
        assert_eq!(
            resolved(&code, Architecture::AArch64, SHELLCODE_BASE + 28),
            None
        );
    }
}

#[test]
fn tables_fail_closed_on_truncation_bad_targets_or_guard_reentry() {
    let (code, branch) = x64_code(false);
    assert_eq!(resolved(&code[..0x88], Architecture::X64, branch), None);
    for target in [u32::MAX, 7] {
        let mut malformed = code.clone();
        malformed[0x88..0x8c].copy_from_slice(&target.to_le_bytes());
        assert_eq!(resolved(&malformed, Architecture::X64, branch), None);
    }
    let mut arm = arm_code();
    arm[0x88..0x8c].copy_from_slice(&(-63i32).to_le_bytes());
    assert_eq!(
        resolved(&arm, Architecture::AArch64, SHELLCODE_BASE + 28),
        None
    );
    let mut arm = arm_code();
    arm[0x44..0x48].fill(0xff); // no decoded instruction at this arm
    assert_eq!(
        resolved(&arm, Architecture::AArch64, SHELLCODE_BASE + 28),
        None
    );
}

#[test]
fn x64_rejects_signed_guard_clobbered_base_and_unbounded_selector() {
    let (code, branch) = x64_code(false);
    let mut signed = code.clone();
    signed[5] = 0x7f; // jg
    assert_eq!(resolved(&signed, Architecture::X64, branch), None);
    let mut wrong_base = code;
    wrong_base[26] = 0xca; // add rcx,r10 instead of r11
    assert_eq!(resolved(&wrong_base, Architecture::X64, branch), None);
    let (mut code, branch) = x64_code(true);
    code[..2].copy_from_slice(&[0x90, 0x90]); // no 32-bit selector definition
    assert_eq!(resolved(&code, Architecture::X64, branch), None);
}

#[test]
fn alternate_entries_cannot_bypass_the_guard() {
    let (code, branch) = x64_code(false);
    let mut analysis = analyze_shellcode(&code, Architecture::X64).unwrap();
    analysis
        .code_xrefs
        .insert(SHELLCODE_BASE + 7, vec![SHELLCODE_BASE + 0x100]);
    assert_eq!(
        targets(&analysis, analysis.instructions.get(&branch).unwrap()),
        None
    );
    analysis.code_xrefs.remove(&(SHELLCODE_BASE + 7));
    analysis
        .seeds
        .insert(SHELLCODE_BASE + 7, BTreeSet::from([SeedKind::CallTarget]));
    assert_eq!(
        targets(&analysis, analysis.instructions.get(&branch).unwrap()),
        None
    );
}

#[test]
fn pinned_switches_recover_the_missing_arms_and_called_functions() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/testfiles");
    for (sample, function, arm) in [
        (
            "aarch64/687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf_",
            0x105128,
            0x105450,
        ),
        (
            "276f691a3df25481f59d79781799e35f.exe_",
            0x14002d780,
            0x14002d83f,
        ),
        (
            "f59035192098e44b86c4648a0de4078edbe80352260276f4755d15d354f5fc58.exe_",
            0x140079a90,
            0x140079b0c,
        ),
    ] {
        let analysis =
            crate::extract::recovery::analyze(&std::fs::read(root.join(sample)).unwrap()).unwrap();
        assert!(
            analysis
                .functions
                .get(&function)
                .unwrap()
                .blocks
                .iter()
                .any(|block| block.insns.iter().any(|insn| insn.address == arm)),
            "{sample}: missing switch arm {arm:#x}"
        );
        if sample.starts_with("276f691") {
            assert!(analysis.functions.contains_key(&0x14002f8d0));
            assert!(analysis.functions.contains_key(&0x140030300));
        }
    }
}
