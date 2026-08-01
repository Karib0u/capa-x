//! Basic-block-scope feature extraction, ported from
//! `capa/features/extractors/viv/basicblock.py` (v9.4.0, see PINNED.md).

use iced_x86::FlowControl;
use iced_x86::Register;

use crate::address::Address;
use crate::features::Feature;

use super::image::DecodedInstruction;
use super::insn_features::mnemonic_text;
use super::operand::{classify_operand, Operand};
use super::recovery::{self, BasicBlock};

/// capa/features/extractors/helpers.py: MIN_STACKSTRING_LEN
const MIN_STACKSTRING_LEN: usize = 8;

/// capa/features/extractors/viv/basicblock.py: `extract_features` /
/// `BASIC_BLOCK_HANDLERS`. Also yields the `BasicBlock` feature itself,
/// needed for rules' `count(basic blocks): N`
/// (`capa/features/basicblock.py`).
pub fn extract_features(block: &BasicBlock) -> Vec<(Address, Feature)> {
    let mut out = vec![(Address::Absolute(block.addr), Feature::BasicBlock)];
    out.extend(extract_bb_tight_loop(block));
    out.extend(extract_stackstring(block));
    out
}

/// port of `extract_bb_tight_loop` / `_bb_has_tight_loop`: does the block's
/// last instruction conditionally branch back to the block's own start?
/// Unlike `extract_function_loop` (Phase 5), an unconditional self-jump
/// does *not* count here -- matches upstream's explicit `BR_COND` check.
fn extract_bb_tight_loop(block: &BasicBlock) -> Vec<(Address, Feature)> {
    if bb_has_tight_loop(block) {
        vec![(
            Address::Absolute(block.addr),
            Feature::Characteristic("tight loop".to_string()),
        )]
    } else {
        Vec::new()
    }
}

fn bb_has_tight_loop(block: &BasicBlock) -> bool {
    let Some(last) = block.insns.last() else {
        return false;
    };
    if last.x86_instruction().flow_control() != FlowControl::ConditionalBranch {
        return false;
    }
    recovery::direct_target(last) == Some(block.addr)
}

/// port of `extract_stackstring` / `_bb_has_stackstring`.
fn extract_stackstring(block: &BasicBlock) -> Vec<(Address, Feature)> {
    if bb_has_stackstring(block) {
        vec![(
            Address::Absolute(block.addr),
            Feature::Characteristic("stack string".to_string()),
        )]
    } else {
        Vec::new()
    }
}

fn bb_has_stackstring(block: &BasicBlock) -> bool {
    let mut count = 0usize;
    for insn in &block.insns {
        if is_mov_imm_to_stack(insn) {
            count += printable_len(insn);
        }
        if count > MIN_STACKSTRING_LEN {
            return true;
        }
    }
    false
}

/// port of `is_mov_imm_to_stack`. `mnem.startswith("mov")` in practice only
/// ever matches plain `mov` here: `movzx`/`movsx`/string-move mnemonics
/// never take an immediate memory-write operand, so the broader prefix
/// check and an exact `"mov"` check are behaviorally the same; the prefix
/// check is kept for fidelity with the source.
fn is_mov_imm_to_stack(insn: &DecodedInstruction) -> bool {
    if !mnemonic_text(insn).starts_with("mov") {
        return false;
    }
    if insn.x86_instruction().op_count() != 2 {
        return false;
    }
    if !matches!(classify_operand(insn.x86_instruction(), 1), Operand::Imm(_)) {
        return false;
    }
    let base = match classify_operand(insn.x86_instruction(), 0) {
        Operand::RegMem { base, .. } => base,
        Operand::Sib { base, .. } => base,
        _ => return false,
    };
    matches!(
        base,
        Register::EBP | Register::RBP | Register::ESP | Register::RSP
    )
}

/// port of `get_printable_len` + `is_printable_ascii` + `is_printable_utf16le`.
/// `oper.tsize` (the destination memory operand's write width) comes from
/// `Instruction::memory_size` rather than the immediate's own encoded width
/// (a `mov` to memory always encodes an immediate exactly matching the
/// destination's operand size).
fn printable_len(insn: &DecodedInstruction) -> usize {
    let Operand::Imm(value) = classify_operand(insn.x86_instruction(), 1) else {
        return 0;
    };
    let tsize = insn.x86_instruction().memory_size().info().size();
    let chars: Vec<u8> = match tsize {
        1 => vec![value as u8],
        2 => (value as u16).to_le_bytes().to_vec(),
        4 => (value as u32).to_le_bytes().to_vec(),
        8 => (value as u64).to_le_bytes().to_vec(),
        _ => return 0,
    };
    if is_printable_ascii(&chars) {
        tsize
    } else if is_printable_utf16le(&chars) {
        // upstream's Python `tsize / 2` is a float division; an odd
        // `tsize` (only possible here for `tsize == 1`) can't occur for a
        // genuine UTF-16 pair, so integer division loses nothing in
        // practice.
        tsize / 2
    } else {
        0
    }
}

/// capa/features/extractors/viv/basicblock.py: `is_printable_ascii`.
/// Python's `string.printable` = digits + ascii letters + punctuation +
/// whitespace (` \t\n\r\x0b\x0c`), which is exactly the printable-ASCII
/// range plus those five whitespace control characters.
fn is_printable_ascii(chars: &[u8]) -> bool {
    chars
        .iter()
        .all(|&b| (0x20..=0x7e).contains(&b) || (0x09..=0x0d).contains(&b))
}

/// capa/features/extractors/viv/basicblock.py: `is_printable_utf16le`.
fn is_printable_utf16le(chars: &[u8]) -> bool {
    if chars.iter().skip(1).step_by(2).all(|&b| b == 0) {
        let low: Vec<u8> = chars.iter().step_by(2).copied().collect();
        is_printable_ascii(&low)
    } else {
        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::extract::image::{
        Architecture, ImageFormat, LoadedImage, MappedSection, Permissions,
    };
    use crate::extract::recovery::Edge;

    const CODE_BASE: u64 = 0x1000;

    fn decode_block(code: &[u8]) -> BasicBlock {
        let image = LoadedImage::for_test(
            ImageFormat::Pe,
            Architecture::X86,
            CODE_BASE,
            vec![MappedSection {
                name: ".text".to_string(),
                address: CODE_BASE,
                virtual_size: code.len() as u64,
                file_offset: 0,
                file_size: code.len() as u64,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
            std::collections::BTreeMap::new(),
            code.to_vec(),
        );
        let mut insns = Vec::new();
        let mut address = CODE_BASE;
        let end = CODE_BASE + code.len() as u64;
        while address < end {
            let insn = image
                .decode_at(address)
                .expect("test block decodes cleanly");
            address = insn.x86_instruction().next_ip();
            insns.push(insn);
        }
        BasicBlock {
            addr: CODE_BASE,
            insns,
            succs: Vec::new(),
        }
    }

    #[test]
    fn extract_features_always_includes_basic_block_feature() {
        let block = decode_block(&[0x90]); // nop
        let out = extract_features(&block);
        assert_eq!(out[0], (Address::Absolute(CODE_BASE), Feature::BasicBlock));
    }

    #[test]
    fn tight_loop_detected_for_conditional_self_branch() {
        // dec ecx; jnz CODE_BASE (jnz is at CODE_BASE+1, 2 bytes long, so
        // next_ip = CODE_BASE+3; rel8 = CODE_BASE - next_ip = -3 = 0xfd).
        let mut block = decode_block(&[0x49, 0x75, 0xfd]);
        block.succs = vec![Edge {
            target: CODE_BASE,
            kind: crate::extract::recovery::EdgeKind::Branch,
        }];
        assert_eq!(
            extract_bb_tight_loop(&block),
            vec![(
                Address::Absolute(CODE_BASE),
                Feature::Characteristic("tight loop".to_string())
            )]
        );
    }

    #[test]
    fn tight_loop_not_detected_for_unconditional_self_jump() {
        // jmp $ (E9 FB FF FF FF -> target = next_ip(5) - 5 = 0, not
        // block.addr on its own; use a direct encoding instead: jmp $-5).
        let block = decode_block(&[0xeb, 0xfe]); // jmp $-2 (short jmp back to itself)
        assert!(extract_bb_tight_loop(&block).is_empty());
    }

    #[test]
    fn tight_loop_not_detected_when_branch_target_is_not_block_start() {
        // cmp eax, 0; jnz +2 -- doesn't branch back to the block start.
        let block = decode_block(&[0x83, 0xf8, 0x00, 0x75, 0x02, 0x90, 0x90]);
        assert!(extract_bb_tight_loop(&block).is_empty());
    }

    #[test]
    fn stackstring_detected_for_enough_printable_immediate_bytes() {
        // three 4-byte printable immediate writes: 12 total, over the
        // MIN_STACKSTRING_LEN=8 (exclusive) threshold. Two 4-byte writes
        // (8 total) would *not* be enough -- upstream's check is `count >
        // MIN_STACKSTRING_LEN`, not `>=`.
        let block = decode_block(&[
            0xc7, 0x45, 0xf0, 0x41, 0x41, 0x41, 0x41, // mov [ebp-0x10], "AAAA"
            0xc7, 0x45, 0xf4, 0x42, 0x42, 0x42, 0x42, // mov [ebp-0x0c], "BBBB"
            0xc7, 0x45, 0xf8, 0x43, 0x43, 0x43, 0x43, // mov [ebp-0x08], "CCCC"
        ]);
        assert_eq!(
            extract_stackstring(&block),
            vec![(
                Address::Absolute(CODE_BASE),
                Feature::Characteristic("stack string".to_string())
            )]
        );
    }

    #[test]
    fn stackstring_not_detected_below_threshold() {
        // a single 4-byte printable immediate write: 4 <= MIN_STACKSTRING_LEN(8).
        let block = decode_block(&[0xc7, 0x45, 0xf0, 0x41, 0x41, 0x41, 0x41]);
        assert!(extract_stackstring(&block).is_empty());
    }

    #[test]
    fn stackstring_not_detected_exactly_at_threshold() {
        // two 4-byte writes = 8 total: the check is strictly `> 8`, so this
        // must *not* trigger.
        let block = decode_block(&[
            0xc7, 0x45, 0xf0, 0x41, 0x41, 0x41, 0x41, // mov [ebp-0x10], "AAAA"
            0xc7, 0x45, 0xf4, 0x42, 0x42, 0x42, 0x42, // mov [ebp-0x0c], "BBBB"
        ]);
        assert!(extract_stackstring(&block).is_empty());
    }

    #[test]
    fn stackstring_not_detected_for_non_printable_bytes() {
        // mov dword [ebp-0x10], 0xdeadbeef -- not printable ascii or utf16le.
        let block = decode_block(&[0xc7, 0x45, 0xf0, 0xef, 0xbe, 0xad, 0xde]);
        assert!(extract_stackstring(&block).is_empty());
    }

    #[test]
    fn stackstring_not_detected_for_register_destination() {
        // mov eax, 0x41414141 -- destination is a register, not memory.
        let block = decode_block(&[0xb8, 0x41, 0x41, 0x41, 0x41]);
        assert!(extract_stackstring(&block).is_empty());
    }

    #[test]
    fn is_mov_imm_to_stack_excludes_non_stack_base() {
        // mov dword [ebx+4], 0x41414141
        let block = decode_block(&[0xc7, 0x43, 0x04, 0x41, 0x41, 0x41, 0x41]);
        assert!(!is_mov_imm_to_stack(&block.insns[0]));
    }
}
