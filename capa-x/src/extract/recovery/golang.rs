//! Port of pinned Vivisect 1.3.2 `vivisect/analysis/i386/golang.py`.
//!
//! Upstream's own summary: "GO binaries start from a single export and proceed
//! thru several functions that initialize GO. Specific application code is
//! launched from the GO function runtime_main(), which is invoked by `call
//! eax` with an address placed on the stack many calls earlier. Vivisect code
//! flow analysis does not track the address; this module finds the address and
//! invokes makeFunction(va)."
//!
//! So `runtime_main` is to a Go binary what `main` is to a glibc one -- the
//! single start that the whole application hangs off, reachable only through an
//! indirect call. Measured on `49a34cfbeed733c24392c9217ef46bb6.exe_`, it is
//! the root of 966 of the reference's 1709 functions.
//!
//! Registered for i386 only, and gated on the same `Go build ID: ` marker
//! upstream checks for.

use iced_x86::{Mnemonic, OpKind};

use super::engine::{BasicBlock, Function};
use super::image::{Architecture, ImageFormat, LoadedImage};

/// `golang.py:24-25`. The instruction at index `len - 5` -- the first `push` --
/// carries the pointer to `runtime_main`.
const GO_I386_SEQUENCE: &[Mnemonic] = &[
    Mnemonic::Cld,
    Mnemonic::Call,
    Mnemonic::Mov,
    Mnemonic::Mov,
    Mnemonic::Mov,
    Mnemonic::Mov,
    Mnemonic::Call,
    Mnemonic::Call,
    Mnemonic::Call,
    Mnemonic::Push,
    Mnemonic::Push,
    Mnemonic::Call,
    Mnemonic::Pop,
    Mnemonic::Pop,
];

/// `golang.py:81` -- `instrs[len(match) - idx]` with `idx = 5`.
const PUSH_INDEX: usize = GO_I386_SEQUENCE.len() - 5;

/// Bytes of `.text` upstream searches for the build marker (`golang.py:36`).
const BUILD_ID_SCAN_BYTES: usize = 10000;
const BUILD_ID_MARKER: &[u8] = b"Go build ID: ";

/// `golang.py:31-41`: a PE whose `.text` segment carries the Go build marker in
/// its first bytes. The section check is upstream's own guard against matching
/// "a `.upxN` segment of a packed sample".
pub fn is_go_image(image: &LoadedImage) -> bool {
    if image.format != ImageFormat::Pe || image.architecture != Architecture::X86 {
        return false;
    }
    image
        .sections
        .iter()
        .filter(|section| section.name == ".text")
        .any(|section| {
            image
                .bytes_at(section.address, BUILD_ID_SCAN_BYTES)
                .is_some_and(|bytes| {
                    bytes
                        .windows(BUILD_ID_MARKER.len())
                        .any(|window| window == BUILD_ID_MARKER)
                })
        })
}

/// The address of `runtime_main`, read out of the Go entry stub.
///
/// `blocks_at` materialises a function's basic blocks, which upstream reaches
/// through `vw.getFunctionBlocks`; the second shape below needs the blocks of a
/// function the entry stub points at, not just the entry's own.
pub fn runtime_main(
    image: &LoadedImage,
    entry: &Function,
    blocks_at: &dyn Fn(u64) -> Option<Function>,
) -> Option<u64> {
    let push = find_sequence_block(&entry.blocks)
        .or_else(|| find_sequence_block_via_stack(image, entry, blocks_at))?;
    // `parse_push_imm(..., get_content=True)`: the immediate is a pointer, and
    // what it points at is `runtime_main`.
    let pointer = push_immediate(&push)?;
    let target = read_u32(image, pointer)?;
    // Upstream proves the target readable before making a function there.
    read_u32(image, target)?;
    Some(target)
}

/// `find_golang_bblock`: the first block that contains [`GO_I386_SEQUENCE`]
/// starting at its first `cld`.
fn find_sequence_block(blocks: &[BasicBlock]) -> Option<iced_x86::Instruction> {
    let recorded = blocks.iter().find_map(|block| {
        let from_cld = block
            .insns
            .iter()
            .position(|insn| insn.x86_instruction().mnemonic() == GO_I386_SEQUENCE[0])?;
        let tail = block.insns.get(from_cld..)?;
        (tail.len() >= GO_I386_SEQUENCE.len()).then_some(tail)
    })?;
    // Upstream stops at the first block long enough and then requires an exact
    // prefix match -- a near miss is not retried against later blocks.
    recorded
        .iter()
        .zip(GO_I386_SEQUENCE)
        .all(|(insn, mnemonic)| insn.x86_instruction().mnemonic() == *mnemonic)
        .then(|| recorded.get(PUSH_INDEX).map(|insn| *insn.x86_instruction()))?
}

/// `find_golang_bblock_via_stack`: some Go executables put the sequence one
/// function further on, reached by an entry stub that is a single block ending
/// `push <next function>; ret`.
fn find_sequence_block_via_stack(
    image: &LoadedImage,
    entry: &Function,
    blocks_at: &dyn Fn(u64) -> Option<Function>,
) -> Option<iced_x86::Instruction> {
    let [block] = entry.blocks.as_slice() else {
        return None;
    };
    let [.., push, ret] = block.insns.as_slice() else {
        return None;
    };
    if ret.x86_instruction().mnemonic() != Mnemonic::Ret
        || push.x86_instruction().mnemonic() != Mnemonic::Push
    {
        return None;
    }
    // Here the immediate is the function's address itself, not a pointer to it.
    let next = push_immediate(push.x86_instruction())?;
    read_u32(image, next)?;
    find_sequence_block(&blocks_at(next)?.blocks)
}

/// `parse_push_imm`: exactly one operand, and it is an immediate.
fn push_immediate(instruction: &iced_x86::Instruction) -> Option<u64> {
    if instruction.op_count() != 1 {
        return None;
    }
    match instruction.op0_kind() {
        OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate32 => {
            Some(instruction.immediate(0))
        }
        _ => None,
    }
}

/// `vw.castPointer` plus upstream's `len(vw.readMemory(va, 4)) != 4` guard.
fn read_u32(image: &LoadedImage, address: u64) -> Option<u64> {
    let raw = image.bytes_at(address, 4)?;
    let value: [u8; 4] = raw.get(..4)?.try_into().ok()?;
    Some(u64::from(u32::from_le_bytes(value)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::extract::image::{MappedSection, Permissions};

    const TEXT: u64 = 0x401000;
    const DATA: u64 = 0x402000;
    /// Where the entry stub's `push` immediate points.
    const POINTER: u64 = DATA + 0x10;
    const RUNTIME_MAIN: u64 = TEXT + 0x200;

    /// Assembled [`GO_I386_SEQUENCE`], with `push <POINTER>` at [`PUSH_INDEX`].
    fn go_entry_sequence() -> Vec<u8> {
        let mut code = vec![0xfc]; // cld
        code.extend_from_slice(&[0xe8, 0x00, 0x00, 0x00, 0x00]); // call $+5
        for _ in 0..4 {
            code.extend_from_slice(&[0x89, 0xc0]); // mov eax, eax
        }
        for _ in 0..3 {
            code.extend_from_slice(&[0xe8, 0x00, 0x00, 0x00, 0x00]); // call
        }
        code.push(0x68); // push imm32 -- the one that matters
        code.extend_from_slice(&(POINTER as u32).to_le_bytes());
        code.extend_from_slice(&[0x6a, 0x00]); // push 0
        code.extend_from_slice(&[0xe8, 0x00, 0x00, 0x00, 0x00]); // call
        code.extend_from_slice(&[0x58, 0x59]); // pop eax; pop ecx
        code
    }

    /// Bytes the build marker occupies before the code in a marked image.
    const MARKER_LEN: u64 = 21;

    fn image_with(text: &[u8], go_marker: bool) -> LoadedImage {
        let mut bytes = if go_marker {
            let mut header = b"\x90\x90Go build ID: \"abc\"\n".to_vec();
            assert_eq!(header.len() as u64, MARKER_LEN);
            header.extend_from_slice(text);
            header
        } else {
            text.to_vec()
        };
        bytes.resize(0x400, 0x90);
        // `.data`, with `POINTER` holding `RUNTIME_MAIN`.
        let mut data = vec![0u8; 0x20];
        data[0x10..0x14].copy_from_slice(&(RUNTIME_MAIN as u32).to_le_bytes());
        bytes.extend_from_slice(&data);
        LoadedImage::for_test(
            ImageFormat::Pe,
            Architecture::X86,
            TEXT,
            vec![
                MappedSection {
                    name: ".text".to_string(),
                    address: TEXT,
                    virtual_size: 0x400,
                    file_offset: 0,
                    file_size: 0x400,
                    permissions: Permissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                },
                MappedSection {
                    name: ".data".to_string(),
                    address: DATA,
                    virtual_size: 0x20,
                    file_offset: 0x400,
                    file_size: 0x20,
                    permissions: Permissions {
                        read: true,
                        write: true,
                        execute: false,
                    },
                },
            ],
            BTreeMap::new(),
            bytes,
        )
    }

    /// One basic block covering `count` instructions decoded from `start`.
    fn block(image: &LoadedImage, start: u64, count: usize) -> Function {
        let mut insns = Vec::new();
        let mut address = start;
        for _ in 0..count {
            let insn = image.decode_at(address).expect("decode test instruction");
            address = insn.x86_instruction().next_ip();
            insns.push(insn);
        }
        Function {
            addr: start,
            blocks: vec![BasicBlock {
                addr: start,
                insns,
                succs: Vec::new(),
            }],
        }
    }

    fn no_blocks(_address: u64) -> Option<Function> {
        None
    }

    #[test]
    fn detects_the_go_build_marker_in_text() {
        assert!(is_go_image(&image_with(&go_entry_sequence(), true)));
        assert!(!is_go_image(&image_with(&go_entry_sequence(), false)));
    }

    #[test]
    fn reads_runtime_main_through_the_entry_sequence() {
        let image = image_with(&go_entry_sequence(), true);
        // The marker prefixes the code, so the sequence starts past it.
        let start = TEXT + MARKER_LEN;
        let entry = block(&image, start, GO_I386_SEQUENCE.len());
        assert_eq!(runtime_main(&image, &entry, &no_blocks), Some(RUNTIME_MAIN));
    }

    #[test]
    fn rejects_a_block_that_does_not_match_the_sequence() {
        // `cld` followed by enough instructions, but not the Go shape.
        let mut code = vec![0xfc];
        code.extend(std::iter::repeat_n([0x89, 0xc0], GO_I386_SEQUENCE.len()).flatten());
        let image = image_with(&code, true);
        let entry = block(&image, TEXT + MARKER_LEN, GO_I386_SEQUENCE.len());
        assert_eq!(runtime_main(&image, &entry, &no_blocks), None);
    }

    #[test]
    fn follows_the_stack_shaped_entry_stub() {
        // `push <sequence>; ret` in a single-block entry, with the sequence
        // living in the function that push points at.
        let sequence_va = TEXT + MARKER_LEN;
        let mut code = go_entry_sequence();
        let stub_offset = code.len();
        code.push(0x68);
        code.extend_from_slice(&(sequence_va as u32).to_le_bytes());
        code.push(0xc3); // ret

        let image = image_with(&code, true);
        let stub_va = TEXT + MARKER_LEN + stub_offset as u64;
        let entry = block(&image, stub_va, 2);
        let sequence = block(&image, sequence_va, GO_I386_SEQUENCE.len());
        let blocks_at = |address: u64| (address == sequence_va).then(|| sequence.clone());
        assert_eq!(runtime_main(&image, &entry, &blocks_at), Some(RUNTIME_MAIN));
    }
}
