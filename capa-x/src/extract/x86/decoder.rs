//! Arch-agnostic decoder boundary
//! The AArch64 decoder is kept behind this architecture-neutral boundary.
//!
//! `recovery.rs`'s control-flow-recovery core (`discover_direct_flow`,
//! `build_function_view`, `rebuild_call_indexes`) only ever needs an
//! instruction's address, its fallthrough address, and a flow
//! classification -- which of next/call/indirect-call/conditional-branch/
//! unconditional-branch/indirect-branch/terminal, plus a resolved direct or
//! memory target where one exists. That is the whole surface this module
//! exposes, matching the brief's "smallest interface... not a general IR".
//!
//! Everything else that reads `iced-x86` types directly today --
//! `insn_features.rs`, `operand.rs`, `basicblock_features.rs`, and the
//! Go-runtime/`__libc_start_main`/MSVC-cookie/no-return heuristic modules --
//! is a direct port of x86-specific upstream Python
//! (`capa/features/extractors/viv/*.py`) and stays x86-only: it reaches the
//! underlying `iced_x86::Instruction` through
//! [`DecodedInstruction::x86_instruction`] rather than through a
//! generalised operand model. AArch64 gets its own parallel
//! feature-extraction module (task 4) written against this same boundary,
//! the same way the `.NET` extractor never touches `recovery.rs` at
//! all.
//!
//! Task 2 adds the AArch64 side of the boundary: `disarm64` (ADR 0004)
//! decodes a fixed-width 32-bit word into a `disarm64::Opcode`, and
//! [`from_aarch64`] classifies its `Flow` and resolves `direct_target` from
//! the small set of PC-relative branch encodings recovery needs (`b`/`bl`,
//! `b.cond`/`bc.cond`, `cbz`/`cbnz`, `tbz`/`tbnz`) directly from the raw
//! instruction word -- `disarm64`'s own per-operand bitfield extraction is
//! private to its crate, so these formulas come straight from the ARM
//! Architecture Reference Manual (ARM DDI 0487, C4.1 "Branches, exception
//! generating, and system instructions"), not a port of upstream Python:
//! pinned capa never decodes AArch64 itself, it reads Ghidra's BinExport2.
//! An unrecognized 32-bit word is not an error -- AArch64 is fixed-width, so
//! recovery can always step over 4 bytes and keep going, matching the
//! brief's "unsupported-but-valid instructions may yield mnemonic-only
//! features ... they may never disappear".

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

use disarm64::{decoder as aarch64_decoder, InsnOpcode, Opcode as Aarch64Opcode};
use disarm64_defn::InsnClass;

/// Arch-agnostic control-flow classification of one decoded instruction.
///
/// `ConditionalBranch` absorbs `iced_x86::FlowControl::XbeginXabortXend` --
/// both already shared one match arm in `recovery.rs`'s CFG walk, which
/// treats `Return` and `Terminal` identically too (empty successor list,
/// nothing queued) but the two are kept distinct here because a *second*
/// consumer, `noreturn.rs`'s no-return analysis, needs to tell a genuine
/// return apart from `iced_x86::FlowControl::Interrupt`/`Exception` (an
/// `int3`/`ud2`-like dead end that must *not* count as "this function
/// returns"). Task 1 originally collapsed all three into one `Terminal`
/// variant on the assumption that the CFG walk was the only consumer that
/// mattered; task 3 (AArch64 recovery) is where that stopped being true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Next,
    Call,
    IndirectCall,
    ConditionalBranch,
    UnconditionalBranch,
    IndirectBranch,
    /// A genuine return to the caller (x86 `ret`; AArch64 `ret`/`retaa`/
    /// `retab`).
    Return,
    /// Every other flow-terminating case that is not a return: x86
    /// `Interrupt`/`Exception` (`int3`, `ud2`, ...); AArch64 `eret`/
    /// `eretaa`/`eretab`/`drps`.
    Terminal,
}

/// One AArch64 32-bit word, decoded or not. `disarm64::decoder::decode`
/// returns `None` for an encoding it does not recognize (unassigned, or a
/// class excluded from the `full` feature such as SVE/SME); that is not an
/// error here -- the word is still exactly 4 bytes, so recovery steps over
/// it with an unknown mnemonic rather than losing the rest of the function.
/// The raw word itself needs no separate field: `DecodedInstruction::bytes`
/// already preserves it.
#[derive(Debug, Clone, Copy)]
struct Aarch64Insn {
    opcode: Option<Aarch64Opcode>,
}

/// Arch-specific detail a `DecodedInstruction` carries, behind a sealed
/// enum so the recovery core above never has to match on it. `Aarch64`
/// is the second and last implementation
/// this boundary needs -- AArch64 on Mach-O/PE reuses this same
/// decoder behind a new loader, not a third `ArchDetail` variant.
#[derive(Debug, Clone)]
enum ArchDetail {
    X86(Instruction),
    Aarch64(Aarch64Insn),
}

/// One decoded instruction, arch-tagged. Replaces the old x86-only
/// `DecodedInsn` (`image.rs`, pre-Phase-D): same data, but `flow`,
/// `direct_target`, and `memory_target` are now computed once at decode
/// time instead of being re-derived from `iced_x86::Instruction` by every
/// caller, and the underlying instruction moves behind
/// [`Self::x86_instruction`].
#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    /// `iced_x86::Instruction::next_ip()` for x86/x64: the fallthrough
    /// address, i.e. `address + length`.
    pub next_address: u64,
    pub flow: Flow,
    /// The near-branch target for `Call`/`ConditionalBranch`/
    /// `UnconditionalBranch`, when the target is statically known from the
    /// encoding alone (op0 is a near-branch operand). `None` for every other
    /// `Flow` variant.
    pub direct_target: Option<u64>,
    /// The resolved absolute address of a RIP-relative or base-less memory
    /// operand, when the instruction has one -- computed for *any*
    /// instruction, not just `IndirectCall`/`IndirectBranch`, since
    /// `discover_direct_flow` also uses this to record data cross-references
    /// for ordinary `Next`-flow instructions (e.g. `mov eax, [rip+0x10]`).
    pub memory_target: Option<u64>,
    /// Mnemonic text to report instead of formatting the decoded
    /// instruction, for the opcodes envi decodes and iced-x86 rejects (see
    /// `image.rs::decode_undocumented`). `None` -- the overwhelmingly common
    /// case -- means "format the instruction normally", which is what
    /// `insn_features.rs::mnemonic_text` does.
    pub mnemonic_override: Option<&'static str>,
    arch: ArchDetail,
}

impl DecodedInstruction {
    /// The underlying x86/x64 instruction. x86-only feature/heuristic
    /// modules (`insn_features.rs`, `operand.rs`, `basicblock_features.rs`,
    /// `golang.rs`, `libc_start_main.rs`, `msvcfunc.rs`, `noreturn.rs`) are
    /// reached only when `Architecture` is `X86`/`X64`, so this is never
    /// called against a non-x86 instruction in practice. That is a
    /// dispatch invariant this crate controls (which extractor module runs
    /// is decided by the file's own already-validated `Architecture`, not
    /// by attacker-chosen content reaching this accessor), not an
    /// untrusted-input path, so a wrong call is a capa-x bug to surface
    /// immediately rather than a malformed sample to tolerate.
    pub fn x86_instruction(&self) -> &Instruction {
        match &self.arch {
            ArchDetail::X86(instruction) => instruction,
            ArchDetail::Aarch64(_) => {
                unreachable!("x86_instruction() called on an AArch64 DecodedInstruction")
            }
        }
    }

    /// The AArch64 mnemonic, or a placeholder for a 32-bit word `disarm64`
    /// did not recognize (see [`Aarch64Insn`]). The AArch64 feature
    /// module is the intended caller; nothing else reaches this yet.
    pub fn aarch64_mnemonic(&self) -> &'static str {
        match &self.arch {
            ArchDetail::X86(_) => {
                unreachable!("aarch64_mnemonic() called on an x86 DecodedInstruction")
            }
            ArchDetail::Aarch64(insn) => insn
                .opcode
                .map_or("(unknown)", |opcode| opcode.definition().mnemonic),
        }
    }

    /// Whether `disarm64` recognized this AArch64 word's encoding. `false`
    /// on a non-AArch64 instruction, since iced-x86 has no equivalent
    /// "unrecognized but not an error" outcome to report here. Exists for
    /// task 2's own acceptance check (recording the unknown-encoding count
    /// across the pinned corpus and a random-byte fuzz); not a feature
    /// source itself.
    #[cfg(test)]
    pub(crate) fn aarch64_is_recognized(&self) -> bool {
        matches!(&self.arch, ArchDetail::Aarch64(insn) if insn.opcode.is_some())
    }

    /// x86-only recovery barrier: `Cli`/`Hlt`/string I/O (`Insb`/`Insd`/
    /// `Insw`/`Outsb`/`Outsd`/`Outsw`)/`Sti` are ring-0-only or a
    /// sandbox/debugger tell, so `discover_direct_flow` stops there rather
    /// than decoding further. `false` for AArch64 -- there is no analogue
    /// yet, and AArch64 recovery is where one would be added if the pinned
    /// corpus needs it.
    pub fn is_privileged_barrier(&self) -> bool {
        match &self.arch {
            ArchDetail::X86(instruction) => matches!(
                instruction.mnemonic(),
                Mnemonic::Cli
                    | Mnemonic::Hlt
                    | Mnemonic::Insb
                    | Mnemonic::Insd
                    | Mnemonic::Insw
                    | Mnemonic::Outsb
                    | Mnemonic::Outsd
                    | Mnemonic::Outsw
                    | Mnemonic::Sti
            ),
            ArchDetail::Aarch64(_) => false,
        }
    }
}

/// x86/x64: a near-branch target, when op0 is a near-branch operand.
/// Moved here unchanged from what was `recovery::direct_target`.
fn x86_direct_target(instruction: &Instruction) -> Option<u64> {
    matches!(
        instruction.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| instruction.near_branch_target())
}

/// x86/x64: the resolved absolute address of a RIP-relative or base-less
/// memory operand. Moved here unchanged from what was
/// `recovery::memory_target`.
fn x86_memory_target(instruction: &Instruction) -> Option<u64> {
    if !instruction.op_kinds().any(|kind| kind == OpKind::Memory) {
        return None;
    }
    if instruction.is_ip_rel_memory_operand() {
        Some(instruction.ip_rel_memory_address())
    } else if instruction.memory_base() == Register::None {
        Some(instruction.memory_displacement64())
    } else {
        None
    }
}

fn x86_flow(instruction: &Instruction) -> Flow {
    match instruction.flow_control() {
        FlowControl::Next => Flow::Next,
        FlowControl::Call => Flow::Call,
        FlowControl::IndirectCall => Flow::IndirectCall,
        FlowControl::ConditionalBranch | FlowControl::XbeginXabortXend => Flow::ConditionalBranch,
        FlowControl::UnconditionalBranch => Flow::UnconditionalBranch,
        FlowControl::IndirectBranch => Flow::IndirectBranch,
        FlowControl::Return => Flow::Return,
        FlowControl::Interrupt | FlowControl::Exception => Flow::Terminal,
    }
}

/// Build a [`DecodedInstruction`] from an x86/x64 `iced_x86::Instruction`.
/// `image.rs::decode_at` is the only caller; `address`/`bytes` are the same
/// values it already computed, and `flow`/`direct_target`/`memory_target`
/// are derived from `instruction` exactly as the pre-Phase-D free functions
/// in `recovery.rs` did, just computed once here instead of on every read.
pub(crate) fn from_x86(
    address: u64,
    bytes: Vec<u8>,
    instruction: Instruction,
    mnemonic_override: Option<&'static str>,
) -> DecodedInstruction {
    let next_address = instruction.next_ip();
    let flow = x86_flow(&instruction);
    let direct_target = x86_direct_target(&instruction);
    let memory_target = x86_memory_target(&instruction);
    DecodedInstruction {
        address,
        bytes,
        next_address,
        flow,
        direct_target,
        memory_target,
        mnemonic_override,
        arch: ArchDetail::X86(instruction),
    }
}

/// Sign-extend the low `bits` bits of `value` (bit `bits - 1` is the sign
/// bit), returned widened to `i64`.
fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    i64::from((value << shift) as i32 >> shift)
}

/// The handful of PC-relative branch-target encodings recovery needs,
/// straight from the ARM Architecture Reference Manual (ARM DDI 0487, C4.1):
/// `b`/`bl` (26-bit word-scaled immediate, bits `[25:0]`), `b.cond`/`bc.cond`
/// (19-bit, bits `[23:5]`), `cbz`/`cbnz` (same 19-bit shape -- excludes the
/// newer CSSC `cb<cond>` compare-and-branch-immediate forms, a different,
/// narrower encoding not yet needed by the pinned corpus), and `tbz`/`tbnz`
/// (14-bit, bits `[18:5]`). `None` for every other class, including a
/// `BRANCH_REG` (`br`/`blr`/`ret`/...) target: those are always a bare
/// register in AArch64, never a directly resolvable encoding -- unlike x86,
/// there is no single-instruction memory-operand form to resolve here, only
/// the multi-instruction `adrp`/`ldr`/`br` PLT/GOT pattern AArch64 recovery
/// recognizes at the recovery level.
fn aarch64_direct_target(address: u64, opcode: &Aarch64Opcode) -> Option<u64> {
    let def = opcode.definition();
    let bits = opcode.bits();
    let offset = match def.class {
        InsnClass::BRANCH_IMM => sign_extend(bits & 0x03ff_ffff, 26) * 4,
        InsnClass::CONDBRANCH => sign_extend((bits >> 5) & 0x7_ffff, 19) * 4,
        InsnClass::COMPBRANCH if matches!(def.mnemonic, "cbz" | "cbnz") => {
            sign_extend((bits >> 5) & 0x7_ffff, 19) * 4
        }
        InsnClass::TESTBRANCH => sign_extend((bits >> 5) & 0x3fff, 14) * 4,
        _ => return None,
    };
    Some(address.wrapping_add_signed(offset))
}

/// Classify one decoded AArch64 instruction's control flow by class and (for
/// `BRANCH_REG`, which covers `br`/`blr`/`ret`/`eret`/`drps` and their
/// pointer-authenticated forms alike) mnemonic prefix. Everything outside
/// these five classes is ordinary straight-line code.
fn aarch64_flow(opcode: &Aarch64Opcode) -> Flow {
    let def = opcode.definition();
    match def.class {
        InsnClass::BRANCH_IMM => {
            if def.mnemonic == "bl" {
                Flow::Call
            } else {
                Flow::UnconditionalBranch
            }
        }
        InsnClass::CONDBRANCH | InsnClass::COMPBRANCH | InsnClass::TESTBRANCH => {
            Flow::ConditionalBranch
        }
        InsnClass::BRANCH_REG => {
            if def.mnemonic.starts_with("blr") {
                Flow::IndirectCall
            } else if def.mnemonic.starts_with("br") {
                Flow::IndirectBranch
            } else if def.mnemonic.starts_with("ret") {
                Flow::Return
            } else {
                // eret/eretaa/eretab, drps: an exception return or debug
                // restore, not an ordinary function return -- like
                // iced-x86's Interrupt/Exception grouping.
                Flow::Terminal
            }
        }
        _ => Flow::Next,
    }
}

/// Build a [`DecodedInstruction`] from one AArch64 32-bit word. `word` is
/// native-endian (the caller already did the little-endian byte-to-`u32`
/// read); `bytes` are the raw little-endian bytes to preserve, matching
/// `from_x86`'s contract.
pub(crate) fn from_aarch64(address: u64, bytes: Vec<u8>, word: u32) -> DecodedInstruction {
    let opcode = aarch64_decoder::decode(word);
    let (flow, direct_target) = match &opcode {
        Some(opcode) => (aarch64_flow(opcode), aarch64_direct_target(address, opcode)),
        // An unrecognized word is still exactly 4 bytes of straight-line
        // code as far as recovery is concerned -- see the module doc.
        None => (Flow::Next, None),
    };
    DecodedInstruction {
        address,
        bytes,
        next_address: address.wrapping_add(4),
        flow,
        direct_target,
        memory_target: None,
        mnemonic_override: None,
        arch: ArchDetail::Aarch64(Aarch64Insn { opcode }),
    }
}

/// The decoded AArch64 opcode, or `None` for an unrecognized word (see
/// [`Aarch64Insn`]) or a non-AArch64 instruction. `pub(crate)` for the
/// task 4's feature-extraction module (`aarch64_features.rs`), which reads
/// `Insn::operands`/`InsnClass`/`InsnOpcode::bits` directly rather than
/// through a generalised operand model -- see this module's doc comment.
/// `Opcode` is `Copy`, so this returns an owned value rather than borrowing
/// `insn`.
pub(crate) fn aarch64_opcode(insn: &DecodedInstruction) -> Option<Aarch64Opcode> {
    match &insn.arch {
        ArchDetail::Aarch64(Aarch64Insn { opcode }) => *opcode,
        ArchDetail::X86(_) => None,
    }
}

/// Recognize the AAPCS64 lazy-PLT stub shape's first two instructions --
/// `adrp Xn, page` immediately followed by `ldr Xn, [Xn, #off]` (same
/// register, 64-bit GPR, unsigned-immediate-offset form) -- and resolve the
/// GOT slot address they compute together, so recovery can attribute the
/// stub to a known import the same way x86's single-instruction
/// `jmp [rip+X]`/`jmp [import]` already is via `memory_target`. AArch64 has
/// no single instruction whose own operand computes an absolute address
/// (every PC-relative reference needs `adrp` plus a second instruction), so
/// this is the smallest pattern that plays the same role -- not a general
/// operand model (the feature extractor's job, if one is ever needed), just
/// enough to answer "does this pair resolve to an already-known import
/// location". `first` must be the instruction immediately preceding
/// `second`. Encoding per the ARM Architecture Reference Manual (ARM DDI
/// 0487, C6.2.10 `ADRP`, C6.2.132 `LDR (immediate)`); verified against the
/// pinned corpus's own real PLT stubs.
pub(crate) fn aarch64_plt_got_target(
    first: &DecodedInstruction,
    second: &DecodedInstruction,
) -> Option<u64> {
    let adrp = aarch64_opcode(first)?;
    let ldr = aarch64_opcode(second)?;
    if adrp.definition().mnemonic != "adrp" || ldr.definition().mnemonic != "ldr" {
        return None;
    }
    let adrp_word = adrp.bits();
    let ldr_word = ldr.bits();
    // LDR (immediate, unsigned offset): size == 0b11 selects the 64-bit GPR
    // form (as opposed to 32-bit, SIMD&FP, or one of `ldr`'s other several
    // addressing-mode encodings, which share the mnemonic but not this bit
    // layout).
    if (ldr_word >> 30) & 0b11 != 0b11 {
        return None;
    }
    let adrp_rd = adrp_word & 0x1f;
    let ldr_rn = (ldr_word >> 5) & 0x1f;
    if adrp_rd != ldr_rn {
        return None;
    }
    let immlo = (adrp_word >> 29) & 0b11;
    let immhi = (adrp_word >> 5) & 0x7_ffff;
    let page_offset = sign_extend((immhi << 2) | immlo, 21) << 12;
    let page = first.address & !0xfff;
    let page = page.wrapping_add_signed(page_offset);
    let imm12 = (ldr_word >> 10) & 0xfff;
    Some(page.wrapping_add(u64::from(imm12) * 8))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! The decoder's acceptance line: "decoding all three samples'
    //! `.text` plus 10 MB of random bytes produces zero panics, and the
    //! unknown-encoding count is recorded for future comparison." Both
    //! checks call `from_aarch64` directly -- no `LoadedImage`/ELF-loading
    //! involvement needed, since this is a decoder-level property, not a
    //! recovery-level one (`Architecture::AArch64` is not yet reachable
    //! through `LoadedImage::from_elf`; see its doc comment).

    use std::path::{Path, PathBuf};

    use goblin::elf::program_header::{PF_X, PT_LOAD};
    use goblin::elf::Elf;

    use super::*;

    fn pinned_samples() -> Vec<PathBuf> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("tests/testfiles/aarch64");
        [
            "687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf_",
            "c7f38027552a3eca84e2bfc846ac1307fbf98657545426bb93a2d63555cbb486.elf_",
            "d1e6506964edbfffb08c0dd32e1486b11fbced7a4bd870ffe79f110298f0efb8.elf_",
        ]
        .iter()
        .map(|name| root.join(name))
        .collect()
    }

    /// The bytes of every executable `PT_LOAD` segment, one contiguous
    /// `Vec` per segment (not the whole file -- segments can be interleaved
    /// with non-code data at the file level).
    fn executable_segments(path: &Path) -> Vec<Vec<u8>> {
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"));
        let elf = Elf::parse(&bytes).unwrap_or_else(|e| panic!("parsing {path:?}: {e}"));
        elf.program_headers
            .iter()
            .filter(|header| header.p_type == PT_LOAD && header.p_flags & PF_X != 0)
            .map(|header| {
                let start = header.p_offset as usize;
                let end = start + header.p_filesz as usize;
                bytes[start..end].to_vec()
            })
            .collect()
    }

    /// Decode every 4-byte-aligned word in `code`, at successive synthetic
    /// addresses starting at `base`. Returns `(words, recognized)` --
    /// reaching this line at all across a whole real `.text` section is
    /// itself most of the assertion: a panic anywhere aborts the test.
    fn decode_all(base: u64, code: &[u8]) -> (usize, usize) {
        let mut words = 0usize;
        let mut recognized = 0usize;
        for (index, chunk) in code.chunks_exact(4).enumerate() {
            let address = base.wrapping_add((index * 4) as u64);
            let word = u32::from_le_bytes(chunk.try_into().expect("chunks_exact(4)"));
            let insn = from_aarch64(address, chunk.to_vec(), word);
            assert_eq!(insn.address, address);
            assert_eq!(insn.next_address, address.wrapping_add(4));
            words += 1;
            if insn.aarch64_is_recognized() {
                recognized += 1;
            }
        }
        (words, recognized)
    }

    /// `__libc_init@plt` from the pinned sample
    /// `687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf_`
    /// (`adrp x16, 0x1f000; ldr x17, [x16, #0xd80]` at file address
    /// `0x4b90`), independently cross-checked against `objdump -R`'s
    /// `R_AARCH64_JUMP_SLOT 0x1fd80 __libc_init` for the same binary.
    #[test]
    fn plt_got_target_matches_a_real_jump_slot_relocation() {
        let adrp = from_aarch64(0x4b90, vec![0xd0, 0x00, 0x00, 0xf0], 0xf000_00d0);
        let ldr = from_aarch64(0x4b94, vec![0x11, 0xc2, 0x46, 0xf9], 0xf946_c211);
        assert_eq!(aarch64_plt_got_target(&adrp, &ldr), Some(0x1fd80));
    }

    #[test]
    fn plt_got_target_rejects_a_register_mismatch() {
        // ldr x17, [x16, ...] but adrp targets x15 instead of x16 -- not a
        // chained pair, so no target should be resolved.
        let adrp_x15 = from_aarch64(0x4b90, vec![0xcf, 0x00, 0x00, 0xf0], 0xf000_00cf);
        let ldr_x16 = from_aarch64(0x4b94, vec![0x11, 0xc2, 0x46, 0xf9], 0xf946_c211);
        assert_eq!(aarch64_plt_got_target(&adrp_x15, &ldr_x16), None);
    }

    #[test]
    fn plt_got_target_rejects_a_non_adrp_ldr_pair() {
        let not_adrp = from_aarch64(0x4b90, vec![0x1f, 0x20, 0x03, 0xd5], 0xd503_201f); // nop
        let ldr = from_aarch64(0x4b94, vec![0x11, 0xc2, 0x46, 0xf9], 0xf946_c211);
        assert_eq!(aarch64_plt_got_target(&not_adrp, &ldr), None);
    }

    #[test]
    fn pinned_samples_text_decodes_without_panicking() {
        let mut total_words = 0usize;
        let mut total_recognized = 0usize;
        for path in pinned_samples() {
            for segment in executable_segments(&path) {
                let (words, recognized) = decode_all(0x1000, &segment);
                total_words += words;
                total_recognized += recognized;
            }
        }
        assert!(total_words > 0, "expected at least one executable word");
        // Recorded for the roadmap's D.2 status note, not asserted against a
        // specific bound: ADR 0004's own spike measured 84.6% on this same
        // corpus (a different, uncommitted decoder wrapper), and Ghidra's
        // BinExport2 recognizing an opcode `disarm64` does not is a
        // legitimate, root-causeable J9 divergence class, not a bug here.
        eprintln!(
            "pinned AArch64 corpus: {total_recognized}/{total_words} words recognized \
             ({:.1}%)",
            100.0 * total_recognized as f64 / total_words as f64
        );
        assert!(
            total_recognized > 0,
            "expected at least some recognized real AArch64 code"
        );
    }

    /// Deterministic xorshift64 PRNG, matching ADR 0004's own fuzz
    /// methodology (`docs/decisions/0004-aarch64-decoder.md`) --
    /// reproducible across runs without pulling in a `rand` dependency for a
    /// single test.
    fn xorshift64(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn ten_megabytes_of_random_words_decode_without_panicking() {
        const TEN_MB: usize = 10 * 1024 * 1024;
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut recognized = 0usize;
        let words = TEN_MB / 4;
        for index in 0..words {
            let word = xorshift64(&mut state) as u32;
            let address = 0x2000_u64.wrapping_add((index * 4) as u64);
            let insn = from_aarch64(address, word.to_le_bytes().to_vec(), word);
            if insn.aarch64_is_recognized() {
                recognized += 1;
            }
        }
        eprintln!(
            "10 MB random-word fuzz: {recognized}/{words} words recognized ({:.1}%)",
            100.0 * recognized as f64 / words as f64
        );
    }
}
