//! Operand classification shared by the instruction-feature
//! extractors. `capa/features/extractors/viv/insn.py` dispatches on envi's
//! operand *classes* (`i386ImmOper`, `i386ImmMemOper`, `i386RegMemOper`,
//! `i386SibOper`, `Amd64RipRelOper`, `i386RegOper`); iced-x86 has no such
//! type hierarchy -- every memory addressing form is `OpKind::Memory` with
//! base/index/displacement fields. This maps an iced-x86 operand back onto
//! envi's classes so the ported extractors can keep the same `isinstance`
//! shape as the Python source.
//!
//! ELF x86 code doesn't use plain absolute-address memory operands (no
//! base/index) the way PE `call dword [0x00473038]` IAT calls do, so the
//! `ImmMem` classification below is exercised primarily by PE binaries, as
//! in the upstream source.

use iced_x86::{CodeSize, Instruction, OpKind, Register};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    /// envi `i386ImmOper`: a register-less immediate value, e.g. `push 0x10`.
    Imm(i64),
    /// envi `i386ImmMemOper`: the classic 32-bit-only non-SIB `[disp32]`
    /// encoding (`mod==0,rm==5`) with no base or index register, e.g.
    /// `call dword [0x00473038]`. The value is the absolute address itself.
    /// Never produced for 64-bit code: that same bit pattern is
    /// RIP-relative there instead (see [`Operand::RipRel`]).
    ImmMem(u64),
    /// envi `i386RegMemOper`: `[base + disp]`, no index register, e.g.
    /// `[ebp-4]`.
    RegMem { base: Register, disp: i64 },
    /// envi `i386SibOper`: any SIB-byte-encoded addressing mode -- a scaled
    /// index register (`[esi + ecx*4 + 0x10]`), and/or (`base ==
    /// Register::None`) the SIB "no base register" special case
    /// (`0x401000[2*ebx]`, or a base-less absolute like `gs:[0x60]`, which
    /// x64 can *only* reach via this SIB form since it has no non-SIB
    /// `[disp32]` encoding to fall back to).
    ///
    /// envi's `i386SibOper.__init__` defaults `imm=None, disp=0`, and
    /// `parse_sib` assigns `imm` in exactly one case: the base-less special
    /// case `base==5, mod==0` (`[imm32 + index*scale]`), where it also leaves
    /// `.disp` at its default. Every other SIB form -- anything with a real
    /// base register -- keeps `imm=None` and carries the displacement in
    /// `.disp`. So `imm` is `Some` only for the base-less form, and it is
    /// **not** a second spelling of `disp`.
    ///
    /// That distinction is load-bearing: the extractors upstream reads
    /// `oper.imm` from (bytes/string derefs, the PEB/TEB segment-access
    /// characteristic) yield nothing for `[base + index + disp32]`, while the
    /// structure-offset features, which read `oper.disp`, still do. Modelling
    /// `imm` as a copy of `disp` made capa-x extract `bytes` features
    /// upstream never produces for table accesses like
    /// `movzx eax, byte [edx + eax + 0x10011B80]`.
    Sib {
        base: Register,
        disp: i64,
        imm: Option<u64>,
    },
    /// envi `Amd64RipRelOper`: an x64 RIP-relative memory operand. The
    /// value is the computed absolute target address (envi's
    /// `oper.getOperAddr(insn)`), not the raw displacement.
    RipRel(u64),
    /// envi `i386RegOper`: a bare register operand, e.g. `call eax`.
    Reg(Register),
    /// Any other operand kind (branch targets, far branches, string-op
    /// implicit memory operands, ...) that the ported extractors never
    /// match on.
    Other,
}

/// `Instruction::memory_displacement64` already sign-extends a disp8/disp16
/// encoding to the effective (32- or 64-bit) address size during decode, but
/// stores the result zero-extended in its 64-bit field -- e.g. `[ebp-4]`
/// reports `0xFFFF_FFFC`, not `0xFFFF_FFFF_FFFF_FFFC`. Truncate back to the
/// address width and re-sign-extend so callers get envi's signed
/// `oper.disp` semantics.
fn sign_extend_displacement(instruction: &Instruction) -> i64 {
    if instruction.memory_displ_size() == 8 {
        instruction.memory_displacement64() as i64
    } else {
        instruction.memory_displacement64() as u32 as i32 as i64
    }
}

fn is_immediate_kind(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

/// Classify operand `index` of `instruction`. `index` must be `<
/// instruction.op_count()`; out-of-range indices behave as `OpKind::None`
/// would (classified `Other`), matching iced-x86's own debug-assert-only
/// bounds checking.
pub fn classify_operand(instruction: &Instruction, index: u32) -> Operand {
    let kind = instruction.op_kind(index);
    match kind {
        OpKind::Register => Operand::Reg(instruction.op_register(index)),
        OpKind::Memory => {
            if instruction.is_ip_rel_memory_operand() {
                Operand::RipRel(instruction.ip_rel_memory_address())
            } else {
                let base = instruction.memory_base();
                let index_reg = instruction.memory_index();
                // x64 has no non-SIB `[disp32]` encoding -- that bit pattern
                // (`mod==0,rm==5`) is RIP-relative there instead (handled
                // above) -- so a base-less memory operand in 64-bit code is
                // unambiguously the SIB special case. x86 is genuinely
                // ambiguous between that same SIB form and the classic
                // non-SIB `i386ImmMemOper`; keep the latter (`ImmMem`) for
                // x86, matching the common 32-bit IAT-call encoding this was
                // originally ported against.
                let base_less_sib =
                    base == Register::None && instruction.code_size() == CodeSize::Code64;
                let encoded_sib_base = matches!(
                    base,
                    Register::ESP | Register::RSP | Register::R12D | Register::R12
                );
                if index_reg != Register::None || base_less_sib || encoded_sib_base {
                    if base == Register::None {
                        Operand::Sib {
                            base,
                            disp: 0,
                            imm: Some(instruction.memory_displacement64()),
                        }
                    } else {
                        Operand::Sib {
                            base,
                            disp: sign_extend_displacement(instruction),
                            imm: None,
                        }
                    }
                } else if base == Register::None {
                    // envi's `i386ImmMemOper.getOperAddr` -- an absolute
                    // address, not a signed structure offset.
                    Operand::ImmMem(instruction.memory_displacement64())
                } else {
                    Operand::RegMem {
                        base,
                        disp: sign_extend_displacement(instruction),
                    }
                }
            }
        }
        _ if is_immediate_kind(kind) => Operand::Imm(instruction.immediate(index) as i64),
        _ => Operand::Other,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(bitness: u32, bytes: &[u8]) -> Instruction {
        let mut decoder = Decoder::with_ip(bitness, bytes, 0x1000, DecoderOptions::NONE);
        decoder.decode()
    }

    #[test]
    fn classifies_plain_immediate() {
        // push 0x10
        let insn = decode(32, &[0x6a, 0x10]);
        assert_eq!(classify_operand(&insn, 0), Operand::Imm(0x10));
    }

    #[test]
    fn classifies_absolute_memory_with_no_base_or_index() {
        // call dword [0x00473038]
        let insn = decode(32, &[0xff, 0x15, 0x38, 0x30, 0x47, 0x00]);
        assert_eq!(classify_operand(&insn, 0), Operand::ImmMem(0x00473038));
    }

    #[test]
    fn classifies_reg_mem_with_base_only() {
        // mov eax, [ebp-4]
        let insn = decode(32, &[0x8b, 0x45, 0xfc]);
        assert_eq!(
            classify_operand(&insn, 1),
            Operand::RegMem {
                base: Register::EBP,
                disp: -4,
            }
        );
    }

    #[test]
    fn classifies_sib_with_scaled_index_and_no_base() {
        // mov eax, [2*ebx + 0x401000] -- envi's `i386SibOper.disp` defaults
        // to 0 here (never passed explicitly for the SIB "no base register"
        // special case); the actual value lives in `.imm` instead.
        let insn = decode(32, &[0x8b, 0x04, 0x5d, 0x00, 0x10, 0x40, 0x00]);
        assert_eq!(
            classify_operand(&insn, 1),
            Operand::Sib {
                base: Register::None,
                disp: 0,
                imm: Some(0x401000),
            }
        );
    }

    #[test]
    fn sib_with_a_base_register_has_no_imm() {
        // movzx eax, byte [edx + eax + 0x10011b80] -- a table access, which
        // envi's `parse_sib` reaches with `base != 5`, so it never assigns
        // `imm` and the displacement lives in `.disp` alone. Upstream's
        // bytes/string extractors read `oper.imm` and therefore yield nothing
        // here; the offset extractors read `oper.disp` and still do.
        let insn = decode(32, &[0x0f, 0xb6, 0x84, 0x02, 0x80, 0x1b, 0x01, 0x10]);
        assert_eq!(
            classify_operand(&insn, 1),
            Operand::Sib {
                base: Register::EDX,
                disp: 0x10011b80,
                imm: None,
            }
        );
    }

    #[test]
    fn classifies_x64_bare_sib_with_no_base_or_index() {
        // mov rax, gs:[0x60] -- x64 has no non-SIB `[disp32]` encoding
        // (that bit pattern is RIP-relative there), so this is
        // unambiguously the SIB special case, unlike the equivalent x86
        // encoding (`classifies_absolute_memory_with_no_base_or_index`).
        let insn = decode(64, &[0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        assert_eq!(
            classify_operand(&insn, 1),
            Operand::Sib {
                base: Register::None,
                disp: 0,
                imm: Some(0x60),
            }
        );
    }

    #[test]
    fn classifies_x64_rip_relative_memory() {
        // mov rax, [rip+0x2000]
        let insn = decode(64, &[0x48, 0x8b, 0x05, 0x00, 0x20, 0x00, 0x00]);
        // next_ip (0x1000 + 7) + 0x2000
        assert_eq!(
            classify_operand(&insn, 1),
            Operand::RipRel(0x1000 + 7 + 0x2000)
        );
    }

    #[test]
    fn classifies_bare_register() {
        // call eax
        let insn = decode(32, &[0xff, 0xd0]);
        assert_eq!(classify_operand(&insn, 0), Operand::Reg(Register::EAX));
    }
}
