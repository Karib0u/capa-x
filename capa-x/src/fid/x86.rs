//! Per-instruction FID inputs for x86-64: the instruction mask and Ghidra's
//! operand object lists, derived with iced-x86 instead of Sleigh.
//!
//! Anything that cannot be described confidently yields `None`; the caller
//! then leaves the function unhashed rather than risk a wrong name.
use super::hash::{Instruction as Hashed, Obj, Operand};
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};

/// Register offset in Ghidra's x86-64 register space.
pub fn register_offset(register: Register) -> Option<u32> {
    use Register::*;
    let gpr = |index: u32| {
        if index < 8 {
            index * 8
        } else {
            128 + (index - 8) * 8
        }
    };
    Some(match register {
        RAX | EAX | AX | AL => gpr(0),
        RCX | ECX | CX | CL => gpr(1),
        RDX | EDX | DX | DL => gpr(2),
        RBX | EBX | BX | BL => gpr(3),
        RSP | ESP | SP | SPL => gpr(4),
        RBP | EBP | BP | BPL => gpr(5),
        RSI | ESI | SI | SIL => gpr(6),
        RDI | EDI | DI | DIL => gpr(7),
        AH => 1,
        CH => 9,
        DH => 17,
        BH => 25,
        R8 | R8D | R8W | R8L => gpr(8),
        R9 | R9D | R9W | R9L => gpr(9),
        R10 | R10D | R10W | R10L => gpr(10),
        R11 | R11D | R11W | R11L => gpr(11),
        R12 | R12D | R12W | R12L => gpr(12),
        R13 | R13D | R13W | R13L => gpr(13),
        R14 | R14D | R14W | R14L => gpr(14),
        R15 | R15D | R15W | R15L => gpr(15),
        ES => 256,
        CS => 258,
        SS => 260,
        DS => 262,
        FS => 264,
        GS => 266,
        ST0 | MM0 => 4352,
        ST1 | MM1 => 4368,
        ST2 | MM2 => 4384,
        ST3 | MM3 => 4400,
        ST4 | MM4 => 4416,
        ST5 | MM5 => 4432,
        ST6 | MM6 => 4448,
        ST7 | MM7 => 4464,
        other => {
            let number = other.number() as u32;
            if other.is_xmm() || other.is_ymm() || other.is_zmm() {
                4608 + 64 * number
            } else if other.is_k() {
                2100 + 8 * number
            } else {
                return Option::None;
            }
        }
    })
}

fn signed_immediate(instruction: &Instruction, operand: u32) -> Option<i64> {
    let value = instruction.try_immediate(operand).ok()?;
    Some(match instruction.try_op_kind(operand).ok()? {
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64 => i64::from(value as u8 as i8),
        OpKind::Immediate16 => i64::from(value as u16 as i16),
        OpKind::Immediate32 | OpKind::Immediate32to64 => i64::from(value as u32 as i32),
        OpKind::Immediate64 => value as i64,
        _ => return None,
    })
}

fn is_prefix(byte: u8) -> bool {
    matches!(
        byte,
        0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3
    )
}

/// Decode `bytes` at `address` and describe it for hashing.
pub fn describe(address: u64, bytes: &[u8]) -> Option<Hashed> {
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return None;
    }
    let offsets = decoder.get_constant_offsets(&instruction);
    let raw = bytes.get(..instruction.len())?.to_vec();
    let mut mask = vec![0_u8; raw.len()];
    let mut set = |index: usize, value: u8| -> Option<()> {
        *mask.get_mut(index)? = value;
        Some(())
    };
    let mut position = 0;
    while is_prefix(*raw.get(position)?) {
        set(position, 0xff)?;
        position += 1;
    }
    let first = *raw.get(position)?;
    let vex = first == 0xc5 || first == 0xc4;
    let mut index_extension = false;
    let mut map = 0_u8;
    if vex {
        // VEX keeps only `pp` of its payload bytes; the C4 map byte is operand data.
        set(position, 0xff)?;
        if first == 0xc5 {
            set(position + 1, 0x03)?;
            map = 1;
            position += 2;
        } else {
            let byte1 = *raw.get(position + 1)?;
            map = byte1 & 0x1f;
            index_extension = byte1 & 0x40 == 0; // inverted X
            set(position + 2, 0x03)?;
            position += 3;
        }
    } else if (0x40..=0x4f).contains(&first) {
        index_extension = first & 2 != 0;
        set(position, 0xf8)?;
        position += 1;
    }
    let mut last = *raw.get(position)?;
    if !vex && last == 0x62 {
        return None; // EVEX is not described yet.
    }
    set(position, 0xff)?;
    position += 1;
    if !vex && last == 0x0f {
        map = 1;
        last = *raw.get(position)?;
        set(position, 0xff)?;
        position += 1;
        if last == 0x38 || last == 0x3a {
            map = if last == 0x38 { 2 } else { 3 };
            last = *raw.get(position)?;
            set(position, 0xff)?;
            position += 1;
        } else if last == 0x0f {
            return None; // 3DNow! carries its opcode after the operands.
        }
    }
    let opcode_end = position;
    if !vex
        && matches!((map, last), (0, 0x50..=0x5f | 0x91..=0x97 | 0xb0..=0xbf) | (1, 0xc8..=0xcf))
    {
        set(opcode_end.checked_sub(1)?, 0xf8)?; // register encoded in the opcode
    }
    let reg_extension = match map {
        0 => matches!(
            last,
            0x80..=0x83 | 0x8f | 0xc0 | 0xc1 | 0xc6 | 0xc7 | 0xd0..=0xdf | 0xf6 | 0xf7 | 0xfe | 0xff
        ),
        1 => matches!(
            last,
            0x00 | 0x01 | 0x0d | 0x18 | 0x1f | 0x71..=0x73 | 0xae | 0xba | 0xc7
        ),
        _ => false,
    };
    let rm_extension = map == 1 && matches!(last, 0x01 | 0xae);
    let displacement = if offsets.has_displacement() {
        offsets.displacement_size()
    } else {
        0
    };
    let immediate = (if offsets.has_immediate() {
        offsets.immediate_size()
    } else {
        0
    }) + (if offsets.has_immediate2() {
        offsets.immediate_size2()
    } else {
        0
    });
    // Whatever follows the opcode beyond displacement and immediate is ModRM (+SIB).
    if raw.len().checked_sub(opcode_end)? > displacement + immediate {
        let modrm = *raw.get(opcode_end)?;
        let (mode, rm) = (modrm >> 6, modrm & 7);
        let mut modrm_mask = 0xc0;
        if reg_extension {
            modrm_mask |= 0x38;
        }
        if mode != 3 {
            if rm == 4 || (mode == 0 && rm == 5) {
                modrm_mask |= 0x07;
            }
        } else if rm_extension {
            modrm_mask |= 0x07;
        }
        set(opcode_end, modrm_mask)?;
        if mode != 3 {
            let mut disp_start = opcode_end + 1;
            let mut base_none = mode == 0 && rm == 5;
            if rm == 4 {
                let sib = *raw.get(opcode_end + 1)?;
                disp_start += 1;
                let mut sib_mask = 0;
                if (sib >> 3) & 7 == 4 && !index_extension && !instruction.is_vsib() {
                    sib_mask |= 0x38; // "no index" is part of the pattern
                }
                base_none = mode == 0 && sib & 7 == 5;
                if base_none {
                    sib_mask |= 0x07;
                }
                set(opcode_end + 1, sib_mask)?;
            }
            // Ghidra has separate constructors for a zero displacement, which
            // keep its bytes in the pattern instead of treating them as operand.
            let has_displacement = mode == 1 || mode == 2 || (base_none && rm == 4);
            if has_displacement
                && !instruction.is_ip_rel_memory_operand()
                && instruction.memory_displacement64() == 0
            {
                for index in disp_start..disp_start + displacement {
                    set(index, 0xff)?;
                }
            }
        }
    }
    let is_call = matches!(
        instruction.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall
    );
    let mut operands = operands(&instruction, &offsets)?;
    // CMPxx with a predicate below 8 (32 for VEX) is a distinct Sleigh
    // constructor: the immediate belongs to the pattern, not to an operand.
    if map == 1 && last == 0xc2 && offsets.has_immediate() {
        let at = offsets.immediate_offset();
        let limit = if vex { 32 } else { 8 };
        if raw.get(at).is_some_and(|predicate| *predicate < limit) {
            set(at, 0xff)?;
            if let Some(operand) = operands.last_mut() {
                operand.objects.clear();
                operand.whole_scalar = false;
            }
        }
    }
    let masked = raw
        .iter()
        .zip(&mask)
        .map(|(byte, mask)| byte & mask)
        .collect();
    Some(Hashed {
        address,
        raw,
        masked,
        is_call,
        operands,
    })
}

fn operands(
    instruction: &Instruction,
    offsets: &iced_x86::ConstantOffsets,
) -> Option<Vec<Operand>> {
    let mut out = Vec::new();
    let string_operation = matches!(
        instruction.mnemonic(),
        Mnemonic::Stosb
            | Mnemonic::Stosw
            | Mnemonic::Stosd
            | Mnemonic::Stosq
            | Mnemonic::Lodsb
            | Mnemonic::Lodsw
            | Mnemonic::Lodsd
            | Mnemonic::Lodsq
            | Mnemonic::Scasb
            | Mnemonic::Scasw
            | Mnemonic::Scasd
            | Mnemonic::Scasq
    );
    for index in 0..instruction.op_count() {
        let kind = instruction.try_op_kind(index).ok()?;
        if string_operation && kind == OpKind::Register {
            continue;
        }
        let mut operand = Operand {
            whole_scalar: false,
            address: false,
            span: (0, 0),
            objects: Vec::new(),
        };
        match kind {
            OpKind::Register => {
                let register = instruction.try_op_register(index).ok()?;
                operand
                    .objects
                    .push(Obj::Register(register_offset(register)?));
            }
            OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => {
                operand.whole_scalar = true;
                operand
                    .objects
                    .push(Obj::Scalar(signed_immediate(instruction, index)?));
                let (start, size) = if matches!(kind, OpKind::Immediate8_2nd) {
                    (offsets.immediate_offset2(), offsets.immediate_size2())
                } else {
                    (offsets.immediate_offset(), offsets.immediate_size())
                };
                operand.span = (start, start + size);
            }
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                operand.objects.push(Obj::Address);
                let start = offsets.immediate_offset();
                operand.span = (start, start + offsets.immediate_size());
            }
            OpKind::Memory => {
                let base = instruction.memory_base();
                let index_register = instruction.memory_index();
                if instruction.segment_prefix() != Register::None {
                    operand.objects.push(Obj::Register(register_offset(
                        instruction.segment_prefix(),
                    )?));
                }
                if instruction.is_ip_rel_memory_operand() {
                    if instruction.mnemonic() == Mnemonic::Lea {
                        // Sleigh resolves LEA's address into a scalar.
                        operand.whole_scalar = true;
                        operand.address = true;
                        operand
                            .objects
                            .push(Obj::Scalar(instruction.ip_rel_memory_address() as i64));
                    } else {
                        operand.objects.push(Obj::Address);
                    }
                } else {
                    let displacement = instruction.memory_displacement64() as i64;
                    let displacement = match instruction.memory_displ_size() {
                        1 => i64::from(displacement as i8),
                        _ => i64::from(displacement as i32),
                    };
                    if base == Register::None
                        && index_register == Register::None
                        && instruction.segment_prefix() == Register::None
                    {
                        operand.objects.push(Obj::Address);
                    } else if base == Register::None && displacement != 0 {
                        operand.objects.push(Obj::Scalar(displacement));
                    }
                    if base != Register::None {
                        operand.objects.push(Obj::Register(register_offset(base)?));
                    }
                    if index_register != Register::None {
                        operand
                            .objects
                            .push(Obj::Register(register_offset(index_register)?));
                        operand
                            .objects
                            .push(Obj::Scalar(i64::from(instruction.memory_index_scale())));
                    }
                    if base != Register::None && displacement != 0 {
                        operand.objects.push(Obj::Scalar(displacement));
                    }
                }
                if offsets.has_displacement() {
                    let start = offsets.displacement_offset();
                    operand.span = (start, start + offsets.displacement_size());
                }
            }
            OpKind::MemoryESRDI => operand
                .objects
                .push(Obj::Register(register_offset(Register::RDI)?)),
            OpKind::MemorySegRSI => operand
                .objects
                .push(Obj::Register(register_offset(Register::RSI)?)),
            _ => return None,
        }
        out.push(operand);
    }
    if matches!(
        instruction.mnemonic(),
        Mnemonic::Cmpsb | Mnemonic::Cmpsw | Mnemonic::Cmpsd | Mnemonic::Cmpsq
    ) && instruction.op_kind(0) == OpKind::MemorySegRSI
        && out.len() == 2
    {
        out.swap(0, 1);
    }
    if matches!(
        instruction.code(),
        Code::Xchg_r64_RAX | Code::Xchg_r32_EAX | Code::Xchg_r16_AX
    ) && out.len() == 2
    {
        out.swap(0, 1);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rows come from Ghidra 12.1.4's own instruction masks and operand objects
    /// (`scripts/decompiler_fid/DumpFidHashes.java`).
    fn row(address: u64, bytes: &[u8], mask: &[u8], operands: &str) {
        let described = describe(address, bytes);
        let Some(described) = described else {
            panic!("undescribed {bytes:02x?}");
        };
        let want: Vec<u8> = bytes.iter().zip(mask).map(|(b, m)| b & m).collect();
        assert_eq!(described.masked, want, "mask of {bytes:02x?}");
        let got: String = described
            .operands
            .iter()
            .map(|operand| {
                let objects: String = operand
                    .objects
                    .iter()
                    .map(|o| match o {
                        Obj::Scalar(v) => format!("S{v},"),
                        Obj::Register(r) => format!("R{r},"),
                        Obj::Address => "A,".into(),
                    })
                    .collect();
                format!("{objects}|")
            })
            .collect();
        assert_eq!(got, operands, "operands of {bytes:02x?}");
    }

    #[test]
    fn stack_store_keeps_the_sib_index_marker() {
        row(
            0x1_4000_1000,
            &[0x48, 0x89, 0x5c, 0x24, 0x10],
            &[0xf8, 0xff, 0xc7, 0x38, 0x00],
            "R32,S16,|R24,|",
        );
    }

    #[test]
    fn indexed_store_masks_the_whole_sib() {
        row(
            0x1000,
            &[0x89, 0x74, 0xc8, 0x04],
            &[0xff, 0xc7, 0x00, 0x00],
            "R0,R8,S8,S4,|R48,|",
        );
    }

    #[test]
    fn segment_absolute_address_is_a_scalar() {
        row(
            0x1000,
            &[0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0, 0, 0],
            &[0xff, 0xf8, 0xff, 0xc7, 0x3f, 0, 0, 0, 0],
            "R0,|R266,S48,|",
        );
    }

    #[test]
    fn zero_displacement_stays_in_the_pattern() {
        row(
            0x1000,
            &[0x0f, 0x1f, 0x40, 0x00],
            &[0xff, 0xff, 0xf8, 0xff],
            "R0,|",
        );
    }

    #[test]
    fn rip_relative_lea_is_an_address_scalar() {
        let described = describe(0x1_4000_1023, &[0x48, 0x8d, 0x05, 0xee, 0x32, 0x04, 0x00]);
        let Some(described) = described else {
            panic!("undescribed lea");
        };
        assert_eq!(described.masked, vec![0x48, 0x8d, 0x05, 0, 0, 0, 0]);
        assert!(described.operands[1].whole_scalar && described.operands[1].address);
        assert_eq!(
            described.operands[1].objects,
            vec![Obj::Scalar(5_368_988_440)]
        );
    }

    #[test]
    fn vex_keeps_only_the_prefix_bits() {
        let described = describe(0x1000, &[0xc5, 0xf9, 0x6f, 0x74, 0x24, 0x20]);
        let Some(described) = described else {
            panic!("undescribed vmovdqa");
        };
        assert_eq!(described.masked, vec![0xc5, 0x01, 0x6f, 0x44, 0x20, 0x00]);
    }

    #[test]
    fn string_operation_lists_only_its_memory_operand() {
        row(0x1000, &[0xf3, 0x48, 0xab], &[0xff, 0xf8, 0xff], "R56,|");
    }

    #[test]
    fn garbage_is_rejected_not_panicked_on() {
        assert!(describe(0, &[]).is_none());
        assert!(describe(0, &[0x0f]).is_none());
        assert!(describe(0, &[0x62, 0xf1]).is_none());
    }
}
