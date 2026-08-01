use super::super::super::clr::{argument::Argument, local::Local, token::Token};
use super::super::instruction::{Instruction, Operand};
use super::super::{enums::*, opcode::*};
use crate::{Result, error::Error};
use byteorder::ReadBytesExt;

use std::io::{Cursor, Seek};

/// Zero-copy CIL bytecode reader.
///
/// Borrows the underlying byte buffer (typically a slice into the parent
/// `DnPe::data`) so parsing a function body does not allocate a copy of
/// the whole file per method.
pub struct Reader<'a> {
    stream: Cursor<&'a [u8]>,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            stream: Cursor::new(bytes),
        }
    }

    pub fn tell(&mut self) -> Result<usize> {
        Ok(self.stream.stream_position()? as usize)
    }

    pub fn seek(&mut self, pos: usize) -> Result<usize> {
        Ok(self.stream.seek(std::io::SeekFrom::Start(pos as u64))? as usize)
    }

    /// Bytes still available in the underlying buffer from the current
    /// cursor position. Used by callers that need to clamp attacker-supplied
    /// counts against the remaining file.
    pub fn stream_remaining(&mut self) -> usize {
        let len = self.stream.get_ref().len();
        let pos = self.tell().unwrap_or(len);
        len.saturating_sub(pos)
    }

    #[allow(clippy::unused_self)]
    pub fn is_arg_operand_instruction(&self, insn: &Instruction) -> bool {
        [
            OpCodeValue::Ldarg,
            OpCodeValue::Ldarg_S,
            OpCodeValue::Ldarga,
            OpCodeValue::Ldarga_S,
            OpCodeValue::Starg,
            OpCodeValue::Starg_S,
        ]
        .contains(&insn.opcode.value)
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.stream.read_u8()?)
    }

    pub fn read_i8(&mut self) -> Result<i8> {
        Ok(self.stream.read_i8()?)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        Ok(self.stream.read_u16::<byteorder::LittleEndian>()?)
    }

    pub fn read_i16(&mut self) -> Result<i16> {
        Ok(self.stream.read_i16::<byteorder::LittleEndian>()?)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        Ok(self.stream.read_u32::<byteorder::LittleEndian>()?)
    }

    pub fn read_i32(&mut self) -> Result<i32> {
        Ok(self.stream.read_i32::<byteorder::LittleEndian>()?)
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        Ok(self.stream.read_u64::<byteorder::LittleEndian>()?)
    }

    pub fn read_i64(&mut self) -> Result<i64> {
        Ok(self.stream.read_i64::<byteorder::LittleEndian>()?)
    }

    pub fn read_f32(&mut self) -> Result<f32> {
        Ok(self.stream.read_f32::<byteorder::LittleEndian>()?)
    }

    pub fn read_f64(&mut self) -> Result<f64> {
        Ok(self.stream.read_f64::<byteorder::LittleEndian>()?)
    }

    pub fn read_inline_br_target(&mut self, insn: &Instruction) -> Result<Operand> {
        // Same signedness bug as `read_short_inline_br_target` above, for
        // the 4-byte branch form (`br`/`brfalse`/`brtrue`/... without the
        // `.s` suffix): pinned `dncil` reads a signed `int32`.
        let branch_offset = self.read_i32()? as i64;
        Ok(Operand::Int(
            insn.offset as i64 + insn.size() as i64 + branch_offset,
        ))
    }

    pub fn read_inline_field(&mut self, _insn: &Instruction) -> Result<Operand> {
        let token_value = self.read_u32()? as usize;
        Ok(Operand::Token(Token::new(token_value)))
    }

    pub fn read_inline_i(&mut self, _insn: &Instruction) -> Result<Operand> {
        // Pinned `dncil` reads `InlineI` (e.g. `ldc.i4`) as a signed
        // `int32` (`read_int32`) -- this fork zero-extended an unsigned
        // read instead, turning every negative 32-bit constant positive.
        let v = self.read_i32()? as i64;
        Ok(Operand::Int(v))
    }

    pub fn read_inline_i8(&mut self, _insn: &Instruction) -> Result<Operand> {
        let v = self.read_i64()?;
        Ok(Operand::Int(v))
    }

    pub fn read_inline_method(&mut self, _insn: &Instruction) -> Result<Operand> {
        let token_value = self.read_u32()? as usize;
        Ok(Operand::Token(Token::new(token_value)))
    }

    pub fn read_inline_none(&mut self, _insn: &Instruction) -> Result<Operand> {
        Ok(Operand::None)
    }

    pub fn read_inline_phi(&mut self, _insn: &Instruction) -> Result<Operand> {
        Ok(Operand::None)
    }

    pub fn read_inline_r(&mut self, _insn: &Instruction) -> Result<Operand> {
        let v = self.read_f64()?;
        Ok(Operand::Float(v))
    }

    pub fn read_inline_sig(&mut self, _insn: &Instruction) -> Result<Operand> {
        let token_value = self.read_u32()? as usize;
        Ok(Operand::Token(Token::new(token_value)))
    }

    pub fn read_inline_string(&mut self, _insn: &Instruction) -> Result<Operand> {
        let token_value = self.read_u32()? as usize;
        Ok(Operand::StringToken(Token::new(token_value)))
    }

    pub fn read_inline_switch(&mut self, insn: &Instruction) -> Result<Operand> {
        let num_branches = self.read_u32()? as usize;
        // Each branch is 4 bytes. Reject if the table can't possibly fit
        // in the remainder of the file buffer — otherwise a crafted
        // `num_branches == u32::MAX` would attempt a ~16 GB allocation.
        let remaining = self.stream.get_ref().len().saturating_sub(self.tell()?);
        let needed = num_branches
            .checked_mul(4)
            .ok_or(Error::MethodBodyFormatError(
                "switch num_branches overflow".to_string(),
            ))?;
        if needed > remaining {
            return Err(Error::MethodBodyFormatError(format!(
                "switch table too large: {num_branches} branches > {} remaining bytes / 4",
                remaining
            )));
        }
        let table_size = insn
            .opcode
            .size()
            .checked_add(4)
            .and_then(|s| s.checked_add(needed))
            .ok_or(Error::MethodBodyFormatError(
                "switch table size overflow".to_string(),
            ))?;
        let offset_after_insn =
            insn.offset
                .checked_add(table_size)
                .ok_or(Error::MethodBodyFormatError(
                    "switch offset_after_insn overflow".to_string(),
                ))?;
        let mut branches = Vec::with_capacity(num_branches);
        for _ in 0..num_branches {
            // Pinned `dncil` reads each branch offset as a signed `int32`
            // (`read_int32`), same as the `br`/`br.s` targets above -- this
            // fork read it unsigned here too.
            let branch_offset = self.read_i32()? as i64;
            let target = (offset_after_insn as i64)
                .checked_add(branch_offset)
                .ok_or(Error::MethodBodyFormatError(
                    "switch branch target overflow".to_string(),
                ))?;
            branches.push(Operand::Int(target));
        }
        Ok(Operand::Arguments(branches))
    }

    pub fn read_inline_tok(&mut self, _insn: &Instruction) -> Result<Operand> {
        let token_value = self.read_u32()? as usize;
        Ok(Operand::Token(Token::new(token_value)))
    }

    pub fn read_inline_type(&mut self, _insn: &Instruction) -> Result<Operand> {
        let token_value = self.read_u32()? as usize;
        Ok(Operand::Token(Token::new(token_value)))
    }

    pub fn read_inline_var(&mut self, insn: &Instruction) -> Result<Operand> {
        let var_value = self.read_u16()?;
        if self.is_arg_operand_instruction(insn) {
            Ok(Operand::Argument(Argument::new(var_value as usize)))
        } else {
            Ok(Operand::Local(Local::new(var_value as usize)))
        }
    }

    pub fn read_short_inline_br_target(&mut self, insn: &Instruction) -> Result<Operand> {
        // Pinned `dncil` (`cil/body/reader.py::read_short_inline_br_target`)
        // reads this as a *signed* byte (`read_int8`) -- this fork read it
        // unsigned, turning every backward short branch (any loop, the
        // overwhelming common case for `br.s`/`blt.s`/etc.) into a wildly
        // wrong forward target. Found auditing this fork against pinned
        // `dncil` for the CIL decoder comparison (`PATCH.md`).
        let branch_offset = self.read_i8()? as i64;
        Ok(Operand::Int(
            insn.offset as i64 + insn.size() as i64 + branch_offset,
        ))
    }

    pub fn read_short_inline_i(&mut self, _insn: &Instruction) -> Result<Operand> {
        // Pinned `dncil` (`cil/body/reader.py::read_short_inline_i`) always
        // reads a signed `int8` here, for every `ShortInlineI` opcode
        // (`ldc.i4.s`, `unaligned.`, `no.`) -- not just `ldc.i4.s`. This
        // fork special-cased `ldc.i4.s` and read the other two unsigned.
        let val = self.read_i8()?;
        Ok(Operand::Int(val as i64))
    }

    pub fn read_short_inline_r(&mut self, _insn: &Instruction) -> Result<Operand> {
        Ok(Operand::Float(self.read_f32()? as f64))
    }

    pub fn read_short_inline_var(&mut self, insn: &Instruction) -> Result<Operand> {
        let var_value = self.read_u8()?;
        if self.is_arg_operand_instruction(insn) {
            Ok(Operand::Argument(Argument::new(var_value as usize)))
        } else {
            Ok(Operand::Local(Local::new(var_value as usize)))
        }
    }

    pub fn read_instruction(&mut self, off: usize) -> Result<Instruction> {
        let mut insn = Instruction::new();
        insn.offset = off;
        insn.opcode = self.read_opcode()?;
        insn.operand = self.read_operand(&insn)?;
        Ok(insn)
    }

    pub fn read_opcode(&mut self) -> Result<OpCode> {
        let op_value_first = self.read_u8()? as usize;
        if op_value_first == 0xFE {
            let op_value_second = self.read_u8()? as usize;
            Ok(OPCODES.two_byte_op_codes[op_value_second].clone())
        } else {
            Ok(OPCODES.one_byte_op_codes[op_value_first].clone())
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn read_operand(&mut self, insn: &Instruction) -> Result<Operand> {
        match insn.opcode.operand_type {
            OperandType::InlineBrTarget => self.read_inline_br_target(insn),
            OperandType::InlineField => self.read_inline_field(insn),
            OperandType::InlineI => self.read_inline_i(insn),
            OperandType::InlineI8 => self.read_inline_i8(insn),
            OperandType::InlineMethod => self.read_inline_method(insn),
            OperandType::InlineNone => self.read_inline_none(insn),
            OperandType::InlinePhi => self.read_inline_phi(insn),
            OperandType::InlineR => self.read_inline_r(insn),
            OperandType::InlineSig => self.read_inline_sig(insn),
            OperandType::InlineString => self.read_inline_string(insn),
            OperandType::InlineSwitch => self.read_inline_switch(insn),
            OperandType::InlineTok => self.read_inline_tok(insn),
            OperandType::InlineType => self.read_inline_type(insn),
            OperandType::InlineVar => self.read_inline_var(insn),
            OperandType::ShortInlineBrTarget => self.read_short_inline_br_target(insn),
            OperandType::ShortInlineI => self.read_short_inline_i(insn),
            OperandType::ShortInlineR => self.read_short_inline_r(insn),
            OperandType::ShortInlineVar => self.read_short_inline_var(insn),
            _ => Err(Error::UndefinedOperandType(
                insn.opcode.operand_type.clone(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_borrows_input_without_copying() {
        let buf = [0x01_u8, 0x02, 0x03, 0x04];
        let mut r = Reader::new(&buf);
        assert_eq!(r.tell().unwrap(), 0);
        assert_eq!(r.read_u8().unwrap(), 0x01);
        assert_eq!(r.tell().unwrap(), 1);
    }

    #[test]
    fn reader_read_u16_little_endian() {
        let mut r = Reader::new(&[0x34, 0x12]);
        assert_eq!(r.read_u16().unwrap(), 0x1234);
    }

    #[test]
    fn reader_read_u32_little_endian() {
        let mut r = Reader::new(&[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(r.read_u32().unwrap(), 0x1234_5678);
    }

    #[test]
    fn reader_read_i32_negative() {
        let mut r = Reader::new(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(r.read_i32().unwrap(), -1_i32);
    }

    #[test]
    fn reader_seek_and_tell() {
        let mut r = Reader::new(&[0_u8; 16]);
        r.seek(8).unwrap();
        assert_eq!(r.tell().unwrap(), 8);
        r.seek(0).unwrap();
        assert_eq!(r.tell().unwrap(), 0);
    }

    #[test]
    fn reader_read_past_end_errors() {
        let mut r = Reader::new(&[]);
        assert!(r.read_u8().is_err());
    }
}
