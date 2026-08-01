use crate::{Result, error::Error};

pub mod flags;
pub mod reader;

use super::super::clr::token::Token;
use super::enums::*;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Function {
    /// The owning `MethodDef` token. Zero (an invalid token -- rid 0 never
    /// exists) until the caller (`DnPe::parse_functions`) sets it; `Function`
    /// itself has no metadata-table context to compute it from.
    pub token: Token,
    pub offset: usize,
    header_size: usize,
    flags: flags::CilMethodBodyFlags,
    max_stack: usize,
    code_size: usize,
    local_var_sig_tok: Option<Token>,
    size: usize,
    exception_handlers_size: usize,
    pub instructions: Vec<super::instruction::Instruction>,
    exception_handlers: Vec<super::exception::ExceptionHandler>,
}

impl Function {
    pub fn new(reader: &mut reader::Reader<'_>) -> Result<Self> {
        let mut res = Self {
            token: Token::new(0),
            offset: reader.tell()?,
            header_size: 0,
            flags: flags::CilMethodBodyFlags::new(0),
            max_stack: 0,
            code_size: 0,
            local_var_sig_tok: None,
            size: 0,
            exception_handlers_size: 0,
            instructions: vec![],
            exception_handlers: vec![],
        };
        res.parse_header(reader)?;
        res.parse_instructions(reader)?;
        res.parse_exception_handlers(reader)?;
        Ok(res)
    }

    #[must_use]
    pub fn header_size(&self) -> usize {
        self.header_size
    }

    #[must_use]
    pub fn code_size(&self) -> usize {
        self.code_size
    }

    #[must_use]
    pub fn max_stack(&self) -> usize {
        self.max_stack
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }

    #[must_use]
    pub fn local_var_sig_tok(&self) -> Option<&Token> {
        self.local_var_sig_tok.as_ref()
    }

    #[must_use]
    pub fn is_tiny(&self) -> bool {
        self.flags.is_tiny()
    }

    #[must_use]
    pub fn is_fat(&self) -> bool {
        self.flags.is_fat()
    }

    #[must_use]
    pub fn more_sects(&self) -> bool {
        self.flags.more_sects()
    }

    #[must_use]
    pub fn exception_handlers(&self) -> &[super::exception::ExceptionHandler] {
        &self.exception_handlers
    }

    pub fn parse_header(&mut self, reader: &mut reader::Reader<'_>) -> Result<()> {
        let header_byte = reader.read_u8()? as usize;
        if [
            CorILMethod::TinyFormat as usize,
            CorILMethod::TinyFormat1 as usize,
        ]
        .contains(&(header_byte & CorILMethod::FormatMask as usize))
        {
            self.flags =
                flags::CilMethodBodyFlags::new(header_byte & CorILMethod::FormatMask as usize);
            self.header_size = 1;
            self.max_stack = 8;
            self.code_size = header_byte >> 2;
            self.local_var_sig_tok = None;
        } else if [CorILMethod::FatFormat as usize]
            .contains(&(header_byte & CorILMethod::FormatMask as usize))
        {
            self.flags =
                flags::CilMethodBodyFlags::new(((reader.read_u8()? as usize) << 8) | header_byte);
            self.header_size = self.flags.flags >> 12;
            self.max_stack = reader.read_u16()? as usize;
            self.code_size = reader.read_u32()? as usize;
            let local_var_sig_tok = reader.read_u32()? as usize;
            if local_var_sig_tok == 0 {
                self.local_var_sig_tok = None;
            } else {
                self.local_var_sig_tok = Some(Token::new(local_var_sig_tok));
            }
            let pos = reader.tell()? - 12 + self.header_size * 4;
            reader.seek(pos)?;
            if self.header_size < 3 {
                self.flags.flags &= 0xFFF7;
            }
            self.header_size *= 4
        } else {
            return Err(Error::MethodBodyFormatError(format!(
                "bad header format {:02x}",
                header_byte & CorILMethod::FormatMask as usize
            )));
        }
        Ok(())
    }

    pub fn parse_instructions(&mut self, reader: &mut reader::Reader<'_>) -> Result<()> {
        let mut current_offset =
            self.offset
                .checked_add(self.header_size)
                .ok_or(Error::MethodBodyFormatError(
                    "method offset+header_size overflow".to_string(),
                ))?;
        let code_end_offset =
            reader
                .tell()?
                .checked_add(self.code_size)
                .ok_or(Error::MethodBodyFormatError(
                    "method code_size overflow".to_string(),
                ))?;
        while reader.tell()? < code_end_offset {
            let insn = reader.read_instruction(current_offset)?;
            // Defensive: a zero-size instruction would loop forever. The
            // current opcode table never produces one, but a future bug
            // shouldn't be able to hang the parser.
            let isize = insn.size();
            if isize == 0 {
                return Err(Error::MethodBodyFormatError(
                    "zero-size instruction".to_string(),
                ));
            }
            current_offset =
                current_offset
                    .checked_add(isize)
                    .ok_or(Error::MethodBodyFormatError(
                        "instruction offset overflow".to_string(),
                    ))?;
            self.instructions.push(insn);
        }
        Ok(())
    }

    pub fn parse_exception_handlers(&mut self, reader: &mut reader::Reader<'_>) -> Result<()> {
        if !self.flags.more_sects() {
            self.size = reader.tell()? - self.offset;
            return Ok(());
        }
        let pos = (reader.tell()? + 3) & !3;
        reader.seek(pos)?;
        let header_byte = reader.read_u8()?;
        if header_byte as usize & CorILMethodSect::KindMask as usize != 1 {
            self.size = reader.tell()? - self.offset;
            return Ok(());
        }
        if header_byte as usize & CorILMethodSect::FatFormat as usize != 0 {
            self.parse_fat_exception_handlers(reader)?;
        } else {
            self.parse_tiny_exception_handlers(reader)?;
        }
        self.size = reader.tell()? - self.offset;
        Ok(())
    }

    pub fn parse_fat_exception_handlers(&mut self, reader: &mut reader::Reader<'_>) -> Result<()> {
        let pos = reader
            .tell()?
            .checked_sub(1)
            .ok_or(Error::MethodBodyFormatError(
                "fat EH header out of bounds".to_string(),
            ))?;
        reader.seek(pos)?;
        let total_size = (reader.read_u32()? >> 8) as usize;
        // Pinned `dncil` (`cil/body/__init__.py::parse_fat_exception_handlers`)
        // computes `num_exceptions = total_size // ExceptionHandler.FAT_SIZE`
        // -- no `-4` for the header, even though ECMA-335 II.25.4.6 defines
        // `total_size` as including it. That's the pinned behavioral spec
        // (AGENTS.md: "capa wins"), so match it exactly rather than "fix" it.
        // No manual bound on `num_exceptions` is needed: `total_size` is a
        // 24-bit value (max ~699,050 after `/ FAT_SIZE`), the loop never
        // pre-allocates, and each field read below returns `Err` via `?` the
        // moment the underlying buffer runs out -- so a crafted `total_size`
        // can only spin through as many iterations as the file actually has
        // bytes for, never further.
        let num_exceptions = total_size / super::exception::FAT_SIZE;
        for _ in 0..num_exceptions {
            let mut eh = super::exception::ExceptionHandler::new(reader.read_u32()? as usize);
            eh.try_start = reader.read_i32()? as i64;
            let bb = reader.read_i32()?;
            eh.try_end = eh.try_start + bb as i64;
            eh.handler_start = reader.read_i32()? as i64;
            eh.handler_end = eh.handler_start + reader.read_i32()? as i64;
            if eh.is_catch() {
                eh.catch_type = Some(Token::new(reader.read_u32()? as usize));
            } else if eh.is_filter() {
                eh.filter_start = reader.read_u32()? as i64;
            } else {
                reader.read_u32()?;
            }
            self.exception_handlers.push(eh);
        }
        Ok(())
    }

    pub fn parse_tiny_exception_handlers(&mut self, reader: &mut reader::Reader<'_>) -> Result<()> {
        // Pinned `dncil` divides the tiny-section data-size byte by
        // `ExceptionHandler.TINY_SIZE` (12) to get the clause count; this
        // fork previously read the raw byte as the count directly, wildly
        // overcounting (found while auditing this fork against pinned
        // `dncil` for the CIL decoder comparison -- see `PATCH.md`).
        let num_exceptions = (reader.read_u8()? as usize) / super::exception::TINY_SIZE;
        let pos = reader.tell()? + 2;
        reader.seek(pos)?;
        for _ in 0..num_exceptions {
            let mut eh = super::exception::ExceptionHandler::new(reader.read_u16()? as usize);
            eh.try_start = reader.read_u16()? as i64;
            eh.try_end = eh.try_start + reader.read_u8()? as i64;
            eh.handler_start = reader.read_u16()? as i64;
            eh.handler_end = eh.handler_start + reader.read_u8()? as i64;
            if eh.is_catch() {
                eh.catch_type = Some(Token::new(reader.read_u32()? as usize));
            } else if eh.is_filter() {
                eh.filter_start = reader.read_u32()? as i64;
            } else {
                reader.read_u32()?;
            }
            self.exception_handlers.push(eh);
        }
        Ok(())
    }
}
