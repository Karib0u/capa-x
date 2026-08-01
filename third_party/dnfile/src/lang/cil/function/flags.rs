use super::super::super::cil::enums::*;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CilMethodBodyFlags {
    pub flags: usize,
}

impl CilMethodBodyFlags {
    pub fn new(value: usize) -> Self {
        Self { flags: value }
    }

    pub fn small_format(&self) -> bool {
        (self.flags & (CorILMethod::FormatMask as usize)) == CorILMethod::SmallFormat as usize
    }

    pub fn tiny_format(&self) -> bool {
        (self.flags & CorILMethod::FormatMask as usize) == CorILMethod::TinyFormat as usize
    }

    pub fn fat_format(&self) -> bool {
        (self.flags & CorILMethod::FormatMask as usize) == CorILMethod::FatFormat as usize
    }

    pub fn tiny_format_1(&self) -> bool {
        (self.flags & CorILMethod::FormatMask as usize) == CorILMethod::TinyFormat1 as usize
    }
    pub fn more_sects(&self) -> bool {
        (self.flags & CorILMethod::MoreSects as usize) != 0
    }
    pub fn init_locals(&self) -> bool {
        (self.flags & CorILMethod::InitLocals as usize) != 0
    }
    pub fn compressed_il(&self) -> bool {
        (self.flags & CorILMethod::CompressedIL as usize) != 0
    }
    pub fn is_tiny(&self) -> bool {
        self.tiny_format() || self.tiny_format_1()
    }
    pub fn is_fat(&self) -> bool {
        self.fat_format()
    }
}
