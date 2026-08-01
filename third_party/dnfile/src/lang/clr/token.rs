use serde::Serialize;

pub const RID_MASK: usize = 0x00FFFFFF;
pub const RID_MAX: usize = RID_MASK;
pub const TABLE_SHIFT: usize = 24;

#[derive(Debug, Default, Clone, Serialize)]
pub struct Token {
    pub value: usize,
}

impl Token {
    #[must_use]
    pub fn new(value: usize) -> Self {
        Self { value }
    }
    #[must_use]
    pub fn rid(&self) -> usize {
        self.value & RID_MASK
    }
    #[must_use]
    pub fn table(&self) -> usize {
        self.value >> TABLE_SHIFT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rid_and_table_split() {
        // TypeDef table = index 2, rid 0x123456
        let tok = Token::new((2 << TABLE_SHIFT) | 0x123456);
        assert_eq!(tok.rid(), 0x123456);
        assert_eq!(tok.table(), 2);
    }

    #[test]
    fn rid_is_24_bit() {
        let tok = Token::new(0xFFFF_FFFF);
        assert_eq!(tok.rid(), RID_MAX);
    }

    #[test]
    fn zero_token_yields_zero_rid_and_table() {
        let tok = Token::new(0);
        assert_eq!(tok.rid(), 0);
        assert_eq!(tok.table(), 0);
    }
}
