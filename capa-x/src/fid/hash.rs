//! FNV-1a digest and the function hasher (`MessageDigestFidHasher`).

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 1_099_511_628_211;
/// Marks "a scalar was present but its value is not used" (Java `0xfeeddead`).
const ABSENT: i32 = 0xfeed_dead_u32 as i32;
const SHORT_CODE_UNIT_LIMIT: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fnv1a64(u64);

impl Fnv1a64 {
    pub fn new() -> Self {
        Self(FNV_OFFSET)
    }
    pub fn update_byte(&mut self, byte: u8) {
        self.0 = (self.0 ^ u64::from(byte)).wrapping_mul(FNV_PRIME);
    }
    pub fn update_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.update_byte(byte);
        }
    }
    /// Java `MessageDigest.update(int)`: big-endian.
    pub fn update_i32(&mut self, value: i32) {
        self.update_bytes(&value.to_be_bytes());
    }
    pub fn finish(self) -> u64 {
        self.0
    }
}

impl Default for Fnv1a64 {
    fn default() -> Self {
        Self::new()
    }
}

/// Object in a Ghidra operand representation list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Obj {
    /// Signed scalar value, sign-extended from its encoded size.
    Scalar(i64),
    /// Offset of the register in Ghidra's register space.
    Register(u32),
    Address,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operand {
    /// Ghidra `OperandType.isScalar`: the whole operand is one scalar.
    pub whole_scalar: bool,
    /// Ghidra `OperandType.isAddress`.
    pub address: bool,
    /// Byte range `[start, end)` inside the instruction covered by the
    /// operand value mask, used for the relocation test.
    pub span: (usize, usize),
    pub objects: Vec<Obj>,
}

/// One hashed instruction: its bytes with the instruction mask applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub address: u64,
    pub raw: Vec<u8>,
    pub masked: Vec<u8>,
    pub is_call: bool,
    pub operands: Vec<Operand>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Quad {
    pub code_units: i16,
    pub full_hash: u64,
    pub specific_additional: i8,
    pub specific_hash: u64,
}

/// x86 `X86InstructionSkipper`: padding the hash ignores.
fn skipped(raw: &[u8]) -> bool {
    const PATTERNS: &[&[u8]] = &[
        &[0x90],
        &[0x8b, 0xc0],
        &[0x8b, 0xc9],
        &[0x8b, 0xd2],
        &[0x8b, 0xdb],
        &[0x8b, 0xe4],
        &[0x8b, 0xed],
        &[0x8b, 0xf6],
        &[0x8b, 0xff],
        &[0x66, 0x90],
        &[0x0f, 0x1f, 0x00],
        &[0x0f, 0x1f, 0x40, 0x00],
        &[0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
        &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    PATTERNS.contains(&raw)
}

/// Hash a function given its instructions in address order. `has_relocation`
/// tells whether a base relocation overlaps `[start, end]` (inclusive).
/// Returns `None` when the function is too short, like Ghidra.
pub fn hash_function(
    instructions: &[Instruction],
    has_relocation: &dyn Fn(u64, u64) -> bool,
) -> Option<Quad> {
    if instructions.len() < SHORT_CODE_UNIT_LIMIT {
        return None;
    }
    let mut full = Fnv1a64::new();
    let mut specific = Fnv1a64::new();
    let mut specific_count = 0_i32;
    let mut call_count = 0_i32;
    let mut index = -1_i32;
    for insn in instructions {
        index += 1;
        if index >= i32::from(i16::MAX) - 1 {
            break;
        }
        if skipped(&insn.raw) {
            index -= 1;
            continue;
        }
        if insn.is_call {
            call_count += 1;
        }
        for (position, operand) in insn.operands.iter().enumerate() {
            let mut specific_update = (position as i32 + 1).wrapping_mul(7777);
            let mut full_update = specific_update;
            for object in &operand.objects {
                match *object {
                    Obj::Scalar(value) => {
                        let (lo, hi) = (
                            insn.address.wrapping_add(operand.span.0 as u64),
                            insn.address.wrapping_add(operand.span.1.max(1) as u64 - 1),
                        );
                        let value = if operand.span.1 > operand.span.0 && has_relocation(lo, hi) {
                            ABSENT
                        } else if operand.whole_scalar {
                            if operand.address {
                                ABSENT
                            } else {
                                specific_count += 1;
                                value as i32
                            }
                        } else if value >= 256 || value <= -256 {
                            ABSENT
                        } else {
                            specific_count += 1;
                            value as i32
                        };
                        specific_update = specific_update
                            .wrapping_add(value.wrapping_add(1_234_567).wrapping_mul(67_999));
                        full_update = full_update.wrapping_add(ABSENT);
                    }
                    Obj::Register(offset) => {
                        let value = (offset as i32).wrapping_add(7_654_321).wrapping_mul(98_777);
                        full_update = full_update.wrapping_add(value);
                        specific_update = specific_update.wrapping_add(value);
                    }
                    Obj::Address => {
                        specific_update = specific_update
                            .wrapping_add(ABSENT.wrapping_add(1_234_567).wrapping_mul(67_999));
                        full_update = full_update.wrapping_add(ABSENT);
                    }
                }
            }
            full.update_i32(full_update);
            specific.update_i32(specific_update);
        }
        full.update_bytes(&insn.masked);
        specific.update_bytes(&insn.masked);
    }
    index += 1;
    if index < SHORT_CODE_UNIT_LIMIT as i32 {
        return None;
    }
    Some(Quad {
        code_units: (index - call_count) as i16,
        full_hash: full.finish(),
        specific_additional: specific_count.min(i32::from(i8::MAX)) as i8,
        specific_hash: specific.finish(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fid::x86::describe;

    #[test]
    fn fnv_1a_matches_published_vectors() {
        let mut digest = Fnv1a64::new();
        assert_eq!(digest.finish(), 0xcbf2_9ce4_8422_2325);
        digest.update_byte(b'a');
        assert_eq!(digest.finish(), 0xaf63_dc4c_8601_ec8c);
        let mut digest = Fnv1a64::new();
        digest.update_bytes(b"foobar");
        assert_eq!(digest.finish(), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn integers_update_the_digest_big_endian() {
        let mut by_int = Fnv1a64::new();
        by_int.update_i32(0x0102_0304);
        let mut by_bytes = Fnv1a64::new();
        by_bytes.update_bytes(&[1, 2, 3, 4]);
        assert_eq!(by_int, by_bytes);
    }

    /// Ghidra 12.1.4 hashed this function (`14003b120` of
    /// c2d46d256b8f9490c9599eea11ecef19fde7d4fdd2dea93604cee3cea8e172ac) as
    /// 9 code units, full a7e135c380614a9, +2, specific a1482f2b820bc749.
    #[test]
    fn matches_ghidra_hash_of_a_small_function() {
        let code: &[&[u8]] = &[
            &[0x40, 0x55],
            &[0x48, 0x83, 0xec, 0x20],
            &[0x48, 0x8b, 0xea],
            &[0x48, 0x8b, 0x01],
            &[0x48, 0x8b, 0xd1],
            &[0x8b, 0x08],
            &[0xe8, 0x72, 0x38, 0xff, 0xff],
            &[0x90],
            &[0x48, 0x83, 0xc4, 0x20],
            &[0x5d],
            &[0xc3],
        ];
        let mut address = 0x1_4003_b120_u64;
        let mut instructions = Vec::new();
        for bytes in code {
            let described = describe(address, bytes);
            assert!(described.is_some(), "{bytes:02x?}");
            instructions.extend(described);
            address += bytes.len() as u64;
        }
        let quad = hash_function(&instructions, &|_, _| false);
        assert_eq!(
            quad,
            Some(Quad {
                code_units: 9,
                full_hash: 0x0a7e_135c_3806_14a9,
                specific_additional: 2,
                specific_hash: 0xa148_2f2b_820b_c749,
            })
        );
    }

    #[test]
    fn short_functions_are_not_hashed() {
        let instructions: Vec<_> = (0..3)
            .filter_map(|i| describe(0x1000 + i, &[0x55]))
            .collect();
        assert_eq!(instructions.len(), 3);
        assert_eq!(hash_function(&instructions, &|_, _| false), None);
    }
}
