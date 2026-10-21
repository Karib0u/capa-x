//! Reader for the compact FID table written by `scripts/decompiler_fid/pack_fid.py`.
//!
//! The table is trusted build input, but every read is still bounds checked
//! and reported as an error so a damaged pack can never panic or loop.
use flate2::read::ZlibDecoder;
use std::io::Read;

const MAGIC: &[u8; 8] = b"CXFID001";
const RECORD_BYTES: usize = 17;
const BUCKETS: usize = 4096;
const FNV_PRIME: u64 = 1_099_511_628_211;
const KEY_MASK: u64 = (1 << 36) - 1;

pub const FLAG_AUTO_PASS: u8 = 2;
pub const FLAG_AUTO_FAIL: u8 = 4;
pub const FLAG_FORCE_SPECIFIC: u8 = 8;
pub const FLAG_FORCE_RELATION: u8 = 16;

#[derive(Debug)]
pub struct PackError(String);

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid FID pack: {}", self.0)
    }
}

impl std::error::Error for PackError {}

fn bad<T>(what: &str) -> Result<T, PackError> {
    Err(PackError(what.to_owned()))
}

/// One Function ID record: a library function's hashes and name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub specific_hash: u32,
    /// Low 40 bits of the database function key.
    pub key: u64,
    pub code_units: u16,
    pub specific_additional: i8,
    pub flags: u8,
    pub db: u8,
    pub name: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    /// The record (caller) is known to call a function with the hash.
    Superior,
    /// The record (callee) is known to be called by a function with the hash.
    Inferior,
}

pub struct Pack<'a> {
    data: &'a [u8],
    records: u32,
    names: u32,
    databases: u32,
    fh: usize,
    rec: usize,
    name_index: usize,
    name_blocks: usize,
    name_block_count: u32,
    relations: usize,
}

fn array<const N: usize>(data: &[u8], at: usize) -> Option<[u8; N]> {
    data.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn read_u32(data: &[u8], at: usize) -> Result<u32, PackError> {
    array(data, at)
        .map(u32::from_le_bytes)
        .ok_or_else(|| PackError("truncated".into()))
}

impl<'a> Pack<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, PackError> {
        if data.get(..8) != Some(&MAGIC[..]) {
            return bad("bad magic");
        }
        let records = read_u32(data, 8)?;
        let names = read_u32(data, 12)?;
        let databases = read_u32(data, 16)?;
        let fh = read_u32(data, 24)? as usize;
        let rec = read_u32(data, 28)? as usize;
        let name_index = read_u32(data, 32)? as usize;
        let name_blocks = read_u32(data, 36)? as usize;
        let relations = read_u32(data, 40)? as usize;
        let need = |start: usize, count: usize, width: usize| -> Result<(), PackError> {
            let bytes = count.checked_mul(width).and_then(|n| n.checked_add(start));
            match bytes {
                Some(end) if end <= data.len() => Ok(()),
                _ => bad("section out of range"),
            }
        };
        need(fh, records as usize, 8)?;
        need(rec, records as usize, RECORD_BYTES)?;
        need(name_index, names as usize + 1, 4)?;
        let name_block_count = read_u32(data, name_blocks)?;
        need(name_blocks + 4, name_block_count as usize, 12)?;
        if read_u32(data, relations)? != databases.saturating_mul(2) {
            return bad("relation set count");
        }
        need(relations + 4, databases as usize * 2, 12)?;
        Ok(Self {
            data,
            records,
            names,
            databases,
            fh,
            rec,
            name_index,
            name_blocks,
            name_block_count,
            relations,
        })
    }

    pub fn record_count(&self) -> usize {
        self.records as usize
    }

    fn full_hash_at(&self, index: usize) -> u64 {
        array(self.data, self.fh + index * 8).map_or(0, u64::from_le_bytes)
    }

    fn record_at(&self, index: usize) -> Option<Record> {
        let b: [u8; RECORD_BYTES] = array(self.data, self.rec + index * RECORD_BYTES)?;
        Some(Record {
            specific_hash: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            key: u64::from_le_bytes([b[4], b[5], b[6], b[7], b[8], 0, 0, 0]),
            code_units: u16::from_le_bytes([b[9], b[10]]),
            specific_additional: i8::from_le_bytes([b[11]]),
            flags: b[12],
            db: b[13],
            name: u32::from_le_bytes([b[14], b[15], b[16], 0]),
        })
    }

    #[cfg(test)]
    pub(crate) fn candidates_at(&self, index: usize) -> Option<Record> {
        self.record_at(index)
    }

    #[cfg(test)]
    pub(crate) fn full_hash_of(&self, index: usize) -> u64 {
        self.full_hash_at(index)
    }

    /// All records whose full hash equals `full_hash`, in pack order.
    pub fn candidates(&self, full_hash: u64) -> Vec<Record> {
        let (mut low, mut high) = (0_usize, self.records as usize);
        while low < high {
            let middle = low + (high - low) / 2;
            if self.full_hash_at(middle) < full_hash {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let mut out = Vec::new();
        let mut index = low;
        while index < self.records as usize && self.full_hash_at(index) == full_hash {
            out.extend(self.record_at(index));
            index += 1;
        }
        out
    }

    /// Whether the record has a recorded call relation with a function of
    /// `other_full_hash`, using Ghidra's `FidDBUtils` smash key truncated to 36 bits.
    pub fn has_relation(&self, relation: Relation, record: &Record, other_full_hash: u64) -> bool {
        if u32::from(record.db) >= self.databases {
            return false;
        }
        let set = usize::from(record.db) * 2 + usize::from(relation == Relation::Inferior);
        let smash = (record.key.wrapping_mul(FNV_PRIME) ^ other_full_hash) & KEY_MASK;
        self.contains(set, smash).unwrap_or(false)
    }

    fn contains(&self, set: usize, key: u64) -> Result<bool, PackError> {
        let entry = self.relations + 4 + set * 12;
        let offset = read_u32(self.data, entry)? as usize;
        let count = read_u32(self.data, entry + 4)? as usize;
        let bucket = (key >> 24) as usize;
        if bucket >= BUCKETS {
            return Ok(false);
        }
        let start = read_u32(self.data, offset + bucket * 4)? as usize;
        let end = read_u32(self.data, offset + bucket * 4 + 4)? as usize;
        if start > end || end > count {
            return bad("relation bucket");
        }
        let base = offset + (BUCKETS + 1) * 4;
        let remainder = (key & 0xff_ffff) as u32;
        let (mut low, mut high) = (start, end);
        while low < high {
            let middle = low + (high - low) / 2;
            let bytes: [u8; 3] =
                array(self.data, base + middle * 3).ok_or_else(|| PackError("truncated".into()))?;
            let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]);
            match value.cmp(&remainder) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return Ok(true),
            }
        }
        Ok(false)
    }

    /// The function name for `id`.
    pub fn name(&self, id: u32) -> Result<String, PackError> {
        if id >= self.names {
            return bad("name id");
        }
        let at = self.name_index + id as usize * 4;
        let start = read_u32(self.data, at)? as usize;
        let end = read_u32(self.data, at + 4)? as usize;
        // Find the block containing `start`.
        let mut chosen = None;
        for block in 0..self.name_block_count as usize {
            let entry = self.name_blocks + 4 + block * 12;
            let raw_start = read_u32(self.data, entry)? as usize;
            if raw_start <= start {
                chosen = Some((
                    raw_start,
                    read_u32(self.data, entry + 4)? as usize,
                    read_u32(self.data, entry + 8)? as usize,
                ));
            } else {
                break;
            }
        }
        let (raw_start, offset, length) = chosen.ok_or_else(|| PackError("name block".into()))?;
        let compressed = self
            .data
            .get(
                offset
                    ..offset
                        .checked_add(length)
                        .ok_or_else(|| PackError("overflow".into()))?,
            )
            .ok_or_else(|| PackError("truncated name block".into()))?;
        let mut raw = Vec::new();
        ZlibDecoder::new(compressed)
            .take(1 << 20)
            .read_to_end(&mut raw)
            .map_err(|e| PackError(e.to_string()))?;
        let bytes = raw
            .get(
                start - raw_start
                    ..end
                        .checked_sub(raw_start)
                        .ok_or_else(|| PackError("range".into()))?,
            )
            .ok_or_else(|| PackError("name range".into()))?;
        let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
        String::from_utf8(bytes.to_vec()).map_err(|e| PackError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static PACK: &[u8] = include_bytes!("../../sigs/fid-x64.pack");

    #[test]
    fn parses_the_embedded_pack() -> Result<(), PackError> {
        let pack = Pack::parse(PACK)?;
        assert!(pack.record_count() > 200_000);
        let record = pack
            .candidates_at(0)
            .ok_or_else(|| PackError("first record".into()))?;
        let candidates = pack.candidates(pack.full_hash_of(0));
        assert!(candidates.contains(&record));
        assert!(!pack.name(record.name)?.is_empty());
        assert!(pack.name(u32::MAX).is_err());
        Ok(())
    }

    #[test]
    fn damaged_packs_error_instead_of_panicking() {
        for length in [
            0,
            7,
            8,
            63,
            64,
            1_000,
            100_000,
            PACK.len() / 2,
            PACK.len() - 1,
        ] {
            let result = Pack::parse(&PACK[..length]);
            if let Ok(pack) = result {
                let _ = pack.candidates(0);
                let _ = pack.name(0);
            }
        }
        let mut broken = PACK.to_vec();
        broken[0] ^= 0xff;
        assert!(Pack::parse(&broken).is_err());
        // Corrupt the relation table offsets: lookups must stay in bounds.
        let mut corrupt = PACK.to_vec();
        let Ok(relations) = read_u32(&corrupt, 40) else {
            return;
        };
        for byte in corrupt.iter_mut().skip(relations as usize + 4).take(36) {
            *byte = 0xff;
        }
        if let Ok(pack) = Pack::parse(&corrupt) {
            let record = pack.candidates_at(5);
            if let Some(record) = record {
                let _ = pack.has_relation(Relation::Superior, &record, 7);
                let _ = pack.has_relation(Relation::Inferior, &record, 7);
            }
        }
    }
}
