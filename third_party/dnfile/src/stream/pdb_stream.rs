//! Portable PDB `#Pdb` stream header (dnfile-rs 0.5.1).
//!
//! When .NET assemblies ship with embedded Portable PDB debug info,
//! the CLR metadata grows a sixth standard stream named `#Pdb`. The
//! stream begins with a small fixed header that identifies:
//!
//!   * **PdbId** (20 bytes) — the Portable PDB build identifier. The
//!     first 16 bytes are the GUID symbol servers look up; the last
//!     4 bytes are a stamp. Equivalent to the (GUID, age) tuple used
//!     by the legacy `.pdb` CodeView debug record.
//!   * **EntryPoint** (u32 token) — metadata token (table id in the
//!     high byte, row index in the low 3 bytes) of the entry method.
//!     Zero for non-executable / library assemblies.
//!   * **ReferencedTypeSystemTables** (u64 bitmap) — bit `i` set
//!     means the assembly's `#~` stream includes table `i`. Tells
//!     consumers which row counts to find in the next field.
//!   * **TypeSystemTableRows** (variable, u32 per set bit) — row
//!     counts for each table referenced by the bitmap. Lets the
//!     Portable PDB tables (Document, MethodDebugInformation, …)
//!     reference rows in the main metadata's `#~` stream by
//!     position without redundantly encoding the count.
//!
//! What this stream IS NOT: the full Portable PDB metadata tables
//! (Document, MethodDebugInformation, LocalScope, LocalVariable,
//! LocalConstant, ImportScope, StateMachineMethod,
//! CustomDebugInformation). Those live in the same `#~` table
//! stream alongside the regular ECMA-335 tables and would need
//! their own row decoders to expose — that's a substantial
//! follow-up, intentionally NOT in 0.5.1.
//!
//! Reference: Microsoft "Portable PDB v1.0" spec, §"Standalone
//! debugging metadata" (`dotnet/runtime/docs/design/specs/PortablePdb-Metadata.md`).

use crate::{Result, error::Error};

/// Parsed `#Pdb` stream header.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PdbStream<'a> {
    /// 20-byte Portable PDB build ID. First 16 bytes = GUID
    /// (printed in symbol-server URLs); last 4 = stamp.
    pub pdb_id: [u8; 20],
    /// Metadata token of the entry-point method, or `0` for
    /// libraries.
    pub entry_point: u32,
    /// Bitmap of `#~` tables referenced by the PDB metadata
    /// (bit `i` ↔ table `i`).
    pub referenced_type_system_tables: u64,
    /// Per-table row counts, ordered by the lowest set bit in
    /// `referenced_type_system_tables` first. Length =
    /// `referenced_type_system_tables.count_ones()`.
    pub type_system_table_rows: Vec<u32>,
    /// The raw stream bytes — borrowed, no copy. Lets consumers
    /// re-parse if they need richer access in the future.
    #[serde(skip_serializing)]
    data: &'a [u8],
}

impl<'a> PdbStream<'a> {
    /// Parse the stream header from a borrowed slice.
    ///
    /// Bounds-checked: returns `Error::NotEnoughData` if the slice
    /// is shorter than the 20+4+8 = 32-byte fixed prefix, or if
    /// the per-table row counts run past the slice end.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        const FIXED_HEADER_LEN: usize = 20 + 4 + 8;
        if data.len() < FIXED_HEADER_LEN {
            return Err(Error::NotEnoughData(data.len(), FIXED_HEADER_LEN));
        }
        let mut pdb_id = [0u8; 20];
        pdb_id.copy_from_slice(&data[0..20]);
        let entry_point = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let referenced_type_system_tables = u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]);
        let n_tables = referenced_type_system_tables.count_ones() as usize;
        let rows_end = FIXED_HEADER_LEN
            .checked_add(
                n_tables
                    .checked_mul(4)
                    .ok_or(Error::NotEnoughData(data.len(), FIXED_HEADER_LEN))?,
            )
            .ok_or(Error::NotEnoughData(data.len(), FIXED_HEADER_LEN))?;
        if rows_end > data.len() {
            return Err(Error::NotEnoughData(data.len(), rows_end));
        }
        let mut rows = Vec::with_capacity(n_tables);
        for i in 0..n_tables {
            let off = FIXED_HEADER_LEN + i * 4;
            rows.push(u32::from_le_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
            ]));
        }
        Ok(Self {
            pdb_id,
            entry_point,
            referenced_type_system_tables,
            type_system_table_rows: rows,
            data,
        })
    }

    /// Symbol-server GUID (the first 16 bytes of `pdb_id`),
    /// formatted as a `uuid::Uuid` for parity with the legacy
    /// `.pdb` CodeView GUID exposed elsewhere in dnfile-rs.
    #[must_use]
    pub fn guid(&self) -> uuid::Uuid {
        let mut g = [0u8; 16];
        g.copy_from_slice(&self.pdb_id[0..16]);
        // The first three GUID fields are little-endian on
        // Windows (DWORD/WORD/WORD), matching how the CLR writes
        // them — `Uuid::from_bytes_le` matches that wire layout.
        uuid::Uuid::from_bytes_le(g)
    }

    /// Raw stamp (the last 4 bytes of `pdb_id`), the Portable
    /// PDB analogue of the legacy PDB `age` field.
    #[must_use]
    pub fn stamp(&self) -> u32 {
        u32::from_le_bytes([
            self.pdb_id[16],
            self.pdb_id[17],
            self.pdb_id[18],
            self.pdb_id[19],
        ])
    }

    /// Borrowed view of the raw stream bytes (the same `&'a [u8]`
    /// passed to `parse`).
    #[must_use]
    pub fn raw(&self) -> &'a [u8] {
        self.data
    }
}

impl<'a> crate::DnPe<'a> {
    pub fn new_pdb_stream(
        &self,
        _metadata_rva: &u32,
        _stream_offset: &u32,
        _stream_size: &usize,
        _stream_name: &str,
        stream_data: &'a [u8],
    ) -> Result<super::Stream<'a>> {
        Ok(super::Stream::PdbStream(PdbStream::parse(stream_data)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic header — minimal valid stream. PdbId all 1s,
    /// entry-point token 0x06000001 (Method row 1), bitmap has
    /// two bits set so the row-counts array holds two u32s.
    #[test]
    fn parses_minimal_header() {
        let mut data = vec![0u8; 32 + 8]; // 32-byte fixed + 2 row counts
        // PdbId
        for b in &mut data[0..20] {
            *b = 0xab;
        }
        // EntryPoint = 0x06000001
        data[20..24].copy_from_slice(&0x06000001u32.to_le_bytes());
        // Bitmap = bits 2 and 5 set (TypeDef + MemberRef)
        let bitmap: u64 = (1 << 2) | (1 << 5);
        data[24..32].copy_from_slice(&bitmap.to_le_bytes());
        // Row counts
        data[32..36].copy_from_slice(&42u32.to_le_bytes());
        data[36..40].copy_from_slice(&7u32.to_le_bytes());

        let s = PdbStream::parse(&data).unwrap();
        assert_eq!(s.pdb_id, [0xab; 20]);
        assert_eq!(s.entry_point, 0x06000001);
        assert_eq!(s.referenced_type_system_tables, bitmap);
        assert_eq!(s.type_system_table_rows, vec![42, 7]);
        assert_eq!(s.stamp(), u32::from_le_bytes([0xab; 4]));
    }

    #[test]
    fn rejects_short_input() {
        let too_short = vec![0u8; 31];
        assert!(PdbStream::parse(&too_short).is_err());
    }

    #[test]
    fn rejects_truncated_row_counts() {
        let mut data = vec![0u8; 32 + 2]; // claims 1 table but only 2 of 4 row-count bytes
        let bitmap: u64 = 1; // one bit set → expects one u32
        data[24..32].copy_from_slice(&bitmap.to_le_bytes());
        assert!(PdbStream::parse(&data).is_err());
    }
}
