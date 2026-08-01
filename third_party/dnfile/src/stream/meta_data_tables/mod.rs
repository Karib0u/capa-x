use crate::{Result, error::Error};

pub mod mdtables;

const STRINGS_MASK: u8 = 0x01;
const GUIDS_MASK: u8 = 0x02;
const BLOBS_MASK: u8 = 0x04;
const _DELTA_ONLY_MASK: u32 = 0x20;
const EXTRA_DATA_MASK: u8 = 0x40;
const _HAS_DELETE_MASK: u32 = 0x80;
const MAX_TABLES: usize = 64;

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetaDataTable {
    //#[serde(skip_serializing)]
    //data: Vec<u8>,
    rva: u32,
    pub tables: std::collections::BTreeMap<usize, mdtables::MetaDataTable>,
}

impl<'a> crate::DnPe<'a> {
    pub fn new_meta_data_table(
        &self,
        metadata_rva: &u32,
        stream_offset: &u32,
        _stream_size: &usize,
        _stream_name: &str,
        _stream_data: &'a [u8],
    ) -> Result<super::Stream<'a>> {
        Ok(super::Stream::MetaDataTables(MetaDataTable {
            //data: stream_data,
            rva: metadata_rva + stream_offset,
            tables: std::collections::BTreeMap::new(),
        }))
    }

    pub fn parse_meta_data_tables(
        &self,
        s: &mut MetaDataTable,
        stream_map: &std::collections::HashMap<String, super::ClrStream<'a>>,
    ) -> Result<std::collections::BTreeMap<usize, mdtables::MetaDataTable>> {
        let mut tables = std::collections::BTreeMap::new();
        let header_len = std::mem::size_of::<MDTablesStruct>();
        let header: MDTablesStruct = self.get_data(&s.rva, &header_len)?;
        let strings_offset_size = if header.heap_offset_sizes & STRINGS_MASK != 0 {
            4
        } else {
            2
        };
        let guids_offset_size = if header.heap_offset_sizes & GUIDS_MASK != 0 {
            4
        } else {
            2
        };
        let blobs_offset_size = if header.heap_offset_sizes & BLOBS_MASK != 0 {
            4
        } else {
            2
        };
        let strings_heap = &stream_map.get("#Strings");
        let guid_heap = &stream_map.get("#GUID");
        let blob_heap = &stream_map.get("#Blob");

        let mut curr_rva = s.rva + header_len as u32;
        let mut table_rowcounts = vec![];
        for i in 0..MAX_TABLES {
            if header.mask_valid & (1 << i) != 0 {
                table_rowcounts.push(self.get_dword_at_rva(&curr_rva)? as usize);
                curr_rva += 4;
            } else {
                table_rowcounts.push(0);
            }
        }

        if header.heap_offset_sizes & EXTRA_DATA_MASK == EXTRA_DATA_MASK {
            curr_rva += 4;
        }

        let mut deferred_exceptions = vec![];

        for i in 0..MAX_TABLES {
            if header.mask_valid & (1 << i) != 0 {
                let is_sorted = header.mask_sorted & (1 << i) != 0;
                match self.create_md_table(
                    &i,
                    &table_rowcounts,
                    is_sorted,
                    strings_offset_size,
                    guids_offset_size,
                    blobs_offset_size,
                ) {
                    Ok(t) => {
                        tables.insert(i, t);
                    }
                    Err(e) => {
                        deferred_exceptions.push(e.to_string());
                        continue;
                    }
                }
            }
        }
        let mut ttables = std::collections::BTreeMap::new();
        for (n, table) in &tables {
            if table.row_size > 0 && table.num_rows > 0 {
                // `num_rows` is a u32 from the file; row_size is derived from
                // schema. Multiply with checked math so a crafted row count
                // can't wrap to a small value that bypasses `get_vec`'s bound
                // check, and can't drive a >4 GiB allocation.
                let bytes = table
                    .row_size
                    .checked_mul(table.num_rows)
                    .ok_or(Error::NotEnoughData(table.row_size, table.num_rows))?;
                let table_data = self.get_vec(&curr_rva, &bytes)?;
                let mut ttable = self.parse_rows(table, &curr_rva, &table_data)?;
                ttable.rva = curr_rva;
                let bytes_u32 = u32::try_from(bytes)
                    .map_err(|_| Error::NotEnoughData(table.row_size, table.num_rows))?;
                curr_rva = curr_rva
                    .checked_add(bytes_u32)
                    .ok_or(Error::UnresolvedRvaError(curr_rva))?;
                ttables.insert(*n, ttable);
            } else {
                ttables.insert(*n, table.clone());
            }
        }
        let mut tttables = std::collections::BTreeMap::new();
        for (n, table) in &ttables {
            tttables.insert(
                *n,
                self.parse_table(table, &ttables, strings_heap, blob_heap, guid_heap)?,
            );
        }
        Ok(tttables)
    }
}

#[repr(C)]
#[derive(serde::Deserialize, Debug, scroll::Pread)]
pub struct MDTablesStruct {
    reserved_1: u32,
    major_version: u8,
    minor_version: u8,
    heap_offset_sizes: u8,
    reserved_2: u8,
    mask_valid: u64,
    mask_sorted: u64,
}
