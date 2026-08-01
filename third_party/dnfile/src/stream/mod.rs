use crate::{Result, error::Error};

pub mod blob_heap;
pub mod generic_stream;
pub mod guid_heap;
pub mod meta_data_tables;
pub mod pdb_stream;
pub mod string_heap;
pub mod user_string_heap;

#[derive(Debug, Clone, serde::Serialize)]
pub enum Stream<'a> {
    GenericStream(generic_stream::GenericStream),
    MetaDataTables(meta_data_tables::MetaDataTable),
    StringHeap(string_heap::StringHeap<'a>),
    BlobHeap(blob_heap::BlobHeap<'a>),
    GuidHeap(guid_heap::GuidHeap<'a>),
    UserStringHeap(user_string_heap::UserStringHeap<'a>),
    /// 0.5.1: Portable PDB `#Pdb` stream header. Identifies
    /// assemblies that ship embedded Portable PDB debug info and
    /// surfaces the PdbId for symbol-server lookup. See
    /// `pdb_stream::PdbStream` for the field layout.
    PdbStream(pdb_stream::PdbStream<'a>),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ClrStream<'a> {
    pub name: String,
    pub rva: u32,
    pub size: usize,
    pub stream_table_entry_size: usize,
    pub stream: Stream<'a>,
}

impl<'a> ClrStream<'a> {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn get_string(&self, index: &[u8]) -> Result<String> {
        if let Stream::StringHeap(s) = &self.stream {
            let index = crate::utils::read_usize(index)?;
            s.get(index)
        } else {
            Err(Error::TryReadStringFromNotStringHeap)
        }
    }

    pub fn get_blob(&self, index: &[u8]) -> Result<Vec<u8>> {
        if let Stream::BlobHeap(s) = &self.stream {
            let index = crate::utils::read_usize(index)?;
            s.get(index)
        } else {
            Err(Error::TryReadStringFromNotStringHeap)
        }
    }

    pub fn get_guid(&self, index: &[u8]) -> Result<uuid::Uuid> {
        if let Stream::GuidHeap(s) = &self.stream {
            let index = crate::utils::read_usize(index)?;
            s.get(index)
        } else {
            Err(Error::TryReadGuidFromNotGuidHeap)
        }
    }
}

impl<'a> crate::DnPe<'a> {
    pub fn nnew_clr_stream(
        &self,
        metadata_rva: &u32,
        stream_offset: &u32,
        stream_size: &usize,
        stream_name: &str,
        stream_data: &'a [u8],
    ) -> Result<ClrStream<'a>> {
        Ok(ClrStream {
            name: stream_name.to_string(),
            rva: metadata_rva + stream_offset,
            size: stream_data.len(),
            stream_table_entry_size: stream_name.len() + (4 - stream_name.len() % 4) + 8,
            stream: match stream_name {
                "#~" | "#-" => self.new_meta_data_table(
                    metadata_rva,
                    stream_offset,
                    stream_size,
                    stream_name,
                    stream_data,
                )?,
                "#Strings" => self.new_string_heap(
                    metadata_rva,
                    stream_offset,
                    stream_size,
                    stream_name,
                    stream_data,
                )?,
                "#GUID" => self.new_guid_heap(
                    metadata_rva,
                    stream_offset,
                    stream_size,
                    stream_name,
                    stream_data,
                )?,
                "#Blob" => self.new_blob_heap(
                    metadata_rva,
                    stream_offset,
                    stream_size,
                    stream_name,
                    stream_data,
                )?,
                "#US" => self.new_user_string_heap(
                    metadata_rva,
                    stream_offset,
                    stream_size,
                    stream_name,
                    stream_data,
                )?,
                "#Pdb" => self.new_pdb_stream(
                    metadata_rva,
                    stream_offset,
                    stream_size,
                    stream_name,
                    stream_data,
                )?,
                "_" => self.new_generic_stream(
                    metadata_rva,
                    stream_offset,
                    stream_size,
                    stream_name,
                    stream_data,
                )?,
                _ => return Err(Error::UndefinedStream),
            },
        })
    }

    pub fn parse_clr_stream(
        &self,
        stream: &ClrStream<'a>,
        stream_map: &std::collections::HashMap<String, ClrStream<'a>>,
    ) -> Result<ClrStream<'a>> {
        let mut res = stream.clone();
        if let Stream::MetaDataTables(m) = &mut res.stream {
            m.tables = self.parse_meta_data_tables(m, stream_map)?;
        }
        Ok(res)
    }
}
