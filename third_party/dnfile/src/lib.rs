// Several private helpers take `&u32` / `&usize` arguments for historical
// reasons (these types are trivially `Copy`). Changing them ripples through
// many call sites for no behavioural benefit.
#![allow(clippy::trivially_copy_pass_by_ref)]
// `ClrHeaderFlags::new` deliberately returns a `BTreeSet<Self>` (bitfield
// expansion) rather than `Self` — this is part of the public API.
#![allow(clippy::new_ret_no_self)]

use serde::{Deserialize, Serialize};

pub mod error;
pub mod lang;
pub mod resource;
/// 0.5.1: typed decoders for `#Blob`-heap signature payloads.
/// Currently covers `CustomAttribute` (ECMA-335 II.23.3) and
/// `MarshalSpec` (II.23.4). The full ECMA-335 II.23.2
/// signature-blob grammar (MethodDef/Ref/FieldSig/PropertySig/
/// LocalVarSig/TypeSpec/MethodSpec + recursive TypeSig) is
/// intentionally NOT here yet — see the module docs.
pub mod signatures;
pub mod stream;
pub mod utils;

use crate::{
    error::Error,
    stream::meta_data_tables::mdtables::{enums::*, *},
};

pub type Result<T> = std::result::Result<T, Error>;

/// A parsed .NET PE file.
///
/// `DnPe` borrows the underlying file buffer (`&'a [u8]`) and exposes the
/// CLR header, metadata streams, tables and CIL method bodies. The caller
/// owns the buffer; back it with `std::fs::read` or `memmap2::Mmap`.
///
/// # Example
///
/// ```no_run
/// let data = std::fs::read("Sample.exe")?;
/// let pe = dnfile::DnPe::parse(&data)?;
/// let clr = pe.net()?;
/// println!("{} functions", clr.functions().len());
/// # Ok::<(), dnfile::error::Error>(())
/// ```
#[derive(Debug, Serialize)]
pub struct DnPe<'a> {
    #[serde(skip_serializing)]
    data: &'a [u8],
    /// PE section table cached at construction.
    /// Avoids re-parsing the whole PE on every `offset()` / `get_data()` call,
    /// which is in the hot path of every metadata-table row and every CIL instruction.
    #[serde(skip_serializing)]
    sections: Vec<goblin::pe::section_table::SectionTable>,
    /// PE optional-header `file_alignment` cached at construction (same reason).
    #[serde(skip_serializing)]
    file_alignment: u32,
    /// PE optional-header `size_of_headers` cached at construction -- see
    /// `offset()`'s header-region carve-out, `PATCH.md` fix 12.
    #[serde(skip_serializing)]
    size_of_headers: u32,
    /// CLR resources directory RVA (from `ClrStruct.resources_rva`). Used by
    /// `resources()` to locate the bytes of each `ManifestResource` entry.
    #[serde(skip_serializing)]
    pub(crate) resources_rva: u32,
    /// CLR resources directory size.
    #[serde(skip_serializing)]
    pub(crate) resources_size: u32,
    net: Option<ClrData<'a>>,
}

impl<'a> DnPe<'a> {
    pub fn net(&self) -> Result<&ClrData<'a>> {
        self.net.as_ref().ok_or(Error::NotImplementedError)
    }

    /// Re-parse and return a fresh `goblin::pe::PE` view over the file bytes.
    ///
    /// Internal hot-path code uses the cached `sections` + `file_alignment`
    /// fields directly; this method is kept on the public surface for
    /// consumers that need the full `goblin::pe::PE` value. Calling it is
    /// linear in file size, so cache the result yourself if you need it
    /// repeatedly.
    pub fn pe(&self) -> Result<goblin::pe::PE<'_>> {
        Ok(goblin::pe::PE::parse(self.data)?)
    }

    /// Parse a .NET PE from a borrowed byte buffer.
    ///
    /// Zero-copy: heaps, streams and method-body readers all hold slices
    /// into `data` rather than copies.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        // Parse the PE exactly once and extract the bits we'll need on the
        // hot path. Previously every `offset()` / `get_data()` call re-parsed
        // the entire binary via `self.pe()`.
        let (sections, file_alignment, size_of_headers, clr_directory) = {
            let pe = goblin::pe::PE::parse(data)?;
            let opt_header = pe
                .header
                .optional_header
                .ok_or(Error::UnsupportedBinaryFormat("optional header absence"))?;
            let file_alignment = opt_header.windows_fields.file_alignment;
            let size_of_headers = opt_header.windows_fields.size_of_headers;
            let clr_directory = opt_header
                .data_directories
                .get_clr_runtime_header()
                .copied()
                .ok_or(Error::UnsupportedBinaryFormat("ClR runtime header absence"))?;
            (
                pe.sections.clone(),
                file_alignment,
                size_of_headers,
                clr_directory,
            )
        };

        let mut res = DnPe {
            data,
            sections,
            file_alignment,
            size_of_headers,
            resources_rva: 0,
            resources_size: 0,
            net: None,
        };
        let clr_struct: ClrStruct = res.get_data(
            &clr_directory.virtual_address,
            &(clr_directory.size as usize),
        )?;
        res.resources_rva = clr_struct.resources_rva;
        res.resources_size = clr_struct.resources_size;
        res.net = Some(res.new_clrdata(clr_struct)?);
        Ok(res)
    }

    fn offset(&self, rva: u32) -> Result<usize> {
        // A Windows PE loader maps the header region (everything before
        // `SizeOfHeaders`) 1:1 -- file offset == RVA -- rather than through
        // any section, so `goblin::pe::utils::find_offset` (which only
        // consults the section table) can never resolve an RVA in that
        // range. pefile's `get_offset_from_rva` (pinned Python `dnfile`'s
        // own RVA resolver) special-cases exactly this, and real managed
        // methods can legitimately carry a header-region RVA (see
        // `PATCH.md` fix 12: a `MethodDef` with `RVA == 0` -- ECMA-335
        // II.22.26 requires a nonzero RVA only when the method actually has
        // an IL body, but this fork attempted to resolve the RVA before
        // discovering the body was malformed/absent, unlike pinned
        // `read_dotnet_method_body`, which reads first and only then fails
        // gracefully). Matches `capa-core/src/extract/pe.rs`'s own
        // `rva_to_offset` carve-out for the same reason.
        let rva_usize = rva as usize;
        if rva_usize < self.size_of_headers as usize && rva_usize < self.data.len() {
            return Ok(rva_usize);
        }
        goblin::pe::utils::find_offset(
            rva_usize,
            &self.sections,
            self.file_alignment,
            &goblin::pe::options::ParseOptions::default(),
        )
        .ok_or(Error::UnresolvedRvaError(rva))
    }

    fn get_data<'b, T>(&'b self, rva: &'b u32, size: &'b usize) -> Result<T>
    where
        T: scroll::ctx::TryFromCtx<'b, goblin::container::Endian, Error = scroll::Error>,
    {
        Ok(goblin::pe::utils::get_data(
            self.data,
            &self.sections,
            goblin::pe::data_directories::DataDirectory {
                virtual_address: *rva,
                size: *size as u32,
            },
            self.file_alignment,
        )?)
    }

    /// Defensive null-terminated string reader. Bounds-checked indexing,
    /// checked-add on RVA, and a hard cap on length (1 KiB — covers every
    /// legitimate ECMA-335 use; stream names are at most 31 characters,
    /// metadata-version strings even less).
    fn get_nullterminated_string(&self, rva: &u32) -> Result<String> {
        const MAX_LEN: usize = 1024;
        let mut res_buf = Vec::with_capacity(32);
        let mut rrva = *rva;
        loop {
            let off = self.offset(rrva)?;
            let c = *self.data.get(off).ok_or(Error::UnresolvedRvaError(rrva))?;
            if c == 0 {
                break;
            }
            if res_buf.len() >= MAX_LEN {
                return Err(Error::UnresolvedRvaError(rrva));
            }
            res_buf.push(c);
            rrva = rrva.checked_add(1).ok_or(Error::UnresolvedRvaError(rrva))?;
        }
        Ok(String::from_utf8(res_buf)?)
    }

    /// Borrowed slice into the file buffer. Replaces the prior `Vec<u8>`-returning
    /// helper to keep stream/heap construction zero-copy.
    fn get_slice(&self, rva: &u32, size: usize) -> Result<&'a [u8]> {
        let offset = self.offset(*rva)?;
        let end = offset
            .checked_add(size)
            .ok_or(Error::UnresolvedRvaError(*rva))?;
        self.data
            .get(offset..end)
            .ok_or(Error::UnresolvedRvaError(*rva))
    }

    /// Owned variant kept for callers (mdtables) that intentionally take ownership.
    fn get_vec(&self, rva: &u32, size: &usize) -> Result<Vec<u8>> {
        Ok(self.get_slice(rva, *size)?.to_vec())
    }

    fn get_dword_at_rva(&self, rva: &u32) -> Result<u32> {
        self.get_data(rva, &4)
    }

    /// Returns the RVA of the CLR resources directory (from the CLR header).
    /// 0 if the binary has no resources directory.
    #[must_use]
    pub fn resources_rva(&self) -> u32 {
        self.resources_rva
    }

    /// Returns the size (bytes) of the CLR resources directory.
    #[must_use]
    pub fn resources_size(&self) -> u32 {
        self.resources_size
    }

    fn new_clrdata(&self, clr_struct: ClrStruct) -> Result<ClrData<'a>> {
        let metadata_struct: MetaDataStruct = self.get_data(
            &clr_struct.meta_data_rva,
            &(clr_struct.meta_data_size as usize),
        )?;
        let metadata = self.new_metadata(&clr_struct.meta_data_rva, metadata_struct)?;
        let flags = ClrHeaderFlags::new(clr_struct.flags as usize);
        let functions = self.parse_functions(&metadata)?;
        Ok(ClrData {
            metadata,
            flags,
            functions,
        })
    }

    fn parse_functions(
        &self,
        metadata: &MetaData<'a>,
    ) -> Result<Vec<lang::cil::function::Function>> {
        let mut res = vec![];
        let method_def_table = metadata.md_table("MethodDef")?;
        let methoddef_table_num = table_name_2_index("MethodDef")?;
        for i in 0..method_def_table.row_count() {
            let row = method_def_table.row::<MethodDef>(i)?;
            if !row
                .impl_flags
                .contains(&ClrMethodImpl::MethodCodeType(CorMethodCodeType::IL))
                || row
                    .flags
                    .contains(&ClrMethodAttr::AttrFlag(CorMethodAttrFlag::Abstract))
                || row
                    .flags
                    .contains(&ClrMethodAttr::AttrFlag(CorMethodAttrFlag::PinvokeImpl))
            {
                continue;
            }
            // Pinned `dnfile`/capa (`helpers.py::read_dotnet_method_body`)
            // catches exactly a malformed-body error for one `MethodDef` and
            // skips it (`logger.debug`, continue), never aborting the whole
            // file over one bad method. Match that per-method degradation:
            // only `MethodBodyFormatError` is swallowed here: an RVA that
            // doesn't map into any section, and other harder failures,
            // still fail the whole parse, same as an uncaught exception
            // would propagate out of pinned `read_dotnet_method_body`.
            let rid = i + 1;
            match self.parse_function(row) {
                Ok(mut function) => {
                    function.token = crate::lang::clr::token::Token::new(
                        ((methoddef_table_num & 0xFF) << 24) | (rid & 0x00FF_FFFF),
                    );
                    res.push(function);
                }
                // Pinned `dncil`'s own reader (`cil/body/reader.py::_unpack`)
                // funnels every short-read/EOF condition into
                // `MethodBodyFormatError` uniformly; this fork's `Reader`
                // instead lets such reads surface as `Error::IoError` (via
                // `?` on `byteorder`), so both variants mean the same thing
                // here: this one method body is truncated/malformed.
                Err(Error::MethodBodyFormatError(_) | Error::IoError(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(res)
    }

    fn parse_function(&self, row: &MethodDef) -> Result<lang::cil::function::Function> {
        let mut reader = lang::cil::function::reader::Reader::new(self.data);
        reader.seek(self.offset(row.rva)?)?;
        lang::cil::function::Function::new(&mut reader)
    }

    fn new_metadata(
        &self,
        metadata_rva: &u32,
        metadata_struct: MetaDataStruct,
    ) -> Result<MetaData<'a>> {
        // All RVA arithmetic here is over attacker-controlled u32s.
        let after_signature_rva = metadata_rva
            .checked_add(16)
            .ok_or(Error::UnresolvedRvaError(*metadata_rva))?;
        let version_offset = self.offset(after_signature_rva)?;
        let version_end = version_offset
            .checked_add(metadata_struct.version_length as usize)
            .ok_or(Error::UnresolvedRvaError(after_signature_rva))?;
        let version = self
            .data
            .get(version_offset..version_end)
            .ok_or(Error::UnresolvedRvaError(after_signature_rva))?
            .to_vec();
        let after_version_rva = after_signature_rva
            .checked_add(metadata_struct.version_length)
            .ok_or(Error::UnresolvedRvaError(after_signature_rva))?;
        let flags: u16 = self.get_data(&after_version_rva, &2)?;
        let after_flags_rva = after_version_rva
            .checked_add(2)
            .ok_or(Error::UnresolvedRvaError(after_version_rva))?;
        let number_of_streams: u16 = self.get_data(&after_flags_rva, &2)?;
        let streams_table_rva = after_flags_rva
            .checked_add(2)
            .ok_or(Error::UnresolvedRvaError(after_flags_rva))?;
        let streams = if number_of_streams > 0 {
            self.new_streams(
                metadata_rva,
                &streams_table_rva,
                &(number_of_streams as usize),
            )?
        } else {
            std::collections::HashMap::new()
        };
        Ok(MetaData {
            _version: String::from_utf8(version)?,
            flags,
            streams,
        })
    }

    fn new_streams(
        &self,
        metadata_rva: &u32,
        streams_table_rva: &u32,
        number_of_streams: &usize,
    ) -> Result<std::collections::HashMap<String, stream::ClrStream<'a>>> {
        // Defensive cap. ECMA-335 has no fixed upper bound but real files
        // have ≤ ~6 streams; a malformed `number_of_streams` (u16, so ≤ 65535)
        // could otherwise drive a 65k-iteration loop full of failing parses.
        const MAX_STREAMS: usize = 64;
        let n = (*number_of_streams).min(MAX_STREAMS);
        let mut res = std::collections::HashMap::with_capacity(n);
        let mut stream_entry_rva = *streams_table_rva;
        for _i in 0..n {
            // Pinned Python `dnfile` (`__init__.py::MetaData.parse_stream_
            // table`): an invalid stream-table entry ("assume this throws
            // off further parsing, so stop") breaks the loop but keeps every
            // stream already parsed, rather than discarding the whole file's
            // metadata over one bad trailing entry -- some real-world (and
            // deliberately obfuscated) .NET binaries have a truncated or
            // malformed stream table after the streams capa actually reads.
            // See `PATCH.md` fix 11.
            let Ok(stream) = self.new_clr_stream(&stream_entry_rva, metadata_rva) else {
                break;
            };
            let Some(next_entry_rva) =
                stream_entry_rva.checked_add(stream.stream_table_entry_size as u32)
            else {
                res.insert(stream.name().to_string(), stream);
                break;
            };
            stream_entry_rva = next_entry_rva;
            res.insert(stream.name().to_string(), stream);
        }
        let mut rres = std::collections::HashMap::with_capacity(res.len());
        for (n, s) in &res {
            rres.insert(n.to_string(), self.parse_clr_stream(s, &res)?);
        }
        Ok(rres)
    }

    fn new_clr_stream(
        &self,
        stream_table_entry_rva: &u32,
        metadata_rva: &u32,
    ) -> Result<stream::ClrStream<'a>> {
        let stream_offset: u32 = self.get_data(stream_table_entry_rva, &4)?;
        let size_rva = stream_table_entry_rva
            .checked_add(4)
            .ok_or(Error::UnresolvedRvaError(*stream_table_entry_rva))?;
        let stream_size: u32 = self.get_data(&size_rva, &4)?;
        let name_rva = stream_table_entry_rva
            .checked_add(8)
            .ok_or(Error::UnresolvedRvaError(*stream_table_entry_rva))?;
        let stream_name = self.get_nullterminated_string(&name_rva)?;
        let data_rva = metadata_rva
            .checked_add(stream_offset)
            .ok_or(Error::UnresolvedRvaError(*metadata_rva))?;
        let stream_data = self.get_slice(&data_rva, stream_size as usize)?;
        self.nnew_clr_stream(
            metadata_rva,
            &stream_offset,
            &(stream_size as usize),
            &stream_name,
            stream_data,
        )
    }
}

#[repr(C)]
#[derive(Deserialize, Debug, scroll::Pread)]
pub struct ClrStruct {
    cb: u32,
    majorr_runtime_version: u16,
    minor_runtime_version: u16,
    meta_data_rva: u32,
    meta_data_size: u32,
    flags: u32,
    entry_point_token_or_rva: u32,
    resources_rva: u32,
    resources_size: u32,
    strong_name_signature_rva: u32,
    strong_name_signature_size: u32,
    code_manager_table_rva: u32,
    code_manager_table_size: u32,
    v_table_fixups_rva: u32,
    v_table_fixups_size: u32,
    export_address_table_jumps_rva: u32,
    export_address_table_jumps_size: u32,
    managed_native_header_rva: u32,
    managed_native_header_size: u32,
}

#[derive(Debug, Serialize, PartialOrd, Ord, PartialEq, Eq)]
pub enum ClrHeaderFlags {
    IlOnly,
    BitRequired32,
    IlLibrary,
    StrongNamesSigned,
    NativeEntryPiont,
    TrackDebugData,
    Prefer32Bit,
}

impl ClrHeaderFlags {
    pub fn new(value: usize) -> std::collections::BTreeSet<Self> {
        let mut res = std::collections::BTreeSet::new();
        if value & 1 != 0 {
            res.insert(Self::IlOnly);
        }
        if value & 2 != 0 {
            res.insert(Self::BitRequired32);
        }
        if value & 4 != 0 {
            res.insert(Self::IlLibrary);
        }
        if value & 8 != 0 {
            res.insert(Self::StrongNamesSigned);
        }
        if value & 0x10 != 0 {
            res.insert(Self::NativeEntryPiont);
        }
        if value & 0x10000 != 0 {
            res.insert(Self::TrackDebugData);
        }
        if value & 0x20000 != 0 {
            res.insert(Self::Prefer32Bit);
        }
        res
    }
}

#[derive(Debug, Serialize)]
pub struct ClrData<'a> {
    pub metadata: MetaData<'a>,
    pub flags: std::collections::BTreeSet<ClrHeaderFlags>,
    pub functions: Vec<lang::cil::function::Function>,
}

impl<'a> ClrData<'a> {
    pub fn md_table(
        &self,
        name: &'static str,
    ) -> Result<&stream::meta_data_tables::mdtables::MetaDataTable> {
        self.metadata.md_table(name)
    }

    pub fn md_table_by_index(
        &self,
        index: &usize,
    ) -> Result<&stream::meta_data_tables::mdtables::MetaDataTable> {
        self.metadata.md_table_by_index(index)
    }

    pub fn resolve_coded_index<T>(
        &self,
        index: &dyn stream::meta_data_tables::mdtables::codedindex::CodedIndex,
    ) -> Result<&T>
    where
        T: stream::meta_data_tables::mdtables::MDTableRowTrait + 'static,
    {
        let table = self.md_table(index.table())?;
        // ECMA-335 row indices are 1-based; a 0 indicates "no reference".
        let idx = index
            .row_index()
            .checked_sub(1)
            .ok_or(Error::UndefinedMetaDataTableName(index.table()))?;
        table.row(idx)
    }

    pub fn functions(&self) -> &Vec<lang::cil::function::Function> {
        &self.functions
    }

    pub fn get_us(&self, rid: usize) -> Result<String> {
        self.metadata.get_us(rid)
    }

    /// Returns the binary's `Assembly` table row 0, if it has one.
    ///
    /// A .NET assembly (an `.exe` or a top-level `.dll` that defines an
    /// assembly identity) always has exactly one row here. Module-only DLLs
    /// (rare; e.g. `netmodule`s linked into an assembly) have an empty
    /// `Assembly` table and this returns `Err(UndefinedMetaDataTableName)`.
    pub fn assembly(&self) -> Result<&stream::meta_data_tables::mdtables::Assembly> {
        let table = self.md_table("Assembly")?;
        if table.row_count() == 0 {
            return Err(Error::UndefinedMetaDataTableName("Assembly"));
        }
        table.row::<stream::meta_data_tables::mdtables::Assembly>(0)
    }
}

#[repr(C)]
#[derive(Deserialize, Debug, Clone, scroll::Pread)]
pub struct MetaDataStruct {
    signature: u32,
    major_version: u16,
    minor_version: u16,
    reserved: u32,
    version_length: u32,
}

#[derive(Debug, Serialize)]
pub struct MetaData<'a> {
    #[serde(skip_serializing)]
    _version: String,
    flags: u16,
    pub streams: std::collections::HashMap<String, stream::ClrStream<'a>>,
}

impl<'a> MetaData<'a> {
    pub fn md_table(
        &self,
        name: &'static str,
    ) -> Result<&stream::meta_data_tables::mdtables::MetaDataTable> {
        for s in self.streams.values() {
            if let stream::Stream::MetaDataTables(mt) = &s.stream {
                match mt
                    .tables
                    .get(&stream::meta_data_tables::mdtables::table_name_2_index(
                        name,
                    )?) {
                    Some(s) => return Ok(s),
                    None => return Err(Error::UndefinedMetaDataTableName(name)),
                }
            }
        }
        Err(Error::UndefinedMetaDataTableName(name))
    }

    pub fn md_table_by_index(
        &self,
        index: &usize,
    ) -> Result<&stream::meta_data_tables::mdtables::MetaDataTable> {
        for s in self.streams.values() {
            if let stream::Stream::MetaDataTables(mt) = &s.stream {
                match mt.tables.get(index) {
                    Some(s) => return Ok(s),
                    None => return Err(Error::UndefinedMetaDataTableIndex(*index as u32)),
                }
            }
        }
        Err(Error::UndefinedMetaDataTableIndex(*index as u32))
    }

    pub fn get_us(&self, rid: usize) -> Result<String> {
        for s in self.streams.values() {
            if let stream::Stream::UserStringHeap(us) = &s.stream {
                return us.get_us(rid);
            }
        }
        Err(Error::UndefinedMetaDataTableName("US"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clr_header_flags_decodes_bits() {
        let flags = ClrHeaderFlags::new(0b0000_0001);
        assert!(flags.contains(&ClrHeaderFlags::IlOnly));
        assert!(!flags.contains(&ClrHeaderFlags::BitRequired32));
    }

    #[test]
    fn clr_header_flags_decodes_all_low_bits() {
        let flags = ClrHeaderFlags::new(0x1F); // bits 0-4
        for v in [
            ClrHeaderFlags::IlOnly,
            ClrHeaderFlags::BitRequired32,
            ClrHeaderFlags::IlLibrary,
            ClrHeaderFlags::StrongNamesSigned,
            ClrHeaderFlags::NativeEntryPiont,
        ] {
            assert!(flags.contains(&v), "missing flag: {v:?}");
        }
    }

    #[test]
    fn clr_header_flags_decodes_high_bits() {
        let flags = ClrHeaderFlags::new(0x30000); // bits 16 + 17
        assert!(flags.contains(&ClrHeaderFlags::TrackDebugData));
        assert!(flags.contains(&ClrHeaderFlags::Prefer32Bit));
    }

    #[test]
    fn clr_header_flags_zero_value_is_empty() {
        let flags = ClrHeaderFlags::new(0);
        assert!(flags.is_empty());
    }
}
