//! Managed-resource enumeration.
//!
//! Walks the `ManifestResource` metadata table and exposes each resource's
//! name, flags, location (Embedded / External / Linked), and — for embedded
//! resources — a borrowed slice over the resource bytes in the file.
//!
//! Note that this module deliberately does NOT decode the .NET
//! `ResourceManager` binary format (`0xBEEFCACE` magic, named entries with
//! typed values). That's a separate format on top of these raw bytes and is
//! planned for a future release. For now consumers receive the raw blob and
//! can decode it themselves if needed.

use crate::{Result, error::Error};
use serde::Serialize;

/// A single managed (.NET) resource declared in the `ManifestResource`
/// metadata table.
#[derive(Debug, Clone, Serialize)]
pub struct DotNetResource<'a> {
    /// The resource name as stored in `#Strings`.
    pub name: String,
    /// `Public` or `Private` (ECMA-335 II.22.24).
    ///
    /// Skipped during JSON serialisation because the underlying flag enums
    /// (`ClrManifestResourceFlags` → `CorManifestResourceVisibility`) don't
    /// derive `Serialize` to keep their definitions decoupled from serde.
    /// Programmatic consumers still have full typed access.
    #[serde(skip)]
    pub flags: Vec<crate::stream::meta_data_tables::mdtables::enums::ClrManifestResourceFlags>,
    /// Where the resource bytes actually live.
    pub location: ResourceLocation,
    /// The resource's raw bytes (4-byte LE length prefix stripped) — only
    /// present for `ResourceLocation::Embedded`. Borrowed from the file
    /// buffer.
    #[serde(skip)]
    pub data: Option<&'a [u8]>,
}

/// Where a managed resource is physically stored.
#[derive(Debug, Clone, Serialize)]
pub enum ResourceLocation {
    /// In this PE's CLR resources directory.
    Embedded,
    /// In an external file referenced by the `File` table. The string is
    /// that referenced file's name (best-effort; may be empty if the
    /// reference is dangling).
    External { file: String },
    /// In another assembly referenced by `AssemblyRef`. The string is that
    /// referenced assembly's name.
    Linked { assembly: String },
}

impl<'a> crate::DnPe<'a> {
    /// Returns every entry in the `ManifestResource` metadata table, with
    /// embedded resource bytes resolved as borrowed slices into the file
    /// buffer.
    ///
    /// Returns `Ok(vec![])` if the binary has no `ManifestResource` table
    /// (most non-assembly DLLs and shellcode-style payloads).
    pub fn resources(&self) -> Result<Vec<DotNetResource<'a>>> {
        let Ok(clr) = self.net() else {
            return Ok(vec![]);
        };
        let Ok(table) = clr.md_table("ManifestResource") else {
            return Ok(vec![]);
        };

        // Defensive cap on the pre-allocation: row_count derives from a
        // file-supplied u32, so on a crafted input we'd otherwise request
        // a multi-GB allocation. The actual loop still walks every row;
        // the Vec just grows naturally past 4096.
        let row_count = table.row_count();
        let mut out = Vec::with_capacity(row_count.min(4096));
        for i in 0..row_count {
            let row =
                table.row::<crate::stream::meta_data_tables::mdtables::ManifestResource>(i)?;

            let location = if row.implementation.row_index == 0 {
                ResourceLocation::Embedded
            } else {
                match row.implementation.table {
                    "File" => ResourceLocation::External {
                        file: self
                            .lookup_file_name(row.implementation.row_index)
                            .unwrap_or_default(),
                    },
                    "AssemblyRef" => ResourceLocation::Linked {
                        assembly: self
                            .lookup_assembly_ref_name(row.implementation.row_index)
                            .unwrap_or_default(),
                    },
                    _ => ResourceLocation::Embedded,
                }
            };

            let data = if matches!(location, ResourceLocation::Embedded) {
                self.read_embedded_resource(row.offset).ok()
            } else {
                None
            };

            out.push(DotNetResource {
                name: row.name.clone(),
                flags: row.flags.clone(),
                location,
                data,
            });
        }
        Ok(out)
    }

    /// Best-effort lookup of a `File` table row's name. Returns `None` if
    /// the row is out of bounds.
    fn lookup_file_name(&self, rid: usize) -> Option<String> {
        let clr = self.net().ok()?;
        let table = clr.md_table("File").ok()?;
        let row = table
            .row::<crate::stream::meta_data_tables::mdtables::File>(rid.saturating_sub(1))
            .ok()?;
        Some(row.name.clone())
    }

    /// Best-effort lookup of an `AssemblyRef` row's name.
    fn lookup_assembly_ref_name(&self, rid: usize) -> Option<String> {
        let clr = self.net().ok()?;
        let table = clr.md_table("AssemblyRef").ok()?;
        let row = table
            .row::<crate::stream::meta_data_tables::mdtables::AssemblyRef>(rid.saturating_sub(1))
            .ok()?;
        Some(row.name.clone())
    }

    /// Read an embedded resource: at `resources_rva + offset` there is a
    /// 4-byte little-endian length prefix followed by the resource bytes.
    fn read_embedded_resource(&self, manifest_offset: u32) -> Result<&'a [u8]> {
        let abs = self
            .resources_rva
            .checked_add(manifest_offset)
            .ok_or(Error::UnresolvedRvaError(manifest_offset))?;
        let header: u32 = self.get_data(&abs, &4)?;
        // The 4-byte length prefix is attacker-controlled. Clamp it to the
        // remaining bytes of the resources directory before passing it to
        // `get_slice` (which also bounds-checks). This means a corrupted
        // length doesn't blow up the parse — we just return the smaller
        // valid slice.
        let payload_rva = abs.checked_add(4).ok_or(Error::UnresolvedRvaError(abs))?;
        let max = self
            .resources_size
            .saturating_sub(manifest_offset.saturating_add(4));
        let length = (header as usize).min(max as usize);
        self.get_slice(&payload_rva, length)
    }
}
