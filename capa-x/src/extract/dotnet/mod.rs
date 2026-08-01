//! CLR metadata reader for the native .NET backend.
//!
//! This module does not parse CLR metadata itself. The COR20 header,
//! metadata root, stream headers, `#~`/`#Strings`/`#US`/`#Blob`/`#GUID`
//! heaps, tables, coded indexes, and tokens are all handled by the vendored
//! `dnfile` fork (`third_party/dnfile`, pinned per
//! `docs/decisions/0003-clr-metadata.md`) -- this module is the
//! integration point between that crate's `Result<T, dnfile::error::Error>`
//! and capa-x's own error/feature model, plus a lightweight CLR-directory
//! probe that later phases (task 5's `-f dotnet`/auto-detection) can use
//! without committing to a full parse.
//!
//! Name resolution lives in `names`/`types` (task 2). CIL decoding, one
//! basic block per method, and the calls-to/calls-from call graph (task 3)
//! live in `function`. Rendering all of this into a `freeze::StaticFeatures`
//! (task 4) lives in `features` (`features::extract_dotnet`). CLI wiring
//! (task 5, `-f dotnet`/auto-detection, `--jobs`) is out of scope here.

pub mod features;
pub mod function;
pub mod names;
pub mod types;

use super::ExtractError;
use types::{DnType, DnUnmanagedMethod};

/// ECMA-335 table 0x2B's standard name (used by pinned Python `dnfile`) vs.
/// the name the vendored Rust fork (`third_party/dnfile`) recognizes for the
/// same table -- a labeling difference between the two crates only; both
/// parse the identical bytes and row count. `table_row_counts` looks the
/// table up by the Rust name and reports it under the canonical one, so its
/// output lines up with `scripts/gen_dotnet_table_counts.py`'s oracle dump.
const METHODSPEC_RUST_NAME: &str = "GenericMethod";

/// ECMA-335 II.22 metadata tables the pinned Python `dnfile` extractor
/// touches (`reference/capa/capa/features/extractors/dnfile/helpers.py`),
/// in `dnfile`/ECMA table-index order, under their canonical (Python
/// `dnfile`) names. Used only to cross-check row counts against a pinned
/// Python `dnfile` dump (`scripts/gen_dotnet_table_counts.py`); the vendored
/// crate has no equivalent public listing.
pub const TABLE_NAMES: &[&str] = &[
    "Module",
    "TypeRef",
    "TypeDef",
    "FieldPtr",
    "Field",
    "MethodPtr",
    "MethodDef",
    "ParamPtr",
    "Param",
    "InterfaceImpl",
    "MemberRef",
    "Constant",
    "CustomAttribute",
    "FieldMarshal",
    "DeclSecurity",
    "ClassLayout",
    "FieldLayout",
    "StandAloneSig",
    "EventMap",
    "EventPtr",
    "Event",
    "PropertyMap",
    "PropertyPtr",
    "Property",
    "MethodSemantics",
    "MethodImpl",
    "ModuleRef",
    "TypeSpec",
    "ImplMap",
    "FieldRva",
    "EncLog",
    "EncMap",
    "Assembly",
    "AssemblyProcessor",
    "AssemblyOS",
    "AssemblyRef",
    "AssemblyRefProcessor",
    "AssemblyRefOS",
    "File",
    "ExportedType",
    "ManifestResource",
    "NestedClass",
    "GenericParam",
    "MethodSpec",
    "GenericParamConstraint",
];

/// capa/loader.py's managed-PE probe, ahead of a full parse: a CLR PE
/// carries a non-empty COM-descriptor (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`,
/// index 14) data directory. `dnfile::DnPe::parse` already performs the
/// equivalent check internally and fails with `UnsupportedBinaryFormat` when
/// it's absent; this standalone probe exists so a future auto-detection
/// path (task 5) can tell "not a managed PE" apart from "malformed managed
/// PE" without paying for a full metadata parse on every non-.NET PE.
pub fn looks_like_dotnet_pe(buf: &[u8]) -> bool {
    let Ok(pe) = goblin::pe::PE::parse(buf) else {
        return false;
    };
    let Some(opt_header) = pe.header.optional_header else {
        return false;
    };
    let Some(clr_dir) = opt_header.data_directories.get_clr_runtime_header() else {
        return false;
    };
    clr_dir.virtual_address != 0 && clr_dir.size != 0
}

/// Parses a managed PE's CLR metadata, mapping every `dnfile::error::Error`
/// (malformed row counts, heap indexes, blobs, coded indexes, and any other
/// contextual failure the vendored crate's checked readers produce) into
/// `ExtractError` -- never a panic, per this project's no-unwrap/no-unchecked-
/// indexing rule for untrusted-input paths.
pub fn load(buf: &[u8]) -> Result<dnfile::DnPe<'_>, ExtractError> {
    dnfile::DnPe::parse(buf).map_err(|e| ExtractError::Parse(e.to_string()))
}

/// Row count for each of `TABLE_NAMES`, in that order. A table absent from
/// the file's `mask_valid` bitmask (never populated, i.e. zero rows) reads
/// as `0`, matching the pinned Python `dnfile`'s `getattr(mdtables, name,
/// None)` returning `None` for the same case.
pub fn table_row_counts(pe: &dnfile::DnPe<'_>) -> Result<Vec<(&'static str, usize)>, ExtractError> {
    let net = pe.net().map_err(|e| ExtractError::Parse(e.to_string()))?;
    Ok(TABLE_NAMES
        .iter()
        .map(|&name| {
            let lookup_name = if name == "MethodSpec" {
                METHODSPEC_RUST_NAME
            } else {
                name
            };
            let count = net
                .md_table(lookup_name)
                .map(|t| t.row_count())
                .unwrap_or(0);
            (name, count)
        })
        .collect())
}

/// `helpers.py is_dotnet_mixed_mode`.
pub fn is_mixed_mode(pe: &dnfile::DnPe<'_>) -> Result<bool, ExtractError> {
    let net = pe.net().map_err(|e| ExtractError::Parse(e.to_string()))?;
    Ok(names::is_mixed_mode(net))
}

/// `helpers.py get_dotnet_types` (the name model).
pub fn types(pe: &dnfile::DnPe<'_>) -> Result<Vec<DnType>, ExtractError> {
    let net = pe.net().map_err(|e| ExtractError::Parse(e.to_string()))?;
    names::types(net)
}

/// `helpers.py get_dotnet_managed_imports`.
pub fn managed_imports(pe: &dnfile::DnPe<'_>) -> Result<Vec<DnType>, ExtractError> {
    let net = pe.net().map_err(|e| ExtractError::Parse(e.to_string()))?;
    names::managed_imports(net)
}

/// `helpers.py get_dotnet_managed_methods`.
pub fn managed_methods(pe: &dnfile::DnPe<'_>) -> Result<Vec<DnType>, ExtractError> {
    let net = pe.net().map_err(|e| ExtractError::Parse(e.to_string()))?;
    names::managed_methods(net)
}

/// `helpers.py get_dotnet_fields`.
pub fn fields(pe: &dnfile::DnPe<'_>) -> Result<Vec<DnType>, ExtractError> {
    let net = pe.net().map_err(|e| ExtractError::Parse(e.to_string()))?;
    names::fields(net)
}

/// `helpers.py get_dotnet_unmanaged_imports`.
pub fn unmanaged_imports(pe: &dnfile::DnPe<'_>) -> Result<Vec<DnUnmanagedMethod>, ExtractError> {
    let net = pe.net().map_err(|e| ExtractError::Parse(e.to_string()))?;
    names::unmanaged_imports(net)
}
