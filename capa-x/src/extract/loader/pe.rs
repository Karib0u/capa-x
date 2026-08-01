//! PE file/global feature extraction, ported from
//! `capa/features/extractors/pefile.py` (v9.4.0, see PINNED.md) --
//! specifically the plain `PefileFeatureExtractor` (no disassembly), which
//! is what this module targets: `extract_global_features` (Os, Arch) and
//! `extract_file_features` (embedded PE, exports, imports, sections,
//! strings, function names [none without disassembly], format) -- in that
//! order, since `FeatureSet` insertion order is observable.

use goblin::pe::export::Reexport;
use goblin::pe::header::{COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64};
use goblin::pe::options::{ParseMode, ParseOptions};
use goblin::pe::PE;

use crate::address::Address;
use crate::features::{Feature, StringFeature};
use crate::freeze::StaticFeatures;

use super::helpers::{carve_pe, generate_symbols, reformat_forwarded_export_name};
use super::strings::{extract_ascii_strings, extract_unicode_strings};
use super::{sample_hashes, ExtractError};

/// capa/features/extractors/strings.py callers always use the default
/// minimum length.
const MIN_STRING_LEN: usize = 4;

fn strip_last_ext_lower(name: &str) -> String {
    // port of `modname.rpartition(".")[0].lower()`: cuts everything after
    // the *last* dot regardless of what the "extension" actually is: a dll
    // name with no dot at all becomes an empty string (`rpartition`'s
    // no-separator quirk), not the whole name.
    match name.rfind('.') {
        Some(idx) => name[..idx].to_lowercase(),
        None => String::new(),
    }
}

fn extract_file_embedded_pe(buf: &[u8], out: &mut Vec<(Address, Feature)>) {
    for (offset, _key) in carve_pe(buf, 1) {
        out.push((
            Address::File(offset as u64),
            Feature::Characteristic("embedded pe".to_string()),
        ));
    }
}

fn extract_file_export_names(pe: &PE, out: &mut Vec<(Address, Feature)>) {
    let base_address = pe.image_base;
    for export in &pe.exports {
        let Some(name) = export.name else { continue };
        if !name.is_ascii() {
            continue;
        }
        let va = base_address.wrapping_add(export.rva as u64);

        match &export.reexport {
            None => {
                out.push((Address::Absolute(va), Feature::Export(name.to_string())));
            }
            Some(reexport) => {
                let raw = match reexport {
                    Reexport::DLLName { export, lib } => format!("{lib}.{export}"),
                    Reexport::DLLOrdinal { ordinal, lib } => format!("{lib}.#{ordinal}"),
                };
                if !raw.is_ascii() {
                    continue;
                }
                let forwarded_name = reformat_forwarded_export_name(&raw);
                out.push((Address::Absolute(va), Feature::Export(forwarded_name)));
                out.push((
                    Address::Absolute(va),
                    Feature::Characteristic("forwarded export".to_string()),
                ));
            }
        }
    }
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_le_bytes(buf.get(offset..end)?.try_into().ok()?))
}

fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    Some(u64::from_le_bytes(buf.get(offset..end)?.try_into().ok()?))
}

fn read_ascii_cstr(buf: &[u8], offset: usize) -> Option<&str> {
    let rest = buf.get(offset..)?;
    let end = rest.iter().position(|byte| *byte == 0)?;
    let value = std::str::from_utf8(rest.get(..end)?).ok()?;
    value.is_ascii().then_some(value)
}

fn rva_to_offset(pe: &PE, buf: &[u8], rva: usize, options: &ParseOptions) -> Option<usize> {
    let optional_header = pe.header.optional_header.as_ref()?;
    if rva < optional_header.windows_fields.size_of_headers as usize && rva < buf.len() {
        return Some(rva);
    }
    goblin::pe::utils::find_offset(
        rva,
        &pe.sections,
        optional_header.windows_fields.file_alignment,
        options,
    )
}

fn extract_file_import_names(
    pe: &PE,
    buf: &[u8],
    options: &ParseOptions,
    out: &mut Vec<(Address, Feature)>,
) {
    let base_address = pe.image_base;
    let Some(optional_header) = pe.header.optional_header.as_ref() else {
        return;
    };
    let Some(directory) = optional_header.data_directories.get_import_table() else {
        return;
    };
    let Some(table_offset) = rva_to_offset(pe, buf, directory.virtual_address as usize, options)
    else {
        return;
    };

    const DIRECTORY_ENTRY_SIZE: usize = 20;
    let available_entries = buf
        .len()
        .saturating_sub(table_offset)
        .checked_div(DIRECTORY_ENTRY_SIZE)
        .unwrap_or(0);
    let declared_entries = (directory.size as usize).checked_div(DIRECTORY_ENTRY_SIZE);
    let max_entries =
        declared_entries.map_or(available_entries, |count| count.min(available_entries));

    for index in 0..max_entries {
        let Some(offset) = index
            .checked_mul(DIRECTORY_ENTRY_SIZE)
            .and_then(|relative| table_offset.checked_add(relative))
        else {
            break;
        };
        let Some(import_lookup_table_rva) = read_u32(buf, offset) else {
            break;
        };
        let Some(name_rva) = read_u32(buf, offset.saturating_add(12)) else {
            break;
        };
        let Some(import_address_table_rva) = read_u32(buf, offset.saturating_add(16)) else {
            break;
        };
        if import_lookup_table_rva == 0 && name_rva == 0 && import_address_table_rva == 0 {
            break;
        }

        let Some(name_offset) = rva_to_offset(pe, buf, name_rva as usize, options) else {
            continue;
        };
        let Some(dll) = read_ascii_cstr(buf, name_offset) else {
            continue;
        };
        let modname = strip_last_ext_lower(dll);

        let lookup_rva = if import_lookup_table_rva == 0 {
            import_address_table_rva
        } else {
            import_lookup_table_rva
        };
        let Some(lookup_offset) = rva_to_offset(pe, buf, lookup_rva as usize, options) else {
            continue;
        };
        let entry_size = if pe.is_64 { 8usize } else { 4usize };
        let ordinal_mask = if pe.is_64 { 1u64 << 63 } else { 1u64 << 31 };
        let max_imports = buf.len().saturating_sub(lookup_offset) / entry_size;

        for import_index in 0..max_imports {
            let Some(entry_offset) = import_index
                .checked_mul(entry_size)
                .and_then(|relative| lookup_offset.checked_add(relative))
            else {
                break;
            };
            let entry = if pe.is_64 {
                read_u64(buf, entry_offset)
            } else {
                read_u32(buf, entry_offset).map(u64::from)
            };
            let Some(entry) = entry else { break };
            if entry == 0 {
                break;
            }

            let impname = if entry & ordinal_mask != 0 {
                format!("#{}", entry & 0xffff)
            } else {
                let Some(hint_name_offset) = rva_to_offset(pe, buf, entry as usize, options) else {
                    continue;
                };
                let Some(string_offset) = hint_name_offset.checked_add(2) else {
                    continue;
                };
                let Some(name) = read_ascii_cstr(buf, string_offset) else {
                    continue;
                };
                name.to_string()
            };

            let Some(slot_rva) = import_index
                .checked_mul(entry_size)
                .and_then(|relative| (import_address_table_rva as usize).checked_add(relative))
            else {
                break;
            };
            let va = base_address.wrapping_add(slot_rva as u64);
            for name in generate_symbols(&modname, &impname, true) {
                out.push((Address::Absolute(va), Feature::Import(name)));
            }
        }
    }
}

fn extract_file_section_names(pe: &PE, out: &mut Vec<(Address, Feature)>) {
    let base_address = pe.image_base;
    for section in &pe.sections {
        let end = section
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(section.name.len());
        let Ok(name) = std::str::from_utf8(&section.name[..end]) else {
            continue;
        };
        if !name.is_ascii() {
            continue;
        }
        let va = base_address.wrapping_add(u64::from(section.virtual_address));
        out.push((Address::Absolute(va), Feature::Section(name.to_string())));
    }
}

fn extract_file_strings(buf: &[u8], out: &mut Vec<(Address, Feature)>) {
    for s in extract_ascii_strings(buf, MIN_STRING_LEN) {
        out.push((
            Address::File(s.offset as u64),
            Feature::String(StringFeature::Plain(s.s)),
        ));
    }
    for s in extract_unicode_strings(buf, MIN_STRING_LEN) {
        out.push((
            Address::File(s.offset as u64),
            Feature::String(StringFeature::Plain(s.s)),
        ));
    }
}

/// port of `PefileFeatureExtractor.extract_global_features` /
/// `.extract_file_features` /  `.get_base_address`, minus everything
/// `NotImplementedError`s (function/bb/insn scope, which need disassembly).
pub fn extract_pe(buf: &[u8]) -> Result<StaticFeatures, ExtractError> {
    // The file-only upstream extractor uses pefile's permissive parser and
    // never consumes TLS, resources, or certificates. Avoid letting damage
    // in those unrelated directories hide valid imports, exports, sections,
    // and strings from packed samples.
    let mut options = ParseOptions::default();
    options.parse_mode = ParseMode::Permissive;
    options.parse_tls_data = false;
    options.parse_resources = false;
    options.parse_attribute_certificates = false;
    let pe =
        PE::parse_with_opts(buf, &options).map_err(|e| ExtractError::Parse(format!("PE: {e}")))?;

    let mut global_features = Vec::new();
    // `VivisectFeatureExtractor.__init__` builds `self.global_features` from
    // `extract_file_format`, `extract_os`, `extract_arch` -- format/os/arch
    // are all *global* features (present at every scope), not file-scope
    // ones, confirmed by the pinned freeze fixtures (`format` lives under
    // `global_`, not `file`, in every `tests/testfiles/fixtures/snapshots/
    // features/*.frz`).
    global_features.push(Feature::Format("pe".to_string()));
    global_features.push(Feature::Os("windows".to_string()));
    match pe.header.coff_header.machine {
        COFF_MACHINE_X86 => global_features.push(Feature::Arch("i386".to_string())),
        COFF_MACHINE_X86_64 => global_features.push(Feature::Arch("amd64".to_string())),
        // Matches ELF/Mach-O's own `"aarch64"` arch-feature
        // string (`extract/elf.rs`, `extract/macho.rs`), not `"arm64"`.
        COFF_MACHINE_ARM64 => global_features.push(Feature::Arch("aarch64".to_string())),
        _ => {
            // upstream logs a warning and yields nothing for an
            // unrecognized machine type; rules keyed on `arch:` simply
            // won't match, same as upstream.
        }
    }

    let mut file_features = Vec::new();
    // FILE_HANDLERS, in order: embedded pe, exports, imports, sections,
    // strings, function names (none).
    extract_file_embedded_pe(buf, &mut file_features);
    extract_file_export_names(&pe, &mut file_features);
    extract_file_import_names(&pe, buf, &options, &mut file_features);
    extract_file_section_names(&pe, &mut file_features);
    extract_file_strings(buf, &mut file_features);

    Ok(StaticFeatures {
        base_address: Address::Absolute(pe.image_base),
        sample_hashes: sample_hashes(buf),
        global_features,
        file_features,
        functions: Default::default(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn strip_last_ext_lower_matches_python_rpartition_quirk() {
        assert_eq!(strip_last_ext_lower("KERNEL32.dll"), "kernel32");
        assert_eq!(strip_last_ext_lower("KERNEL32.DLL"), "kernel32");
        // no dot at all: rpartition("." ) -> ("", "", "foo"), so [0] is "".
        assert_eq!(strip_last_ext_lower("foo"), "");
        // only the *last* dot counts.
        assert_eq!(strip_last_ext_lower("some.thing.dll"), "some.thing");
    }
}
