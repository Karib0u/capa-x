//! ELF file/global feature extraction, ported from
//! `capa/features/extractors/elffile.py` (v9.4.0, see PINNED.md) --
//! `ElfFeatureExtractor`'s `extract_global_features` (Os via
//! [`super::elf_os::detect_elf_os`], Arch) and `extract_file_features`
//! (exports, imports, sections, strings, format) -- in that order.
//!
//! Uses `goblin::elf::Elf` (an `.so`/pyelftools-equivalent parser) for
//! structural data, distinct from [`super::elf_os`]'s hand-rolled parser
//! (which only exists to port `elf.py`'s OS-detection heuristics
//! byte-for-byte).

use goblin::elf::header::{EM_386, EM_AARCH64, EM_ARM, EM_X86_64};
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::section_header::SHT_NULL;
use goblin::elf::sym::{Sym, STT_FUNC, STT_GNU_IFUNC, STT_OBJECT};
use goblin::elf::Elf;

use crate::address::Address;
use crate::features::Feature;
use crate::freeze::StaticFeatures;

use super::elf_os::detect_elf_os;
use super::strings::{extract_ascii_strings, extract_unicode_strings};
use super::{sample_hashes, ExtractError};
use crate::features::StringFeature;

const MIN_STRING_LEN: usize = 4;
const SHN_UNDEF: usize = 0;

fn is_exportable_type(st_info: u8) -> bool {
    let t = goblin::elf::sym::st_type(st_info);
    t == STT_FUNC || t == STT_OBJECT || t == STT_GNU_IFUNC
}

/// port of the two export-name loops in `extract_file_export_names`: one
/// over every `SymbolTableSection` found via section headers, one over the
/// dynamic segment's symtab. `goblin::elf::Elf::syms` (`.symtab`, via
/// section headers) and `::dynsyms` (via `PT_DYNAMIC`'s `DT_SYMTAB`, which
/// in practice is the same table `.dynsym` section headers would also
/// expose) together cover both -- each paired with *its own* string table
/// (`.strtab`/`.dynstrtab` are two unrelated blobs of NUL-terminated
/// strings; an `st_name` offset valid in one is not meaningfully "the same
/// name" if it also happens to decode in the other, so a symbol's table
/// origin must be tracked, not guessed after the fact).
fn extract_one_table<'a>(
    syms: impl Iterator<Item = Sym>,
    strtab: &goblin::strtab::Strtab<'a>,
    out: &mut Vec<(Address, Feature)>,
) {
    for sym in syms {
        let Some(name) = strtab.get_at(sym.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        if !is_exportable_type(sym.st_info) {
            continue;
        }
        if sym.st_value == 0 {
            continue;
        }
        if sym.st_shndx == SHN_UNDEF {
            continue;
        }
        out.push((
            Address::Absolute(sym.st_value),
            Feature::Export(name.to_string()),
        ));
    }
}

fn extract_file_export_names(elf: &Elf, out: &mut Vec<(Address, Feature)>) {
    extract_one_table(elf.syms.iter(), &elf.strtab, out);
    extract_one_table(elf.dynsyms.iter(), &elf.dynstrtab, out);
}

/// `symbol_name_by_index` comes from [`super::elf_os::dynamic_import_symbol_names`]
/// -- a dedicated port of pyelftools' `DynamicSegment.num_symbols`/
/// `iter_symbols` (see that function's doc comment for why this can't
/// reuse `goblin::elf::Elf::dynsyms`).
fn extract_file_import_names(elf: &Elf, buf: &[u8], out: &mut Vec<(Address, Feature)>) {
    let symbol_name_by_index = super::elf_os::dynamic_import_symbol_names(buf);

    for reloc in elf
        .dynrelas
        .iter()
        .chain(elf.dynrels.iter())
        .chain(elf.pltrelocs.iter())
    {
        let Some(name) = symbol_name_by_index.get(&reloc.r_sym) else {
            continue;
        };
        out.push((Address::File(reloc.r_offset), Feature::Import(name.clone())));
    }
}

fn extract_file_section_names(elf: &Elf, out: &mut Vec<(Address, Feature)>) {
    for shdr in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(shdr.sh_name);
        match name {
            Some(n) if !n.is_empty() => {
                out.push((
                    Address::Absolute(shdr.sh_addr),
                    Feature::Section(n.to_string()),
                ));
            }
            _ => {
                if shdr.sh_type == SHT_NULL {
                    out.push((
                        Address::Absolute(shdr.sh_addr),
                        Feature::Section("NULL".to_string()),
                    ));
                }
            }
        }
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

/// port of `ElfFeatureExtractor.extract_global_features` /
/// `.extract_file_features` / `.get_base_address`.
pub fn extract_elf(buf: &[u8]) -> Result<StaticFeatures, ExtractError> {
    let elf = Elf::parse(buf).map_err(|e| ExtractError::Parse(format!("ELF: {e}")))?;

    // `ElfFeatureExtractor.get_base_address` falls off the end (implicit
    // `None`) when there's no `PT_LOAD` segment (e.g. a relocatable `.o`,
    // which has no program headers at all) -- `frz.Address.from_capa`
    // encodes that as `NO_ADDRESS` (via the `a == NO_ADDRESS` branch,
    // which -- `_NoAddress.__eq__` returning `True` unconditionally --
    // actually matches *any* value, `None` included), so this mirrors that
    // rather than treating it as a hard error.
    let base_address = elf
        .program_headers
        .iter()
        .find(|p| p.p_type == PT_LOAD)
        .map_or(Address::NoAddress, |p| Address::Absolute(p.p_vaddr));

    let mut global_features = Vec::new();
    // `VivisectFeatureExtractor.__init__` builds `self.global_features` from
    // `extract_file_format`, `extract_os`, `extract_arch` -- format/os/arch
    // are all *global* features (present at every scope), not file-scope
    // ones, confirmed by the pinned freeze fixtures (`format` lives under
    // `global_`, not `file`, in every `tests/testfiles/fixtures/snapshots/
    // features/*.frz`).
    //
    // The "unknown" fallback in `extract_file_os` (for a `detect_elf_os`
    // result that isn't in `VALID_OS`) and the plain success path both boil
    // down to "always emit whatever `detect_elf_os` returned" -- see the
    // elf_os module comment.
    global_features.push(Feature::Format("elf".to_string()));
    global_features.push(Feature::Os(detect_elf_os(buf)));
    match elf.header.e_machine {
        EM_386 => global_features.push(Feature::Arch("i386".to_string())),
        EM_X86_64 => global_features.push(Feature::Arch("amd64".to_string())),
        EM_ARM => global_features.push(Feature::Arch("arm".to_string())),
        EM_AARCH64 => global_features.push(Feature::Arch("aarch64".to_string())),
        _ => {
            // unsupported architecture: upstream logs a warning and yields
            // nothing.
        }
    }

    let mut file_features = Vec::new();
    // FILE_HANDLERS, in order: exports, imports, sections, strings.
    extract_file_export_names(&elf, &mut file_features);
    extract_file_import_names(&elf, buf, &mut file_features);
    extract_file_section_names(&elf, &mut file_features);
    extract_file_strings(buf, &mut file_features);

    Ok(StaticFeatures {
        base_address,
        sample_hashes: sample_hashes(buf),
        global_features,
        file_features,
        functions: Default::default(),
    })
}
