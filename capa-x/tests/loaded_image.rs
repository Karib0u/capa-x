//! Loaded-image and instruction-decode regression tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use capa_x::extract::image::{Architecture, ImageFormat, LoadedImage};

mod common;

fn testfiles_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("testfiles")
}

fn load(name: &str) -> LoadedImage {
    let path = testfiles_dir().join(name);
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    LoadedImage::parse(&bytes).unwrap_or_else(|error| panic!("loading {}: {error}", path.display()))
}

#[test]
fn pe_mapping_bindings_and_entry_decode() {
    let image = load("Practical Malware Analysis Lab 01-01.exe_");
    assert_eq!(image.format, ImageFormat::Pe);
    assert_eq!(image.architecture, Architecture::X86);
    assert!(!image.sections.is_empty());
    assert!(!image.external_bindings.is_empty());
    assert_eq!(image.va_to_file_offset(image.image_base), Some(0));
    assert_eq!(image.file_offset_to_va(0), Some(image.image_base));

    let entry = image.entry_point.expect("sample has an entry point");
    let offset = image
        .va_to_file_offset(entry)
        .expect("entry point is file-backed");
    assert_eq!(image.file_offset_to_va(offset), Some(entry));

    let instruction = image.decode_at(entry).expect("entry instruction decodes");
    assert_eq!(instruction.address, entry);
    assert!(!instruction.bytes.is_empty());
    assert_eq!(instruction.bytes.len(), instruction.x86_instruction().len());
}

#[test]
fn elf_mapping_bindings_and_entry_decode() {
    let image = load("microsocks.elf_");
    assert_eq!(image.format, ImageFormat::Elf);
    assert_eq!(image.architecture, Architecture::X64);
    assert!(image
        .sections
        .iter()
        .any(|section| section.permissions.execute));
    assert!(!image.external_bindings.is_empty());

    let entry = image.entry_point.expect("sample has an entry point");
    let offset = image
        .va_to_file_offset(entry)
        .expect("entry point is file-backed");
    assert_eq!(image.file_offset_to_va(offset), Some(entry));
    image.decode_at(entry).expect("entry instruction decodes");
}

#[test]
fn delay_imported_ordinals_are_named_from_the_ordinal_database() {
    // `ws2_32` ordinal 6 is `getsockname`. Vivisect's PE parser resolves a
    // delay-load ordinal through `PE/ordlookup` exactly as it does a bound
    // one, so the reference names this slot `ws2_32.getsockname`; capa-x
    // named only the main import table's ordinals and left this one `#6`,
    // which no `api:` feature can match.
    let image = load("112f9f0e8d349858a80dd8c14190e620.exe_");
    assert_eq!(
        image.import_locations.get(&0x92777c).map(String::as_str),
        Some("ws2_32.getsockname")
    );
}

#[test]
fn pe_loader_matches_vivisect_execute_rules() {
    let code_characteristic = load("f0a6a1bd6d760497623611e8297a81df.exe_");
    let pelock = code_characteristic
        .sections
        .iter()
        .find(|section| section.name == "PELOCKnt")
        .expect("sample has PELOCKnt section");
    assert!(pelock.permissions.execute, "CNT_CODE implies execute");

    let entry_override = load("c335a9d41185a32ad918c5389ee54235.exe_");
    let entry = entry_override.entry_point.expect("sample has entry point");
    let entry_section = entry_override
        .section_containing(entry)
        .expect("entry point is mapped");
    assert!(
        entry_section.permissions.execute,
        "the entry-point section is executable regardless of section flags"
    );

    // `vivisect/parsers/pe.py` would grant execute to any readable section of
    // a pre-Vista non-NX image, but only when `viv.parsers.pe.nx` is false --
    // and the pinned reference reaches the loader through
    // `viv_utils.getWorkspace`, which sets it true (`viv_utils/__init__.py:102`).
    // Checked directly against the pinned workspace: this sample's `.data` map
    // is `MM_READ|MM_WRITE` (0o6), with no `MM_EXEC`.
    let legacy_nx = load("Practical Malware Analysis Lab 03-02.dll_");
    let writable_data = legacy_nx
        .sections
        .iter()
        .find(|section| section.name == ".data")
        .expect("sample has data section");
    assert!(
        !writable_data.permissions.execute,
        "the pinned reference sets nx = true, so a writable data section stays non-executable"
    );
}

#[test]
fn pe_loader_exposes_zero_fill_and_dead_data() {
    let zero_fill = load("Practical Malware Analysis Lab 03-02.dll_");
    let data = zero_fill
        .sections
        .iter()
        .find(|section| section.name == ".data")
        .expect("sample has data section");
    let zero_address = data.address.saturating_add(data.file_size);
    assert!(data.virtual_size > data.file_size);
    assert_eq!(zero_fill.va_to_file_offset(zero_address), None);
    assert!(zero_fill
        .bytes_at(zero_address, 16)
        .is_some_and(|bytes| bytes.len() == 16 && bytes.iter().all(|byte| *byte == 0)));

    let dead = load("Practical Malware Analysis Lab 14-02.exe_");
    let rdata = dead
        .sections
        .iter()
        .find(|section| section.name == ".rdata")
        .expect("sample has rdata section");
    assert!(dead.is_dead_data(rdata.address));
    let resources = dead
        .sections
        .iter()
        .find(|section| section.name == ".rsrc")
        .expect("viv_utils maps resource sections");
    assert!(!resources.permissions.execute);
    assert!(dead.bytes_at(resources.address, 1).is_some());
}

#[test]
fn embedded_pe_overlay_is_dead_data_for_candidate_discovery() {
    let image = load("0596c4ea5aa8def47f22c85d75aaca95.exe_");
    // PE.carve finds the nested image at file offset 0x17000. Upstream's
    // offsetToRva maps this overlay to RVA zero, then marks its 0x12400
    // byte extent as data. Explicit code flow remains permitted.
    assert!(image.is_dead_data(0x1072db9));
    assert!(image.is_dead_data(0x1072dd3));
    assert!(image.decode_at(0x1072db9).is_ok());
}

#[test]
fn resource_directory_does_not_hide_executable_packer_code() {
    let image = load("0cd2b334aede270b14868db28211cde3.exe_");
    let code = image
        .section_containing(0x531cb3)
        .expect("resource-hosted code is mapped");
    assert!(code.permissions.execute);
    assert_eq!(image.decode_at(0x531cb3).unwrap().bytes, [0x60]);
}

#[test]
fn an_explicit_empty_lookup_table_does_not_fall_back_to_the_iat() {
    let mut bytes =
        std::fs::read(testfiles_dir().join("3fdfb2d522e7deecaaaf2f87420f7e75.exe_")).unwrap();
    let image = LoadedImage::parse(&bytes).unwrap();
    assert!(!image.external_bindings.contains_key(&0x411322));
    assert!(image
        .load_diagnostics
        .iter()
        .any(|message| message.contains("ignoring fallback IAT bindings")));

    // OriginalFirstThunk = 0 explicitly selects the IAT, unlike the sample's
    // nonzero RVA 0x11, which names an empty lookup table in the DOS header.
    let directory = image.va_to_file_offset(0x4112f2).unwrap() as usize;
    bytes[directory..directory + 4].copy_from_slice(&0u32.to_le_bytes());
    let fallback = LoadedImage::parse(&bytes).unwrap();
    assert!(fallback.external_bindings[&0x411322]
        .iter()
        .any(|name| name == "GetProcAddress"));
}

#[test]
fn every_layout_gate_input_loads_and_decodes_executable_bytes() {
    let corpus_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("scripts")
        .join("corpus-layout.txt");

    for name in common::read_corpus_list(&corpus_path) {
        let name = name.as_str();
        let image = load(name);
        let section = image
            .sections
            .iter()
            .find(|section| section.permissions.execute && section.file_size > 0)
            .unwrap_or_else(|| panic!("{name}: no file-backed executable mapping"));
        image
            .decode_at(section.address)
            .unwrap_or_else(|error| panic!("{name}: decoding first executable byte: {error}"));
    }
}
