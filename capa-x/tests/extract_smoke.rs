//! File-scope smoke tests: run the PE/ELF extractors against a couple of real
//! corpus samples and sanity-check the shapes of what comes out. The
//! quantitative parity check against Python capa is
//! `scripts/difftest.py --mode file-features` (a full corpus run, not a
//! unit test); this just guards against gross breakage (panics, empty
//! output) on `cargo test`.

use std::path::{Path, PathBuf};

use capa_x::extract::{elf::extract_elf, pe::extract_pe};
use capa_x::features::Feature;

fn testfiles_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("testfiles")
}

#[test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
fn extract_pe_on_real_sample() {
    let path = testfiles_dir().join("Practical Malware Analysis Lab 01-01.exe_");
    let buf = std::fs::read(&path).expect("sample present (capa-testfiles submodule checked out?)");

    let sf = extract_pe(&buf).expect("valid PE");

    assert!(sf
        .global_features
        .contains(&Feature::Os("windows".to_string())));
    assert!(sf
        .global_features
        .iter()
        .any(|f| matches!(f, Feature::Arch(_))));
    assert!(sf
        .file_features
        .iter()
        .any(|(_, f)| matches!(f, Feature::Import(_))));
    assert!(sf
        .file_features
        .iter()
        .any(|(_, f)| matches!(f, Feature::Section(_))));
    assert!(sf
        .file_features
        .iter()
        .any(|(_, f)| matches!(f, Feature::String(_))));
    assert!(sf
        .global_features
        .contains(&Feature::Format("pe".to_string())));
    assert!(sf.functions.is_empty());
    assert_eq!(sf.sample_hashes.md5.len(), 32);
}

#[test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
fn extract_elf_on_real_sample() {
    let path = testfiles_dir().join("e17e6a79ed614f5468d0eed758629697.elf_");
    let buf = std::fs::read(&path).expect("sample present (capa-testfiles submodule checked out?)");

    let sf = extract_elf(&buf).expect("valid ELF");

    assert!(sf
        .global_features
        .iter()
        .any(|f| matches!(f, Feature::Os(_))));
    assert!(sf
        .global_features
        .iter()
        .any(|f| matches!(f, Feature::Arch(_))));
    assert!(sf
        .global_features
        .contains(&Feature::Format("elf".to_string())));
    assert!(sf
        .file_features
        .iter()
        .any(|(_, f)| matches!(f, Feature::String(_))));
    assert!(sf.functions.is_empty());
    assert_eq!(sf.sample_hashes.sha256.len(), 64);
}

#[test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
fn extract_pe_tolerates_damage_in_unneeded_directories() {
    let path = testfiles_dir().join("068a76d4823419b376d418cf03215d5c.exe_");
    let buf = std::fs::read(&path).expect("sample present");
    let sf = extract_pe(&buf).expect("file-only extraction ignores malformed TLS data");
    assert!(sf
        .file_features
        .iter()
        .any(|(_, feature)| matches!(feature, Feature::Import(_))));
}

#[test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
fn extract_pe_resolves_import_names_stored_in_headers() {
    let path = testfiles_dir().join("9d98f8519d9fee8219caca5b31eef0bd.exe_");
    let buf = std::fs::read(&path).expect("sample present");
    let sf = extract_pe(&buf).expect("packed PE remains parseable");
    assert!(sf.file_features.contains(&(
        capa_x::address::Address::Absolute(4_375_599),
        Feature::Import("kernel32.LoadLibraryA".to_string()),
    )));
}
