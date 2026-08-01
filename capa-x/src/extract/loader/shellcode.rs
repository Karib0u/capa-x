//! `-f sc32`/`sc64` file/global feature extraction.
//!
//! Ported from `capa/loader.py:get_workspace`'s `FORMAT_SC32`/`FORMAT_SC64`
//! branches (which build a `viv_utils` "shellcode workspace" instead of
//! parsing a PE/ELF container) plus `VivisectFeatureExtractor.__init__`'s
//! global-feature precomputation and `viv/file.py`'s `FILE_HANDLERS`. Unlike
//! PE/ELF, a raw shellcode buffer never matches `capa.features.extractors.
//! common.extract_format`'s magic-byte checks, so:
//!   - no `Format` global feature is ever emitted (`meta.analysis.format`
//!     falls back to the CLI's resolved `sc32`/`sc64` string instead -- see
//!     `capa-x-cli/src/main.rs` and `MetaInputs::input_format_fallback`);
//!   - no `Os` global feature is emitted unless the user passes `--os`
//!     explicitly (`common.extract_os` only yields the buf-independent
//!     override when `os != OS_AUTO`; shellcode bytes never satisfy the
//!     buf-based PE/ELF/result branches that would supply one otherwise).
//!
//! `Arch` is always present (from vivisect's `Architecture` workspace meta,
//! set directly from the `sc32`/`sc64` flag).
//!
//! There are no imports/exports/relocations/sections to report beyond the
//! one synthetic segment `viv_utils.getShellcodeWorkspace` creates, and FLIRT
//! is PE-only (`extract/flirt.rs`), so `enrich_static_features` is called
//! with an empty library map by `capa-x-cli`, same as ELF.

use crate::address::Address;
use crate::features::{Feature, StringFeature};
use crate::freeze::StaticFeatures;

use super::helpers::carve_pe;
use super::image::{Architecture, SHELLCODE_BASE};
use super::sample_hashes;
use super::strings::{extract_ascii_strings, extract_unicode_strings};

/// capa/features/extractors/strings.py callers always use the default
/// minimum length.
const MIN_STRING_LEN: usize = 4;

fn extract_file_embedded_pe(buf: &[u8], out: &mut Vec<(Address, Feature)>) {
    for (offset, _key) in carve_pe(buf, 1) {
        out.push((
            Address::File(offset as u64),
            Feature::Characteristic("embedded pe".to_string()),
        ));
    }
}

/// port of `viv/file.py:extract_file_section_names`'s `vw.getSegments()`
/// loop for the single segment `viv_utils.getShellcodeWorkspace` creates
/// (`vw.addSegment(base, len(buf), "shellcode_0x%x" % base, "shellcode")`).
fn extract_file_section_names(out: &mut Vec<(Address, Feature)>) {
    out.push((
        Address::Absolute(SHELLCODE_BASE),
        Feature::Section(format!("shellcode_0x{SHELLCODE_BASE:x}")),
    ));
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

/// port of `VivisectFeatureExtractor`'s global/file feature precomputation
/// for the shellcode workspace case; function/bb/insn scopes are filled in
/// separately by `recovery::analyze_shellcode` + `flirt::
/// enrich_static_features` (capa-x-cli wires the two together, mirroring
/// `extract_pe_input`/`extract_elf_input`).
///
/// `os_override` is `Some(value)` only for an explicit, non-`auto` `--os`
/// flag -- see this module's doc comment for why that's the only source of
/// an `Os` feature here.
pub fn extract_sc(
    buf: &[u8],
    architecture: Architecture,
    os_override: Option<&str>,
) -> StaticFeatures {
    let mut global_features = Vec::new();
    if let Some(os) = os_override {
        global_features.push(Feature::Os(os.to_string()));
    }
    global_features.push(Feature::Arch(
        match architecture {
            Architecture::X86 => "i386",
            Architecture::X64 => "amd64",
            // No `-f sc<n>` flag constructs this today (only sc32/sc64 do),
            // so this arm is unreached in practice; the name matches
            // `elf.rs`'s existing `EM_AARCH64` -> "aarch64" mapping in case
            // shellcode ever gains an AArch64 mode.
            Architecture::AArch64 => "aarch64",
        }
        .to_string(),
    ));

    let mut file_features = Vec::new();
    extract_file_embedded_pe(buf, &mut file_features);
    extract_file_section_names(&mut file_features);
    extract_file_strings(buf, &mut file_features);

    StaticFeatures {
        base_address: Address::Absolute(SHELLCODE_BASE),
        sample_hashes: sample_hashes(buf),
        global_features,
        file_features,
        functions: Default::default(),
    }
}
