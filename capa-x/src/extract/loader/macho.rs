//! Mach-O file/global feature extraction. This is a capa-x extension because
//! pinned capa 9.4.0 has no raw Mach-O input or Python source to port from;
//! the structural and feature fixture corpus is the oracle. See
//! [`super::image::ImageFormat::Macho`]'s doc comment.
//!
//! Mirrors `extract/elf.rs`'s split from `extract/image.rs`: this module
//! walks `goblin::mach::MachO` directly for *feature* extraction (which
//! wants fine-grained, per-Mach-O-*section* data), independent of
//! `LoadedImage`'s coarser per-*segment* mapping used for code recovery.

use goblin::mach::load_command::CommandVariant;
use goblin::mach::MachO;

use crate::address::Address;
use crate::features::{Feature, StringFeature};
use crate::freeze::StaticFeatures;

use super::image::{select_macho_slice, Architecture, LoadedImage};
use super::strings::{extract_ascii_strings, extract_unicode_strings};
use super::{sample_hashes, ExtractError};

const MIN_STRING_LEN: usize = 4;

// `mach-o/loader.h`'s `LC_BUILD_VERSION` platform constants. `goblin`
// 0.10.7 only names `PLATFORM_MACOS`/`PLATFORM_IOS`/`PLATFORM_IOSSIMULATOR`;
// the rest are transcribed here so a build-version load command from any of
// them still resolves to a real name rather than falling through to the
// "macos" default. `PLATFORM_MACOS` itself needs no constant: it is the
// fallback arm below.
const PLATFORM_IOS: u32 = 2;
const PLATFORM_TVOS: u32 = 3;
const PLATFORM_WATCHOS: u32 = 4;

/// `os: macos`/`ios` **from load commands, never from the architecture**
/// `LC_BUILD_VERSION`'s `platform` field when present
/// (modern toolchains), else the legacy `LC_VERSION_MIN_*` command's own
/// identity. Defaults to `"macos"` when a slice carries neither -- every
/// Every fixture has one or the other, but a hand-crafted or very old
/// Mach-O might not.
fn macho_os(macho: &MachO) -> &'static str {
    for command in &macho.load_commands {
        match command.command {
            CommandVariant::BuildVersion(build) => {
                return match build.platform {
                    PLATFORM_IOS => "ios",
                    PLATFORM_TVOS => "tvos",
                    PLATFORM_WATCHOS => "watchos",
                    // `PLATFORM_MACOS` (1) and anything else this fixture
                    // corpus doesn't exercise yet both default to "macos".
                    _ => "macos",
                };
            }
            CommandVariant::VersionMinIphoneos(_) => return "ios",
            CommandVariant::VersionMinTvos(_) => return "tvos",
            CommandVariant::VersionMinWatchos(_) => return "watchos",
            CommandVariant::VersionMinMacosx(_) => return "macos",
            _ => {}
        }
    }
    "macos"
}

/// `amd64` for the x86_64 slice, `aarch64` for
/// `arm64`/`arm64e` -- matching ELF's own `EM_X86_64 -> "amd64"`/
/// `EM_AARCH64 -> "aarch64"` naming (`extract/elf.rs`), since capa-rules
/// rules keyed on `arch:` are written against those upstream strings and
/// this format has no naming convention of its own to follow instead.
fn macho_arch_feature_name(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X64 => "amd64",
        Architecture::AArch64 => "aarch64",
        // `from_macho` never resolves a 32-bit or unsupported slice to this
        // extractor; kept exhaustive so a future `Architecture` variant is a
        // compile error here rather than a silently wrong feature.
        Architecture::X86 => "i386",
    }
}

fn extract_global_features(macho: &MachO, architecture: Architecture) -> Vec<Feature> {
    vec![
        Feature::Format("macho".to_string()),
        Feature::Os(macho_os(macho).to_string()),
        Feature::Arch(macho_arch_feature_name(architecture).to_string()),
    ]
}

/// Per Mach-O *section* (not per `LC_SEGMENT_64`, which is what
/// `LoadedImage`'s mapping uses) -- `"__TEXT,__text"` mirrors how Mach-O
/// tooling (`otool`, `nm`) always names a section alongside its owning
/// segment, since section names alone are not unique across segments. No
/// upstream convention exists to match (this format has no Python oracle at
/// all).
fn extract_file_section_names(macho: &MachO, out: &mut Vec<(Address, Feature)>) {
    for segment in &macho.segments {
        let Ok(segment_name) = segment.name() else {
            continue;
        };
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, _data) in sections {
            let Ok(section_name) = section.name() else {
                continue;
            };
            out.push((
                Address::Absolute(section.addr),
                Feature::Section(format!("{segment_name},{section_name}")),
            ));
        }
    }
}

/// Bare symbol name, leading `_` (the Mach-O C-symbol convention) stripped
/// -- matches [`super::image::register_macho_import`]'s convention for the
/// same reason, and ELF's file-scope `Import`/`Export` features, which are
/// likewise bare names with no library qualifier
/// (`extract/elf.rs::extract_file_export_names`/`extract_file_import_names`).
fn strip_c_symbol_prefix(name: &str) -> &str {
    name.strip_prefix('_').unwrap_or(name)
}

/// `image.external_bindings` already resolved every import this slice has,
/// through whichever mechanism it actually uses (classic bind opcodes or
/// `LC_DYLD_CHAINED_FIXUPS`, mutually exclusive per binary -- see
/// `image.rs::load_macho_imports`); reusing it here is simpler and more
/// complete than re-decoding `goblin::mach::MachO::imports()` a second time
/// (which is empty for every chained-fixups binary, i.e. most of this
/// corpus -- `goblin` 0.10.7 has no chained-fixups support at all).
fn extract_file_import_names(image: &LoadedImage, out: &mut Vec<(Address, Feature)>) {
    for (address, names) in &image.external_bindings {
        for name in names {
            out.push((Address::Absolute(*address), Feature::Import(name.clone())));
        }
    }
}

fn extract_file_export_names(macho: &MachO, out: &mut Vec<(Address, Feature)>) {
    let Ok(exports) = macho.exports() else {
        return;
    };
    let image_base = macho_image_base(macho);
    for export in &exports {
        let Some(address) = image_base.checked_add(export.offset) else {
            continue;
        };
        out.push((
            Address::Absolute(address),
            Feature::Export(strip_c_symbol_prefix(&export.name).to_string()),
        ));
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

/// The `__TEXT` segment's `vmaddr`, or the lowest `LC_SEGMENT_64` `vmaddr`
/// when there is none -- same rule `LoadedImage::from_macho` uses for
/// `image_base`, duplicated here because this extractor parses its own
/// `MachO` independently (see this module's doc comment).
fn macho_image_base(macho: &MachO) -> u64 {
    let mut fallback_min: Option<u64> = None;
    for command in &macho.load_commands {
        if let CommandVariant::Segment64(seg) = command.command {
            if seg.segname.starts_with(b"__TEXT\0") {
                return seg.vmaddr;
            }
            fallback_min = Some(fallback_min.map_or(seg.vmaddr, |min| min.min(seg.vmaddr)));
        }
    }
    fallback_min.unwrap_or(0)
}

/// port of no Python source (see module doc): `format`/`os`/`arch` as
/// global features, then imports/exports/sections/strings as file features
/// -- the same shape and handler order `extract/elf.rs::extract_elf`
/// follows, for a format with no upstream analogue to follow instead.
pub fn extract_macho(bytes: &[u8], arch: Option<&str>) -> Result<StaticFeatures, ExtractError> {
    let (slice, _resolved_arch) =
        select_macho_slice(bytes, arch).map_err(|error| ExtractError::Parse(error.to_string()))?;
    let macho =
        MachO::parse(slice, 0).map_err(|error| ExtractError::Parse(format!("Mach-O: {error}")))?;
    let image = LoadedImage::from_macho(bytes, arch)
        .map_err(|error| ExtractError::Parse(error.to_string()))?;

    let base_address = Address::Absolute(macho_image_base(&macho));
    let global_features = extract_global_features(&macho, image.architecture);

    let mut file_features = Vec::new();
    extract_file_import_names(&image, &mut file_features);
    extract_file_export_names(&macho, &mut file_features);
    extract_file_section_names(&macho, &mut file_features);
    extract_file_strings(slice, &mut file_features);

    Ok(StaticFeatures {
        base_address,
        sample_hashes: sample_hashes(bytes),
        global_features,
        file_features,
        functions: Default::default(),
    })
}
