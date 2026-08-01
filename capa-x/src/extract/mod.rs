//! File-scope and global feature extraction from PE and ELF samples, with no
//! disassembly -- code scopes are filled in separately by `recovery` and the
//! instruction/basic-block/function extractors. Ported from
//! `capa/features/extractors/{pefile,elffile,elf,strings,helpers,common}.py`
//! (v9.4.0, see PINNED.md).
//!
//! Deliberately produces a [`crate::freeze::StaticFeatures`] directly
//! (rather than introducing a separate `Extractor` trait) so the existing
//! freeze-driven matching/rendering pipeline needs no changes: a
//! PE/ELF sample and a freeze file both end up as the exact same in-memory
//! shape before matching.

pub mod aarch64;
pub mod dotnet;
pub mod features;
pub mod helpers;
pub mod loader;
pub mod recovery;
pub mod x86;

pub use aarch64::{
    basicblock_features as aarch64_basicblock_features, features as aarch64_features,
};
pub use features::{function_features, importcalls, strings};
pub use loader::{elf, elf_os, image, macho, pe, shellcode};
pub use recovery::{flirt, golang, libc_start_main, msvcfunc, noreturn};
pub use shellcode as sc;
pub use x86::{basicblock_features, decoder, insn_features, operand};

use crate::freeze::SampleHashes;

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("{0}")]
    Parse(String),
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // infallible: writing to a String never fails.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// capa/features/extractors/base_extractor.py: `SampleHashes.from_bytes`
pub(crate) fn sample_hashes(buf: &[u8]) -> SampleHashes {
    use md5::Md5;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};

    SampleHashes {
        md5: to_hex(&Md5::digest(buf)),
        sha1: to_hex(&Sha1::digest(buf)),
        sha256: to_hex(&Sha256::digest(buf)),
    }
}

/// capa/features/extractors/common.py: `MATCH_PE` / `MATCH_ELF`, used by
/// `-f auto` detection (CLI-side) to pick which extractor to run.
pub fn looks_like_pe(buf: &[u8]) -> bool {
    buf.starts_with(b"MZ")
}

pub fn looks_like_elf(buf: &[u8]) -> bool {
    buf.starts_with(b"\x7fELF")
}

/// Thin (64-bit) or fat Mach-O magic, in either byte order. Unlike
/// `looks_like_pe`/`looks_like_elf` this is **not** part of `-f auto`
/// detection: pinned capa 9.4.0 has no raw Mach-O input at all, so Mach-O is
/// only ever analysed via an explicit
/// `-f macho`, never guessed at. Used by [`image::LoadedImage::parse`] (a
/// general convenience, e.g. for tests) and by `-f macho`'s own dispatch.
pub fn looks_like_macho(buf: &[u8]) -> bool {
    let Ok(magic) = buf
        .get(0..4)
        .map_or(Err(()), |b| <[u8; 4]>::try_from(b).map_err(|_| ()))
    else {
        return false;
    };
    let magic_be = u32::from_be_bytes(magic);
    magic_be == goblin::mach::fat::FAT_MAGIC
        || magic_be == goblin::mach::header::MH_MAGIC_64
        || magic_be == goblin::mach::header::MH_CIGAM_64
}
