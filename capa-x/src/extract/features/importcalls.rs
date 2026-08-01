//! Port of pinned Vivisect 1.3.2 `vivisect/analysis/i386/importcalls.py`.
//!
//! The pass finds *code* that ordinary recursive descent never reaches, by
//! looking for the byte encoding of `call [<import>]` sitting in memory no
//! earlier analysis has defined: a dword whose value is an import location,
//! with `ff 15` immediately in front of it.
//!
//! Upstream's own words: "looks for likely *code* pointers by checking for
//! them to be pointing to imports and having `call [deref]` bytes before
//! them."
//!
//! What it makes is deliberately *not* a function. Upstream calls
//! `vw.makeCode(va - 2)`, so the recovered run stays loose code with no owning
//! function; only the direct call targets reached while flowing through it
//! become functions. capa-x reproduces that split -- [`fragment_starts`]
//! returns flow starts, and the caller walks them for their call targets
//! without registering a function at the start itself.
//!
//! Registered for i386 workspaces only (there is no amd64 counterpart in
//! pinned vivisect), which is why [`fragment_starts`] returns nothing for
//! anything but 32-bit x86.

use super::image::{Architecture, LoadedImage};

/// Pointer size of the only architecture upstream registers this pass for.
/// Upstream reads `vw.psize` bytes per candidate
/// (`vivisect/__init__.py::findPointers`).
const PTR_SIZE: usize = 4;

/// `call dword ptr [imm32]` -- the two opcode bytes upstream tests for
/// immediately before the candidate pointer
/// (`vivisect/analysis/i386/importcalls.py:26`).
const CALL_INDIRECT: [u8; 2] = [0xff, 0x15];

/// Flow starts for [`vivisect/analysis/i386/importcalls.py`]'s `makeCode` sites,
/// in ascending address order.
///
/// `defined_end` reports whether an address is already covered by a defined
/// location and, if so, where that location ends -- upstream's `getLocation`
/// jump-past-the-location step. capa-x has no location database, so its
/// caller passes instruction coverage, which is the part of vivisect's
/// location set this scan can actually collide with.
pub fn fragment_starts(image: &LoadedImage, defined_end: &dyn Fn(u64) -> Option<u64>) -> Vec<u64> {
    if image.architecture != Architecture::X86 {
        return Vec::new();
    }

    let mut starts = Vec::new();
    for section in &image.sections {
        // `findPointers` skips `MM_UNINIT` maps: their bytes are loader zero
        // fill, not file content.
        if image.is_uninitialized(section.address) {
            continue;
        }
        let Ok(virtual_size) = usize::try_from(section.virtual_size) else {
            continue;
        };
        let Some(bytes) = image.bytes_at(section.address, virtual_size) else {
            continue;
        };
        // Upstream's bound is `maxsize = len(bytes) - size` with the loop
        // condition `offset + size < maxsize`, i.e. the last candidate starts
        // at `len - 2 * PTR_SIZE - 1`.
        let Some(limit) = bytes.len().checked_sub(2 * PTR_SIZE) else {
            continue;
        };

        let mut offset = 0usize;
        while offset < limit {
            let Some(va) = section.address.checked_add(offset as u64) else {
                break;
            };
            // A defined location is not undiscovered space; resume after it.
            if let Some(end) = defined_end(va) {
                let Some(next) = end.checked_sub(section.address) else {
                    break;
                };
                let Ok(next) = usize::try_from(next) else {
                    break;
                };
                // `getLocation` always reports a location containing `va`, so
                // its end is past `va`; guard anyway so a caller that reports
                // otherwise cannot spin here.
                offset = next.max(offset.saturating_add(1));
                continue;
            }
            let Some(raw) = bytes
                .get(offset..offset.saturating_add(PTR_SIZE))
                .and_then(|slice| <[u8; PTR_SIZE]>::try_from(slice).ok())
            else {
                break;
            };
            let target = u64::from(u32::from_le_bytes(raw));
            if !is_valid_pointer(image, target) {
                offset = offset.saturating_add(1);
                continue;
            }
            // `importcalls.analyze`: the pointer must resolve to an *import*
            // location, and the two bytes before it must encode `call [..]`.
            // `offset < 2` is upstream's own guard against reading before the
            // start of the memory map.
            if offset >= 2
                && image.import_locations.contains_key(&target)
                && bytes.get(offset - 2..offset) == Some(&CALL_INDIRECT)
            {
                if let Some(start) = va.checked_sub(2) {
                    starts.push(start);
                }
            }
            // A recognised pointer consumes its whole width, so bytes inside
            // it are never themselves candidates.
            offset = offset.saturating_add(PTR_SIZE);
        }
    }

    starts.sort_unstable();
    starts.dedup();
    starts
}

/// `VivWorkspace.isValidPointer`: the value lands inside some memory map.
fn is_valid_pointer(image: &LoadedImage, address: u64) -> bool {
    image.section_containing(address).is_some()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::extract::image::{ImageFormat, MappedSection, Permissions};

    const CODE: u64 = 0x1000;
    const IAT: u64 = 0x2000;

    /// One executable section holding `body`, plus a data section standing in
    /// for the IAT, with `IAT` registered as an import location.
    fn image_with(architecture: Architecture, body: &[u8]) -> LoadedImage {
        let mut bytes = body.to_vec();
        bytes.resize(0x100, 0);
        // The IAT slot's own contents are irrelevant -- only that `IAT` is a
        // mapped address carrying an import location.
        bytes.extend_from_slice(&[0u8; 0x10]);
        LoadedImage::for_test(
            ImageFormat::Pe,
            architecture,
            CODE,
            vec![
                MappedSection {
                    name: ".text".to_string(),
                    address: CODE,
                    virtual_size: 0x100,
                    file_offset: 0,
                    file_size: 0x100,
                    permissions: Permissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                },
                MappedSection {
                    name: ".idata".to_string(),
                    address: IAT,
                    virtual_size: 0x10,
                    file_offset: 0x100,
                    file_size: 0x10,
                    permissions: Permissions {
                        read: true,
                        write: true,
                        execute: false,
                    },
                },
            ],
            BTreeMap::new(),
            bytes,
        )
        .with_import_location(IAT, "kernel32.CreateFileA")
    }

    fn undefined(_address: u64) -> Option<u64> {
        None
    }

    /// `call dword ptr [IAT]` at `CODE + offset`, padded to `offset`.
    fn call_import_at(offset: usize) -> Vec<u8> {
        let mut body = vec![0u8; offset];
        body.extend_from_slice(&CALL_INDIRECT);
        body.extend_from_slice(&(IAT as u32).to_le_bytes());
        body
    }

    #[test]
    fn finds_call_through_import_slot() {
        let image = image_with(Architecture::X86, &call_import_at(0x20));
        assert_eq!(
            fragment_starts(&image, &undefined),
            vec![CODE.saturating_add(0x20)]
        );
    }

    #[test]
    fn ignores_pointer_that_is_not_an_import() {
        // Same encoding, but the dword points at plain mapped code rather than
        // an import location: upstream requires `LOC_IMPORT`.
        let mut body = vec![0u8; 0x20];
        body.extend_from_slice(&CALL_INDIRECT);
        body.extend_from_slice(&(CODE as u32).to_le_bytes());
        let image = image_with(Architecture::X86, &body);
        assert!(fragment_starts(&image, &undefined).is_empty());
    }

    #[test]
    fn ignores_import_pointer_without_call_prefix() {
        // A plain IAT-pointer dword (an ordinary data reference) is not code.
        let mut body = vec![0u8; 0x20];
        body.extend_from_slice(&[0x90, 0x90]);
        body.extend_from_slice(&(IAT as u32).to_le_bytes());
        let image = image_with(Architecture::X86, &body);
        assert!(fragment_starts(&image, &undefined).is_empty());
    }

    #[test]
    fn skips_candidates_inside_defined_locations() {
        let image = image_with(Architecture::X86, &call_import_at(0x20));
        let covered = |address: u64| {
            // Stand in for an instruction spanning the whole `call [IAT]`.
            (CODE.saturating_add(0x20)..CODE.saturating_add(0x28))
                .contains(&address)
                .then_some(CODE.saturating_add(0x28))
        };
        assert!(fragment_starts(&image, &covered).is_empty());
    }

    #[test]
    fn is_registered_for_i386_only() {
        // Pinned vivisect has no amd64 counterpart to
        // `vivisect/analysis/i386/importcalls.py`.
        let image = image_with(Architecture::X64, &call_import_at(0x20));
        assert!(fragment_starts(&image, &undefined).is_empty());
    }

    #[test]
    fn a_recognised_pointer_consumes_its_whole_width() {
        // Two `call [IAT]` encodings back to back: the second must still be
        // found, i.e. the scan resumes exactly after the first pointer rather
        // than mid-way through it.
        let mut body = call_import_at(0x20);
        body.extend_from_slice(&CALL_INDIRECT);
        body.extend_from_slice(&(IAT as u32).to_le_bytes());
        let image = image_with(Architecture::X86, &body);
        assert_eq!(
            fragment_starts(&image, &undefined),
            vec![CODE.saturating_add(0x20), CODE.saturating_add(0x26)]
        );
    }
}
