#!/usr/bin/env python3
"""
Derives capa-x's Mach-O malformed-input corpus by direct byte
patching of the clean fixtures `build.sh` just built. Run by build.sh, not
directly (needs thin-x86_64-exe / fat-x86_64-arm64-exe to already exist in
this directory).

Each function patches one specific, well-understood structural field --
never random-byte fuzzing -- so every malformed fixture exercises exactly
the defect its name says, and `MANIFEST.md` can describe each one
precisely rather than "some bytes changed".
"""
from __future__ import annotations

import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
LC_SEGMENT_64 = 0x19


def read_mach_header_64(data: bytes, off: int = 0) -> dict:
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
        "<IiiIIIII", data, off
    )
    assert magic == MH_MAGIC_64, f"expected MH_MAGIC_64, got {magic:#x}"
    return {
        "magic": magic,
        "cputype": cputype,
        "cpusubtype": cpusubtype,
        "filetype": filetype,
        "ncmds": ncmds,
        "sizeofcmds": sizeofcmds,
        "flags": flags,
        "reserved": reserved,
        "header_size": 32,
    }


def iter_load_commands(data: bytes, base: int, header: dict):
    """Yields (offset, cmd, cmdsize) for each of the header's load commands."""
    off = base + header["header_size"]
    for _ in range(header["ncmds"]):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        yield off, cmd, cmdsize
        off += cmdsize


def find_segments(data: bytes, base: int, header: dict) -> list[dict]:
    segments = []
    for off, cmd, cmdsize in iter_load_commands(data, base, header):
        if cmd != LC_SEGMENT_64:
            continue
        (
            segname,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            nsects,
            flags,
        ) = struct.unpack_from("<16sQQQQiiII", data, off + 8)
        segments.append(
            {
                "offset": off,
                "cmdsize": cmdsize,
                "segname": segname.rstrip(b"\0").decode(),
                "vmaddr": vmaddr,
                "vmsize": vmsize,
                "fileoff": fileoff,
                "filesize": filesize,
            }
        )
    return segments


def patch_u64(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", buf, offset, value)


def patch_u32(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buf, offset, value)


def truncated_load_commands(source: Path, dest: Path) -> str:
    """Cuts the file off partway through its load commands -- a loader
    that trusts `ncmds`/`sizeofcmds` without checking the file is long
    enough will read past EOF."""
    data = source.read_bytes()
    header = read_mach_header_64(data)
    cutoff = header["header_size"] + header["sizeofcmds"] // 2
    dest.write_bytes(data[:cutoff])
    return f"truncated at byte {cutoff} (halfway through the load commands; file was {len(data)} bytes)"


def bad_ncmds(source: Path, dest: Path) -> str:
    """Doubles `ncmds` without changing `sizeofcmds` or adding commands, so
    parsing the declared command count walks off the end of the real
    command list."""
    data = bytearray(source.read_bytes())
    header = read_mach_header_64(bytes(data))
    new_ncmds = header["ncmds"] * 2
    patch_u32(data, 16, new_ncmds)  # mach_header_64.ncmds is at offset 16
    dest.write_bytes(data)
    return f"ncmds patched {header['ncmds']} -> {new_ncmds} (sizeofcmds unchanged at {header['sizeofcmds']})"


def overlapping_segments(source: Path, dest: Path) -> str:
    """Makes one `LC_SEGMENT_64`'s file range overlap an earlier one's --
    picks the first two segments with a *non-zero* file range (skips
    `__PAGEZERO`, which is `[0, 0)` on disk by design and can't overlap
    anything)."""
    data = bytearray(source.read_bytes())
    header = read_mach_header_64(bytes(data))
    segments = find_segments(bytes(data), 0, header)
    with_content = [s for s in segments if s["filesize"] > 0]
    assert len(with_content) >= 2, "fixture needs at least two non-empty LC_SEGMENT_64 commands"
    first, second = with_content[0], with_content[1]
    # move the second segment's fileoff to land inside the first segment's
    # file range, keeping its size the same.
    new_fileoff = first["fileoff"] + max(1, first["filesize"] // 2)
    fileoff_field_offset = second["offset"] + 8 + 16 + 8 + 8  # cmd,cmdsize,segname,vmaddr,vmsize
    patch_u64(data, fileoff_field_offset, new_fileoff)
    dest.write_bytes(data)
    return (
        f"{second['segname']!r} fileoff patched {second['fileoff']:#x} -> {new_fileoff:#x}, "
        f"landing inside {first['segname']!r}'s file range "
        f"[{first['fileoff']:#x}, {first['fileoff'] + first['filesize']:#x})"
    )


def filesize_gt_vmsize(source: Path, dest: Path) -> str:
    """Sets a segment's `filesize` larger than its `vmsize` -- ECMA-worthy
    for Mach-O too: `filesize` must never exceed `vmsize` (the mapped
    region), and a loader that maps `vmsize` bytes but reads `filesize`
    from the file can over-read."""
    data = bytearray(source.read_bytes())
    header = read_mach_header_64(bytes(data))
    segments = find_segments(bytes(data), 0, header)
    target = next(s for s in segments if s["filesize"] > 0)
    filesize_field_offset = target["offset"] + 8 + 16 + 8 + 8 + 8  # + fileoff
    new_filesize = target["vmsize"] + 0x10000
    patch_u64(data, filesize_field_offset, new_filesize)
    dest.write_bytes(data)
    return (
        f"{target['segname']!r} filesize patched {target['filesize']:#x} -> {new_filesize:#x} "
        f"(vmsize stays {target['vmsize']:#x})"
    )


def slice_offset_past_eof(source: Path, dest: Path) -> str:
    """Patches a fat (universal) binary's second `fat_arch` entry to claim
    an offset past the end of the file."""
    data = bytearray(source.read_bytes())
    magic = struct.unpack_from(">I", data, 0)[0]
    assert magic == FAT_MAGIC, f"expected a fat binary (magic {FAT_MAGIC:#x}), got {magic:#x}"
    nfat_arch = struct.unpack_from(">I", data, 4)[0]
    assert nfat_arch >= 2, "fixture needs at least two fat_arch entries"
    # fat_header is 8 bytes (big-endian); each fat_arch is 20 bytes:
    # cputype, cpusubtype, offset, size, align (all uint32, big-endian).
    second_arch_offset = 8 + 20  # start of the second fat_arch entry
    offset_field = second_arch_offset + 8  # cputype, cpusubtype, then offset
    old_offset = struct.unpack_from(">I", data, offset_field)[0]
    new_offset = len(data) + 0x1000
    struct.pack_into(">I", data, offset_field, new_offset)
    dest.write_bytes(data)
    return f"second fat_arch.offset patched {old_offset:#x} -> {new_offset:#x} (file is {len(data)} bytes)"


def main() -> None:
    malformed_dir = HERE / "malformed"
    malformed_dir.mkdir(exist_ok=True)

    entries: list[tuple[str, str]] = []
    base = HERE / "thin-x86_64-exe"
    fat = HERE / "fat-x86_64-arm64-exe"

    for name, fn, source in [
        ("truncated-load-commands", truncated_load_commands, base),
        ("bad-ncmds", bad_ncmds, base),
        ("overlapping-segments", overlapping_segments, base),
        ("filesize-gt-vmsize", filesize_gt_vmsize, base),
        ("slice-offset-past-eof", slice_offset_past_eof, fat),
    ]:
        dest = malformed_dir / name
        description = fn(source, dest)
        entries.append((name, description))
        print(f"{name}: {description}")

    (malformed_dir / "DESCRIPTIONS.md").write_text(
        "# Malformed Mach-O fixtures\n\n"
        "Generated by `../patch_malformed.py`; each row's \"derived from\" is a base fixture in the parent directory.\n\n"
        "| Fixture | Patch |\n|---|---|\n"
        + "\n".join(f"| `{name}` | {desc} |" for name, desc in entries)
        + "\n"
    )


if __name__ == "__main__":
    main()
