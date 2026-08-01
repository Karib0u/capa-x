//! ELF OS-detection heuristics, ported nearly line-for-line from
//! `capa/features/extractors/elf.py` (v9.4.0, see PINNED.md): OSABI, GNU
//! notes (program-header and section-header), `.ident`/`.comment` GCC
//! banners, the dynamic linker path, GLIBC symbol-versioning requirements,
//! `DT_NEEDED` library names, a stripped symbol table's leftover names, and
//! Go's embedded buildinfo/source-path/vDSO-string heuristics -- in that
//! priority order (`detect_elf_os`'s fallthrough chain).
//!
//! Unlike Python's `ELF`, which wraps a seekable file object and re-reads
//! from it lazily, this holds the whole sample in memory and slices it
//! directly by absolute file offset -- there's no separate `phbuf`/`shbuf`
//! staging copy, so out-of-bounds reads are handled per-entry (bounds
//! failure on one program/section header header is skipped, like Python's
//! per-entry `except ValueError: continue`) rather than upfront zeroing
//! `e_phnum`/`e_shnum` when the *whole* table can't be read. In practice a
//! truncated table fails per-entry anyway, so this converges to the same
//! "no headers" result for corrupt files without needing the same
//! two-stage bookkeeping.
//!
//! No panics: every field read is bounds-checked; a malformed structure
//! anywhere degrades to "this one guess/entry contributes nothing" (mirrors
//! Python's per-guess `try/except Exception` in `detect_elf_os`), and the
//! whole thing degrades to `"unknown"` if even the base ELF header doesn't
//! parse.

/// capa/features/extractors/elf.py: OS (string values used directly, since
/// this module's only job is to hand a string to `Feature::Os`).
mod os_names {
    pub const HPUX: &str = "hpux";
    pub const NETBSD: &str = "netbsd";
    pub const LINUX: &str = "linux";
    pub const HURD: &str = "hurd";
    pub const _86OPEN: &str = "86open";
    pub const SOLARIS: &str = "solaris";
    pub const AIX: &str = "aix";
    pub const IRIX: &str = "irix";
    pub const FREEBSD: &str = "freebsd";
    pub const TRU64: &str = "tru64";
    pub const MODESTO: &str = "modesto";
    pub const OPENBSD: &str = "openbsd";
    pub const OPENVMS: &str = "openvms";
    pub const NSK: &str = "nsk";
    pub const AROS: &str = "aros";
    pub const FENIXOS: &str = "fenixos";
    pub const CLOUD: &str = "cloud";
    pub const SYLLABLE: &str = "syllable";
    pub const NACL: &str = "nacl";
    pub const ANDROID: &str = "android";
    pub const DRAGONFLYBSD: &str = "dragonfly BSD";
    pub const ILLUMOS: &str = "illumos";
    pub const UNIX: &str = "unix";
}

/// capa/features/extractors/elf.py: GNU_ABI_TAG
fn gnu_abi_tag(v: u32) -> Option<&'static str> {
    Some(match v {
        0 => os_names::LINUX,
        1 => os_names::HURD,
        2 => os_names::SOLARIS,
        3 => os_names::FREEBSD,
        4 => os_names::NETBSD,
        5 => os_names::SYLLABLE,
        6 => os_names::NACL,
        _ => return None,
    })
}

/// capa/features/extractors/elf.py: ELF.OSABI
fn osabi_to_os(v: u8) -> Option<&'static str> {
    Some(match v {
        1 => os_names::HPUX,
        2 => os_names::NETBSD,
        3 => os_names::LINUX,
        4 => os_names::HURD,
        5 => os_names::_86OPEN,
        6 => os_names::SOLARIS,
        7 => os_names::AIX,
        8 => os_names::IRIX,
        9 => os_names::FREEBSD,
        10 => os_names::TRU64,
        11 => os_names::MODESTO,
        12 => os_names::OPENBSD,
        13 => os_names::OPENVMS,
        14 => os_names::NSK,
        15 => os_names::AROS,
        16 => os_names::FENIXOS,
        17 => os_names::CLOUD,
        _ => return None,
    })
}

/// capa/features/extractors/elf.py: ELF.MACHINE (only the entries actually
/// consulted by a heuristic here -- `guess_os_from_abi_versions_needed`
/// only ever compares against `"i386"`).
fn e_machine_name(v: u16) -> Option<&'static str> {
    Some(match v {
        3 => "i386",
        62 => "amd64",
        40 => "ARM",
        183 => "aarch64",
        _ => return None,
    })
}

fn align(v: usize, alignment: usize) -> usize {
    let remainder = v % alignment;
    if remainder == 0 {
        v
    } else {
        v + (alignment - remainder)
    }
}

/// port of `read_cstr`: read from `buf[offset..]`, stop at the first NUL,
/// UTF-8 decode.
fn read_cstr(buf: &[u8], offset: usize) -> Option<String> {
    let s = buf.get(offset..)?;
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    std::str::from_utf8(&s[..end]).ok().map(str::to_string)
}

fn get_u16(buf: &[u8], off: usize, be: bool) -> Option<u16> {
    let b: [u8; 2] = buf.get(off..off.checked_add(2)?)?.try_into().ok()?;
    Some(if be {
        u16::from_be_bytes(b)
    } else {
        u16::from_le_bytes(b)
    })
}
fn get_u32(buf: &[u8], off: usize, be: bool) -> Option<u32> {
    let b: [u8; 4] = buf.get(off..off.checked_add(4)?)?.try_into().ok()?;
    Some(if be {
        u32::from_be_bytes(b)
    } else {
        u32::from_le_bytes(b)
    })
}
fn get_u64(buf: &[u8], off: usize, be: bool) -> Option<u64> {
    let b: [u8; 8] = buf.get(off..off.checked_add(8)?)?.try_into().ok()?;
    Some(if be {
        u64::from_be_bytes(b)
    } else {
        u64::from_le_bytes(b)
    })
}
/// a "word": u32 on ELF32, u64 on ELF64 (used for the many fields whose
/// size depends on bitness, e.g. `sh_flags`/`sh_addr`/program header
/// fields).
fn get_word(buf: &[u8], off: usize, be: bool, bitness: u8) -> Option<u64> {
    if bitness == 32 {
        get_u32(buf, off, be).map(u64::from)
    } else {
        get_u64(buf, off, be)
    }
}

#[derive(Debug, Clone)]
struct Phdr {
    p_type: u32,
    vaddr: u64,
    memsz: u64,
    flags: u32,
    /// contents at `[p_offset, p_offset+p_filesz)`, bounds-checked.
    buf: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Shdr {
    name_idx: u32,
    sh_type: u32,
    addr: u64,
    link: u32,
    /// contents at `[sh_offset, sh_offset+sh_size)`, bounds-checked.
    buf: Vec<u8>,
}

impl Shdr {
    fn get_name(&self, elf: &Elf) -> Option<String> {
        elf.shstrtab()?.name_at(self.name_idx as usize)
    }
}

struct Elf<'a> {
    buf: &'a [u8],
    bitness: u8,
    big_endian: bool,
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
    e_shoff: u64,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

impl<'a> Elf<'a> {
    fn parse(buf: &'a [u8]) -> Option<Elf<'a>> {
        if !buf.starts_with(b"\x7fELF") {
            return None;
        }
        let ei_class = *buf.get(4)?;
        let ei_data = *buf.get(5)?;
        let bitness = match ei_class {
            1 => 32,
            2 => 64,
            _ => return None,
        };
        let big_endian = match ei_data {
            1 => false,
            2 => true,
            _ => return None,
        };

        let (e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) =
            if bitness == 32 {
                let e_phoff = get_u32(buf, 0x1c, big_endian)? as u64;
                let e_shoff = get_u32(buf, 0x20, big_endian)? as u64;
                let e_phentsize = get_u16(buf, 0x2a, big_endian)?;
                let e_phnum = get_u16(buf, 0x2c, big_endian)?;
                let e_shentsize = get_u16(buf, 0x2e, big_endian)?;
                let e_shnum = get_u16(buf, 0x30, big_endian)?;
                let e_shstrndx = get_u16(buf, 0x32, big_endian)?;
                (
                    e_phoff,
                    e_shoff,
                    e_phentsize,
                    e_phnum,
                    e_shentsize,
                    e_shnum,
                    e_shstrndx,
                )
            } else {
                let e_phoff = get_u64(buf, 0x20, big_endian)?;
                let e_shoff = get_u64(buf, 0x28, big_endian)?;
                let e_phentsize = get_u16(buf, 0x36, big_endian)?;
                let e_phnum = get_u16(buf, 0x38, big_endian)?;
                let e_shentsize = get_u16(buf, 0x3a, big_endian)?;
                let e_shnum = get_u16(buf, 0x3c, big_endian)?;
                let e_shstrndx = get_u16(buf, 0x3e, big_endian)?;
                (
                    e_phoff,
                    e_shoff,
                    e_phentsize,
                    e_phnum,
                    e_shentsize,
                    e_shnum,
                    e_shstrndx,
                )
            };

        Some(Elf {
            buf,
            bitness,
            big_endian,
            e_phoff,
            e_phentsize,
            e_phnum,
            e_shoff,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        })
    }

    fn ei_osabi(&self) -> Option<&'static str> {
        osabi_to_os(*self.buf.get(7)?)
    }

    fn e_machine(&self) -> Option<&'static str> {
        e_machine_name(get_u16(self.buf, 0x12, self.big_endian)?)
    }

    fn parse_program_header(&self, i: u16) -> Option<Phdr> {
        let off = self
            .e_phoff
            .checked_add(u64::from(i) * u64::from(self.e_phentsize))?;
        let off = usize::try_from(off).ok()?;
        let be = self.big_endian;
        let (p_type, p_offset, p_vaddr, p_filesz, p_flags, p_memsz) = if self.bitness == 32 {
            let p_type = get_u32(self.buf, off, be)?;
            let p_offset = get_u32(self.buf, off + 0x4, be)? as u64;
            let p_vaddr = get_u32(self.buf, off + 0x8, be)? as u64;
            // p_paddr at off+0xc, unused
            let p_filesz = get_u32(self.buf, off + 0x10, be)? as u64;
            let p_memsz = get_u32(self.buf, off + 0x14, be)? as u64;
            let p_flags = get_u32(self.buf, off + 0x18, be)?;
            (p_type, p_offset, p_vaddr, p_filesz, p_flags, p_memsz)
        } else {
            let p_type = get_u32(self.buf, off, be)?;
            let p_flags = get_u32(self.buf, off + 0x4, be)?;
            let p_offset = get_u64(self.buf, off + 0x8, be)?;
            let p_vaddr = get_u64(self.buf, off + 0x10, be)?;
            // p_paddr at off+0x18, unused
            let p_filesz = get_u64(self.buf, off + 0x20, be)?;
            let p_memsz = get_u64(self.buf, off + 0x28, be)?;
            (p_type, p_offset, p_vaddr, p_filesz, p_flags, p_memsz)
        };

        let start = usize::try_from(p_offset).ok()?;
        let len = usize::try_from(p_filesz).ok()?;
        let end = start.checked_add(len)?;
        let buf = self.buf.get(start..end)?.to_vec();

        Some(Phdr {
            p_type,
            vaddr: p_vaddr,
            memsz: p_memsz,
            flags: p_flags,
            buf,
        })
    }

    fn program_headers(&self) -> Vec<Phdr> {
        (0..self.e_phnum)
            .filter_map(|i| self.parse_program_header(i))
            .collect()
    }

    fn parse_section_header(&self, i: u16) -> Option<Shdr> {
        let off = self
            .e_shoff
            .checked_add(u64::from(i) * u64::from(self.e_shentsize))?;
        let off = usize::try_from(off).ok()?;
        let be = self.big_endian;
        let bn = self.bitness;
        let sh_name = get_u32(self.buf, off, be)?;
        let sh_type = get_u32(self.buf, off + 0x4, be)?;
        // layout diverges after sh_flags: elf32 packs sh_link/sh_info as
        // u32 right after sh_size, elf64 the same but at 8-byte strides.
        let (sh_addr, sh_offset, sh_size, sh_link) = if bn == 32 {
            let sh_addr = get_word(self.buf, off + 0xc, be, bn)?;
            let sh_offset = get_word(self.buf, off + 0x10, be, bn)?;
            let sh_size = get_word(self.buf, off + 0x14, be, bn)?;
            let sh_link = get_u32(self.buf, off + 0x18, be)?;
            (sh_addr, sh_offset, sh_size, sh_link)
        } else {
            let sh_addr = get_word(self.buf, off + 0x10, be, bn)?;
            let sh_offset = get_word(self.buf, off + 0x18, be, bn)?;
            let sh_size = get_word(self.buf, off + 0x20, be, bn)?;
            let sh_link = get_u32(self.buf, off + 0x28, be)?;
            (sh_addr, sh_offset, sh_size, sh_link)
        };

        let start = usize::try_from(sh_offset).ok()?;
        let len = usize::try_from(sh_size).ok()?;
        // SHT_NOBITS (.bss-like) sections have no file content -- treat as
        // empty rather than reading (or failing to read) `sh_size` bytes
        // that don't actually exist on disk.
        const SHT_NOBITS: u32 = 0x8;
        let buf = if sh_type == SHT_NOBITS {
            Vec::new()
        } else {
            let end = start.checked_add(len)?;
            self.buf.get(start..end)?.to_vec()
        };

        Some(Shdr {
            name_idx: sh_name,
            sh_type,
            addr: sh_addr,
            link: sh_link,
            buf,
        })
    }

    fn section_headers(&self) -> Vec<Shdr> {
        (0..self.e_shnum)
            .filter_map(|i| self.parse_section_header(i))
            .collect()
    }

    fn shstrtab(&self) -> Option<Shdr> {
        self.parse_section_header(self.e_shstrndx)
    }

    fn linker(&self) -> Option<String> {
        const PT_INTERP: u32 = 0x3;
        for phdr in self.program_headers() {
            if phdr.p_type == PT_INTERP {
                return read_cstr(&phdr.buf, 0);
            }
        }
        None
    }

    /// port of `versions_needed`: DLL name -> set of ABI-version strings,
    /// read from the `SHT_GNU_VERNEED` (0x6ffffffe) section.
    fn versions_needed(
        &self,
    ) -> std::collections::HashMap<String, std::collections::HashSet<String>> {
        const SHT_GNU_VERNEED: u32 = 0x6ffffffe;
        let mut out = std::collections::HashMap::new();
        for shdr in self.section_headers() {
            if shdr.sh_type != SHT_GNU_VERNEED {
                continue;
            }
            let Some(linked) = self.parse_section_header(shdr.link as u16) else {
                continue;
            };

            let mut vn_offset = 0usize;
            loop {
                let be = self.big_endian;
                let Some(vn_version) = get_u16(&shdr.buf, vn_offset, be) else {
                    break;
                };
                let Some(vn_cnt) = get_u16(&shdr.buf, vn_offset + 2, be) else {
                    break;
                };
                let Some(vn_file) = get_u32(&shdr.buf, vn_offset + 4, be) else {
                    break;
                };
                let Some(vn_aux) = get_u32(&shdr.buf, vn_offset + 8, be) else {
                    break;
                };
                let Some(vn_next) = get_u32(&shdr.buf, vn_offset + 12, be) else {
                    break;
                };
                if vn_version != 1 {
                    break;
                }

                let Some(so_name) = read_cstr(&linked.buf, vn_file as usize) else {
                    break;
                };

                let Some(mut vna_offset) = vn_offset.checked_add(vn_aux as usize) else {
                    break;
                };
                for _ in 0..vn_cnt {
                    let Some(vna_name) = get_u32(&shdr.buf, vna_offset + 8, be) else {
                        break;
                    };
                    let Some(vna_next) = get_u32(&shdr.buf, vna_offset + 12, be) else {
                        break;
                    };
                    if let Some(abi) = read_cstr(&linked.buf, vna_name as usize) {
                        out.entry(so_name.clone())
                            .or_insert_with(std::collections::HashSet::new)
                            .insert(abi);
                    }
                    if vna_next == 0 {
                        break;
                    }
                    let Some(next_offset) = vna_offset.checked_add(vna_next as usize) else {
                        break;
                    };
                    vna_offset = next_offset;
                }

                if vn_next == 0 {
                    break;
                }
                let Some(next_offset) = vn_offset.checked_add(vn_next as usize) else {
                    break;
                };
                vn_offset = next_offset;
            }
        }
        out
    }

    /// port of `dynamic_entries`: (tag, value) pairs from the `PT_DYNAMIC`
    /// segment, up to `DT_NULL`.
    fn dynamic_entries(&self) -> Vec<(u64, u64)> {
        const DT_NULL: u64 = 0x0;
        const PT_DYNAMIC: u32 = 0x2;
        let mut out = Vec::new();
        for phdr in self.program_headers() {
            if phdr.p_type != PT_DYNAMIC {
                continue;
            }
            let mut offset = 0usize;
            loop {
                let be = self.big_endian;
                let entry = if self.bitness == 32 {
                    get_u32(&phdr.buf, offset, be)
                        .zip(get_u32(&phdr.buf, offset + 4, be))
                        .map(|(t, v)| (t as u64, v as u64))
                } else {
                    get_u64(&phdr.buf, offset, be).zip(get_u64(&phdr.buf, offset + 8, be))
                };
                let Some((d_tag, d_val)) = entry else { break };
                offset += if self.bitness == 32 { 8 } else { 16 };
                if d_tag == DT_NULL {
                    break;
                }
                out.push((d_tag, d_val));
            }
        }
        out
    }

    /// port of `strtab`: the dynamic string table's bytes, located via
    /// `DT_STRTAB`/`DT_STRSZ` (a virtual address, mapped back to a file
    /// offset via whichever section header covers that address).
    fn strtab(&self) -> Option<Vec<u8>> {
        const DT_STRTAB: u64 = 0x5;
        const DT_STRSZ: u64 = 0xa;
        let entries = self.dynamic_entries();
        let strtab_addr = entries.iter().find(|(t, _)| *t == DT_STRTAB)?.1;
        let strtab_size = entries.iter().find(|(t, _)| *t == DT_STRSZ)?.1;

        let mut strtab_offset = None;
        for shdr in self.section_headers() {
            if shdr.addr != 0 && shdr.addr <= strtab_addr {
                // recompute sh_size from the parsed buf length isn't
                // reliable for SHT_NOBITS, but strtab is never NOBITS.
                let sh_size = shdr.buf.len() as u64;
                if strtab_addr < shdr.addr.checked_add(sh_size)? {
                    strtab_offset = Some(shdr);
                    break;
                }
            }
        }
        let shdr = strtab_offset?;
        let rel = (strtab_addr - shdr.addr) as usize;
        let size = strtab_size as usize;
        shdr.buf
            .get(rel..rel.checked_add(size)?)
            .map(<[u8]>::to_vec)
    }

    /// port of `needed`: `DT_NEEDED` (0x1) entries resolved through `strtab`.
    fn needed(&self) -> Vec<String> {
        const DT_NEEDED: u64 = 0x1;
        let Some(strtab) = self.strtab() else {
            return Vec::new();
        };
        self.dynamic_entries()
            .into_iter()
            .filter(|(t, _)| *t == DT_NEEDED)
            .filter_map(|(_, v)| read_cstr(&strtab, v as usize))
            .collect()
    }

    /// port of `symtab`: the first `SHT_SYMTAB` (0x2) section header, plus
    /// its linked string table section header.
    fn symtab(&self) -> Option<(Shdr, Shdr)> {
        const SHT_SYMTAB: u32 = 0x2;
        for shdr in self.section_headers() {
            if shdr.sh_type != SHT_SYMTAB {
                continue;
            }
            let strtab = self.parse_section_header(shdr.link as u16)?;
            return Some((shdr, strtab));
        }
        None
    }
}

impl Shdr {
    fn name_at(&self, offset: usize) -> Option<String> {
        read_cstr(&self.buf, offset)
    }
}

struct ABITag {
    os: &'static str,
}

/// shared by `PHNote`/`SHNote`: parse a `namesz, descsz, type_` note header
/// plus the (4-byte-aligned) name field.
struct NoteHeader {
    type_: u32,
    name: String,
    desc_offset: usize,
    descsz: u32,
}

fn parse_note(buf: &[u8], big_endian: bool) -> Option<NoteHeader> {
    let namesz = get_u32(buf, 0x0, big_endian)?;
    let descsz = get_u32(buf, 0x4, big_endian)?;
    let type_ = get_u32(buf, 0x8, big_endian)?;
    let name_offset: usize = 0xc;
    let desc_offset = name_offset.checked_add(align(usize::try_from(namesz).ok()?, 0x4))?;
    let name_end = name_offset.checked_add(usize::try_from(namesz).ok()?)?;
    let name_bytes = buf.get(name_offset..name_end)?;
    let end = name_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_bytes.len());
    let name = std::str::from_utf8(&name_bytes[..end]).ok()?.to_string();
    Some(NoteHeader {
        type_,
        name,
        desc_offset,
        descsz,
    })
}

fn note_abi_tag(note: &NoteHeader, buf: &[u8], big_endian: bool) -> Option<ABITag> {
    if note.name != "GNU" || note.descsz < 16 {
        return None;
    }
    let desc_end = note.desc_offset.checked_add(note.descsz as usize)?;
    let desc = buf.get(note.desc_offset..desc_end)?;
    let abi_tag = get_u32(desc, 0x0, big_endian)?;
    let os = gnu_abi_tag(abi_tag)?;
    Some(ABITag { os })
}

fn guess_os_from_osabi(elf: &Elf) -> Option<&'static str> {
    elf.ei_osabi()
}

fn guess_os_from_ph_notes(elf: &Elf) -> Option<&'static str> {
    const PT_NOTE: u32 = 0x4;
    for phdr in elf.program_headers() {
        if phdr.p_type != PT_NOTE {
            continue;
        }
        let Some(note) = parse_note(&phdr.buf, elf.big_endian) else {
            continue;
        };
        if note.type_ != 1 {
            continue;
        }
        match note.name.as_str() {
            "Linux" => return Some(os_names::LINUX),
            "OpenBSD" => return Some(os_names::OPENBSD),
            "NetBSD" => return Some(os_names::NETBSD),
            "FreeBSD" => return Some(os_names::FREEBSD),
            "Android" => return Some(os_names::ANDROID),
            "GNU" => {
                if let Some(tag) = note_abi_tag(&note, &phdr.buf, elf.big_endian) {
                    return Some(tag.os);
                }
            }
            _ => {}
        }
    }
    None
}

fn guess_os_from_sh_notes(elf: &Elf) -> Option<&'static str> {
    const SHT_NOTE: u32 = 0x7;
    for shdr in elf.section_headers() {
        if shdr.sh_type != SHT_NOTE {
            continue;
        }
        let Some(note) = parse_note(&shdr.buf, elf.big_endian) else {
            continue;
        };
        match note.name.as_str() {
            "Linux" => return Some(os_names::LINUX),
            "OpenBSD" => return Some(os_names::OPENBSD),
            "NetBSD" => return Some(os_names::NETBSD),
            "FreeBSD" => return Some(os_names::FREEBSD),
            "GNU" => {
                if let Some(tag) = note_abi_tag(&note, &shdr.buf, elf.big_endian) {
                    return Some(tag.os);
                }
            }
            _ => {}
        }
    }
    None
}

fn guess_os_from_ident_directive(elf: &Elf) -> Option<&'static str> {
    const SHT_PROGBITS: u32 = 0x1;
    for shdr in elf.section_headers() {
        if shdr.sh_type != SHT_PROGBITS {
            continue;
        }
        if shdr.get_name(elf).as_deref() != Some(".comment") {
            continue;
        }
        let Ok(comment) = std::str::from_utf8(&shdr.buf) else {
            continue;
        };
        if !comment.contains("GCC:") {
            continue;
        }
        if comment.contains("Debian")
            || comment.contains("Ubuntu")
            || comment.contains("Red Hat")
            || comment.contains("Alpine")
        {
            return Some(os_names::LINUX);
        } else if comment.contains("Android") {
            return Some(os_names::ANDROID);
        }
    }
    None
}

fn guess_os_from_linker(elf: &Elf) -> Option<&'static str> {
    let linker = elf.linker()?;
    if linker.contains("ld-linux") {
        Some(os_names::LINUX)
    } else {
        None
    }
}

fn guess_os_from_abi_versions_needed(elf: &Elf) -> Option<&'static str> {
    let versions_needed = elf.versions_needed();
    let any_glibc = versions_needed
        .values()
        .flatten()
        .any(|abi| abi.starts_with("GLIBC"));
    if !any_glibc {
        return None;
    }

    if elf.e_machine() != Some("i386") {
        return Some(os_names::LINUX);
    }

    match elf.linker() {
        Some(l) if l.contains("ld-linux") => Some(os_names::LINUX),
        Some(l) if l.contains("/ld.so") => Some(os_names::HURD),
        _ => Some(os_names::LINUX),
    }
}

fn guess_os_from_needed_dependencies(elf: &Elf) -> Option<&'static str> {
    for needed in elf.needed() {
        if needed.starts_with("libmachuser.so") || needed.starts_with("libhurduser.so") {
            return Some(os_names::HURD);
        }
        if needed.starts_with("libandroid.so") || needed.starts_with("liblog.so") {
            return Some(os_names::ANDROID);
        }
    }
    None
}

fn guess_os_from_symtab(elf: &Elf) -> Option<&'static str> {
    let (symtab_shdr, strtab_shdr) = elf.symtab()?;
    for sym in parse_symtab(&symtab_shdr.buf, elf.bitness, elf.big_endian) {
        let Some(name) = strtab_shdr.name_at(sym.name_offset as usize) else {
            continue;
        };
        if name.contains("linux") || name.contains("/linux/") {
            return Some(os_names::LINUX);
        }
    }
    None
}

struct Sym {
    name_offset: u32,
}

fn parse_symtab(buf: &[u8], bitness: u8, be: bool) -> Vec<Sym> {
    let entsize = if bitness == 32 { 16usize } else { 24usize };
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + entsize <= buf.len() {
        if let Some(name_offset) = get_u32(buf, off, be) {
            out.push(Sym { name_offset });
        }
        off += entsize;
    }
    out
}

fn is_go_binary(elf: &Elf) -> bool {
    for shdr in elf.section_headers() {
        let name = shdr.get_name(elf);
        if name.as_deref() == Some(".note.go.buildid") || name.as_deref() == Some(".go.buildinfo") {
            return true;
        }
    }
    false
}

fn get_go_buildinfo_data(elf: &Elf) -> Option<Vec<u8>> {
    for shdr in elf.section_headers() {
        if shdr.get_name(elf).as_deref() == Some(".go.buildinfo") {
            return Some(shdr.buf.clone());
        }
    }
    const PT_LOAD: u32 = 0x1;
    const PF_X: u32 = 1;
    const PF_W: u32 = 2;
    for phdr in elf.program_headers() {
        if phdr.p_type != PT_LOAD {
            continue;
        }
        if (phdr.flags & (PF_X | PF_W)) == PF_W {
            return Some(phdr.buf.clone());
        }
    }
    None
}

fn read_data(elf: &Elf, rva: u64, size: usize) -> Option<Vec<u8>> {
    for phdr in elf.program_headers() {
        let Some(segment_end) = phdr.vaddr.checked_add(phdr.memsz) else {
            continue;
        };
        if phdr.vaddr <= rva && rva < segment_end {
            let mut segment_data = phdr.buf.clone();
            if (segment_data.len() as u64) < phdr.memsz {
                let pad = (phdr.memsz - segment_data.len() as u64) as usize;
                segment_data.extend(std::iter::repeat_n(0u8, pad));
            }
            let segment_offset = usize::try_from(rva - phdr.vaddr).ok()?;
            let end = segment_offset.checked_add(size)?;
            return segment_data.get(segment_offset..end).map(<[u8]>::to_vec);
        }
    }
    None
}

fn read_go_slice(elf: &Elf, rva: u64) -> Option<Vec<u8>> {
    let (struct_size, is64) = if elf.bitness == 32 {
        (8usize, false)
    } else {
        (16usize, true)
    };
    let struct_buf = read_data(elf, rva, struct_size)?;
    let be = elf.big_endian;
    let (addr, length) = if is64 {
        (get_u64(&struct_buf, 0, be)?, get_u64(&struct_buf, 8, be)?)
    } else {
        (
            get_u32(&struct_buf, 0, be)? as u64,
            get_u32(&struct_buf, 4, be)? as u64,
        )
    };
    read_data(elf, addr, usize::try_from(length).ok()?)
}

const BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// port of `guess_os_from_go_buildinfo`. See the Python docstring for the
/// buildinfo blob layout; ported as directly as the byte-fiddling allows.
fn guess_os_from_go_buildinfo(elf: &Elf) -> Option<&'static str> {
    let buf = get_go_buildinfo_data(elf)?;
    let index = find_subslice(&buf, BUILDINFO_MAGIC)?;

    let hdr = buf.get(index + BUILDINFO_MAGIC.len()..index + BUILDINFO_MAGIC.len() + 2)?;
    let psize = hdr[0];
    let flags = hdr[1];
    if psize != 4 && psize != 8 {
        return None;
    }
    let is_big_endian = flags & 0b01 != 0;
    let has_inline_strings = flags & 0b10 != 0;

    const GOOS_TO_OS: &[(&[u8], Option<&str>)] = &[
        (b"aix", Some(os_names::AIX)),
        (b"android", Some(os_names::ANDROID)),
        (b"dragonfly", Some(os_names::DRAGONFLYBSD)),
        (b"freebsd", Some(os_names::FREEBSD)),
        (b"hurd", Some(os_names::HURD)),
        (b"illumos", Some(os_names::ILLUMOS)),
        (b"linux", Some(os_names::LINUX)),
        (b"netbsd", Some(os_names::NETBSD)),
        (b"openbsd", Some(os_names::OPENBSD)),
        (b"solaris", Some(os_names::SOLARIS)),
        (b"zos", Some("z/os")),
        (b"windows", None),
        (b"plan9", None),
        (b"ios", None),
        (b"darwin", None),
        (b"nacl", None),
        (b"js", None),
    ];

    if has_inline_strings {
        for (key, os) in GOOS_TO_OS {
            let mut needle = b"GOOS=".to_vec();
            needle.extend_from_slice(key);
            if find_subslice(&buf, &needle).is_some() {
                return *os;
            }
        }
        None
    } else {
        let (build_version_address, modinfo_address) = match (psize, is_big_endian) {
            (4, false) => (
                get_u32(&buf, index + 0x10, false)? as u64,
                get_u32(&buf, index + 0x14, false)? as u64,
            ),
            (8, false) => (
                get_u64(&buf, index + 0x10, false)?,
                get_u64(&buf, index + 0x18, false)?,
            ),
            (4, true) => (
                get_u32(&buf, index + 0x10, true)? as u64,
                get_u32(&buf, index + 0x14, true)? as u64,
            ),
            (8, true) => (
                get_u64(&buf, index + 0x10, true)?,
                get_u64(&buf, index + 0x18, true)?,
            ),
            _ => return None,
        };
        let _build_version = read_go_slice(elf, build_version_address);

        let mut modinfo = read_go_slice(elf, modinfo_address)?;
        if modinfo.is_empty() {
            return None;
        }
        if modinfo.len() >= 0x11 && modinfo[modinfo.len() - 0x11] == b'\n' {
            let end = modinfo.len().saturating_sub(0x10);
            if modinfo.len() >= 0x10 && end >= 0x10 {
                modinfo = modinfo[0x10..end].to_vec();
            }
        }

        for (key, os) in GOOS_TO_OS {
            let mut needle = b"GOOS=".to_vec();
            needle.extend_from_slice(key);
            if find_subslice(&modinfo, &needle).is_some() {
                return *os;
            }
        }
        None
    }
}

fn guess_os_from_go_source(elf: &Elf) -> Option<&'static str> {
    if !is_go_binary(elf) {
        return None;
    }

    const OS_FILENAME_TO_OS: &[(&str, &str)] = &[
        ("aix", os_names::AIX),
        ("android", os_names::ANDROID),
        ("dragonfly", os_names::DRAGONFLYBSD),
        ("freebsd", os_names::FREEBSD),
        ("freebsd2", os_names::FREEBSD),
        ("freebsd_", os_names::FREEBSD),
        ("illumos", os_names::ILLUMOS),
        ("linux", os_names::LINUX),
        ("netbsd", os_names::NETBSD),
        ("only_solaris", os_names::SOLARIS),
        ("openbsd", os_names::OPENBSD),
        ("solaris", os_names::SOLARIS),
        ("unix_nonlinux", os_names::UNIX),
    ];
    const NEEDLE_OS: &[u8] = b"/src/runtime/os_";
    for phdr in elf.program_headers() {
        let Some(index) = find_subslice(&phdr.buf, NEEDLE_OS) else {
            continue;
        };
        let start = index + NEEDLE_OS.len();
        let rest = &phdr.buf[start..(start + 32).min(phdr.buf.len())];
        let end = find_subslice(rest, b".go").unwrap_or(rest.len());
        let Ok(filename) = std::str::from_utf8(&rest[..end]) else {
            continue;
        };
        for (prefix, os) in OS_FILENAME_TO_OS {
            if filename.starts_with(prefix) {
                return Some(os);
            }
        }
    }

    const RT0_FILENAME_TO_OS: &[(&str, &str)] = &[
        ("aix", os_names::AIX),
        ("android", os_names::ANDROID),
        ("dragonfly", os_names::DRAGONFLYBSD),
        ("freebsd", os_names::FREEBSD),
        ("illumos", os_names::ILLUMOS),
        ("linux", os_names::LINUX),
        ("netbsd", os_names::NETBSD),
        ("openbsd", os_names::OPENBSD),
        ("solaris", os_names::SOLARIS),
    ];
    const NEEDLE_RT0: &[u8] = b"/src/runtime/rt0_";
    for phdr in elf.program_headers() {
        let Some(index) = find_subslice(&phdr.buf, NEEDLE_RT0) else {
            continue;
        };
        let start = index + NEEDLE_RT0.len();
        let rest = &phdr.buf[start..(start + 32).min(phdr.buf.len())];
        let end = find_subslice(rest, b".s").unwrap_or(rest.len());
        let Ok(filename) = std::str::from_utf8(&rest[..end]) else {
            continue;
        };
        for (prefix, os) in RT0_FILENAME_TO_OS {
            if filename.starts_with(prefix) {
                return Some(os);
            }
        }
    }

    None
}

/// capa/features/extractors/elf.py: `guess_os_from_vdso_strings`'s
/// (symbol, version) pairs -- the arch column is documentation-only
/// upstream and dropped here too.
const VDSO_PAIRS: &[(&[u8], &[u8])] = &[
    (b"__vdso_gettimeofday", b"LINUX_2.6"),
    (b"__vdso_clock_gettime", b"LINUX_2.6"),
    (b"__kernel_rt_sigreturn", b"LINUX_2.6.39"),
    (b"__kernel_gettimeofday", b"LINUX_2.6.39"),
    (b"__kernel_clock_gettime", b"LINUX_2.6.39"),
    (b"__kernel_clock_getres", b"LINUX_2.6.39"),
    (b"__kernel_sigtramp", b"LINUX_2.5"),
    (b"__kernel_syscall_via_break", b"LINUX_2.5"),
    (b"__kernel_syscall_via_epc", b"LINUX_2.5"),
    (b"__kernel_clock_getres", b"LINUX_2.6.15"),
    (b"__kernel_clock_gettime", b"LINUX_2.6.15"),
    (b"__kernel_clock_gettime64", b"LINUX_5.11"),
    (b"__kernel_datapage_offset", b"LINUX_2.6.15"),
    (b"__kernel_get_syscall_map", b"LINUX_2.6.15"),
    (b"__kernel_get_tbfreq", b"LINUX_2.6.15"),
    (b"__kernel_getcpu", b"LINUX_2.6.15"),
    (b"__kernel_gettimeofday", b"LINUX_2.6.15"),
    (b"__kernel_sigtramp_rt32", b"LINUX_2.6.15"),
    (b"__kernel_sigtramp32", b"LINUX_2.6.15"),
    (b"__kernel_sync_dicache", b"LINUX_2.6.15"),
    (b"__kernel_sync_dicache_p5", b"LINUX_2.6.15"),
    (b"__kernel_sigtramp_rt64", b"LINUX_2.6.15"),
    (b"__vdso_rt_sigreturn", b"LINUX_4.15"),
    (b"__vdso_getcpu", b"LINUX_4.15"),
    (b"__vdso_flush_icache", b"LINUX_4.15"),
    (b"__kernel_sigreturn", b"LINUX_2.6.29"),
    (b"__kernel_vsyscall", b"LINUX_2.6"),
    (b"__vdso_time", b"LINUX_2.6"),
];

fn guess_os_from_vdso_strings(elf: &Elf) -> Option<&'static str> {
    for phdr in elf.program_headers() {
        for (symbol, version) in VDSO_PAIRS {
            if find_subslice(&phdr.buf, symbol).is_some()
                && find_subslice(&phdr.buf, version).is_some()
            {
                return Some(os_names::LINUX);
            }
        }
    }
    None
}

/// port of `detect_elf_os`: run every heuristic (each independently
/// fallible -- a parse failure inside one just makes that guess `None`,
/// mirroring Python's per-guess `try/except`), then take the first
/// non-`None` result in the documented priority order. Returns `"unknown"`
/// if nothing matched, or if the base ELF header itself doesn't parse.
pub fn detect_elf_os(buf: &[u8]) -> String {
    let Some(elf) = Elf::parse(buf) else {
        return "unknown".to_string();
    };

    guess_os_from_osabi(&elf)
        .or_else(|| guess_os_from_ph_notes(&elf))
        .or_else(|| guess_os_from_sh_notes(&elf))
        .or_else(|| guess_os_from_linker(&elf))
        .or_else(|| guess_os_from_abi_versions_needed(&elf))
        .or_else(|| guess_os_from_needed_dependencies(&elf))
        .or_else(|| guess_os_from_symtab(&elf))
        .or_else(|| guess_os_from_go_buildinfo(&elf))
        .or_else(|| guess_os_from_go_source(&elf))
        .or_else(|| guess_os_from_ident_directive(&elf))
        .or_else(|| guess_os_from_vdso_strings(&elf))
        .unwrap_or("unknown")
        .to_string()
}

// ---------------------------------------------------------------------
// dynamic-segment symbol table resolution, for ELF import extraction
// (elf.rs's `extract_file_import_names`).
// ---------------------------------------------------------------------
//
// Ported from `pyelftools`' `elftools.elf.dynamic.DynamicSegment.
// num_symbols`/`iter_symbols` (v0.32, vendored into `.venv`) -- NOT from
// `capa`'s own source, which just calls into pyelftools. This is the
// dynamic-segment-only symbol enumeration `elffile.py`'s file-only
// `ElfFeatureExtractor.extract_file_import_names` actually uses: unlike
// `goblin::elf::Elf::dynsyms` (whose own symbol count comes from a
// different, more complete heuristic -- effectively `max(reloc r_sym) + 1`
// as a floor under the hash-table-derived count), pyelftools trusts
// *only* the hash table (`DT_GNU_HASH` preferred, else `DT_HASH`, else a
// "nearest pointer above `DT_SYMTAB`" byte-range guess) to bound the
// table -- which can, for some binaries, under-report relative to what
// the relocations actually reference (confirmed empirically against the
// corpus: a GNU hash table whose bucket-chain walk terminates below the
// highest symbol index any relocation names). Matching this exactly
// (rather than a more "complete" scan) is required for import-name
// parity with the pinned Python capa.

/// capa/features/extractors/elf.py doesn't define these DT_* tags (they're
/// only needed here); values from the ELF/GNU ABI.
mod dt {
    pub const SYMTAB: u64 = 0x6;
    pub const HASH: u64 = 0x4;
    pub const GNU_HASH: u64 = 0x6ffffef5;
}

struct FullSym {
    st_name: u32,
    st_value: u64,
    st_shndx: u16,
    st_info: u8,
}

fn parse_full_sym(buf: &[u8], off: usize, bitness: u8, be: bool) -> Option<FullSym> {
    if bitness == 32 {
        let st_name = get_u32(buf, off, be)?;
        let st_value = get_u32(buf, off + 4, be)? as u64;
        let st_info = *buf.get(off + 12)?;
        let st_shndx = get_u16(buf, off + 14, be)?;
        Some(FullSym {
            st_name,
            st_value,
            st_shndx,
            st_info,
        })
    } else {
        let st_name = get_u32(buf, off, be)?;
        let st_info = *buf.get(off + 4)?;
        let st_shndx = get_u16(buf, off + 6, be)?;
        let st_value = get_u64(buf, off + 8, be)?;
        Some(FullSym {
            st_name,
            st_value,
            st_shndx,
            st_info,
        })
    }
}

/// port of `GNUHashTable.get_number_of_symbols`.
fn gnu_hash_num_symbols(elf: &Elf, vaddr: u64) -> Option<u64> {
    let be = elf.big_endian;
    let xwordsize: u64 = if elf.bitness == 32 { 4 } else { 8 };

    let header = read_data(elf, vaddr, 16)?;
    let nbuckets = get_u32(&header, 0, be)?;
    let symoffset = get_u32(&header, 4, be)?;
    let bloom_size = get_u32(&header, 8, be)?;

    let buckets_vaddr = vaddr
        .checked_add(16)?
        .checked_add(u64::from(bloom_size).checked_mul(xwordsize)?)?;
    let buckets_len = usize::try_from(nbuckets).ok()?.checked_mul(4)?;
    let buckets_bytes = read_data(elf, buckets_vaddr, buckets_len)?;

    let mut max_idx: Option<u32> = None;
    for i in 0..nbuckets as usize {
        let v = get_u32(&buckets_bytes, i * 4, be)?;
        max_idx = Some(max_idx.map_or(v, |m| m.max(v)));
    }
    let mut max_idx = max_idx?;
    if max_idx < symoffset {
        return Some(u64::from(symoffset));
    }

    let chain_pos = buckets_vaddr.checked_add(u64::from(nbuckets) * 4)?;
    // guard against a corrupt/adversarial chain that never sets the
    // terminator bit -- real hash chains are bounded by the symbol count,
    // which is never anywhere near this large.
    #[allow(clippy::explicit_counter_loop)]
    for _ in 0..10_000_000u32 {
        let word_vaddr = chain_pos.checked_add(u64::from(max_idx - symoffset) * 4)?;
        let word = read_data(elf, word_vaddr, 4)?;
        let cur_hash = get_u32(&word, 0, be)?;
        if cur_hash & 1 != 0 {
            return Some(u64::from(max_idx) + 1);
        }
        max_idx = max_idx.checked_add(1)?;
    }
    None
}

/// port of `ELFHashTable.get_number_of_symbols` (just `nchains`).
fn elf_hash_num_symbols(elf: &Elf, vaddr: u64) -> Option<u64> {
    let header = read_data(elf, vaddr, 8)?;
    let nchains = get_u32(&header, 4, elf.big_endian)?;
    Some(u64::from(nchains))
}

/// port of `DynamicSegment._num_symbols`'s final fallback: the nearest
/// other dynamic-tag value above `DT_SYMTAB`'s, else the end of whichever
/// `PT_LOAD` segment contains it (last match wins, matching Python's
/// non-short-circuiting loop).
fn nearest_ptr_num_symbols(
    elf: &Elf,
    entries: &[(u64, u64)],
    symtab_vaddr: u64,
    entsize: u64,
) -> Option<u64> {
    let mut nearest: Option<u64> = None;
    for &(_tag, val) in entries {
        if val > symtab_vaddr && nearest.is_none_or(|n| val < n) {
            nearest = Some(val);
        }
    }
    if let Some(n) = nearest {
        return Some((n - symtab_vaddr) / entsize);
    }

    const PT_LOAD: u32 = 0x1;
    let mut end_of_segment: Option<u64> = None;
    for phdr in elf.program_headers() {
        if phdr.p_type != PT_LOAD {
            continue;
        }
        let start = phdr.vaddr;
        let end = start.checked_add(phdr.buf.len() as u64)?;
        if start <= symtab_vaddr && symtab_vaddr <= end {
            end_of_segment = Some(end);
        }
    }
    end_of_segment.map(|end| (end - symtab_vaddr) / entsize)
}

/// port of `DynamicSegment.num_symbols` + `.iter_symbols`, filtered exactly
/// like `elffile.py`'s `extract_file_import_names`'s first loop (the one
/// that builds `symbol_name_by_index`): named, `STT_FUNC`/`STT_OBJECT`/
/// `STT_GNU_IFUNC`, undefined (`st_value == 0`, `st_shndx == SHN_UNDEF`).
pub(crate) fn dynamic_import_symbol_names(buf: &[u8]) -> std::collections::HashMap<usize, String> {
    let mut out = std::collections::HashMap::new();
    let Some(elf) = Elf::parse(buf) else {
        return out;
    };

    let entries = elf.dynamic_entries();
    let get = |tag: u64| entries.iter().find(|(t, _)| *t == tag).map(|(_, v)| *v);

    let Some(symtab_vaddr) = get(dt::SYMTAB) else {
        return out;
    };
    let entsize: u64 = if elf.bitness == 32 { 16 } else { 24 };

    let num_syms = if let Some(gnu_hash_vaddr) = get(dt::GNU_HASH) {
        gnu_hash_num_symbols(&elf, gnu_hash_vaddr)
    } else if let Some(hash_vaddr) = get(dt::HASH) {
        elf_hash_num_symbols(&elf, hash_vaddr)
    } else {
        nearest_ptr_num_symbols(&elf, &entries, symtab_vaddr, entsize)
    };
    let Some(num_syms) = num_syms else { return out };

    let Some(num_syms) = usize::try_from(num_syms).ok() else {
        return out;
    };
    let Some(symtab_len) = num_syms.checked_mul(entsize as usize) else {
        return out;
    };
    let Some(symtab_bytes) = read_data(&elf, symtab_vaddr, symtab_len) else {
        return out;
    };
    let Some(strtab_bytes) = elf.strtab() else {
        return out;
    };

    const STT_FUNC: u8 = 2;
    const STT_OBJECT: u8 = 1;
    const STT_GNU_IFUNC: u8 = 10;
    const SHN_UNDEF: u16 = 0;

    for i in 0..num_syms {
        let Some(off) = i.checked_mul(entsize as usize) else {
            break;
        };
        let Some(sym) = parse_full_sym(&symtab_bytes, off, elf.bitness, elf.big_endian) else {
            continue;
        };
        if sym.st_name == 0 {
            continue;
        }
        let sym_type = sym.st_info & 0xf;
        if !matches!(sym_type, STT_FUNC | STT_OBJECT | STT_GNU_IFUNC) {
            continue;
        }
        if sym.st_value != 0 {
            continue;
        }
        if sym.st_shndx != SHN_UNDEF {
            continue;
        }
        let Some(name) = read_cstr(&strtab_bytes, sym.st_name as usize) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        out.insert(i, name);
    }

    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn garbage_input_yields_unknown() {
        assert_eq!(detect_elf_os(b"not an elf file"), "unknown");
        assert_eq!(detect_elf_os(b""), "unknown");
    }

    #[test]
    fn minimal_elf_header_only_is_unknown_without_further_hints() {
        // ELFCLASS64/ELFDATA2LSB, everything else zeroed -- osabi field
        // (byte 7) is 0 (SYSV, not in our OSABI map), no program/section
        // headers at all.
        let mut buf = vec![0u8; 0x40];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // little-endian
        assert_eq!(detect_elf_os(&buf), "unknown");
    }
}
