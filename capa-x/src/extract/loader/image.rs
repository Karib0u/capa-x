//! The format-neutral loaded-image and instruction-decode model.
//!
//! PE sections and ELF `PT_LOAD` segments are represented using the same
//! address, file-backing, and permission fields. Recovery code can therefore
//! stay independent of the container format and cannot read beyond a mapped
//! executable region.

use std::collections::BTreeMap;

use goblin::elf::header::{EM_386, EM_AARCH64, EM_X86_64, ET_DYN};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use goblin::elf::Elf;
use goblin::mach::constants::cputype::CPU_TYPE_X86_64;
use goblin::mach::constants::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use goblin::mach::fat::{FatArch, FAT_MAGIC, SIZEOF_FAT_ARCH};
use goblin::mach::header::{MH_CIGAM_64, MH_MAGIC_64};
use goblin::mach::load_command::{CommandVariant, SIZEOF_SECTION_64, SIZEOF_SEGMENT_COMMAND_64};
use goblin::mach::MachO;
use goblin::pe::header::{COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64};
use goblin::pe::options::{ParseMode, ParseOptions};
use goblin::pe::section_table::{
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Instruction};

use super::helpers::generate_symbols;

const MAX_INSN_LEN: usize = 15;
const DELAY_DESCRIPTOR_SIZE: usize = 32;
const MAX_DELAY_DESCRIPTORS: usize = 4_096;
const MAX_DELAY_IMPORTS: usize = 65_536;
const PE_SECTION_HEADER_SIZE: u64 = 40;
const PE_COFF_HEADER_SIZE: u64 = 20;
const PE_SIGNATURE_SIZE: u64 = 4;
const MAX_MAPPED_IMAGE_BYTES: usize = 256 * 1024 * 1024;
// `capa/loader.py:get_workspace` delegates ET_DYN placement to the pinned
// Vivisect loader, which uses this base for PIEs and shared objects.
const VIV_ELF_DYN_BASE: u64 = 0x0200_0000;
// Native AArch64 ELF has no Vivisect baseline to reproduce -- its oracle is
// Ghidra's BinExport2, and Ghidra's own default AArch64 ET_DYN image base
// is this value, not `VIV_ELF_DYN_BASE`. Confirmed empirically against the
// pinned corpus (`tests/testfiles/aarch64/`, paired with
// `tests/testfiles/binexport2/*.ghidra.BinExport`): every function address
// the upstream fixture table names resolves under this base and none under
// `VIV_ELF_DYN_BASE`. Using the wrong base doesn't fail loudly -- recovery
// still succeeds, just at addresses that can never line up with the paired
// BinExport2 file, which is why this was caught by task 4's feature-parity
// table rather than task 3's recovery-only acceptance.
const GHIDRA_AARCH64_ELF_DYN_BASE: u64 = 0x0010_0000;

/// Resolve the ordinal-only imports that the pinned Vivisect backend names
/// from its *own* vendored ordinal database (`PE/ordlookup/`, the `PE`
/// package vivisect ships), not from pefile's. The two disagree: pefile
/// keeps a separate, newer `wsock32` table where ordinal 10 is `inet_addr`,
/// while `PE/ordlookup/__init__.py` maps `wsock32.dll` at the same
/// `ws2_32.ord_names` table, making ordinal 10 `ioctlsocket`. capa's viv
/// backend reads `vw.getImports()`, so vivisect's table is the reference.
/// Unknown ordinals keep their original `#N` form, as capa does for ordinal
/// imports it cannot name.
///
/// Only the socket tables are transcribed. `PE/ordlookup` also ships
/// `mfc42`, `oledlg`, `msvbvm60`, `comctl32` and `oleaut32`; no corpus
/// sample has needed them yet, and each is a large table best added when a
/// measurement asks for it.
fn resolve_pe_ordinal(dll: &str, ordinal: u16) -> Option<&'static str> {
    let dll = dll.trim_end_matches(".dll");
    // `PE/ordlookup/__init__.py`: `'ws2_32.dll'` and `'wsock32.dll'` both
    // resolve against `ws2_32.ord_names`.
    if dll.eq_ignore_ascii_case("ws2_32") || dll.eq_ignore_ascii_case("wsock32") {
        return match ordinal {
            1 => Some("accept"),
            2 => Some("bind"),
            3 => Some("closesocket"),
            4 => Some("connect"),
            5 => Some("getpeername"),
            6 => Some("getsockname"),
            7 => Some("getsockopt"),
            8 => Some("htonl"),
            9 => Some("htons"),
            10 => Some("ioctlsocket"),
            11 => Some("inet_addr"),
            12 => Some("inet_ntoa"),
            13 => Some("listen"),
            14 => Some("ntohl"),
            15 => Some("ntohs"),
            16 => Some("recv"),
            17 => Some("recvfrom"),
            18 => Some("select"),
            19 => Some("send"),
            20 => Some("sendto"),
            21 => Some("setsockopt"),
            22 => Some("shutdown"),
            23 => Some("socket"),
            24 => Some("GetAddrInfoW"),
            25 => Some("GetNameInfoW"),
            26 => Some("WSApSetPostRoutine"),
            27 => Some("FreeAddrInfoW"),
            28 => Some("WPUCompleteOverlappedRequest"),
            29 => Some("WSAAccept"),
            30 => Some("WSAAddressToStringA"),
            31 => Some("WSAAddressToStringW"),
            32 => Some("WSACloseEvent"),
            33 => Some("WSAConnect"),
            34 => Some("WSACreateEvent"),
            35 => Some("WSADuplicateSocketA"),
            36 => Some("WSADuplicateSocketW"),
            37 => Some("WSAEnumNameSpaceProvidersA"),
            38 => Some("WSAEnumNameSpaceProvidersW"),
            39 => Some("WSAEnumNetworkEvents"),
            40 => Some("WSAEnumProtocolsA"),
            41 => Some("WSAEnumProtocolsW"),
            42 => Some("WSAEventSelect"),
            43 => Some("WSAGetOverlappedResult"),
            44 => Some("WSAGetQOSByName"),
            45 => Some("WSAGetServiceClassInfoA"),
            46 => Some("WSAGetServiceClassInfoW"),
            47 => Some("WSAGetServiceClassNameByClassIdA"),
            48 => Some("WSAGetServiceClassNameByClassIdW"),
            49 => Some("WSAHtonl"),
            50 => Some("WSAHtons"),
            51 => Some("gethostbyaddr"),
            52 => Some("gethostbyname"),
            53 => Some("getprotobyname"),
            54 => Some("getprotobynumber"),
            55 => Some("getservbyname"),
            56 => Some("getservbyport"),
            57 => Some("gethostname"),
            58 => Some("WSAInstallServiceClassA"),
            59 => Some("WSAInstallServiceClassW"),
            60 => Some("WSAIoctl"),
            61 => Some("WSAJoinLeaf"),
            62 => Some("WSALookupServiceBeginA"),
            63 => Some("WSALookupServiceBeginW"),
            64 => Some("WSALookupServiceEnd"),
            65 => Some("WSALookupServiceNextA"),
            66 => Some("WSALookupServiceNextW"),
            67 => Some("WSANSPIoctl"),
            68 => Some("WSANtohl"),
            69 => Some("WSANtohs"),
            70 => Some("WSAProviderConfigChange"),
            71 => Some("WSARecv"),
            72 => Some("WSARecvDisconnect"),
            73 => Some("WSARecvFrom"),
            74 => Some("WSARemoveServiceClass"),
            75 => Some("WSAResetEvent"),
            76 => Some("WSASend"),
            77 => Some("WSASendDisconnect"),
            78 => Some("WSASendTo"),
            79 => Some("WSASetEvent"),
            80 => Some("WSASetServiceA"),
            81 => Some("WSASetServiceW"),
            82 => Some("WSASocketA"),
            83 => Some("WSASocketW"),
            84 => Some("WSAStringToAddressA"),
            85 => Some("WSAStringToAddressW"),
            86 => Some("WSAWaitForMultipleEvents"),
            87 => Some("WSCDeinstallProvider"),
            88 => Some("WSCEnableNSProvider"),
            89 => Some("WSCEnumProtocols"),
            90 => Some("WSCGetProviderPath"),
            91 => Some("WSCInstallNameSpace"),
            92 => Some("WSCInstallProvider"),
            93 => Some("WSCUnInstallNameSpace"),
            94 => Some("WSCUpdateProvider"),
            95 => Some("WSCWriteNameSpaceOrder"),
            96 => Some("WSCWriteProviderOrder"),
            97 => Some("freeaddrinfo"),
            98 => Some("getaddrinfo"),
            99 => Some("getnameinfo"),
            101 => Some("WSAAsyncSelect"),
            102 => Some("WSAAsyncGetHostByAddr"),
            103 => Some("WSAAsyncGetHostByName"),
            104 => Some("WSAAsyncGetProtoByNumber"),
            105 => Some("WSAAsyncGetProtoByName"),
            106 => Some("WSAAsyncGetServByPort"),
            107 => Some("WSAAsyncGetServByName"),
            108 => Some("WSACancelAsyncRequest"),
            109 => Some("WSASetBlockingHook"),
            110 => Some("WSAUnhookBlockingHook"),
            111 => Some("WSAGetLastError"),
            112 => Some("WSASetLastError"),
            113 => Some("WSACancelBlockingCall"),
            114 => Some("WSAIsBlocking"),
            115 => Some("WSAStartup"),
            116 => Some("WSACleanup"),
            151 => Some("__WSAFDIsSet"),
            500 => Some("WEP"),
            _ => None,
        };
    }
    None
}

/// Port of `VivWorkspace.normFileName` (`vivisect/__init__.py:2958-2977`):
/// take the basename, lowercase it, drop the last dot-separated component and
/// join the rest with `_`, then replace every character outside
/// `[A-Za-z0-9_]` with `_`.
fn norm_file_name(filename: &str) -> String {
    // `os.path.basename` on the reference (POSIX) platform splits on `/` only.
    let base = filename
        .rsplit('/')
        .next()
        .unwrap_or(filename)
        .to_lowercase();
    let stem = match base.rfind('.') {
        Some(index) => base[..index].replace('.', "_"),
        None => base,
    };
    stem.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// The `tinfo` string `VivWorkspace.makeImport` records for a PE import
/// (`vivisect/__init__.py:919-927`), which is what the no-return API lists in
/// `vivisect/parsers/pe.py` are matched against.
fn import_location_name(dll: &str, symbol: &str) -> String {
    format!("{}.{symbol}", norm_file_name(dll))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Pe,
    Elf,
    /// `-f sc32`/`sc64`: a raw code blob with no container format at all.
    Sc,
    /// `-f macho`: a capa-x extension -- pinned capa 9.4.0 has
    /// no raw Mach-O input, so this is never a parity claim, only capa's own
    /// feature semantics applied to a format upstream does not accept.
    Macho,
}

/// `viv_utils.SHELLCODE_BASE` (pinned via `flare-capa==9.4.0`'s `viv_utils`
/// dependency, `.venv/lib/*/site-packages/viv_utils/__init__.py`):
/// `capa/loader.py:get_workspace`'s `FORMAT_SC32`/`FORMAT_SC64` branches call
/// `viv_utils.getShellcodeWorkspaceFromFile(path, arch=..., analyze=False)`,
/// whose `base`/`entry_point` defaults place the whole buffer at this fixed
/// address with the entry point at its first byte -- *not* address 0.
pub const SHELLCODE_BASE: u64 = 0x0069_0000;

/// `AArch64` decodes through `disarm64` instead of `iced-x86`
/// (see `decode_at` and `super::decoder::from_aarch64`). `from_elf` maps
/// `EM_AARCH64` to it (task 3); every x86-only recovery heuristic reachable
/// from the ELF path (`libc_start_main`, `golang`, `noreturn.rs`) is either
/// architecture-gated or, for `noreturn.rs`, rewritten against the generic
/// `Flow` boundary, so none of them can reach
/// [`super::decoder::DecodedInstruction::x86_instruction`] (which panics by
/// design for this variant) against an AArch64 image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X64,
    AArch64,
}

impl Architecture {
    pub fn bitness(self) -> u32 {
        match self {
            Self::X86 => 32,
            Self::X64 | Self::AArch64 => 64,
        }
    }

    /// Native pointer/GPR width in bytes -- `bitness() / 8`, named for the
    /// several call sites in `recovery.rs` (relocation/init-array/jump-table
    /// pointer reads) that used to spell this `== Architecture::X64` before
    /// AArch64 existed, silently reading 32-bit halves of a 64-bit pointer
    /// had it ever reached one.
    pub fn pointer_width(self) -> usize {
        (self.bitness() / 8) as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedSection {
    pub name: String,
    pub address: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub permissions: Permissions,
}

impl MappedSection {
    pub fn end_address(&self) -> Option<u64> {
        self.address.checked_add(self.virtual_size)
    }

    pub fn contains_va(&self, address: u64) -> bool {
        address
            .checked_sub(self.address)
            .is_some_and(|offset| offset < self.virtual_size)
    }

    pub fn contains_file_offset(&self, offset: u64) -> bool {
        offset
            .checked_sub(self.file_offset)
            .is_some_and(|relative| relative < self.file_size)
    }
}

pub use super::decoder::DecodedInstruction;

/// `vpcext imm8, imm8` -- Virtual PC's hypercall opcode. envi decodes it
/// (`envi/archs/i386/opcode86.py:357`, the `cpu_VIRTUALPC` row, and
/// `envi/tests/test_arch_i386.py:222`'s `0F3F070B -> vpcext 7,11`); iced-x86
/// has no entry for it and reports `InvalidInstruction`, which truncates the
/// containing function at the hypercall rather than merely losing one
/// mnemonic feature.
const VPCEXT_OPCODE: [u8; 2] = [0x0f, 0x3f];
const VPCEXT_LEN: usize = 4;

/// Decode the opcodes envi knows and iced-x86 does not, so recovery does not
/// stop at them. The returned `Instruction` is a *carrier*: its `code` is
/// meaningless and only its length, `Next` flow control and operand kinds are
/// read -- the mnemonic comes from [`DecodedInstruction::mnemonic_override`].
fn decode_undocumented(address: u64, bytes: &[u8]) -> Option<(Instruction, &'static str, usize)> {
    if bytes.len() < VPCEXT_LEN || bytes[..2] != VPCEXT_OPCODE {
        return None;
    }
    // envi builds two `i386ImmOper`s from the trailing bytes, so
    // `extract_op_number_features` sees `Number(imm)`/`OperandNumber(i, imm)`
    // for both. `enter imm16, imm8` is the carrier because it is the only
    // shape iced-x86 offers that is two immediates wide with `FlowControl::Next`.
    let mut instruction = Instruction::default();
    instruction.set_code(iced_x86::Code::Enterd_imm16_imm8);
    instruction.set_op0_kind(iced_x86::OpKind::Immediate8);
    instruction.set_immediate8(bytes[2]);
    instruction.set_op1_kind(iced_x86::OpKind::Immediate8_2nd);
    instruction.set_immediate8_2nd(bytes[3]);
    instruction.set_len(VPCEXT_LEN);
    instruction.set_ip(address);
    instruction.set_next_ip(address.wrapping_add(VPCEXT_LEN as u64));
    Some((instruction, "vpcext", VPCEXT_LEN))
}

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("unsupported input format")]
    UnsupportedFormat,
    #[error("unsupported {format:?} machine type {machine:#x}")]
    UnsupportedArchitecture { format: ImageFormat, machine: u16 },
    #[error("parsing PE image: {0}")]
    Pe(String),
    #[error("parsing ELF image: {0}")]
    Elf(String),
    #[error("mapping {format:?} image: {context}")]
    Mapping {
        format: ImageFormat,
        context: String,
    },
    #[error("{format:?} address computation overflow: {context}")]
    AddressOverflow {
        format: ImageFormat,
        context: &'static str,
    },
    #[error("address {address:#x} is not file-backed mapped data")]
    AddressNotMapped { address: u64 },
    #[error("address {address:#x} is not in an executable mapping")]
    AddressNotExecutable { address: u64 },
    #[error("invalid or truncated instruction at {address:#x}: {reason}")]
    InvalidInstruction { address: u64, reason: String },
    #[error("malformed PE delay import data at RVA {rva:#x}: {context}")]
    DelayImport { rva: u64, context: String },
    #[error("parsing Mach-O image: {0}")]
    Macho(String),
    #[error(
        "no {requested} slice in this Mach-O: available architectures are [{}]",
        .available.join(", ")
    )]
    NoCompatibleMachoSlice {
        requested: String,
        available: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct LoadedImage {
    pub format: ImageFormat,
    pub architecture: Architecture,
    pub image_base: u64,
    pub load_bias: u64,
    pub entry_point: Option<u64>,
    pub sections: Vec<MappedSection>,
    /// Maps IAT/GOT addresses to capa API-name variants.
    pub external_bindings: BTreeMap<u64, Vec<String>>,
    /// Maps the same IAT/GOT addresses to Vivisect's *import location* name --
    /// the `tinfo` string `VivWorkspace.makeImport` stores, i.e.
    /// `"{normFileName(libname)}.{impname}"` for PE and `"*.{impname}"` for
    /// ELF (`vivisect/__init__.py:919-927`). This is the exact string
    /// `addNoReturnApi`/`addNoReturnApiRegex` match against, so it is kept
    /// verbatim alongside the capa-flavoured `external_bindings` variants
    /// rather than reconstructed from them.
    pub import_locations: BTreeMap<u64, String>,
    /// Recoverable malformed optional-directory conditions encountered while
    /// loading. Code recovery exposes these without rejecting the sample.
    pub load_diagnostics: Vec<String>,
    /// Vivisect's PE loader marks directory sections and sections without
    /// code, execute, or write characteristics as dead data. The end address
    /// is inclusive because `VivWorkspace.isDeadData()` uses `<= end`.
    dead_data: Vec<(u64, u64)>,
    /// Regions carrying Vivisect's `MM_UNINIT` permission. Code flow must not
    /// enter these even if another loader rule also made the map executable.
    uninitialized: Vec<(u64, u64)>,
    /// Regions identified as code before Vivisect's pre-Vista NX fallback
    /// broadens executable permission to every readable PE section.
    primary_code: Vec<(u64, u64)>,
    /// Bytes as mapped into virtual memory, parallel to `sections`. PE entries
    /// include loader-created zero fill and file-alignment padding.
    mapped_bytes: Vec<Vec<u8>>,
}

impl LoadedImage {
    pub fn parse(bytes: &[u8]) -> Result<Self, ImageError> {
        if bytes.starts_with(b"MZ") {
            Self::from_pe(bytes)
        } else if bytes.starts_with(b"\x7fELF") {
            Self::from_elf(bytes)
        } else if super::looks_like_macho(bytes) {
            Self::from_macho(bytes, None)
        } else {
            Err(ImageError::UnsupportedFormat)
        }
    }

    pub fn from_pe(bytes: &[u8]) -> Result<Self, ImageError> {
        let mut options = ParseOptions::default();
        options.parse_mode = ParseMode::Permissive;
        options.parse_tls_data = false;
        options.parse_resources = false;
        options.parse_attribute_certificates = false;
        let pe = PE::parse_with_opts(bytes, &options)
            .map_err(|error| ImageError::Pe(error.to_string()))?;

        let architecture = match pe.header.coff_header.machine {
            COFF_MACHINE_X86 => Architecture::X86,
            COFF_MACHINE_X86_64 => Architecture::X64,
            // `IMAGE_FILE_MACHINE_ARM64`. Every mapping/import/
            // export/relocation path below this match is already format-
            // generic (RVA-based, no x86-specific assumption) -- verified
            // against the `tests/fixtures/aarch64-pe/` corpus rather than
            // reimplemented; see `aarch64_pe_features.rs`.
            // `aarch64_pe_features.rs`.
            COFF_MACHINE_ARM64 => Architecture::AArch64,
            machine => {
                return Err(ImageError::UnsupportedArchitecture {
                    format: ImageFormat::Pe,
                    machine,
                });
            }
        };
        let entry_point = if pe.entry == 0 {
            None
        } else {
            Some(pe.image_base.checked_add(u64::from(pe.entry)).ok_or(
                ImageError::AddressOverflow {
                    format: ImageFormat::Pe,
                    context: "entry point",
                },
            )?)
        };

        let optional_header = pe
            .header
            .optional_header
            .as_ref()
            .ok_or_else(|| ImageError::Pe("missing optional header".to_string()))?;
        let section_alignment = u64::from(optional_header.windows_fields.section_alignment);
        if section_alignment == 0 {
            return Err(ImageError::Pe("section alignment is zero".to_string()));
        }
        let file_alignment = u64::from(optional_header.windows_fields.file_alignment);
        let mut sections = Vec::with_capacity(pe.sections.len().saturating_add(1));
        let mut mapped_bytes = Vec::with_capacity(pe.sections.len().saturating_add(1));
        let mut dead_data = Vec::new();
        let mut uninitialized = Vec::new();
        let mut primary_code = Vec::new();
        let mut mapped_total = 0usize;

        // Port of pinned Vivisect 1.3.2 `vivisect/parsers/pe.py:185-216`.
        // SizeOfHeaders is spoofable, so Vivisect maps the bytes through the
        // section table and pads that mapping to SectionAlignment.
        let header_size = u64::from(pe.header.dos_header.pe_pointer)
            .checked_add(PE_SIGNATURE_SIZE)
            .and_then(|value| value.checked_add(PE_COFF_HEADER_SIZE))
            .and_then(|value| {
                value.checked_add(u64::from(pe.header.coff_header.size_of_optional_header))
            })
            .and_then(|value| {
                value.checked_add(
                    u64::from(pe.header.coff_header.number_of_sections)
                        .checked_mul(PE_SECTION_HEADER_SIZE)?,
                )
            })
            .ok_or(ImageError::AddressOverflow {
                format: ImageFormat::Pe,
                context: "header mapping",
            })?;
        let header_file_size = header_size.min(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if header_file_size != header_size {
            return Err(ImageError::Pe("truncated PE header".to_string()));
        }
        let header_map_size =
            align_up(header_size, section_alignment).ok_or(ImageError::AddressOverflow {
                format: ImageFormat::Pe,
                context: "aligned header mapping",
            })?;
        let mut header =
            mapped_region(bytes, 0, header_file_size, header_map_size, ImageFormat::Pe)?;
        account_mapping(&mut mapped_total, header.len())?;
        sections.push(MappedSection {
            name: "<headers>".to_string(),
            address: pe.image_base,
            virtual_size: header_map_size,
            file_offset: 0,
            file_size: header_file_size,
            permissions: Permissions {
                read: true,
                write: false,
                execute: false,
            },
        });
        mapped_bytes.push(std::mem::take(&mut header));

        let entry_rva = u64::from(pe.entry);
        let code_start = optional_header.standard_fields.base_of_code;
        let code_end = code_start.saturating_add(optional_header.standard_fields.size_of_code);
        let resource_rva = optional_header
            .data_directories
            .get_resource_table()
            .map_or(0, |directory| directory.virtual_address);
        let dead_directory_rvas: Vec<u32> = optional_header
            .data_directories
            .data_directories
            .iter()
            .filter_map(Option::as_ref)
            .map(|(_, directory)| directory.virtual_address)
            .filter(|rva| *rva != 0)
            .collect();

        for (index, section) in pe.sections.iter().enumerate() {
            let name_end = section
                .name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(section.name.len());
            let name = String::from_utf8_lossy(section.name.get(..name_end).unwrap_or_default())
                .into_owned();
            let address = pe
                .image_base
                .checked_add(u64::from(section.virtual_address))
                .ok_or(ImageError::AddressOverflow {
                    format: ImageFormat::Pe,
                    context: "section address",
                })?;
            let characteristics = section.characteristics;
            // `vivisect/parsers/pe.py:267-268` skips a readable section whose
            // RVA is the resource directory's when `loadresources` is false.
            // The pinned reference never sees that default -- capa reaches the
            // loader through `viv_utils.getWorkspace`, which sets
            // `loadresources = True` (`viv_utils/__init__.py:101`) -- so
            // upstream *does* map the section. capa-x deliberately does not;
            // see KD-011. Mapping it was implemented and measured
            // and made results strictly worse: on `0cd2b334`, whose packer
            // points the resource directory at a second executable section,
            // the newly reachable range sent recovery past 200k instructions
            // in a single direct-flow walk and turned a sample that
            // under-reported by 2 rules into one that fails to analyse at all.
            let is_resource = section.virtual_address == resource_rva;
            if characteristics & IMAGE_SCN_MEM_READ != 0 && is_resource {
                continue;
            }

            let section_rva = u64::from(section.virtual_address);
            let declared_virtual_size = u64::from(section.virtual_size);
            let declared_raw_size = u64::from(section.size_of_raw_data);
            let file_offset = u64::from(section.pointer_to_raw_data);
            let (virtual_size, read_size, align_mapping) = if declared_virtual_size == 0
                || declared_raw_size == 0
            {
                let Some(next) = pe.sections.get(index.saturating_add(1)) else {
                    continue;
                };
                let gap = u64::from(next.virtual_address)
                    .checked_sub(section_rva)
                    .ok_or_else(|| {
                        ImageError::Pe(format!("section {name} ends after the following section"))
                    })?;
                (gap, 0, false)
            } else {
                // `pe.py:337-354` reads min(RawSize, VirtualSize), pads to
                // VirtualSize, then addMemoryMap pads to FileAlignment.
                if declared_raw_size < declared_virtual_size
                    && declared_raw_size > u64::try_from(bytes.len()).unwrap_or(u64::MAX)
                {
                    continue;
                }
                (
                    declared_virtual_size,
                    declared_raw_size.min(declared_virtual_size),
                    true,
                )
            };
            let map_size = if align_mapping && file_alignment != 0 {
                align_up(virtual_size, file_alignment).ok_or(ImageError::AddressOverflow {
                    format: ImageFormat::Pe,
                    context: "aligned section mapping",
                })?
            } else {
                virtual_size
            };
            if map_size == 0 {
                continue;
            }
            let available = u64::try_from(bytes.len())
                .unwrap_or(u64::MAX)
                .saturating_sub(file_offset);
            let file_size = read_size.min(available);
            let data = mapped_region(bytes, file_offset, file_size, map_size, ImageFormat::Pe)?;
            account_mapping(&mut mapped_total, data.len())?;

            let mut primary = characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0;
            if section_rva >= code_start && section_rva < code_end {
                primary = true;
            }
            if section_rva <= entry_rva
                && entry_rva < section_rva.saturating_add(declared_virtual_size)
            {
                primary = true;
            }
            // `vivisect/parsers/pe.py:278` and `:309-311` grant execute to any
            // readable section of a pre-Vista non-NX image -- but both are
            // guarded by `not vw.config.viv.parsers.pe.nx`, and the pinned
            // reference sets `nx = True` (`viv_utils/__init__.py:102`), so
            // neither ever fires. Verified against the pinned workspace:
            // `Practical Malware Analysis Lab 03-02.dll_` is a pre-Vista
            // non-NX image whose `.data` map is `MM_READ|MM_WRITE`, with no
            // `MM_EXEC`. Execute therefore comes only from the flags, the
            // BaseOfCode range, and the entry-point section.
            let execute = primary;
            let read = characteristics & IMAGE_SCN_MEM_READ != 0;
            sections.push(MappedSection {
                name,
                address,
                virtual_size: map_size,
                file_offset,
                file_size,
                permissions: Permissions {
                    read,
                    write: characteristics & IMAGE_SCN_MEM_WRITE != 0,
                    execute,
                },
            });
            mapped_bytes.push(data);

            let raw_map_end = address.saturating_add(virtual_size);
            if dead_directory_rvas.contains(&section.virtual_address)
                || characteristics
                    & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)
                    == 0
            {
                dead_data.push((address, raw_map_end));
            }
            if characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
                uninitialized.push((address, address.saturating_add(map_size)));
            }
            if primary {
                primary_code.push((address, address.saturating_add(map_size)));
            }
        }

        let mut image = Self {
            format: ImageFormat::Pe,
            architecture,
            image_base: pe.image_base,
            load_bias: 0,
            entry_point,
            sections,
            external_bindings: BTreeMap::new(),
            import_locations: BTreeMap::new(),
            load_diagnostics: Vec::new(),
            dead_data,
            uninitialized,
            primary_code,
            mapped_bytes,
        };

        for import in &pe.imports {
            let address = pe
                .image_base
                .checked_add(u64::try_from(import.offset).map_err(|_| {
                    ImageError::AddressOverflow {
                        format: ImageFormat::Pe,
                        context: "IAT address",
                    }
                })?)
                .ok_or(ImageError::AddressOverflow {
                    format: ImageFormat::Pe,
                    context: "IAT address",
                })?;
            let symbol = import.name.strip_prefix("ORDINAL ").map_or_else(
                || import.name.to_string(),
                |ordinal| {
                    ordinal
                        .parse::<u16>()
                        .ok()
                        .and_then(|ordinal| resolve_pe_ordinal(import.dll, ordinal))
                        .map_or_else(|| format!("#{ordinal}"), str::to_string)
                },
            );
            // `viv/insn.py:extract_insn_api_features` calls
            // `generate_symbols(dll, symbol)` (`include_dll` defaults
            // `False`) for the insn-scope `api:` feature -- unlike
            // `pefile.py`'s *file*-scope `Import` feature, which passes
            // `include_dll=True`. `external_bindings` only ever feeds the
            // former (`insn_features.rs::push_api_names`); the file-scope
            // Import feature is built independently in this file's own
            // `extract_file_import_names`, so this doesn't affect it.
            image.add_external_binding(address, generate_symbols(import.dll, &symbol, false));
            image
                .import_locations
                .insert(address, import_location_name(import.dll, &symbol));
        }
        image.load_pe_delay_imports(&pe)?;

        Ok(image)
    }

    pub fn from_elf(bytes: &[u8]) -> Result<Self, ImageError> {
        let elf = Elf::parse(bytes).map_err(|error| ImageError::Elf(error.to_string()))?;
        let architecture = match elf.header.e_machine {
            EM_386 => Architecture::X86,
            EM_X86_64 => Architecture::X64,
            EM_AARCH64 => Architecture::AArch64,
            machine => {
                return Err(ImageError::UnsupportedArchitecture {
                    format: ImageFormat::Elf,
                    machine,
                });
            }
        };

        let raw_image_base = elf
            .program_headers
            .iter()
            .filter(|header| header.p_type == PT_LOAD)
            .map(|header| header.p_vaddr)
            .min()
            .unwrap_or(0);
        let load_bias = if elf.header.e_type == ET_DYN {
            let dyn_base = if architecture == Architecture::AArch64 {
                GHIDRA_AARCH64_ELF_DYN_BASE
            } else {
                VIV_ELF_DYN_BASE
            };
            dyn_base.saturating_sub(raw_image_base)
        } else {
            0
        };
        let image_base =
            raw_image_base
                .checked_add(load_bias)
                .ok_or(ImageError::AddressOverflow {
                    format: ImageFormat::Elf,
                    context: "image base",
                })?;
        let entry_point = if elf.entry == 0 {
            None
        } else {
            Some(
                elf.entry
                    .checked_add(load_bias)
                    .ok_or(ImageError::AddressOverflow {
                        format: ImageFormat::Elf,
                        context: "entry point",
                    })?,
            )
        };
        let mut sections = Vec::new();
        let mut mapped_bytes = Vec::new();
        let mut primary_code = Vec::new();
        for (index, header) in elf
            .program_headers
            .iter()
            .enumerate()
            .filter(|(_, header)| header.p_type == PT_LOAD)
        {
            let available = u64::try_from(bytes.len())
                .unwrap_or(u64::MAX)
                .saturating_sub(header.p_offset);
            let file_size = header.p_filesz.min(available);
            let data = mapped_region(
                bytes,
                header.p_offset,
                file_size,
                file_size,
                ImageFormat::Elf,
            )?;
            let address =
                header
                    .p_vaddr
                    .checked_add(load_bias)
                    .ok_or(ImageError::AddressOverflow {
                        format: ImageFormat::Elf,
                        context: "segment address",
                    })?;
            sections.push(MappedSection {
                name: format!("PT_LOAD[{index}]"),
                address,
                virtual_size: header.p_memsz.max(header.p_filesz),
                file_offset: header.p_offset,
                file_size,
                permissions: Permissions {
                    read: header.p_flags & PF_R != 0,
                    write: header.p_flags & PF_W != 0,
                    execute: header.p_flags & PF_X != 0,
                },
            });
            mapped_bytes.push(data);
            if header.p_flags & PF_X != 0 {
                primary_code.push((address, address.saturating_add(header.p_memsz)));
            }
        }

        let mut image = Self {
            format: ImageFormat::Elf,
            architecture,
            image_base,
            load_bias,
            entry_point,
            sections,
            external_bindings: BTreeMap::new(),
            import_locations: BTreeMap::new(),
            load_diagnostics: Vec::new(),
            dead_data: Vec::new(),
            uninitialized: Vec::new(),
            primary_code,
            mapped_bytes,
        };
        for relocation in elf
            .dynrelas
            .iter()
            .chain(elf.dynrels.iter())
            .chain(elf.pltrelocs.iter())
        {
            let Some(symbol) = elf.dynsyms.get(relocation.r_sym) else {
                continue;
            };
            let Some(name) = elf.dynstrtab.get_at(symbol.st_name) else {
                continue;
            };
            if !name.is_empty() {
                let address = relocation.r_offset.checked_add(load_bias).ok_or(
                    ImageError::AddressOverflow {
                        format: ImageFormat::Elf,
                        context: "relocation binding",
                    },
                )?;
                image.add_external_binding(address, vec![name.to_string()]);
                // `vivisect/parsers/elf.py` passes `"*"` as the library name
                // for every dynamic relocation import (elf.py:844 and friends),
                // and `makeImport` leaves `"*"` un-normalised.
                image.import_locations.insert(address, format!("*.{name}"));
            }
        }

        Ok(image)
    }

    /// `viv_utils.getShellcodeWorkspace`: the whole buffer becomes one
    /// `MM_RWX` memory map/segment named `shellcode_0x{base:x}`, loaded at
    /// [`SHELLCODE_BASE`] with the entry point at that same address
    /// (`entry_point=0`, relative to `base`). No imports/exports/relocations
    /// exist for a raw blob, so `external_bindings` stays empty.
    pub fn from_shellcode(bytes: &[u8], architecture: Architecture) -> Self {
        let base = SHELLCODE_BASE;
        let size = bytes.len() as u64;
        Self {
            format: ImageFormat::Sc,
            architecture,
            image_base: base,
            load_bias: 0,
            entry_point: Some(base),
            sections: vec![MappedSection {
                name: format!("shellcode_0x{base:x}"),
                address: base,
                virtual_size: size,
                file_offset: 0,
                file_size: size,
                permissions: Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            }],
            external_bindings: BTreeMap::new(),
            import_locations: BTreeMap::new(),
            load_diagnostics: Vec::new(),
            dead_data: Vec::new(),
            uninitialized: Vec::new(),
            primary_code: vec![(
                SHELLCODE_BASE,
                SHELLCODE_BASE.saturating_add(bytes.len() as u64),
            )],
            mapped_bytes: vec![bytes.to_vec()],
        }
    }

    /// Load a thin or fat Mach-O, selecting `arch` (`Some("arm64")`) or,
    /// when `None` ("`--arch auto`"), the first slice in
    /// [`SUPPORTED_MACHO_ARCHES`] in fat-header order -- host-independent by
    /// construction, since it never consults the running machine's own
    /// architecture.
    pub fn from_macho(bytes: &[u8], arch: Option<&str>) -> Result<Self, ImageError> {
        let (slice, resolved_arch) = select_macho_slice(bytes, arch)?;
        let macho = MachO::parse(slice, 0).map_err(|error| ImageError::Macho(error.to_string()))?;
        if !macho.is_64 {
            return Err(ImageError::Macho(
                "32-bit Mach-O is not supported".to_string(),
            ));
        }
        // `select_macho_slice` already restricted `resolved_arch` to
        // `SUPPORTED_MACHO_ARCHES`; this only maps that name to the
        // `Architecture` recovery/decode dispatch on -- both `arm64` and
        // `arm64e` decode through `disarm64` identically (see
        // `SUPPORTED_MACHO_ARCHES`'s doc comment).
        let architecture = match resolved_arch {
            "x86_64" => Architecture::X64,
            "arm64" | "arm64e" => Architecture::AArch64,
            other => {
                return Err(ImageError::Macho(format!(
                    "internal error: select_macho_slice returned unsupported arch {other}"
                )));
            }
        };
        validate_macho_load_commands(&macho, slice)?;

        // (segname, vmaddr, vmsize, fileoff, filesize, initprot), in
        // load-command order -- collected once so both the overlap check
        // (ADR 0005) and the mapping loop below share one validated view.
        let mut segments: Vec<(String, u64, u64, u64, u64, u32)> = Vec::new();
        for command in &macho.load_commands {
            let CommandVariant::Segment64(seg) = command.command else {
                continue;
            };
            let expected_cmdsize = u32::try_from(SIZEOF_SEGMENT_COMMAND_64)
                .ok()
                .and_then(|base| {
                    seg.nsects
                        .checked_mul(u32::try_from(SIZEOF_SECTION_64).ok()?)
                        .and_then(|sections_size| base.checked_add(sections_size))
                })
                .ok_or_else(|| ImageError::Macho("segment nsects overflows cmdsize".to_string()))?;
            if expected_cmdsize != seg.cmdsize {
                return Err(ImageError::Macho(format!(
                    "segment {} declares {} sections, inconsistent with cmdsize {}",
                    cstr16(&seg.segname),
                    seg.nsects,
                    seg.cmdsize
                )));
            }
            if seg.filesize > seg.vmsize {
                return Err(ImageError::Macho(format!(
                    "segment {} filesize {:#x} exceeds vmsize {:#x}",
                    cstr16(&seg.segname),
                    seg.filesize,
                    seg.vmsize
                )));
            }
            let fileoff = usize::try_from(seg.fileoff).map_err(|_| {
                ImageError::Macho(format!(
                    "segment {} fileoff does not fit in memory",
                    cstr16(&seg.segname)
                ))
            })?;
            let filesize = usize::try_from(seg.filesize).map_err(|_| {
                ImageError::Macho(format!(
                    "segment {} filesize does not fit in memory",
                    cstr16(&seg.segname)
                ))
            })?;
            let in_bounds = fileoff
                .checked_add(filesize)
                .is_some_and(|end| end <= slice.len());
            if !in_bounds {
                return Err(ImageError::Macho(format!(
                    "segment {} file range [{:#x}, {:#x}+{:#x}) is past the end of the file",
                    cstr16(&seg.segname),
                    seg.fileoff,
                    seg.fileoff,
                    seg.filesize
                )));
            }
            segments.push((
                cstr16(&seg.segname),
                seg.vmaddr,
                seg.vmsize,
                seg.fileoff,
                seg.filesize,
                seg.initprot,
            ));
        }
        validate_no_overlapping_macho_segments(&segments)?;

        let image_base = segments
            .iter()
            .find(|(name, ..)| name == "__TEXT")
            .map(|(_, vmaddr, ..)| *vmaddr)
            .or_else(|| segments.iter().map(|(_, vmaddr, ..)| *vmaddr).min())
            .unwrap_or(0);

        let mut sections = Vec::with_capacity(segments.len());
        let mut mapped_bytes = Vec::with_capacity(segments.len());
        let mut primary_code = Vec::new();
        let mut mapped_total = 0usize;
        for (name, vmaddr, vmsize, fileoff, filesize, initprot) in &segments {
            if name == "__PAGEZERO" {
                // Unreadable, not 4 GiB of zero fill: never mapped at all, so
                // `section_containing`/`bytes_at` correctly treat every
                // address inside it as unmapped rather than serving
                // synthesized zero bytes for a region that was never backed
                // by anything -- `__PAGEZERO` maps unreadable.
                continue;
            }
            let data = mapped_region(slice, *fileoff, *filesize, *vmsize, ImageFormat::Macho)?;
            account_mapping(&mut mapped_total, data.len())?;
            let read = initprot & VM_PROT_READ != 0;
            let write = initprot & VM_PROT_WRITE != 0;
            let execute = initprot & VM_PROT_EXECUTE != 0;
            sections.push(MappedSection {
                name: name.clone(),
                address: *vmaddr,
                virtual_size: *vmsize,
                file_offset: *fileoff,
                file_size: (*filesize).min(*vmsize),
                permissions: Permissions {
                    read,
                    write,
                    execute,
                },
            });
            mapped_bytes.push(data);
            if execute {
                primary_code.push((*vmaddr, vmaddr.saturating_add(*vmsize)));
            }
        }

        let entry_point = (macho.entry != 0).then_some(macho.entry);

        let mut image = Self {
            format: ImageFormat::Macho,
            architecture,
            image_base,
            load_bias: 0,
            entry_point,
            sections,
            external_bindings: BTreeMap::new(),
            import_locations: BTreeMap::new(),
            load_diagnostics: Vec::new(),
            dead_data: Vec::new(),
            uninitialized: Vec::new(),
            primary_code,
            mapped_bytes,
        };

        load_macho_imports(&macho, slice, &mut image);

        Ok(image)
    }

    pub fn section_containing(&self, address: u64) -> Option<&MappedSection> {
        self.sections
            .iter()
            .find(|section| section.contains_va(address))
    }

    pub fn is_dead_data(&self, address: u64) -> bool {
        self.dead_data
            .iter()
            .any(|(start, end)| address >= *start && address <= *end)
    }

    pub fn is_uninitialized(&self, address: u64) -> bool {
        self.uninitialized
            .iter()
            .any(|(start, end)| address >= *start && address < *end)
    }

    pub(crate) fn is_primary_code_address(&self, address: u64) -> bool {
        self.primary_code
            .iter()
            .any(|(start, end)| address >= *start && address < *end)
    }

    pub fn is_executable_address(&self, address: u64) -> bool {
        self.section_containing(address)
            .is_some_and(|section| section.permissions.execute)
            && !self.is_uninitialized(address)
            && self.bytes_at(address, 1).is_some()
    }

    pub fn va_to_file_offset(&self, address: u64) -> Option<u64> {
        self.sections.iter().find_map(|section| {
            let relative = address.checked_sub(section.address)?;
            (relative < section.file_size).then(|| section.file_offset.checked_add(relative))?
        })
    }

    pub fn file_offset_to_va(&self, offset: u64) -> Option<u64> {
        self.sections.iter().find_map(|section| {
            let relative = offset.checked_sub(section.file_offset)?;
            (relative < section.file_size).then(|| section.address.checked_add(relative))?
        })
    }

    /// Returns at most `max_len` bytes without crossing the containing mapped
    /// region. PE zero-fill and file-alignment padding are visible here just
    /// as they are through Vivisect's memory maps.
    pub fn bytes_at(&self, address: u64, max_len: usize) -> Option<&[u8]> {
        let (index, section) = self
            .sections
            .iter()
            .enumerate()
            .find(|(_, section)| section.contains_va(address))?;
        let relative = address.checked_sub(section.address)?;
        let start = usize::try_from(relative).ok()?;
        let data = self.mapped_bytes.get(index)?;
        let section_remaining = data.len().checked_sub(start)?;
        let len = max_len.min(section_remaining);
        let end = start.checked_add(len)?;
        data.get(start..end)
    }

    pub fn decode_at(&self, address: u64) -> Result<DecodedInstruction, ImageError> {
        let section = self
            .section_containing(address)
            .ok_or(ImageError::AddressNotMapped { address })?;
        if !section.permissions.execute {
            return Err(ImageError::AddressNotExecutable { address });
        }
        if self.architecture == Architecture::AArch64 {
            return self.decode_at_aarch64(address);
        }
        let bytes = self
            .bytes_at(address, MAX_INSN_LEN)
            .ok_or(ImageError::AddressNotMapped { address })?;
        let mut decoder = Decoder::with_ip(
            self.architecture.bitness(),
            bytes,
            address,
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        let mut mnemonic_override = None;
        let instruction = if instruction.is_invalid() {
            let Some((carrier, mnemonic, _)) = decode_undocumented(address, bytes) else {
                return Err(ImageError::InvalidInstruction {
                    address,
                    reason: format!("{:?}", decoder.last_error()),
                });
            };
            mnemonic_override = Some(mnemonic);
            carrier
        } else {
            instruction
        };
        let length = instruction.len();
        let raw = bytes
            .get(..length)
            .ok_or_else(|| ImageError::InvalidInstruction {
                address,
                reason: "decoder consumed beyond the mapped bytes".to_string(),
            })?
            .to_vec();
        Ok(super::decoder::from_x86(
            address,
            raw,
            instruction,
            mnemonic_override,
        ))
    }

    /// AArch64 is fixed-width: every instruction is exactly 4 little-endian
    /// bytes, so there is no variable-length-decode failure mode to carry a
    /// fallback for the way `decode_undocumented` does for x86 -- an
    /// unrecognized word is handled inside `decoder::from_aarch64` itself,
    /// never here.
    fn decode_at_aarch64(&self, address: u64) -> Result<DecodedInstruction, ImageError> {
        let bytes = self
            .bytes_at(address, 4)
            .ok_or(ImageError::AddressNotMapped { address })?;
        let raw: [u8; 4] = bytes
            .get(..4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| ImageError::InvalidInstruction {
                address,
                reason: "fewer than 4 bytes mapped for an AArch64 instruction".to_string(),
            })?;
        let word = u32::from_le_bytes(raw);
        Ok(super::decoder::from_aarch64(address, raw.to_vec(), word))
    }

    pub(crate) fn add_external_binding(&mut self, address: u64, names: Vec<String>) {
        let bindings = self.external_bindings.entry(address).or_default();
        for name in names {
            if !bindings.contains(&name) {
                bindings.push(name);
            }
        }
    }

    fn load_pe_delay_imports(&mut self, pe: &PE<'_>) -> Result<(), ImageError> {
        let Some(optional_header) = pe.header.optional_header.as_ref() else {
            return Ok(());
        };
        let Some(directory) = optional_header
            .data_directories
            .get_delay_import_descriptor()
        else {
            return Ok(());
        };
        if directory.virtual_address == 0 || directory.size == 0 {
            return Ok(());
        }

        let descriptor_count = usize::try_from(directory.size)
            .unwrap_or(usize::MAX)
            .checked_div(DELAY_DESCRIPTOR_SIZE)
            .unwrap_or(0);
        if usize::try_from(directory.size).unwrap_or(usize::MAX) % DELAY_DESCRIPTOR_SIZE != 0 {
            // pefile's permissive parser processes every complete descriptor
            // and records a warning for the trailing bytes. Do the same so a
            // malformed optional directory cannot suppress analysis of the
            // rest of an otherwise loadable PE.
            self.load_diagnostics.push(format!(
                "delay import directory at RVA {:#x} has size {}, which is not a multiple of {DELAY_DESCRIPTOR_SIZE}; ignoring trailing bytes",
                directory.virtual_address, directory.size
            ));
        }
        if descriptor_count > MAX_DELAY_DESCRIPTORS {
            return Err(ImageError::DelayImport {
                rva: u64::from(directory.virtual_address),
                context: format!(
                    "descriptor count {descriptor_count} exceeds limit {MAX_DELAY_DESCRIPTORS}"
                ),
            });
        }
        for index in 0..descriptor_count {
            let descriptor_rva = u64::from(directory.virtual_address)
                .checked_add(
                    u64::try_from(index)
                        .ok()
                        .and_then(|value| value.checked_mul(DELAY_DESCRIPTOR_SIZE as u64))
                        .ok_or(ImageError::AddressOverflow {
                            format: ImageFormat::Pe,
                            context: "delay import descriptor",
                        })?,
                )
                .ok_or(ImageError::AddressOverflow {
                    format: ImageFormat::Pe,
                    context: "delay import descriptor",
                })?;
            let raw = self.read_array_at_rva::<32>(descriptor_rva)?;
            if raw.iter().all(|byte| *byte == 0) {
                break;
            }
            let attrs = read_u32_field(&raw, 0, descriptor_rva)?;
            let uses_rvas = attrs & 1 != 0;
            let name_rva =
                self.delay_field_to_rva(read_u32_field(&raw, 4, descriptor_rva)?, uses_rvas)?;
            let iat_rva =
                self.delay_field_to_rva(read_u32_field(&raw, 12, descriptor_rva)?, uses_rvas)?;
            let int_rva =
                self.delay_field_to_rva(read_u32_field(&raw, 16, descriptor_rva)?, uses_rvas)?;
            if name_rva == 0 || iat_rva == 0 || int_rva == 0 {
                return Err(ImageError::DelayImport {
                    rva: descriptor_rva,
                    context: "descriptor has a zero name, IAT, or INT address".to_string(),
                });
            }
            let dll = self.read_ascii_cstr_at_rva(name_rva)?.to_string();
            let pointer_size = if self.architecture == Architecture::X64 {
                8
            } else {
                4
            };

            let mut terminated = false;
            for import_index in 0..MAX_DELAY_IMPORTS {
                let relative = u64::try_from(import_index)
                    .ok()
                    .and_then(|value| value.checked_mul(pointer_size))
                    .ok_or(ImageError::AddressOverflow {
                        format: ImageFormat::Pe,
                        context: "delay import thunk",
                    })?;
                let thunk_rva =
                    int_rva
                        .checked_add(relative)
                        .ok_or(ImageError::AddressOverflow {
                            format: ImageFormat::Pe,
                            context: "delay import thunk",
                        })?;
                let value = self.read_pointer_at_rva(thunk_rva)?;
                if value == 0 {
                    terminated = true;
                    break;
                }
                let ordinal_mask = if pointer_size == 8 {
                    1u64 << 63
                } else {
                    1u64 << 31
                };
                let symbol = if value & ordinal_mask != 0 {
                    // Same ordinal database the main import table is named
                    // from: vivisect's PE parser resolves delay-load ordinals
                    // through `PE/ordlookup` exactly as it does bound ones, so
                    // a delay-imported `ws2_32` ordinal 6 is `getsockname`
                    // upstream, not `#6`. Naming only the main table left
                    // every `api:` feature behind a delay-loaded ordinal
                    // import unresolvable.
                    let ordinal = u16::try_from(value & 0xffff).unwrap_or(u16::MAX);
                    resolve_pe_ordinal(&dll, ordinal)
                        .map_or_else(|| format!("#{ordinal}"), str::to_string)
                } else {
                    let hint_name_rva = self.delay_field_to_rva(value, uses_rvas)?;
                    self.read_ascii_cstr_at_rva(hint_name_rva.checked_add(2).ok_or(
                        ImageError::AddressOverflow {
                            format: ImageFormat::Pe,
                            context: "delay import hint/name",
                        },
                    )?)?
                    .to_string()
                };
                let binding_rva =
                    iat_rva
                        .checked_add(relative)
                        .ok_or(ImageError::AddressOverflow {
                            format: ImageFormat::Pe,
                            context: "delay IAT binding",
                        })?;
                let address = self.image_base.checked_add(binding_rva).ok_or(
                    ImageError::AddressOverflow {
                        format: ImageFormat::Pe,
                        context: "delay IAT binding",
                    },
                )?;
                // see the main-import binding site above: `include_dll:
                // false` matches `viv/insn.py`'s insn-scope `api:` feature,
                // not the file-scope `Import` feature.
                self.add_external_binding(address, generate_symbols(&dll, &symbol, false));
                self.import_locations
                    .insert(address, import_location_name(&dll, &symbol));
            }
            if !terminated {
                return Err(ImageError::DelayImport {
                    rva: int_rva,
                    context: format!(
                        "import thunk count exceeds limit {MAX_DELAY_IMPORTS} without a terminator"
                    ),
                });
            }
        }
        Ok(())
    }

    fn delay_field_to_rva(&self, value: u64, uses_rvas: bool) -> Result<u64, ImageError> {
        if uses_rvas {
            Ok(value)
        } else {
            value
                .checked_sub(self.image_base)
                .ok_or_else(|| ImageError::DelayImport {
                    rva: value,
                    context: "VA lies below the image base".to_string(),
                })
        }
    }

    fn read_pointer_at_rva(&self, rva: u64) -> Result<u64, ImageError> {
        if self.architecture == Architecture::X64 {
            Ok(u64::from_le_bytes(self.read_array_at_rva::<8>(rva)?))
        } else {
            Ok(u64::from(u32::from_le_bytes(
                self.read_array_at_rva::<4>(rva)?,
            )))
        }
    }

    fn read_array_at_rva<const N: usize>(&self, rva: u64) -> Result<[u8; N], ImageError> {
        let address = self
            .image_base
            .checked_add(rva)
            .ok_or(ImageError::AddressOverflow {
                format: ImageFormat::Pe,
                context: "RVA read",
            })?;
        let bytes = self
            .bytes_at(address, N)
            .ok_or_else(|| ImageError::DelayImport {
                rva,
                context: format!("cannot read {N} mapped bytes"),
            })?;
        bytes.try_into().map_err(|_| ImageError::DelayImport {
            rva,
            context: format!("expected {N} bytes, found {}", bytes.len()),
        })
    }

    fn read_ascii_cstr_at_rva(&self, rva: u64) -> Result<&str, ImageError> {
        let address = self
            .image_base
            .checked_add(rva)
            .ok_or(ImageError::AddressOverflow {
                format: ImageFormat::Pe,
                context: "string RVA",
            })?;
        let section = self
            .section_containing(address)
            .ok_or(ImageError::DelayImport {
                rva,
                context: "string is outside mapped sections".to_string(),
            })?;
        let relative = address
            .checked_sub(section.address)
            .ok_or(ImageError::AddressOverflow {
                format: ImageFormat::Pe,
                context: "string section offset",
            })?;
        let remaining =
            usize::try_from(section.file_size.saturating_sub(relative)).unwrap_or(usize::MAX);
        let bytes = self
            .bytes_at(address, remaining)
            .ok_or(ImageError::DelayImport {
                rva,
                context: "string is not file-backed".to_string(),
            })?;
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ImageError::DelayImport {
                rva,
                context: "unterminated string".to_string(),
            })?;
        let value = std::str::from_utf8(bytes.get(..end).ok_or(ImageError::DelayImport {
            rva,
            context: "invalid string range".to_string(),
        })?)
        .map_err(|error| ImageError::DelayImport {
            rva,
            context: format!("non-UTF-8 string: {error}"),
        })?;
        if !value.is_ascii() {
            return Err(ImageError::DelayImport {
                rva,
                context: "non-ASCII string".to_string(),
            });
        }
        Ok(value)
    }
}

fn read_u32_field(raw: &[u8; 32], offset: usize, rva: u64) -> Result<u64, ImageError> {
    let end = offset.checked_add(4).ok_or(ImageError::DelayImport {
        rva,
        context: "descriptor field offset overflow".to_string(),
    })?;
    let bytes = raw.get(offset..end).ok_or(ImageError::DelayImport {
        rva,
        context: "descriptor field is truncated".to_string(),
    })?;
    Ok(u64::from(u32::from_le_bytes(bytes.try_into().map_err(
        |_| ImageError::DelayImport {
            rva,
            context: "descriptor field has the wrong width".to_string(),
        },
    )?)))
}

/// `mach_header_64`: magic, cputype, cpusubtype, filetype, ncmds,
/// sizeofcmds, flags, reserved -- eight `u32` fields (`mach-o/loader.h`).
const MACHO_HEADER_64_SIZE: u64 = 32;
/// `dyld_chained_starts_in_image.seg_count` is a `u32`; a real image never
/// has more than a handful of `LC_SEGMENT_64`s, so this is a generous but
/// finite bound against a malformed count driving an unbounded read loop.
const MAX_MACHO_FIXUP_SEGMENTS: u32 = 256;
/// Bind/rebase chain walk step cap, mirroring this file's other untrusted-
/// input loop bounds (`MAX_DELAY_IMPORTS` etc.) -- a real chain is at most
/// one entry per pointer-sized slot in a segment, which for any fixture or
/// realistic sample is orders of magnitude below this.
const MAX_MACHO_CHAIN_STEPS: usize = 1_000_000;

/// `x86_64`/`arm64`/`arm64e`/... names for [`ImageError::NoCompatibleMachoSlice`]
/// and `--arch` matching. `x86_64`, `arm64` and `arm64e`
/// are *supported* slices ([`SUPPORTED_MACHO_ARCHES`]) -- this still names
/// the others so a fat binary's error lists what it actually contains.
fn macho_cputype_name(cputype: u32) -> &'static str {
    use goblin::mach::constants::cputype::{CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_I386};
    match cputype {
        CPU_TYPE_X86_64 => "x86_64",
        CPU_TYPE_ARM64 => "arm64",
        CPU_TYPE_ARM => "arm",
        CPU_TYPE_I386 => "i386",
        _ => "unknown",
    }
}

/// The architecture names the loader accepts for `--arch` and auto-selection;
/// anything else (`arm`, `i386`, `arm64_32`, ...) is named in
/// an error message but never selected. `arm64`/`arm64e` are cputype
/// `CPU_TYPE_ARM64` distinguished only by cpusubtype --
/// pinned Vivisect never loaded Mach-O at all, so both decode identically
/// through `disarm64` (`Architecture::AArch64`); pac*/aut* instructions are
/// flow-neutral either way (no cryptographic modelling).
const SUPPORTED_MACHO_ARCHES: [&str; 3] = ["x86_64", "arm64", "arm64e"];

/// Like [`macho_cputype_name`] but distinguishes `arm64` from `arm64e` by
/// cpusubtype (`CPU_SUBTYPE_ARM64_E`), matching Apple's own naming
/// (`goblin::mach::constants::cputype::get_arch_name_from_types`, the same
/// table `lipo -detailed_info`/`file` read from). `cpusubtype` must already
/// have `CPU_SUBTYPE_MASK`'s feature-flag byte cleared -- both
/// [`FatArch::cpusubtype`] and [`goblin::mach::header::Header::cpusubtype`]
/// do this themselves; [`peek_macho_cpusubtype`] (the pre-parse path) does
/// it explicitly.
fn macho_arch_name(cputype: u32, cpusubtype: u32) -> &'static str {
    goblin::mach::constants::cputype::get_arch_name_from_types(cputype, cpusubtype)
        .unwrap_or_else(|| macho_cputype_name(cputype))
}

fn cstr16(raw: &[u8; 16]) -> String {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(16);
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Peeks `mach_header_64.cputype` without a full [`MachO::parse`], for slice
/// selection (which must happen *before* deciding whether the rest of the
/// header is even a supported (64-bit, x86_64) Mach-O). `magic_be` is the
/// first 4 bytes read big-endian, as [`select_macho_slice`] already
/// computed: `MH_CIGAM_64` means the file is little-endian on disk (the
/// common case for every real x86_64/arm64 Mach-O), `MH_MAGIC_64` means
/// big-endian.
fn peek_macho_cputype(bytes: &[u8], magic_be: u32) -> Result<u32, ImageError> {
    let raw = bytes
        .get(4..8)
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .ok_or_else(|| ImageError::Macho("truncated Mach-O header".to_string()))?;
    Ok(if magic_be == MH_CIGAM_64 {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

/// Same pre-parse peek as [`peek_macho_cputype`], for `mach_header_64`'s
/// very next field (`cpusubtype`, offset 8) -- needed to distinguish
/// `arm64` from `arm64e` (both `CPU_TYPE_ARM64`) before slice selection
/// decides whether the rest of the header is even worth parsing. The
/// feature-flag byte (`CPU_SUBTYPE_MASK`, e.g. `CPU_SUBTYPE_LIB64` or the
/// arm64e ptrauth-ABI bits) is cleared, matching what
/// `FatArch::cpusubtype`/`Header::cpusubtype` do internally.
fn peek_macho_cpusubtype(bytes: &[u8], magic_be: u32) -> Result<u32, ImageError> {
    use goblin::mach::constants::cputype::CPU_SUBTYPE_MASK;
    let raw = bytes
        .get(8..12)
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .ok_or_else(|| ImageError::Macho("truncated Mach-O header".to_string()))?;
    let cpusubtype = if magic_be == MH_CIGAM_64 {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    };
    Ok(cpusubtype & !CPU_SUBTYPE_MASK)
}

/// Deterministic, host-independent Mach-O slice selection. `arch` explicit
/// (`Some("arm64")`)
/// picks that architecture by name; `None` ("`--arch auto`") takes the
/// first slice in [`SUPPORTED_MACHO_ARCHES`] **in fat-header order** --
/// never by host architecture, so a fat binary selects identically on an M1
/// and an x86 runner, and never by a preference among supported
/// architectures either (a fat binary listing `arm64` before `x86_64`
/// auto-selects `arm64`). A thin (non-fat) input is its own only "slice".
/// Returns the selected slice's raw bytes plus its resolved architecture
/// name, for [`LoadedImage::from_macho`] and the file/global feature
/// extractor (`extract/macho.rs`) to share one selection.
pub fn select_macho_slice<'a>(
    bytes: &'a [u8],
    arch: Option<&str>,
) -> Result<(&'a [u8], &'static str), ImageError> {
    if bytes.len() < 4 {
        return Err(ImageError::Macho(
            "file is too short for a Mach-O magic number".to_string(),
        ));
    }
    let magic_be = u32::from_be_bytes(bytes[0..4].try_into().unwrap_or_default());
    if magic_be == FAT_MAGIC {
        select_fat_macho_slice(bytes, arch)
    } else if magic_be == MH_MAGIC_64 || magic_be == MH_CIGAM_64 {
        let cputype = peek_macho_cputype(bytes, magic_be)?;
        let cpusubtype = peek_macho_cpusubtype(bytes, magic_be)?;
        let name = macho_arch_name(cputype, cpusubtype);
        let supported = SUPPORTED_MACHO_ARCHES.contains(&name);
        if !supported || arch.is_some_and(|requested| requested != name) {
            return Err(ImageError::NoCompatibleMachoSlice {
                requested: arch.unwrap_or("auto").to_string(),
                available: vec![name.to_string()],
            });
        }
        Ok((bytes, name))
    } else {
        Err(ImageError::UnsupportedFormat)
    }
}

/// Manual big-endian field reads (fat headers are always big-endian on
/// disk, regardless of host or slice byte order) rather than pulling in
/// `scroll`'s `Pread` trait just for this one struct -- `FatArch`'s fields
/// are all public, so a plain struct literal is enough.
fn read_fat_arch(bytes: &[u8], offset: usize) -> Result<FatArch, ImageError> {
    let field = |field_offset: usize| -> Result<u32, ImageError> {
        bytes
            .get(field_offset..field_offset.saturating_add(4))
            .and_then(|value| <[u8; 4]>::try_from(value).ok())
            .map(u32::from_be_bytes)
            .ok_or_else(|| ImageError::Macho("truncated fat_arch entry".to_string()))
    };
    Ok(FatArch {
        cputype: field(offset)?,
        cpusubtype: field(offset.saturating_add(4))?,
        offset: field(offset.saturating_add(8))?,
        size: field(offset.saturating_add(12))?,
        align: field(offset.saturating_add(16))?,
    })
}

fn select_fat_macho_slice<'a>(
    bytes: &'a [u8],
    arch: Option<&str>,
) -> Result<(&'a [u8], &'static str), ImageError> {
    if bytes.len() < 8 {
        return Err(ImageError::Macho(
            "file is too short for a fat Mach-O header".to_string(),
        ));
    }
    let nfat_arch = u32::from_be_bytes(bytes[4..8].try_into().unwrap_or_default());
    let arches_len = usize::try_from(nfat_arch)
        .ok()
        .and_then(|count| count.checked_mul(SIZEOF_FAT_ARCH))
        .ok_or_else(|| ImageError::Macho("fat_arch count overflows".to_string()))?;
    if arches_len > bytes.len().saturating_sub(8) {
        return Err(ImageError::Macho(format!(
            "fat header declares {nfat_arch} architectures, which does not fit in the file"
        )));
    }

    let mut available = Vec::with_capacity(usize::try_from(nfat_arch).unwrap_or_default());
    let mut entries: Vec<(FatArch, &'static str)> =
        Vec::with_capacity(usize::try_from(nfat_arch).unwrap_or_default());
    for index in 0..nfat_arch {
        let offset = 8usize.saturating_add((index as usize).saturating_mul(SIZEOF_FAT_ARCH));
        let entry = read_fat_arch(bytes, offset)
            .map_err(|error| ImageError::Macho(format!("parsing fat_arch[{index}]: {error}")))?;
        // Checked loading validates every declared slice's bounds up front,
        // not only the one this call happens to select -- a fat header with
        // any out-of-range `fat_arch` entry is structurally malformed
        // regardless of which architecture a caller asked for.
        let entry_start = usize::try_from(entry.offset).unwrap_or(usize::MAX);
        let entry_in_bounds = entry_start
            .checked_add(usize::try_from(entry.size).unwrap_or(usize::MAX))
            .is_some_and(|end| end <= bytes.len());
        if !entry_in_bounds {
            return Err(ImageError::Macho(format!(
                "fat_arch[{index}] slice [{entry_start:#x}, +{:#x}) is past the end of the file",
                entry.size
            )));
        }
        let name = macho_arch_name(entry.cputype(), entry.cpusubtype());
        available.push(name.to_string());
        entries.push((entry, name));
    }
    // `arch` explicit: the first (fat-header-order) entry matching that
    // exact name, whether or not it is one of `SUPPORTED_MACHO_ARCHES` (an
    // unsupported explicit request always errors, listing what's there).
    // `arch` auto: the first entry whose name is a supported architecture,
    // never a preference among them (the same file-order rule -- a fat binary
    // listing `arm64` before `x86_64` auto-selects
    // `arm64`).
    let selected = match arch {
        Some(requested) if SUPPORTED_MACHO_ARCHES.contains(&requested) => {
            entries.iter().find(|(_, name)| *name == requested)
        }
        Some(_) => None,
        None => entries
            .iter()
            .find(|(_, name)| SUPPORTED_MACHO_ARCHES.contains(name)),
    };
    let Some((entry, resolved_name)) = selected else {
        return Err(ImageError::NoCompatibleMachoSlice {
            requested: arch.unwrap_or("auto").to_string(),
            available,
        });
    };
    let start = usize::try_from(entry.offset).unwrap_or(usize::MAX);
    let end = start
        .checked_add(usize::try_from(entry.size).unwrap_or(usize::MAX))
        .ok_or_else(|| ImageError::Macho("fat_arch offset+size overflows".to_string()))?;
    let slice = bytes.get(start..end).ok_or_else(|| {
        ImageError::Macho(format!(
            "the {resolved_name} fat_arch slice [{start:#x}, {end:#x}) is past the end of the file"
        ))
    })?;
    Ok((slice, resolved_name))
}

/// ADR 0005: `goblin`'s own `MachO::parse` bounds `ncmds` against the whole
/// buffer (`ncmds > sizeofcmds / 8 || sizeofcmds > bytes.len()`) but does not
/// cross-check that the commands it actually reads stay inside
/// `header_size + sizeofcmds` -- the `bad-ncmds` fixture (declared `ncmds`
/// doubled, `sizeofcmds` unchanged) parses without error under that check
/// alone. This closes the gap: every command must immediately follow the
/// previous one (a nonzero, 4-byte-aligned `cmdsize`, advancing validation),
/// and the last one must end at or before the declared boundary.
fn validate_macho_load_commands(macho: &MachO, slice: &[u8]) -> Result<(), ImageError> {
    let limit = MACHO_HEADER_64_SIZE
        .checked_add(u64::from(macho.header.sizeofcmds))
        .ok_or_else(|| ImageError::Macho("sizeofcmds overflow".to_string()))?;
    let mut expected_offset = MACHO_HEADER_64_SIZE;
    for command in &macho.load_commands {
        let offset = u64::try_from(command.offset).unwrap_or(u64::MAX);
        let size = u64::try_from(command.command.cmdsize()).unwrap_or(u64::MAX);
        if size == 0 {
            return Err(ImageError::Macho(format!(
                "load command at offset {offset:#x} has cmdsize 0"
            )));
        }
        if !size.is_multiple_of(4) {
            return Err(ImageError::Macho(format!(
                "load command at offset {offset:#x} has unaligned cmdsize {size}"
            )));
        }
        if offset != expected_offset {
            return Err(ImageError::Macho(format!(
                "load command at offset {offset:#x} does not immediately follow the previous command (expected {expected_offset:#x})"
            )));
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| ImageError::Macho("load command offset+cmdsize overflow".to_string()))?;
        if end > limit {
            return Err(ImageError::Macho(format!(
                "load command at offset {offset:#x} ends at {end:#x}, past the sizeofcmds boundary {limit:#x}"
            )));
        }
        expected_offset = end;
    }
    if usize::try_from(limit).unwrap_or(usize::MAX) > slice.len() {
        return Err(ImageError::Macho(
            "file is shorter than the declared load-command region".to_string(),
        ));
    }
    Ok(())
}

/// ADR 0005's second check: no two `LC_SEGMENT_64`s' `[fileoff, fileoff +
/// filesize)` ranges may overlap (the `overlapping-segments` fixture moves
/// `__DATA_CONST.fileoff` inside `__TEXT`'s range; `goblin` accepts it
/// without complaint).
fn validate_no_overlapping_macho_segments(
    segments: &[(String, u64, u64, u64, u64, u32)],
) -> Result<(), ImageError> {
    for (i, (name_a, _, _, fileoff_a, filesize_a, _)) in segments.iter().enumerate() {
        if *filesize_a == 0 {
            continue;
        }
        let end_a = fileoff_a.checked_add(*filesize_a).ok_or_else(|| {
            ImageError::Macho(format!("segment {name_a} fileoff+filesize overflows"))
        })?;
        for (name_b, _, _, fileoff_b, filesize_b, _) in &segments[i.saturating_add(1)..] {
            if *filesize_b == 0 {
                continue;
            }
            let end_b = fileoff_b.checked_add(*filesize_b).ok_or_else(|| {
                ImageError::Macho(format!("segment {name_b} fileoff+filesize overflows"))
            })?;
            if *fileoff_a < end_b && *fileoff_b < end_a {
                return Err(ImageError::Macho(format!(
                    "segments {name_a} and {name_b} have overlapping file ranges"
                )));
            }
        }
    }
    Ok(())
}

/// Populates `image.import_locations`/`external_bindings` from whichever
/// dyld binding mechanism the slice actually used -- `LC_DYLD_INFO(_ONLY)`
/// classic bind opcodes (which `goblin::mach::MachO::imports()` already
/// decodes) or `LC_DYLD_CHAINED_FIXUPS` (which it does not; see
/// [`parse_macho_chained_fixups`]). A given binary uses exactly one of the
/// two, never both, so trying the classic path first and falling back is
/// enough rather than needing to detect which one up front.
fn load_macho_imports(macho: &MachO, slice: &[u8], image: &mut LoadedImage) {
    if let Ok(imports) = macho.imports() {
        if !imports.is_empty() {
            for import in &imports {
                register_macho_import(image, import.address, import.dylib, import.name);
            }
            return;
        }
    }
    for command in &macho.load_commands {
        if let CommandVariant::DyldChainedFixups(linkedit) = command.command {
            match parse_macho_chained_fixups(
                image,
                slice,
                &macho.libs,
                linkedit.dataoff,
                linkedit.datasize,
            ) {
                Ok(binds) => {
                    for (address, dylib, symbol) in &binds {
                        register_macho_import(image, *address, dylib, symbol);
                    }
                }
                Err(diagnostic) => image.load_diagnostics.push(diagnostic.to_string()),
            }
        }
    }
}

fn register_macho_import(image: &mut LoadedImage, address: u64, dylib: &str, symbol: &str) {
    let symbol = symbol.strip_prefix('_').unwrap_or(symbol);
    let dylib = macho_dylib_short_name(dylib);
    image.add_external_binding(address, vec![symbol.to_string()]);
    image
        .import_locations
        .insert(address, format!("{dylib}.{symbol}"));
}

/// Basename minus a trailing `.dylib`/`.framework` extension. Mach-O has no
/// upstream capa naming convention to match (this format has no Python
/// oracle at all -- see the module-level honesty-constraint doc); this
/// mirrors this file's PE `norm_file_name` in spirit (basename, extension
/// stripped) without adopting its Windows-specific lowercasing.
fn macho_dylib_short_name(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    let base = base.strip_suffix(".dylib").unwrap_or(base);
    base.strip_suffix(".framework").unwrap_or(base).to_string()
}

fn macho_chained_lib_name(libs: &[&str], lib_ordinal: u8) -> String {
    // `dyld_chained_import.lib_ordinal`: 0x00..=0xF0 index `libs` directly
    // (0 is `libs[0]`, "self"/the image's own `LC_ID_DYLIB` name, exactly as
    // `goblin`'s own classic-bind `Import::new` indexes the same vector);
    // 0xF1..=0xFF are the special negative ordinals from `mach-o/loader.h`.
    if lib_ordinal <= 0xF0 {
        return libs
            .get(lib_ordinal as usize)
            .map(|name| (*name).to_string())
            .unwrap_or_else(|| format!("ordinal_{lib_ordinal}"));
    }
    match lib_ordinal {
        0xFF => "main_executable".to_string(),
        0xFE => "flat_lookup".to_string(),
        0xFD => "weak_lookup".to_string(),
        other => format!("special_{other:#x}"),
    }
}

fn read_macho_u16(data: &[u8], offset: usize, context: &str) -> Result<u16, ImageError> {
    data.get(offset..offset.saturating_add(2))
        .and_then(|raw| <[u8; 2]>::try_from(raw).ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| ImageError::Macho(format!("truncated chained-fixups {context}")))
}

fn read_macho_u32(data: &[u8], offset: usize, context: &str) -> Result<u32, ImageError> {
    data.get(offset..offset.saturating_add(4))
        .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| ImageError::Macho(format!("truncated chained-fixups {context}")))
}

fn read_macho_u64(data: &[u8], offset: usize, context: &str) -> Result<u64, ImageError> {
    data.get(offset..offset.saturating_add(8))
        .and_then(|raw| <[u8; 8]>::try_from(raw).ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| ImageError::Macho(format!("truncated chained-fixups {context}")))
}

/// Resolves one `dyld_chained_import` (format `DYLD_CHAINED_IMPORT` == 1;
/// the only format any fixture or corpus sample has needed so far -- the
/// addend variants would need their own field widths added here) to a
/// `(dylib, symbol)` pair.
fn resolve_macho_chained_import(
    chain_data: &[u8],
    libs: &[&str],
    imports_offset: u32,
    symbols_offset: u32,
    ordinal: u32,
) -> Result<(String, String), ImageError> {
    let entry_offset = usize::try_from(imports_offset)
        .ok()
        .and_then(|base| base.checked_add((ordinal as usize).checked_mul(4)?))
        .ok_or_else(|| ImageError::Macho("chained import ordinal overflows".to_string()))?;
    let raw = read_macho_u32(chain_data, entry_offset, "import entry")?;
    // `dyld_chained_import`: `lib_ordinal: 8, weak_import: 1, name_offset:
    // 23` -- a little-endian C bitfield packs the first-declared field into
    // the low bits, so `lib_ordinal` is the low byte and `name_offset` is
    // everything from bit 9 up (`mach-o/fixup-chains.h`).
    let lib_ordinal = (raw & 0xFF) as u8;
    let name_offset = raw >> 9;
    let name_start = usize::try_from(symbols_offset)
        .ok()
        .and_then(|base| base.checked_add(usize::try_from(name_offset).ok()?))
        .ok_or_else(|| ImageError::Macho("chained import name offset overflows".to_string()))?;
    let name = chain_data
        .get(name_start..)
        .and_then(|tail| {
            let end = tail.iter().position(|byte| *byte == 0)?;
            std::str::from_utf8(&tail[..end]).ok()
        })
        .ok_or_else(|| {
            ImageError::Macho("chained import name is not a terminated UTF-8 string".to_string())
        })?;
    Ok((macho_chained_lib_name(libs, lib_ordinal), name.to_string()))
}

/// Reads `LC_DYLD_CHAINED_FIXUPS`, which `goblin` 0.10.7 does not support at
/// all (only classic `LC_DYLD_INFO(_ONLY)` bind opcodes) -- the corpus's
/// "chained fixups if the corpus has them", and the corpus does: every
/// fixture built by a modern (chained-fixups-by-default) toolchain has one
/// instead of `LC_DYLD_INFO`. Ported from Apple's own
/// `mach-o/fixup-chains.h` (`/Library/Developer/CommandLineTools/SDKs/
/// MacOSX.sdk/usr/include/mach-o/fixup-chains.h`), scoped to pointer formats
/// `DYLD_CHAINED_PTR_64` (2) and `DYLD_CHAINED_PTR_64_OFFSET` (6), which
/// share one bind/rebase encoding (12-bit `next`, 4-byte stride).
///
/// Earlier x86_64-only assumptions did not hold for the corpus, and the ARM64e-specific formats
/// (`DYLD_CHAINED_PTR_ARM64E` and its variants, which add pointer-
/// authentication bits) would be needed for a pointer-authenticated target.
/// Verified empirically
/// against the `arm64` fixture corpus (`tests/fixtures/macho/thin-
/// arm64-exe`/`thin-arm64.dylib`, not `arm64e`): plain `arm64` binaries use
/// the *same* `DYLD_CHAINED_PTR_64_OFFSET` format as x86_64 -- pointer
/// format is a linker/deployment-target choice, not a CPU-architecture one.
/// So this reader already covers every fixture and needs no ARM64e-specific
/// pointer format added; a real `arm64e` binary (pointer-authenticated
/// pointers, format 1/9/11/...) would silently resolve zero imports on its
/// chained pages rather than fail -- the same soft-degradation this
/// function already has for `imports_format != 1` below.
fn parse_macho_chained_fixups(
    image: &LoadedImage,
    slice: &[u8],
    libs: &[&str],
    dataoff: u32,
    datasize: u32,
) -> Result<Vec<(u64, String, String)>, ImageError> {
    let base = usize::try_from(dataoff).unwrap_or(usize::MAX);
    let size = usize::try_from(datasize).unwrap_or(usize::MAX);
    let end = base
        .checked_add(size)
        .ok_or_else(|| ImageError::Macho("chained-fixups payload size overflows".to_string()))?;
    let chain_data = slice.get(base..end).ok_or_else(|| {
        ImageError::Macho("LC_DYLD_CHAINED_FIXUPS payload is not file-backed".to_string())
    })?;

    let starts_offset = read_macho_u32(chain_data, 4, "header.starts_offset")?;
    let imports_offset = read_macho_u32(chain_data, 8, "header.imports_offset")?;
    let symbols_offset = read_macho_u32(chain_data, 12, "header.symbols_offset")?;
    let imports_format = read_macho_u32(chain_data, 20, "header.imports_format")?;
    if imports_format != 1 {
        // DYLD_CHAINED_IMPORT only; ..._ADDEND/..._ADDEND64 have wider entry
        // structs this reader does not decode yet -- no fixture needs them.
        return Ok(Vec::new());
    }

    let starts_base = usize::try_from(starts_offset).unwrap_or(usize::MAX);
    let seg_count = read_macho_u32(chain_data, starts_base, "starts_in_image.seg_count")?;
    if seg_count > MAX_MACHO_FIXUP_SEGMENTS {
        return Err(ImageError::Macho(format!(
            "chained-fixups seg_count {seg_count} exceeds limit {MAX_MACHO_FIXUP_SEGMENTS}"
        )));
    }

    let mut binds = Vec::new();
    let mut steps = 0usize;
    for seg_index in 0..seg_count {
        let seg_info_field = starts_base
            .saturating_add(4)
            .saturating_add((seg_index as usize).saturating_mul(4));
        let seg_info_offset = read_macho_u32(
            chain_data,
            seg_info_field,
            "starts_in_image.seg_info_offset",
        )?;
        if seg_info_offset == 0 {
            continue;
        }
        let seg_start = starts_base.saturating_add(seg_info_offset as usize);
        let page_size = read_macho_u16(
            chain_data,
            seg_start.saturating_add(4),
            "starts_in_segment.page_size",
        )?;
        let pointer_format = read_macho_u16(
            chain_data,
            seg_start.saturating_add(6),
            "starts_in_segment.pointer_format",
        )?;
        let segment_offset = read_macho_u64(
            chain_data,
            seg_start.saturating_add(8),
            "starts_in_segment.segment_offset",
        )?;
        let page_count = read_macho_u16(
            chain_data,
            seg_start.saturating_add(20),
            "starts_in_segment.page_count",
        )?;
        if page_size == 0 || !matches!(pointer_format, 2 | 6) {
            // Only DYLD_CHAINED_PTR_64/_64_OFFSET are in scope for an x86_64
            // slice (see this function's doc comment); skip anything else
            // rather than mis-decoding it as that layout.
            continue;
        }
        for page in 0..page_count {
            let page_start_field = seg_start
                .saturating_add(22)
                .saturating_add((page as usize).saturating_mul(2));
            let page_start =
                read_macho_u16(chain_data, page_start_field, "starts_in_segment.page_start")?;
            if page_start == 0xFFFF {
                continue;
            }
            let mut va = image
                .image_base
                .wrapping_add(segment_offset)
                .wrapping_add(u64::from(page).wrapping_mul(u64::from(page_size)))
                .wrapping_add(u64::from(page_start));
            loop {
                steps = steps.saturating_add(1);
                if steps > MAX_MACHO_CHAIN_STEPS {
                    return Err(ImageError::Macho(
                        "chained-fixups walk exceeded the step limit".to_string(),
                    ));
                }
                let Some(raw) = image.bytes_at(va, 8) else {
                    break;
                };
                let Ok(raw) = <[u8; 8]>::try_from(raw) else {
                    break;
                };
                let value = u64::from_le_bytes(raw);
                let bind = (value >> 63) & 1;
                let next = (value >> 51) & 0xFFF;
                if bind == 1 {
                    let ordinal = (value & 0x00FF_FFFF) as u32;
                    if let Ok((dylib, symbol)) = resolve_macho_chained_import(
                        chain_data,
                        libs,
                        imports_offset,
                        symbols_offset,
                        ordinal,
                    ) {
                        binds.push((va, dylib, symbol));
                    }
                }
                if next == 0 {
                    break;
                }
                va = va.wrapping_add(next.wrapping_mul(4));
            }
        }
    }
    Ok(binds)
}

/// Test-only constructor for other test modules (feature
/// extraction) that need a hand-built image rather than a real PE/ELF byte
/// buffer -- e.g. several disjoint code/data sections at addresses chosen
/// to make a specific extractor's inputs obvious.
#[cfg(test)]
impl LoadedImage {
    pub(crate) fn for_test(
        format: ImageFormat,
        architecture: Architecture,
        image_base: u64,
        sections: Vec<MappedSection>,
        external_bindings: BTreeMap<u64, Vec<String>>,
        bytes: Vec<u8>,
    ) -> Self {
        let mapped_bytes = sections
            .iter()
            .map(|section| {
                let start = usize::try_from(section.file_offset).unwrap_or(usize::MAX);
                let len = usize::try_from(section.file_size).unwrap_or(0);
                let end = start.saturating_add(len);
                bytes.get(start..end).unwrap_or_default().to_vec()
            })
            .collect();
        let primary_code = sections
            .iter()
            .filter(|section| section.permissions.execute)
            .filter_map(|section| Some((section.address, section.end_address()?)))
            .collect();
        Self {
            format,
            architecture,
            image_base,
            load_bias: 0,
            entry_point: Some(image_base),
            sections,
            external_bindings,
            import_locations: BTreeMap::new(),
            load_diagnostics: Vec::new(),
            dead_data: Vec::new(),
            uninitialized: Vec::new(),
            primary_code,
            mapped_bytes,
        }
    }

    /// Register an IAT/GOT slot under the Vivisect `makeImport` name form, so
    /// a hand-built image can exercise import-driven analysis (no-return APIs,
    /// thunk classification) without a real import directory.
    pub(crate) fn with_import_location(mut self, address: u64, name: &str) -> Self {
        self.import_locations.insert(address, name.to_string());
        self
    }
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 {
        return Some(value);
    }
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|sum| sum / alignment * alignment)
}

fn mapped_region(
    bytes: &[u8],
    file_offset: u64,
    file_size: u64,
    mapped_size: u64,
    format: ImageFormat,
) -> Result<Vec<u8>, ImageError> {
    let mapped_len = usize::try_from(mapped_size).map_err(|_| ImageError::Mapping {
        format,
        context: format!("region size {mapped_size:#x} does not fit in memory"),
    })?;
    if mapped_len > MAX_MAPPED_IMAGE_BYTES {
        return Err(ImageError::Mapping {
            format,
            context: format!(
                "region size {mapped_size:#x} exceeds limit {MAX_MAPPED_IMAGE_BYTES:#x}"
            ),
        });
    }
    let start = usize::try_from(file_offset).unwrap_or(usize::MAX);
    let requested = usize::try_from(file_size).unwrap_or(usize::MAX);
    let available = bytes.len().saturating_sub(start);
    let copy_len = requested.min(available).min(mapped_len);
    let mut mapped = vec![0; mapped_len];
    if copy_len != 0 {
        let source_end = start.saturating_add(copy_len);
        if let (Some(source), Some(destination)) =
            (bytes.get(start..source_end), mapped.get_mut(..copy_len))
        {
            destination.copy_from_slice(source);
        }
    }
    Ok(mapped)
}

fn account_mapping(total: &mut usize, size: usize) -> Result<(), ImageError> {
    *total = total
        .checked_add(size)
        .ok_or_else(|| ImageError::Pe("mapped image size overflow".to_string()))?;
    if *total > MAX_MAPPED_IMAGE_BYTES {
        return Err(ImageError::Pe(format!(
            "mapped image size {total:#x} exceeds limit {MAX_MAPPED_IMAGE_BYTES:#x}"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn synthetic_image(bytes: Vec<u8>, permissions: Permissions) -> LoadedImage {
        LoadedImage {
            format: ImageFormat::Pe,
            architecture: Architecture::X64,
            image_base: 0x1000,
            load_bias: 0,
            entry_point: Some(0x1000),
            sections: vec![MappedSection {
                name: ".text".to_string(),
                address: 0x1000,
                virtual_size: bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len() as u64,
                permissions,
            }],
            external_bindings: BTreeMap::new(),
            import_locations: BTreeMap::new(),
            load_diagnostics: Vec::new(),
            dead_data: Vec::new(),
            uninitialized: Vec::new(),
            primary_code: vec![(0x1000, 0x1000u64.saturating_add(bytes.len() as u64))],
            mapped_bytes: vec![bytes],
        }
    }

    #[test]
    fn truncated_instruction_is_a_contextual_error() {
        let image = synthetic_image(
            vec![0x48, 0x8b],
            Permissions {
                read: true,
                write: false,
                execute: true,
            },
        );
        let error = image
            .decode_at(0x1000)
            .expect_err("instruction is truncated");
        assert!(matches!(
            error,
            ImageError::InvalidInstruction {
                address: 0x1000,
                ..
            }
        ));
        assert!(error.to_string().contains("truncated instruction"));
    }

    /// envi's own fixture (`envi/tests/test_arch_i386.py:222`):
    /// `0F3F070B` -> `vpcext 7,11`, four bytes, two immediate operands.
    /// `PE/ordlookup/__init__.py` maps `wsock32.dll` at `ws2_32.ord_names`;
    /// pefile keeps a separate `wsock32` table that shifts 10/11/12. Getting
    /// this wrong named `wsock32` ordinal 10 `inet_addr`, and cost
    /// `set socket configuration` on `74fa32d2b277f583010b692a3f91b627.exe_`.
    #[test]
    fn wsock32_ordinals_resolve_against_the_ws2_32_table() {
        assert_eq!(resolve_pe_ordinal("WSOCK32.dll", 10), Some("ioctlsocket"));
        assert_eq!(resolve_pe_ordinal("ws2_32.dll", 10), Some("ioctlsocket"));
        assert_eq!(resolve_pe_ordinal("WSOCK32.dll", 11), Some("inet_addr"));
        assert_eq!(resolve_pe_ordinal("wsock32", 116), Some("WSACleanup"));
        assert_eq!(resolve_pe_ordinal("wsock32.dll", 9999), None);
        assert_eq!(resolve_pe_ordinal("kernel32.dll", 10), None);
    }

    #[test]
    fn decodes_vpcext_the_way_envi_does() {
        let image = synthetic_image(
            vec![0x0f, 0x3f, 0x07, 0x0b, 0x90],
            Permissions {
                read: true,
                write: false,
                execute: true,
            },
        );
        let insn = image.decode_at(0x1000).expect("vpcext decodes");
        assert_eq!(insn.mnemonic_override, Some("vpcext"));
        assert_eq!(insn.bytes, vec![0x0f, 0x3f, 0x07, 0x0b]);
        assert_eq!(insn.x86_instruction().len(), 4);
        assert_eq!(insn.flow, super::super::decoder::Flow::Next);
        assert_eq!(insn.x86_instruction().op_count(), 2);
        assert_eq!(
            super::super::operand::classify_operand(insn.x86_instruction(), 0),
            super::super::operand::Operand::Imm(7)
        );
        assert_eq!(
            super::super::operand::classify_operand(insn.x86_instruction(), 1),
            super::super::operand::Operand::Imm(11)
        );
        // and the following instruction is still reachable, which is the
        // point: an undecodable `0F 3F` truncates the whole function.
        assert!(image.decode_at(0x1004).is_ok());
    }

    /// A `0F 3F` with fewer than two trailing immediate bytes in the mapping
    /// is still an error -- envi would not decode it either.
    #[test]
    fn truncated_vpcext_stays_an_error() {
        let image = synthetic_image(
            vec![0x0f, 0x3f, 0x07],
            Permissions {
                read: true,
                write: false,
                execute: true,
            },
        );
        assert!(matches!(
            image.decode_at(0x1000),
            Err(ImageError::InvalidInstruction {
                address: 0x1000,
                ..
            })
        ));
    }

    #[test]
    fn decoder_rejects_non_executable_mapping() {
        let image = synthetic_image(
            vec![0x90],
            Permissions {
                read: true,
                write: true,
                execute: false,
            },
        );
        assert!(matches!(
            image.decode_at(0x1000),
            Err(ImageError::AddressNotExecutable { address: 0x1000 })
        ));
    }

    #[test]
    fn sparse_test_mapping_does_not_invent_zero_fill() {
        let mut image = synthetic_image(
            vec![0x90],
            Permissions {
                read: true,
                write: false,
                execute: true,
            },
        );
        image.sections[0].virtual_size = 4;
        assert!(image.section_containing(0x1002).is_some());
        assert_eq!(image.va_to_file_offset(0x1002), None);
        assert!(matches!(
            image.decode_at(0x1002),
            Err(ImageError::AddressNotMapped { address: 0x1002 })
        ));
    }
}
