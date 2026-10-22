//! Optional, serial, in-process x86 and x86-64 PE decompilation.
//!
//! A session owns one image and its native SLEIGH translator. Reuse it for
//! explicit function requests. Native failures poison the session; construct
//! a new session after such an error. Invalid Rust requests do not poison it.
use std::collections::BTreeMap;
use std::time::Instant;

use serde::Serialize;

/// Scalar and pointer types accepted by explicit function signatures.
pub use capa_x_ghidra::ValueType;

use crate::extract::decoder::Flow;
use crate::extract::image::{Architecture, ImageFormat, LoadedImage};
use crate::extract::recovery::flirt::{self, Signatures};
use crate::extract::recovery::{self, Analysis};
use crate::fid;

mod effects;

/// Ghidra 12.1.4 Function ID data for x64 and x86 Visual Studio runtimes; see `sigs/FID.md`.
static FID_PACK_X64: &[u8] = include_bytes!("../sigs/fid-x64.pack");
static FID_PACK_X86: &[u8] = include_bytes!("../sigs/fid-x86.pack");

#[derive(Debug, thiserror::Error)]
pub enum DecompileError {
    #[error("decompilation supports only native x86 and x86-64 PE images: {0}")]
    Unsupported(String),
    #[error("preparing decompiler image: {0}")]
    Input(String),
    #[error("invalid decompilation request: {0}")]
    Request(String),
    #[error("initializing native decompiler: {0}")]
    Initialization(String),
    #[error("decompiling function {address:#x}: {message}")]
    Native { address: u64, message: String },
}

/// Local safety policy, not constants copied from upstream. Deadlines are
/// cooperative: checked during translation, allocation and action processing.
#[derive(Clone, Copy, Debug)]
pub struct ResourceLimits {
    pub timeout_ms: u32,
    pub max_instructions: u32,
    pub max_work: u32,
}
impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout_ms: 5_000,
            max_instructions: 10_000,
            max_work: 2_000_000,
        }
    }
}

/// Windows x64 uses Ghidra's x86-64-win.cspec default __fastcall model. Windows x86
/// has several conventions; `x86win.cspec` defaults to __stdcall with the stack
/// purge inferred per function, and the packed archives name each import's own.
#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallingConvention {
    #[default]
    WindowsX64,
    WindowsX86,
}
impl CallingConvention {
    fn of(architecture: Architecture) -> Self {
        match architecture {
            Architecture::X86 => Self::WindowsX86,
            _ => Self::WindowsX64,
        }
    }
    fn wide(self) -> bool {
        matches!(self, Self::WindowsX64)
    }
}

#[derive(Debug, Serialize)]
pub struct DecompilationTimings {
    /// Session preparation, recorded once. `from_pe` includes recovery and
    /// library recognition; `from_analysis` includes only native adapter setup.
    pub initialization_ms: f64,
    pub decompilation_ms: f64,
}

/// Separate from capa's capability result document.
#[derive(Debug, Serialize)]
pub struct Decompilation {
    pub address: u64,
    pub name: Option<String>,
    pub calling_convention: CallingConvention,
    pub text: String,
    pub warnings: Vec<String>,
    /// Any gap: a native error or warning, or a load diagnostic.
    pub incomplete: bool,
    /// At least one callee has no known prototype, so call arguments and return
    /// values may be missing. This is the usual reason for `incomplete`; when it is
    /// the only one, the control flow and data flow of the function itself are sound.
    pub unknown_callees: bool,
    pub timings: DecompilationTimings,
}

pub struct DecompilerSession {
    native: capa_x_ghidra::Session,
    executable_ranges: Vec<(u64, u64)>,
    names: BTreeMap<u64, String>,
    warnings: Vec<String>,
    initialization_ms: f64,
    limits: ResourceLimits,
    convention: CallingConvention,
}
impl DecompilerSession {
    /// Parse and recover once. Native SLEIGH, not iced-x86, translates the
    /// requested function. Existing callers can avoid recovery via from_analysis.
    pub fn from_pe(bytes: &[u8]) -> Result<Self, DecompileError> {
        let started = Instant::now();
        // A malformed import directory only costs the imports, with a warning.
        let image =
            LoadedImage::parse_partial(bytes).map_err(|e| DecompileError::Input(e.to_string()))?;
        validate_image(&image)?;
        let image_base = image.image_base;
        let imports_skipped = image.imports_skipped;
        drop(image);
        let mut options = goblin::pe::options::ParseOptions::default();
        options.parse_mode = goblin::options::ParseMode::Permissive;
        options.parse_tls_data = false;
        options.parse_resources = false;
        options.parse_attribute_certificates = false;
        options.parse_imports = !imports_skipped;
        let pe = goblin::pe::PE::parse_with_opts(bytes, &options)
            .map_err(|e| DecompileError::Input(e.to_string()))?;
        if pe
            .header
            .optional_header
            .as_ref()
            .is_some_and(|h| h.data_directories.get_clr_runtime_header().is_some())
        {
            return Err(DecompileError::Unsupported("managed PE image".into()));
        }
        let analysis = recovery::analyze_partial_pe(bytes)
            .map_err(|e| DecompileError::Input(e.to_string()))?;
        let convention = CallingConvention::of(analysis.image.architecture);
        let wide = convention.wide();
        let signatures =
            Signatures::decompiler_runtime().map_err(|e| DecompileError::Input(e.to_string()))?;
        let libraries = flirt::identify_library_functions(&analysis, &signatures)
            .map_err(|e| DecompileError::Input(e.to_string()))?;
        let mut names = libraries.clone();
        for export in &pe.exports {
            if export.reexport.is_none() {
                if let Some(name) = export.name {
                    let address = image_base
                        .checked_add(export.rva as u64)
                        .ok_or_else(|| DecompileError::Input("export address overflow".into()))?;
                    names.insert(address, name.to_owned());
                }
            }
        }
        // A function that is only `jmp [import slot]` is the import under another address;
        // Ghidra names such a thunk after the import and types it the same way.
        let thunks = import_thunks(&analysis);
        for (address, name) in &thunks {
            names.entry(*address).or_insert_with(|| name.clone());
        }
        let export_addresses: Vec<(u64, String)> = names
            .iter()
            .filter(|(address, _)| {
                pe.exports.iter().any(|export| {
                    export.reexport.is_none()
                        && image_base.checked_add(export.rva as u64) == Some(**address)
                })
            })
            .map(|(address, name)| (*address, name.clone()))
            .collect();
        let dll_entry = pe.is_lib.then_some(analysis.image.entry_point).flatten();
        if let Some(entry) = dll_entry {
            names.entry(entry).or_insert_with(|| "DllEntryPoint".into());
        }
        let pack = fid::pack::Pack::parse(if wide { FID_PACK_X64 } else { FID_PACK_X86 })
            .map_err(|e| DecompileError::Input(e.to_string()))?;
        let (recognized, conflicts) =
            fid::names::name_functions_with_conflicts(&analysis, &pack, &|address| {
                names.contains_key(&address)
            });
        for (address, name) in &recognized {
            names.insert(*address, name.clone());
        }
        let mut session = Self::from_analysis(&analysis, &names, convention)?;
        for (address, name) in &recognized {
            // Naming a runtime function also types it when the archives know it.
            session
                .native
                .apply_prototype(*address, name)
                .map_err(|error| {
                    DecompileError::Initialization(format!(
                        "prototype for {name} at {address:#x}: {error}"
                    ))
                })?;
        }
        for (address, import) in &thunks {
            if let Some(function) = system_import_function(import) {
                session.native.apply_prototype(*address, function).map_err(|error| {
                    DecompileError::Initialization(format!(
                        "prototype for thunk {import} at {address:#x}: {error}"
                    ))
                })?;
            }
        }
        // Ghidra also types a function by its exported name when the archives know it
        // (a proxy DLL's `GetFileVersionInfoA`). An unknown name keeps the generic prototype.
        for (address, name) in &export_addresses {
            // Decorated C++ names never match an archive function, and the lookup key is bounded.
            let plain = name.len() <= 256 && !name.contains(['?', '@']);
            if plain && !thunks.contains_key(address) && !recognized.contains_key(address) {
                session.native.apply_prototype(*address, name).map_err(|error| {
                    DecompileError::Initialization(format!(
                        "prototype for export {name} at {address:#x}: {error}"
                    ))
                })?;
            }
        }
        for (address, name) in &libraries {
            // Apply runtime prototypes only to validated FLIRT matches.
            let prototype = match name.trim_start_matches('_') {
                "security_init_cookie" => Some((ValueType::Void, vec![])),
                "security_check_cookie" if wide => Some((ValueType::Void, vec![ValueType::U64])),
                "DllMainCRTStartup" | "DllMain" => Some((
                    ValueType::I32,
                    vec![ValueType::Pointer, ValueType::U32, ValueType::Pointer],
                )),
                _ => None,
            };
            if let Some((result, parameters)) = prototype {
                session.set_signature(*address, result, &parameters)?;
            }
        }
        // Effect models need a name from a validated source, FLIRT or Function ID.
        // An export is only a claim by the image, so it never selects a model.
        for (address, name) in libraries.iter().chain(recognized.iter()) {
            if let Some(fixup) = effects::call_fixup(name, wide) {
                session
                    .native
                    .set_call_fixup(*address, fixup)
                    .map_err(|error| {
                        DecompileError::Initialization(format!(
                            "{fixup} fixup for {name} at {address:#x}: {error}"
                        ))
                    })?;
            }
        }
        // Ghidra labels an ambiguous match `FID_conflict:<name>` for every candidate, and its
        // fixups list those labels. Here a function is left unnamed, but when every candidate
        // selects the same fixup (`__SEH_prolog4` and `__SEH_prolog4_GS`), the effect is known.
        for (address, candidates) in &conflicts {
            let mut fixups = candidates.iter().map(|name| effects::call_fixup(name, wide));
            if let Some(Some(fixup)) = fixups.next() {
                if fixups.all(|other| other == Some(fixup)) {
                    session
                        .native
                        .set_call_fixup(*address, fixup)
                        .map_err(|error| {
                            DecompileError::Initialization(format!(
                                "{fixup} fixup for {candidates:?} at {address:#x}: {error}"
                            ))
                        })?;
                }
            }
        }
        if let Some(entry) = dll_entry {
            session.set_signature(
                entry,
                ValueType::I32,
                &[ValueType::Pointer, ValueType::U32, ValueType::Pointer],
            )?;
        }
        session.initialization_ms = started.elapsed().as_secs_f64() * 1000.0;
        Ok(session)
    }

    /// Reuse capa-x's loaded bytes, recovered entry points and no-return set.
    /// `names` can supply exports, FLIRT or caller-provided symbols.
    pub fn from_analysis(
        analysis: &Analysis,
        names: &BTreeMap<u64, String>,
        convention: CallingConvention,
    ) -> Result<Self, DecompileError> {
        let started = Instant::now();
        let image = &analysis.image;
        validate_image(image)?;
        let wide = image.architecture == Architecture::X64;
        if convention.wide() != wide {
            return Err(DecompileError::Request(format!(
                "{convention:?} does not match the {:?} image",
                image.architecture
            )));
        }
        let init = |e: capa_x_ghidra::Error| DecompileError::Initialization(e.to_string());
        let mut native = capa_x_ghidra::Session::new(wide).map_err(init)?;
        let mut executable_ranges = Vec::new();
        for section in &image.sections {
            if section.virtual_size == 0 {
                continue;
            }
            let size = usize::try_from(section.virtual_size)
                .map_err(|_| DecompileError::Input("section size overflow".into()))?;
            let bytes = image.bytes_at(section.address, size).ok_or_else(|| {
                DecompileError::Input(format!("unmapped section at {:#x}", section.address))
            })?;
            if bytes.len() != size {
                return Err(DecompileError::Input(format!(
                    "truncated mapped section at {:#x}",
                    section.address
                )));
            }
            let end = section
                .address
                .checked_add(section.virtual_size)
                .ok_or_else(|| DecompileError::Input("section address overflow".into()))?;
            // Native import registration clears read-only only on each IAT
            // slot, retaining constants and strings elsewhere in the section.
            native
                .add_section(
                    section.address,
                    bytes,
                    section.permissions.execute,
                    !section.permissions.write,
                )
                .map_err(init)?;
            if section.permissions.execute {
                executable_ranges.push((section.address, end));
            }
        }
        for address in analysis.functions.keys().chain(names.keys()) {
            let name = names
                .get(address)
                .cloned()
                .unwrap_or_else(|| format!("FUN_{address:x}"));
            native
                .add_function(*address, &name, analysis.noreturn.contains(address))
                .map_err(init)?;
        }
        for (address, name) in &image.import_locations {
            native
                .add_import(*address, name, analysis.noreturn.contains(address))
                .map_err(init)?;
            if let Some(function) = system_import_function(name) {
                // Unknown names are fine: the call keeps its warning.
                native.apply_prototype(*address, function).map_err(init)?;
            }
        }
        for (caller, function) in &analysis.functions {
            for block in &function.blocks {
                for insn in &block.insns {
                    // Preserve direct jumps to separate recovered entries and
                    // IAT jump thunks. Self-loops and local branches stay flow.
                    let target = match insn.flow {
                        Flow::UnconditionalBranch => insn.direct_target.filter(|target| {
                            target != caller && analysis.functions.contains_key(target)
                        }),
                        Flow::IndirectBranch => insn
                            .memory_target
                            .filter(|target| image.import_locations.contains_key(target)),
                        _ => None,
                    };
                    if let Some(target) = target {
                        native
                            .add_tail_call(*caller, insn.address, target)
                            .map_err(init)?;
                    }
                }
            }
        }
        let mut warnings = image.load_diagnostics.clone();
        // Discovery diagnostics describe the independent iced-x86 graph.
        // Keep them on Analysis; Ghidra reports its own unresolved flow.
        warnings.sort();
        warnings.dedup();
        Ok(Self {
            native,
            executable_ranges,
            names: names.clone(),
            warnings,
            initialization_ms: started.elapsed().as_secs_f64() * 1000.0,
            limits: ResourceLimits::default(),
            convention,
        })
    }

    /// Supply a known fixed-argument Windows x64 signature for a registered
    /// function entry or import slot. No speculative prototypes are installed.
    pub fn set_signature(
        &mut self,
        address: u64,
        result: ValueType,
        parameters: &[ValueType],
    ) -> Result<(), DecompileError> {
        if parameters.len() > 32 || parameters.contains(&ValueType::Void) {
            return Err(DecompileError::Request(
                "signatures allow at most 32 non-void parameters".into(),
            ));
        }
        self.native
            .set_signature(address, result, parameters)
            .map_err(|e| DecompileError::Request(format!("signature at {address:#x}: {e}")))
    }

    pub fn set_limits(&mut self, limits: ResourceLimits) -> Result<(), DecompileError> {
        if limits.timeout_ms == 0
            || limits.timeout_ms > 60_000
            || limits.max_instructions == 0
            || limits.max_instructions > 100_000
            || limits.max_work == 0
            || limits.max_work > 10_000_000
        {
            return Err(DecompileError::Request("limits must be nonzero and at most 60000 ms, 100000 instructions, 10000000 work units".into()));
        }
        self.limits = limits;
        Ok(())
    }

    pub fn decompile_function(&mut self, address: u64) -> Result<Decompilation, DecompileError> {
        if !self
            .executable_ranges
            .iter()
            .any(|(start, end)| *start <= address && address < *end)
        {
            return Err(DecompileError::Request(format!(
                "{address:#x} is not in executable mapped memory"
            )));
        }
        let started = Instant::now();
        let error = |e: capa_x_ghidra::Error| DecompileError::Native {
            address,
            message: e.to_string(),
        };
        // Explicit selection is allowed even if recovery did not discover it.
        let name = self.names.get(&address).cloned();
        let output = self
            .native
            .decompile(
                address,
                self.limits.timeout_ms,
                self.limits.max_instructions,
                self.limits.max_work,
            )
            .map_err(error)?;
        // The native layer decides which of its own warnings mean incomplete.
        let incomplete = output.incomplete || !self.warnings.is_empty();
        let mut warnings = self.warnings.clone();
        warnings.extend(output.warnings);
        // Inferred types remain a quality limitation even without native errors.
        warnings.push("Types and prototypes without supplied signatures are inferred; validate pseudocode against machine code.".into());
        Ok(Decompilation {
            address,
            name,
            calling_convention: self.convention,
            text: output.text,
            warnings,
            incomplete,
            unknown_callees: output.unknown_callees,
            timings: DecompilationTimings {
                initialization_ms: self.initialization_ms,
                decompilation_ms: started.elapsed().as_secs_f64() * 1000.0,
            },
        })
    }
}
/// Recovered functions whose only instruction is an indirect jump through an import slot,
/// with the import's name.
fn import_thunks(analysis: &Analysis) -> BTreeMap<u64, String> {
    let mut thunks = BTreeMap::new();
    for (address, function) in &analysis.functions {
        let mut instructions = function.blocks.iter().flat_map(|block| block.insns.iter());
        let (Some(only), None) = (instructions.next(), instructions.next()) else {
            continue;
        };
        if only.flow != Flow::IndirectBranch {
            continue;
        }
        if let Some(name) = only
            .memory_target
            .and_then(|slot| analysis.image.import_locations.get(&slot))
        {
            thunks.insert(*address, name.clone());
        }
    }
    thunks
}

fn validate_image(image: &LoadedImage) -> Result<(), DecompileError> {
    if image.format != ImageFormat::Pe
        || !matches!(image.architecture, Architecture::X64 | Architecture::X86)
    {
        return Err(DecompileError::Unsupported(format!(
            "{:?} {:?}",
            image.format, image.architecture
        )));
    }
    Ok(())
}

/// The function name of an import from a Windows system DLL, whose prototype
/// Ghidra's bundled Windows and C library archives describe. Matching by module
/// as well as name keeps a same-named export of an unrelated DLL untyped.
fn system_import_function(name: &str) -> Option<&str> {
    const MODULES: &[&str] = &[
        "kernel32",
        "kernelbase",
        "advapi32",
        "user32",
        "ntdll",
        "ws2_32",
        "wsock32",
        "shell32",
        "shlwapi",
        "ole32",
        "oleaut32",
        "gdi32",
        "wininet",
        "winhttp",
        "urlmon",
        "crypt32",
        "secur32",
        "netapi32",
        "iphlpapi",
        "comctl32",
        "comdlg32",
        "psapi",
        "version",
        "winmm",
        "rpcrt4",
        "bcrypt",
        "ncrypt",
        "dbghelp",
        "imm32",
        "mpr",
        "userenv",
        "wtsapi32",
        "msvcrt",
        "ucrtbase",
        "wintrust",
        "setupapi",
        "cfgmgr32",
        "powrprof",
        "dnsapi",
        "ws2help",
    ];
    let (module, function) = name.rsplit_once('.')?;
    let module = module.to_ascii_lowercase();
    let module = module.strip_suffix(".dll").unwrap_or(&module);
    (MODULES.contains(&module) || module.starts_with("api-ms-win-")).then_some(function)
}
