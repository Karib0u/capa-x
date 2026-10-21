//! Optional, serial, in-process x86-64 PE decompilation.
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
use crate::extract::recovery::{self, Analysis, RecoveryBackend};

#[derive(Debug, thiserror::Error)]
pub enum DecompileError {
    #[error("decompilation supports only native x86-64 PE images: {0}")]
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

/// Windows x64 uses Ghidra's x86-64-win.cspec default __fastcall model.
#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallingConvention {
    #[default]
    WindowsX64,
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
    pub incomplete: bool,
    pub timings: DecompilationTimings,
}

pub struct DecompilerSession {
    native: capa_x_ghidra::Session,
    executable_ranges: Vec<(u64, u64)>,
    names: BTreeMap<u64, String>,
    warnings: Vec<String>,
    initialization_ms: f64,
    limits: ResourceLimits,
}
impl DecompilerSession {
    /// Parse and recover once. Native SLEIGH, not iced-x86, translates the
    /// requested function. Existing callers can avoid recovery via from_analysis.
    pub fn from_pe(bytes: &[u8]) -> Result<Self, DecompileError> {
        let started = Instant::now();
        let image = LoadedImage::parse(bytes).map_err(|e| DecompileError::Input(e.to_string()))?;
        validate_image(&image)?;
        let image_base = image.image_base;
        drop(image);
        let pe = goblin::pe::PE::parse(bytes).map_err(|e| DecompileError::Input(e.to_string()))?;
        if pe
            .header
            .optional_header
            .as_ref()
            .is_some_and(|h| h.data_directories.get_clr_runtime_header().is_some())
        {
            return Err(DecompileError::Unsupported("managed PE image".into()));
        }
        let analysis = recovery::analyze_with_backend(bytes, RecoveryBackend::Native)
            .map_err(|e| DecompileError::Input(e.to_string()))?;
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
        let dll_entry = pe.is_lib.then_some(analysis.image.entry_point).flatten();
        if let Some(entry) = dll_entry {
            names.entry(entry).or_insert_with(|| "DllEntryPoint".into());
        }
        let mut session = Self::from_analysis(&analysis, &names, CallingConvention::WindowsX64)?;
        for (address, name) in libraries {
            // Apply runtime prototypes only to validated FLIRT matches.
            let prototype = match name.trim_start_matches('_') {
                "security_init_cookie" => Some((ValueType::Void, vec![])),
                "security_check_cookie" => Some((ValueType::Void, vec![ValueType::U64])),
                "DllMainCRTStartup" | "DllMain" => Some((
                    ValueType::I32,
                    vec![ValueType::Pointer, ValueType::U32, ValueType::Pointer],
                )),
                _ => None,
            };
            if let Some((result, parameters)) = prototype {
                session.set_signature(address, result, &parameters)?;
            }
            if name.trim_start_matches('_') == "security_check_cookie" {
                // The MSVC x64 cookie helper preserves RAX on normal return.
                // An ordinary void Windows x64 call instead kills that register.
                session.native.set_preserves_rax(address).map_err(|error| {
                    DecompileError::Initialization(format!(
                        "cookie helper at {address:#x}: {error}"
                    ))
                })?;
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
        _convention: CallingConvention,
    ) -> Result<Self, DecompileError> {
        let started = Instant::now();
        let image = &analysis.image;
        validate_image(image)?;
        let init = |e: capa_x_ghidra::Error| DecompileError::Initialization(e.to_string());
        let mut native = capa_x_ghidra::Session::new().map_err(init)?;
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
            if let Some((result, parameters)) = windows_import_signature(name) {
                native
                    .set_signature(*address, result, parameters)
                    .map_err(init)?;
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
        let mut warnings = self.warnings.clone();
        warnings.extend(output.warnings);
        let incomplete = output.incomplete || !warnings.is_empty();
        // Inferred types remain a quality limitation even without native errors.
        warnings.push("Types and prototypes without supplied signatures are inferred; validate pseudocode against machine code.".into());
        Ok(Decompilation {
            address,
            name,
            calling_convention: CallingConvention::WindowsX64,
            text: output.text,
            warnings,
            incomplete,
            timings: DecompilationTimings {
                initialization_ms: self.initialization_ms,
                decompilation_ms: started.elapsed().as_secs_f64() * 1000.0,
            },
        })
    }
}
fn validate_image(image: &LoadedImage) -> Result<(), DecompileError> {
    if image.format != ImageFormat::Pe || image.architecture != Architecture::X64 {
        return Err(DecompileError::Unsupported(format!(
            "{:?} {:?}",
            image.format, image.architecture
        )));
    }
    Ok(())
}

/// Small, explicit Windows SDK signature set. Module-qualified matching avoids
/// assigning a Windows prototype to an unrelated DLL's same-named export.
/// Declarations and structure layouts are linked in docs/DECOMPILER.md.
/// Windows DWORD/UINT/BOOL remain 32-bit, including on Windows x64.
fn windows_import_signature(name: &str) -> Option<(ValueType, &'static [ValueType])> {
    use ValueType as T;
    let (module, function) = name.rsplit_once('.')?;
    if module.eq_ignore_ascii_case("advapi32") {
        return Some(match function {
            "OpenProcessToken" => (T::I32, &[T::Pointer, T::U32, T::PointerPointer]),
            "LookupPrivilegeValueA" => (T::I32, &[T::CharPointer, T::CharPointer, T::LuidPointer]),
            "LookupPrivilegeValueW" => (
                T::I32,
                &[T::WideCharPointer, T::WideCharPointer, T::LuidPointer],
            ),
            "AdjustTokenPrivileges" => (
                T::I32,
                &[
                    T::Pointer,
                    T::I32,
                    T::TokenPrivilegesPointer,
                    T::U32,
                    T::TokenPrivilegesPointer,
                    T::U32Pointer,
                ],
            ),
            _ => return None,
        });
    }
    if !module.eq_ignore_ascii_case("kernel32") && !module.eq_ignore_ascii_case("kernelbase") {
        return None;
    }
    Some(match function {
        "GetTickCount" | "GetCurrentProcessId" | "GetCurrentThreadId" | "GetLastError" => {
            (T::U32, &[])
        }
        "GetTickCount64" => (T::U64, &[]),
        "GetCurrentProcess" | "GetCurrentThread" => (T::Pointer, &[]),
        "ExitProcess" | "ExitThread" | "SetLastError" | "Sleep" => (T::Void, &[T::U32]),
        "IsDebuggerPresent" => (T::I32, &[]),
        "CloseHandle" => (T::I32, &[T::Pointer]),
        "CreateFileA" => (
            T::Pointer,
            &[
                T::CharPointer,
                T::U32,
                T::U32,
                T::Pointer,
                T::U32,
                T::U32,
                T::Pointer,
            ],
        ),
        "CreateFileW" => (
            T::Pointer,
            &[
                T::WideCharPointer,
                T::U32,
                T::U32,
                T::Pointer,
                T::U32,
                T::U32,
                T::Pointer,
            ],
        ),
        "ReadFile" | "WriteFile" => (
            T::I32,
            &[T::Pointer, T::Pointer, T::U32, T::U32Pointer, T::Pointer],
        ),
        "VirtualAlloc" => (T::Pointer, &[T::Pointer, T::U64, T::U32, T::U32]),
        "VirtualFree" => (T::I32, &[T::Pointer, T::U64, T::U32]),
        "VirtualProtect" => (T::I32, &[T::Pointer, T::U64, T::U32, T::U32Pointer]),
        "LoadLibraryA" | "GetModuleHandleA" => (T::Pointer, &[T::CharPointer]),
        "LoadLibraryW" | "GetModuleHandleW" => (T::Pointer, &[T::WideCharPointer]),
        "GetProcAddress" => (T::Pointer, &[T::Pointer, T::CharPointer]),
        "GetModuleFileNameA" => (T::U32, &[T::Pointer, T::CharPointer, T::U32]),
        "GetModuleFileNameW" => (T::U32, &[T::Pointer, T::WideCharPointer, T::U32]),
        "CreateThread" => (
            T::Pointer,
            &[
                T::Pointer,
                T::U64,
                T::Pointer,
                T::Pointer,
                T::U32,
                T::U32Pointer,
            ],
        ),
        _ => return None,
    })
}
