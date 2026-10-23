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

use crate::bundled::bundled;
use crate::extract::decoder::Flow;
use crate::extract::image::{Architecture, ImageFormat, LoadedImage};
use crate::extract::recovery::flirt::{self, Signatures};
use crate::extract::recovery::{self, Analysis};
use crate::fid;

mod ctypes;
mod effects;
mod unit;

pub use unit::{Guess, Unit, UnitFunction};

/// Ghidra 12.1.4 Function ID data for x64 and x86 Visual Studio runtimes; see `sigs/FID.md`.

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
            timeout_ms: 10_000,
            max_instructions: 10_000,
            max_work: 20_000_000,
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
    /// For each line of `text` (split on `\n`), the sorted instruction addresses of the p-code
    /// operations printed on it. Empty when the mapping could not be established. Not serialized:
    /// the CLI's `--decompile-all` is its only consumer.
    #[serde(skip)]
    pub line_addresses: Vec<Vec<u64>>,
    /// Gaps only: each one is a reason for `incomplete`.
    pub warnings: Vec<String>,
    /// Informational: a call replaced by its modeled effect, inferred prototypes and
    /// types. None of these makes the result incomplete, so they stay out of `warnings`.
    pub notes: Vec<String>,
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
    /// The type archive as C declarations, read on the first unit request.
    unit_pack: std::cell::OnceCell<ctypes::Pack>,
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
        // Three instructions, below the signature databases' minimum. Ghidra names the x86-32
        // check but prints the call, unlike the x64 one, so it gets a name and a prototype and
        // no call fixup.
        let cookie_checks: Vec<u64> = if wide {
            Vec::new()
        } else {
            analysis
                .functions
                .keys()
                .copied()
                .filter(|address| is_x86_cookie_check(&analysis.image, *address))
                .collect()
        };
        let mut names = libraries.clone();
        for address in &cookie_checks {
            names
                .entry(*address)
                .or_insert_with(|| "__security_check_cookie".into());
        }
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
        let pack_bytes = if wide {
            bundled!("fid-x64.pack")
        } else {
            bundled!("fid-x86.pack")
        }
        .map_err(DecompileError::Input)?;
        let pack = fid::pack::Pack::parse(&pack_bytes)
            .map_err(|e| DecompileError::Input(e.to_string()))?;
        let (recognized, conflicts) =
            fid::names::name_functions_with_conflicts(&analysis, &pack, &|address| {
                names.contains_key(&address)
            });
        for (address, name) in &recognized {
            names.insert(*address, name.clone());
        }
        // An ambiguous match is named as Ghidra does, `FID_conflict:<name>`, so the reader sees
        // that the name is a guess. It gets no prototype, and its fixup is decided below.
        for (address, candidates) in &conflicts {
            if let Some(name) = fid::matcher::conflict_name(candidates) {
                names.entry(*address).or_insert(name);
            }
        }
        let mut session = Self::from_analysis(&analysis, &names, convention)?;
        // Only entries inside file-backed executable memory are registered with the engine.
        let registered = |session: &Self, address: u64| session.in_code(address);
        let recognized: BTreeMap<u64, String> = recognized
            .into_iter()
            .filter(|(address, _)| registered(&session, *address))
            .collect();
        let libraries: BTreeMap<u64, String> = libraries
            .into_iter()
            .filter(|(address, _)| registered(&session, *address))
            .collect();
        let thunks: BTreeMap<u64, String> = thunks
            .into_iter()
            .filter(|(address, _)| registered(&session, *address))
            .collect();
        let conflicts: BTreeMap<u64, Vec<String>> = conflicts
            .into_iter()
            .filter(|(address, _)| registered(&session, *address))
            .collect();
        let cookie_checks: Vec<u64> = cookie_checks
            .into_iter()
            .filter(|address| registered(&session, *address))
            .collect();
        let export_addresses: Vec<(u64, String)> = export_addresses
            .into_iter()
            .filter(|(address, _)| registered(&session, *address))
            .collect();
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
        for address in &cookie_checks {
            session
                .native
                .apply_prototype(*address, "__security_check_cookie")
                .map_err(|error| {
                    DecompileError::Initialization(format!(
                        "prototype for the cookie check at {address:#x}: {error}"
                    ))
                })?;
        }
        for (address, import) in &thunks {
            if let Some(function) = system_import_function(import) {
                session
                    .native
                    .apply_prototype(*address, function)
                    .map_err(|error| {
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
                session
                    .native
                    .apply_prototype(*address, name)
                    .map_err(|error| {
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
            let mut fixups = candidates
                .iter()
                .map(|name| effects::call_fixup(name, wide));
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
            // Zero-filled space that the file does not carry (a packer's unpack target) holds no
            // code to read. Ghidra reports bad instruction data there and ends the flow; mapping
            // it as executable would decode the zeros as instructions until the limit.
            let code = section.permissions.execute
                && !(section.file_size == 0 && image.is_uninitialized(section.address));
            native
                .add_section(section.address, bytes, code, !section.permissions.write)
                .map_err(init)?;
            if code {
                executable_ranges.push((section.address, end));
            }
        }
        let mut skipped_entries = 0usize;
        for address in analysis.functions.keys().chain(names.keys()) {
            // Recovery can decode zero-filled space as code; that is not mapped as code here.
            if !executable_ranges
                .iter()
                .any(|(start, end)| *start <= *address && *address < *end)
            {
                skipped_entries += 1;
                continue;
            }
            let name = names.get(address).cloned().unwrap_or_else(|| {
                // Ghidra pads default names to the address width of the image.
                if wide {
                    format!("FUN_{address:x}")
                } else {
                    format!("FUN_{address:08x}")
                }
            });
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
        let in_code = |address: u64| {
            executable_ranges
                .iter()
                .any(|(start, end)| *start <= address && address < *end)
        };
        for (caller, function) in &analysis.functions {
            if !in_code(*caller) {
                continue;
            }
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
                    if let Some(target) =
                        target.filter(|t| in_code(*t) || image.import_locations.contains_key(t))
                    {
                        native
                            .add_tail_call(*caller, insn.address, target)
                            .map_err(init)?;
                    }
                }
            }
        }
        let mut warnings = image.load_diagnostics.clone();
        if skipped_entries > 0 {
            warnings.push(format!(
                "{skipped_entries} recovered entries lie outside executable file-backed code and were not registered"
            ));
        }
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
            unit_pack: std::cell::OnceCell::new(),
        })
    }

    fn in_code(&self, address: u64) -> bool {
        self.executable_ranges
            .iter()
            .any(|(start, end)| *start <= address && address < *end)
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
            || limits.max_work > 200_000_000
        {
            return Err(DecompileError::Request("limits must be nonzero and at most 60000 ms, 100000 instructions, 10000000 work units".into()));
        }
        self.limits = limits;
        Ok(())
    }

    /// Decompile one function or a set and wrap the text in a unit a C compiler accepts
    /// (see [`Unit`]). Duplicate addresses are decompiled once. Any function that fails to
    /// decompile fails the unit: a partial unit would hide the gap.
    pub fn decompile_unit(&mut self, addresses: &[u64]) -> Result<Unit, DecompileError> {
        const MAX_FUNCTIONS: usize = 256;
        let mut unique = Vec::new();
        for address in addresses {
            if !unique.contains(address) {
                unique.push(*address);
            }
        }
        if unique.is_empty() || unique.len() > MAX_FUNCTIONS {
            return Err(DecompileError::Request(format!(
                "a unit needs between 1 and {MAX_FUNCTIONS} functions"
            )));
        }
        let mut bodies = Vec::new();
        for address in unique {
            let result = self.decompile_function(address)?;
            bodies.push(unit::Body {
                address,
                text: result.text,
                incomplete: result.incomplete,
                unknown_callees: result.unknown_callees,
            });
        }
        let wide = self.convention.wide();
        if self.unit_pack.get().is_none() {
            let pack = ctypes::Pack::parse(capa_x_ghidra::prototype_pack(wide))
                .map_err(DecompileError::Initialization)?;
            let _ = self.unit_pack.set(pack);
        }
        let pack = self
            .unit_pack
            .get()
            .ok_or_else(|| DecompileError::Initialization("type archive unavailable".into()))?;
        unit::build(pack, wide, &bodies).map_err(DecompileError::Initialization)
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
        let mut notes = output.notes;
        // Inferred types remain a quality limitation even without native errors.
        notes.push("Types and prototypes without supplied signatures are inferred; validate pseudocode against machine code.".into());
        let line_addresses = line_addresses(&output.markup, &output.op_times, &output.op_addrs, &output.text);
        Ok(Decompilation {
            address,
            name,
            calling_convention: self.convention,
            text: output.text,
            line_addresses,
            warnings,
            notes,
            incomplete,
            unknown_callees: output.unknown_callees,
            timings: DecompilationTimings {
                initialization_ms: self.initialization_ms,
                decompilation_ms: started.elapsed().as_secs_f64() * 1000.0,
            },
        })
    }
}
/// Maps each printed line to the instruction addresses behind it, using the `opref` attributes of
/// Ghidra's token markup. Returns nothing unless the markup's line count matches the plain text's,
/// so a misaligned mapping is never shown.
fn line_addresses(markup: &[u8], op_times: &[u32], op_addrs: &[u64], text: &str) -> Vec<Vec<u64>> {
    if markup.is_empty() {
        return Vec::new();
    }
    let address_of: BTreeMap<u32, u64> = op_times.iter().copied().zip(op_addrs.iter().copied()).collect();
    let markup = String::from_utf8_lossy(markup);
    let mut lines: Vec<std::collections::BTreeSet<u64>> = vec![Default::default()];
    let mut rest = markup.as_ref();
    while let Some(start) = rest.find('<') {
        let Some(end) = rest[start..].find('>') else { break };
        let tag = &rest[start + 1..start + end];
        rest = &rest[start + end + 1..];
        if tag.starts_with('/') {
            continue;
        }
        if tag.starts_with("break") {
            lines.push(Default::default());
        } else if let Some(at) = tag.find("opref=\"") {
            let value = &tag[at + 7..];
            let value = value.split('"').next().unwrap_or("");
            let parsed = match value.strip_prefix("0x") {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => value.parse().ok(),
            };
            if let Some(address) = parsed.and_then(|time| address_of.get(&time)) {
                if let Some(line) = lines.last_mut() {
                    line.insert(*address);
                }
            }
        }
    }
    if lines.len() != text.split('\n').count() {
        return Vec::new();
    }
    lines.into_iter().map(|line| line.into_iter().collect()).collect()
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

/// The Visual C++ `/GS` check on x86-32: `cmp ecx, [__security_cookie]`, a `jne` over a
/// (possibly `rep`-prefixed) `ret`, then the jump or call to the failure reporter.
/// Both the compiler's `ret` and its `rep ret` form exist, and the `jne` distance is 1 or 2.
fn is_x86_cookie_check(image: &LoadedImage, address: u64) -> bool {
    let Some(code) = image.bytes_at(address, 14) else {
        return false;
    };
    let tail = match code {
        [0x3b, 0x0d, a, b, c, d, rest @ ..] => {
            let slot = u64::from(u32::from_le_bytes([*a, *b, *c, *d]));
            if image.bytes_at(slot, 4).is_none() || image.is_executable_address(slot) {
                return false;
            }
            rest
        }
        _ => return false,
    };
    let tail = match tail {
        [0xf2, rest @ ..] => rest,
        rest => rest,
    };
    let [0x75, skip, rest @ ..] = tail else {
        return false;
    };
    let (ret, rest) = match rest {
        [0xf3 | 0xf2, 0xc3, rest @ ..] => (2u8, rest),
        [0xc3, rest @ ..] => (1u8, rest),
        _ => return false,
    };
    // The branch lands on the instruction after the `ret`.
    *skip == ret && matches!(rest, [0xe9 | 0xe8 | 0xff, ..] | [0xf2, 0xe9, ..])
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
