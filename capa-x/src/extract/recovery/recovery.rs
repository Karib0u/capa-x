//! x86/x64 function and control-flow recovery.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use goblin::elf::dynamic::{
    DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ,
};
use goblin::elf::sym::{st_type, STT_FUNC, STT_GNU_IFUNC};
use goblin::elf::Elf;
use goblin::mach::load_command::CommandVariant;
use goblin::mach::MachO;
use goblin::pe::options::{ParseMode, ParseOptions};
use goblin::pe::PE;
use iced_x86::{Mnemonic, OpKind};

use super::decoder;
use super::decoder::Flow;
use super::golang;
use super::image::{Architecture, DecodedInstruction, ImageError, ImageFormat, LoadedImage};
use super::importcalls;
use super::libc_start_main;
use super::msvcfunc;
use super::noreturn;

const MAX_FUNCTIONS: usize = 100_000;
const MAX_INSNS_PER_FUNCTION: usize = 200_000;
const MAX_PROLOGUE_SCAN_BYTES: usize = 32 * 1024 * 1024;
const MAX_PROLOGUE_SEEDS_PER_SECTION: usize = 8_192;
const MAX_SWEEP_CALL_SEEDS: usize = 32_768;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeedKind {
    EntryPoint,
    Export,
    TlsCallback,
    SafeSeh,
    Unwind,
    Symbol,
    Init,
    Fini,
    InitArray,
    FiniArray,
    Relocation,
    /// Undefined pointer target accepted by candidate evaluation.
    PointerTarget,
    /// Named or instruction-referenced address accepted by candidate evaluation.
    Emulated,
    /// Known API argument explicitly typed as a function pointer.
    ApiCallback,
    /// Undefined local symbol from a validated FLIRT signature.
    FlirtLocal,
    LibcMain,
    GoRuntimeMain,
    FunctionSignature,
    MsvcCookieBlock,
    Prologue,
    SweepCallTarget,
    CallTarget,
    /// `LC_FUNCTION_STARTS` (Mach-O only): a high-quality, linker-emitted
    /// function-start table, ULEB128-delta-encoded from `__TEXT`'s load
    /// address. See the Mach-O loader's function-start handling.
    /// task 3.
    MachoFunctionStarts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryBackend {
    /// Reproduce the pinned Vivisect loader and deterministic analysis inputs.
    VivisectCompat,
    /// Enable recovery heuristics that are useful but not Vivisect-compatible.
    Native,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    Fallthrough,
    Branch,
    TailCall,
    JumpTable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    pub target: u64,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub addr: u64,
    pub insns: Vec<DecodedInstruction>,
    pub succs: Vec<Edge>,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub addr: u64,
    pub blocks: Vec<BasicBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryDiagnostic {
    pub address: u64,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct Analysis {
    pub image: LoadedImage,
    pub seeds: BTreeMap<u64, BTreeSet<SeedKind>>,
    pub functions: BTreeMap<u64, Function>,
    /// Order of function completion during compatibility codeflow. FLIRT
    /// public names can only label functions that already exist at that point.
    pub function_order: BTreeMap<u64, usize>,
    /// Functions visible after recursive function analyzers finish. FLIRT
    /// public names are applied after its local functions have been created.
    pub function_analysis_counts: BTreeMap<u64, usize>,
    /// Functions visible when FLIRT starts, after calling analysis completes.
    pub function_flirt_counts: BTreeMap<u64, usize>,
    /// Opcode discovery count when FLIRT starts.
    pub function_location_counts: BTreeMap<u64, usize>,
    /// First-definition order for opcode locations.
    pub instruction_order: BTreeMap<u64, usize>,
    /// Discovered opcode locations. In compatibility mode, block extraction
    /// may expose a different stream starting inside one of these locations.
    pub instructions: BTreeMap<u64, DecodedInstruction>,
    pub code_xrefs: BTreeMap<u64, Vec<u64>>,
    pub data_xrefs: BTreeMap<u64, Vec<u64>>,
    pub callers: BTreeMap<u64, BTreeSet<u64>>,
    pub callees: BTreeMap<u64, BTreeSet<u64>>,
    pub diagnostics: Vec<RecoveryDiagnostic>,
    /// ELF `STT_FUNC`/`STT_GNU_IFUNC` symbol names by address, from `.symtab`
    /// and `.dynsym`. Ported from `capa.features.extractors.elf.SymTab`:
    /// `viv/insn.py`'s ELF `api` branch and `viv/function.py`'s
    /// `extract_function_symtab_names` both look up a call/function address
    /// in this table (`sym_value == target and sym_info & STT_FUNC != 0`).
    /// Also carries Mach-O `LC_SYMTAB` `N_SECT` symbol names by address
    /// (`collect_macho_seeds`) -- same "address to
    /// function-name feature" role, no upstream source since Mach-O has
    /// none. Empty for PE and shellcode input.
    pub elf_function_symbols: BTreeMap<u64, Vec<String>>,
    /// Addresses Vivisect treats as non-returning procedural branch targets --
    /// `CodeFlowContext._cf_noret` (`envi/codeflow.py:41`). Holds import
    /// locations *and* function entry VAs in one map, matching upstream; see
    /// [`super::noreturn`].
    pub noreturn: BTreeSet<u64>,
    /// Call sites whose fallthrough edge was suppressed because the target is
    /// no-return -- Vivisect's `NoReturnCalls` VA set
    /// (`vivisect/base.py:810`).
    pub noreturn_calls: BTreeSet<u64>,
}

impl Analysis {
    /// Port of `VivWorkspace.isNoReturnVa` (`vivisect/__init__.py:521-527`):
    /// an address is no-return if it is a registered no-return VA *or* the
    /// site of a suppressed no-return call.
    pub fn is_noreturn_va(&self, address: u64) -> bool {
        self.noreturn.contains(&address) || self.noreturn_calls.contains(&address)
    }
}

#[derive(Default)]
struct DirectFlowGraph {
    compatibility: bool,
    flirt: Option<super::flirt::Discovery>,
    known_noreturn: BTreeSet<u64>,
    successors: BTreeMap<u64, Vec<Edge>>,
    /// Preserve the codeblocks.py view when each compatibility function
    /// completes. Later discoveries must not expand an earlier function.
    completed_functions: BTreeMap<u64, Function>,
    /// A branch into a loose code-flow root can defer a function forever:
    /// that root has no function callback to release the dependency.
    delayed_functions: BTreeSet<u64>,
    /// Functions created while walking otherwise unclaimed import-call fragments.
    import_functions: BTreeSet<u64>,
    pending_table_locations: Vec<(u64, usize)>,
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error(transparent)]
    Signature(#[from] super::flirt::FlirtError),
    #[error(transparent)]
    Image(#[from] ImageError),
    #[error("collecting {format:?} recovery seeds: {context}")]
    Seeds {
        format: ImageFormat,
        context: String,
    },
    #[error("recovery limit exceeded: {0}")]
    Limit(String),
}

pub fn analyze(bytes: &[u8]) -> Result<Analysis, RecoveryError> {
    analyze_with_backend(bytes, RecoveryBackend::VivisectCompat)
}

pub fn analyze_with_backend(
    bytes: &[u8],
    backend: RecoveryBackend,
) -> Result<Analysis, RecoveryError> {
    let image = if super::super::looks_like_elf(bytes) {
        LoadedImage::from_elf_with_import_policy(bytes, backend == RecoveryBackend::VivisectCompat)?
    } else {
        LoadedImage::parse(bytes)?
    };
    analyze_image(bytes, image, backend)
}

/// PE recovery with the same signatures used by the caller for library recognition.
pub fn analyze_with_signatures(
    bytes: &[u8],
    signatures: &super::flirt::Signatures,
) -> Result<Analysis, RecoveryError> {
    let image = LoadedImage::parse(bytes)?;
    let backend = RecoveryBackend::VivisectCompat;
    let (seeds, symbols, diagnostics) = collect_seeds(bytes, &image, backend)?;
    analyze_seeded_image_with_signatures(
        image,
        backend,
        seeds,
        symbols,
        diagnostics,
        Some(signatures),
    )
}

/// `-f sc32`/`sc64`, matching capa.loader.get_workspace's shellcode
/// workspace. There are no container-specific exports, TLS callbacks,
/// relocations, or symbol tables.
pub fn analyze_shellcode(
    bytes: &[u8],
    architecture: Architecture,
) -> Result<Analysis, RecoveryError> {
    let image = LoadedImage::from_shellcode(bytes, architecture);
    analyze_image(bytes, image, RecoveryBackend::VivisectCompat)
}

/// `-f macho` uses native recovery because the pinned reference does not
/// load this format.
pub fn analyze_macho(bytes: &[u8], arch: Option<&str>) -> Result<Analysis, RecoveryError> {
    let image = LoadedImage::from_macho(bytes, arch)?;
    analyze_image(bytes, image, RecoveryBackend::Native)
}

fn analyze_image(
    bytes: &[u8],
    image: LoadedImage,
    backend: RecoveryBackend,
) -> Result<Analysis, RecoveryError> {
    let (seeds, elf_function_symbols, diagnostics) = collect_seeds(bytes, &image, backend)?;
    analyze_seeded_image(image, backend, seeds, elf_function_symbols, diagnostics)
}

fn analyze_seeded_image(
    image: LoadedImage,
    backend: RecoveryBackend,
    seeds: SeedMap,
    elf_function_symbols: FunctionSymbolMap,
    diagnostics: Vec<RecoveryDiagnostic>,
) -> Result<Analysis, RecoveryError> {
    let signatures =
        if backend == RecoveryBackend::VivisectCompat && image.format == ImageFormat::Pe {
            Some(super::flirt::Signatures::embedded()?)
        } else {
            None
        };
    analyze_seeded_image_with_signatures(
        image,
        backend,
        seeds,
        elf_function_symbols,
        diagnostics,
        signatures.as_ref(),
    )
}

fn analyze_seeded_image_with_signatures(
    image: LoadedImage,
    backend: RecoveryBackend,
    mut seeds: SeedMap,
    elf_function_symbols: FunctionSymbolMap,
    diagnostics: Vec<RecoveryDiagnostic>,
    signatures: Option<&super::flirt::Signatures>,
) -> Result<Analysis, RecoveryError> {
    if backend == RecoveryBackend::Native {
        seeds.retain(|address, kinds| {
            kinds.remove(&SeedKind::Emulated);
            if image.format == ImageFormat::Pe
                && matches!(image.architecture, Architecture::X86 | Architecture::X64)
                && !plausible_relocation_function(&image, *address)
            {
                kinds.remove(&SeedKind::Relocation);
            }
            !kinds.is_empty()
        });
    }
    let mut fallback = BTreeMap::new();
    add_backend_fallback_seeds(&image, backend, &mut fallback);
    for (&address, kinds) in &fallback {
        seeds
            .entry(address)
            .or_default()
            .extend(kinds.iter().copied());
    }

    // The import locations `addNoReturnApi` resolves are known before any code
    // flow runs; everything else is derived from a completed pass.
    let noreturn_seed = noreturn::seed_addresses(&image);
    let base_seeds = seeds.clone();
    let base_diagnostics = diagnostics.clone();

    let mut analysis = Analysis {
        image,
        seeds,
        functions: BTreeMap::new(),
        function_order: BTreeMap::new(),
        function_analysis_counts: BTreeMap::new(),
        function_flirt_counts: BTreeMap::new(),
        function_location_counts: BTreeMap::new(),
        instruction_order: BTreeMap::new(),
        instructions: BTreeMap::new(),
        code_xrefs: BTreeMap::new(),
        data_xrefs: BTreeMap::new(),
        callers: BTreeMap::new(),
        callees: BTreeMap::new(),
        diagnostics,
        elf_function_symbols,
        noreturn: BTreeSet::new(),
        noreturn_calls: BTreeSet::new(),
    };

    // Vivisect interleaves no-return discovery with code flow: `addEntryPoint`
    // descends into a callee *before* deciding whether the call site falls
    // through (`envi/codeflow.py:239-256`), so a callee later proven
    // non-returning truncates the caller that was still being walked.
    // capa-x discovers flow for the whole image in one sweep instead, so it
    // reaches the same fixpoint by re-running the sweep with the enlarged set
    // until it stops growing. Suppressing a fallthrough only ever *removes*
    // edges, so the set is monotonic and the loop terminates.
    let mut noreturn = noreturn_seed.clone();
    for pass in 0..noreturn::MAX_PASSES {
        if pass > 0 {
            analysis.seeds.clone_from(&base_seeds);
            analysis.diagnostics.clone_from(&base_diagnostics);
            analysis.functions.clear();
            analysis.function_order.clear();
            analysis.function_analysis_counts.clear();
            analysis.function_flirt_counts.clear();
            analysis.function_location_counts.clear();
            analysis.instruction_order.clear();
            analysis.instructions.clear();
            analysis.code_xrefs.clear();
            analysis.data_xrefs.clear();
            analysis.noreturn_calls.clear();
        }
        let next = recover_functions(&mut analysis, &fallback, &noreturn, backend, signatures)?;
        if backend == RecoveryBackend::VivisectCompat
            && matches!(
                analysis.image.architecture,
                Architecture::X86 | Architecture::X64
            )
        {
            noreturn = next;
            break;
        }
        if next == noreturn || pass.saturating_add(1) == noreturn::MAX_PASSES {
            break;
        }
        noreturn = next;
    }
    analysis.noreturn = noreturn;

    rebuild_call_indexes(&mut analysis);
    analysis
        .diagnostics
        .sort_by(|left, right| (left.address, &left.message).cmp(&(right.address, &right.message)));
    analysis.diagnostics.dedup();
    Ok(analysis)
}

/// One full recursive-descent sweep: discover direct flow from every seed,
/// then materialise a function view per discovered start. `noreturn` is the
/// call-target set whose fallthrough edges this sweep must suppress.
fn recover_functions(
    analysis: &mut Analysis,
    fallback: &SeedMap,
    noreturn: &BTreeSet<u64>,
    backend: RecoveryBackend,
    signatures: Option<&super::flirt::Signatures>,
) -> Result<BTreeSet<u64>, RecoveryError> {
    let evaluate_candidates = backend == RecoveryBackend::VivisectCompat
        && matches!(
            analysis.image.architecture,
            Architecture::X86 | Architecture::X64
        );
    let mut pointers = super::pointers::Discovery::new(analysis, evaluate_candidates);
    let mut initial: Vec<u64> = analysis.seeds.keys().copied().collect();
    initial.sort_by_key(|address| {
        let priority = analysis
            .seeds
            .get(address)
            .map(|kinds| seed_priority(kinds, evaluate_candidates))
            .unwrap_or(usize::MAX);
        // pe.py registers the image entry point before exports, SafeSEH,
        // and unwind entries. Its call tree must finish before those later
        // roots: function-analyzer order affects FLIRT reference matching.
        let pe_root_order = if evaluate_candidates && analysis.image.format == ImageFormat::Pe {
            let kinds = analysis.seeds.get(address);
            if analysis.image.entry_point == Some(*address) {
                0
            } else if kinds.is_some_and(|kinds| kinds.contains(&SeedKind::Export)) {
                1
            } else if kinds.is_some_and(|kinds| kinds.contains(&SeedKind::SafeSeh)) {
                2
            } else {
                3
            }
        } else {
            0
        };
        (priority, pe_root_order, *address)
    });
    let mut pending: VecDeque<u64> = initial.into();
    let mut function_starts = BTreeSet::new();
    let mut isolated_starts = BTreeSet::new();
    let mut direct_flow = DirectFlowGraph {
        compatibility: evaluate_candidates,
        flirt: signatures.cloned().map(super::flirt::Discovery::new),
        known_noreturn: noreturn.clone(),
        ..DirectFlowGraph::default()
    };
    if evaluate_candidates && analysis.image.format == ImageFormat::Elf {
        // elf.elfplt analyzes undefined PLT bytes before entry points. Its
        // loose code can call ordinary functions, which finish immediately.
        let ranges = analysis.image.elf_plt_ranges.clone();
        let mut known_functions = BTreeSet::new();
        for (mut address, end) in ranges {
            while address < end {
                if let Some(instruction) = instruction_location(analysis, address) {
                    address = instruction.next_address;
                    continue;
                }
                let calls = discover_flow(
                    analysis,
                    &mut direct_flow,
                    address,
                    &mut pointers,
                    Some(&mut known_functions),
                )?;
                for target in calls {
                    analysis
                        .seeds
                        .entry(target)
                        .or_default()
                        .insert(SeedKind::CallTarget);
                    pending.push_back(target);
                }
                address = instruction_location(analysis, address)
                    .map(|instruction| instruction.next_address)
                    .unwrap_or_else(|| address.saturating_add(1));
            }
        }
    }
    let mut late_waves_done = false;
    let mut early_candidates_done = !evaluate_candidates;
    let mut function_budget_reported = false;
    loop {
        for (address, size) in direct_flow.pending_table_locations.drain(..) {
            pointers.mark_data(address, size);
        }
        // `generic.relocations/pointers` and `generic.emucode` precede
        // `i386.importcalls` and `generic.funcentries`. In particular, a
        // relocation to `call [TlsAlloc]; ret` must become a function before
        // importcalls can claim it as loose code.
        if !early_candidates_done
            && pending.front().is_none_or(|address| {
                analysis.image.format == ImageFormat::Pe
                    && analysis.seeds.get(address).is_some_and(|kinds| {
                        kinds.iter().all(|kind| {
                            matches!(
                                kind,
                                SeedKind::FunctionSignature
                                    | SeedKind::Prologue
                                    | SeedKind::SweepCallTarget
                            )
                        })
                    })
            })
        {
            if let Some(address) = pointers.next(analysis, &direct_flow.known_noreturn) {
                pending.push_front(address);
            } else {
                if let Some(signatures) = signatures {
                    // FLIRT local symbols can expose code that must exist
                    // before generic.funcentries scans undefined bytes.
                    // Keep oversized functions out of this optional pass;
                    // final materialization emits their limit diagnostic.
                    for &address in &function_starts {
                        match build_function_view(analysis, &direct_flow, address, false) {
                            Ok(function) => {
                                analysis.functions.insert(address, function);
                            }
                            Err(RecoveryError::Limit(_)) => {
                                analysis.functions.remove(&address);
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    let (_, mut locals) =
                        super::flirt::identify_with_local_starts(analysis, signatures)?;
                    locals.retain(|address| !function_starts.contains(address));
                    if !locals.is_empty() && function_starts.len() < MAX_FUNCTIONS {
                        for address in locals.into_iter().rev() {
                            analysis
                                .seeds
                                .entry(address)
                                .or_default()
                                .insert(SeedKind::FlirtLocal);
                            pending.push_front(address);
                        }
                        continue;
                    }
                }
                early_candidates_done = true;
                pointers.finish_emucode();
                run_import_call_wave(
                    analysis,
                    &mut direct_flow,
                    &mut pending,
                    &mut pointers,
                    Some(&function_starts),
                )?;
            }
        }
        let Some(start) = pending.pop_front() else {
            if late_waves_done {
                if evaluate_candidates {
                    if let Some(address) = pointers.next(analysis, &direct_flow.known_noreturn) {
                        pending.push_back(address);
                        continue;
                    }
                }
                break;
            }
            // Compatibility import-call discovery ran after emucode and
            // before function signatures, as in the reference module order.
            // Native recovery keeps its late import-call scan.
            // The Go pass reads
            // the *recovered* entry function's basic blocks, so it cannot run
            // until that function's flow exists.
            late_waves_done = true;
            run_go_runtime_main_wave(analysis, &direct_flow, &mut pending)?;
            if !evaluate_candidates {
                run_import_call_wave(
                    analysis,
                    &mut direct_flow,
                    &mut pending,
                    &mut pointers,
                    None,
                )?;
            }
            // `vivisect.analysis.ms.msvcfunc` is amodlist[9]/[10] -- after
            // the import-call pass, and reading the function set the earlier
            // ones produced.
            run_msvc_cookie_wave(analysis, &direct_flow, &function_starts, &mut pending);
            // Not a pinned Vivisect pass (there is none to port -- Vivisect
            // never analysed AArch64): reads `analysis.instructions`, so it
            // waits for the same reason the passes above do.
            run_aarch64_plt_wave(analysis);
            continue;
        };
        if direct_flow.delayed_functions.contains(&start) {
            continue;
        }
        let late_signature_only = analysis.seeds.get(&start).is_some_and(|kinds| {
            kinds
                .iter()
                .all(|kind| matches!(kind, SeedKind::FunctionSignature | SeedKind::Prologue))
        });
        // generic/funcentries.py scans undefined locations only. A match
        // inside an instruction is not a new function, even if its bytes
        // look like an entry signature.
        if function_starts.contains(&start)
            || (late_signature_only
                && (analysis.instructions.contains_key(&start)
                    || (evaluate_candidates && super::pointers::covered(analysis, start))))
            || !is_executable(&analysis.image, start)
        {
            continue;
        }
        if function_starts.len() >= MAX_FUNCTIONS {
            // Degrade like the two walk budgets: stop taking new starts and
            // analyse the ones already found. Reported once, not once per
            // remaining seed.
            if !function_budget_reported {
                function_budget_reported = true;
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address: start,
                    message: format!("stopped taking function starts at {MAX_FUNCTIONS}"),
                });
            }
            continue;
        }
        if should_isolate_overlapping_candidate(
            fallback,
            &analysis.seeds,
            start,
            analysis.instructions.contains_key(&start),
        ) {
            // Native relocation candidates retain the existing containment
            // rule: an overlapping speculative seed must not claim an
            // entire shared graph. Compatibility pointers have already been
            // evaluated against defined instruction locations.
            isolated_starts.insert(start);
        }
        function_starts.insert(start);
        // Same rule as the import-call wave below: upstream has no per-walk
        // instruction budget, so a walk that blows past capa-x's is a
        // statement about this backend's guard rail, not about the image.
        // Keep what the walk did discover and record why it stopped, rather
        // than failing the whole image on one runaway start.
        let calls = discover_direct_flow(analysis, &mut direct_flow, start, &mut pointers)?;
        for target in calls.into_iter().rev() {
            if !is_executable(&analysis.image, target) {
                continue;
            }
            let is_new = !analysis.seeds.contains_key(&target);
            // A call target is discovered code, so it has to be walked before
            // the prologue-signature seeds: vivisect's codeflow completes for
            // every entry point before `generic/funcentries.py` scans what is
            // *still undefined* for prologue byte patterns. This queue is
            // priority-sorted once, at its initial fill, so an address that
            // was a signature seed then keeps that seed's last-place position
            // even after a call proves it a real function. Requeue it at the
            // front; otherwise a lower-addressed signature hit inside its body
            // -- the `jmp` target of an MSVC hot-patch thunk, say -- is walked
            // first and becomes a function of its own, which vivisect never
            // creates.
            let was_heuristic_only = !is_new
                && analysis.seeds.get(&target).is_some_and(|kinds| {
                    kinds.iter().all(|kind| {
                        matches!(
                            kind,
                            SeedKind::FunctionSignature
                                | SeedKind::Prologue
                                | SeedKind::SweepCallTarget
                        )
                    })
                });
            analysis
                .seeds
                .entry(target)
                .or_default()
                .insert(SeedKind::CallTarget);
            if is_new
                || (!function_starts.contains(&target)
                    && (was_heuristic_only
                        || direct_flow.completed_functions.contains_key(&target)))
            {
                pending.push_front(target);
            }
        }
    }
    analysis.functions.clear();
    for start in function_starts {
        if direct_flow.delayed_functions.contains(&start) {
            continue;
        }
        let function = match build_function_view(
            analysis,
            &direct_flow,
            start,
            isolated_starts.contains(&start),
        ) {
            Ok(function) => function,
            // A function whose reachable set is past the budget is dropped
            // rather than truncated: a partial view would invent an extent
            // neither backend has, and rules evaluated at function scope would
            // see an arbitrary prefix of it. The diagnostic keeps it visible.
            Err(RecoveryError::Limit(message)) => {
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address: start,
                    message: format!("dropped oversized function: {message}"),
                });
                continue;
            }
            Err(error) => return Err(error),
        };
        analysis.functions.insert(start, function);
    }
    // Compatibility propagates no-return decisions as functions complete.
    // Native recovery uses the complete graph for its fixed point. Preserve
    // import-call fragments in that graph, then apply captured feature scopes
    // after recovery decisions.
    for address in &direct_flow.import_functions {
        if let Some(captured) = direct_flow.completed_functions.get(address) {
            analysis.functions.insert(*address, captured.clone());
        }
    }
    let next = if direct_flow.compatibility {
        direct_flow.known_noreturn.clone()
    } else {
        noreturn::propagate(analysis, &noreturn::seed_addresses(&analysis.image))
    };
    for (address, captured) in direct_flow.completed_functions {
        if let Some(function) = analysis.functions.get_mut(&address) {
            *function = captured;
        }
    }
    Ok(next)
}

/// Vivisect's `i386.golang` pass: seed `runtime_main`, the start every Go
/// application hangs off and that no direct call reaches.
fn run_go_runtime_main_wave(
    analysis: &mut Analysis,
    direct_flow: &DirectFlowGraph,
    pending: &mut VecDeque<u64>,
) -> Result<(), RecoveryError> {
    if !golang::is_go_image(&analysis.image) {
        return Ok(());
    }
    let Some(entry) = analysis.image.entry_point else {
        return Ok(());
    };
    if !direct_flow.successors.contains_key(&entry) {
        return Ok(());
    }
    // The Go wave is an optional enrichment; if the entry walk is past the
    // budget there is nothing to enrich from, and that is not a reason to fail
    // the image.
    let Ok(entry_view) = build_function_view(analysis, direct_flow, entry, false) else {
        return Ok(());
    };
    // `find_golang_bblock_via_stack` needs the blocks of a *second* function,
    // the one the entry stub pushes; build it the same way on demand.
    let blocks_at = |address: u64| {
        direct_flow
            .successors
            .contains_key(&address)
            .then(|| build_function_view(analysis, direct_flow, address, false).ok())
            .flatten()
    };
    let Some(runtime_main) = golang::runtime_main(&analysis.image, &entry_view, &blocks_at) else {
        return Ok(());
    };
    if !is_executable(&analysis.image, runtime_main) {
        return Ok(());
    }
    let is_new = !analysis.seeds.contains_key(&runtime_main);
    analysis
        .seeds
        .entry(runtime_main)
        .or_default()
        .insert(SeedKind::GoRuntimeMain);
    if is_new {
        pending.push_front(runtime_main);
    }
    Ok(())
}

/// `vw.getCodeBlock(va)[L_VA]`: the start of the code block containing `va`.
/// capa-x has no standing block graph -- [`build_function_view`] derives
/// block starts per function -- so walk back to the nearest one using the
/// same two rules it does: an address begins a block if something branches to
/// it, or if the instruction it follows ends one.
fn code_block_start(analysis: &Analysis, direct_flow: &DirectFlowGraph, va: u64) -> Option<u64> {
    if direct_flow.compatibility {
        // getCodeBlock reads the last block written to the workspace map.
        // Reconstructing a boundary from nearby instruction addresses loses
        // that ownership when instruction streams or function views overlap.
        return direct_flow
            .completed_functions
            .iter()
            .flat_map(|(function, view)| {
                view.blocks.iter().filter_map(|block| {
                    let end = block.insns.last()?.next_address;
                    (block.addr <= va && va < end).then_some((
                        analysis.function_order.get(function).copied().unwrap_or(0),
                        block.addr,
                    ))
                })
            })
            .max()
            .map(|(_, start)| start);
    }
    let mut address = va;
    loop {
        if !analysis.instructions.contains_key(&address) {
            return None;
        }
        if analysis.code_xrefs.contains_key(&address) {
            return Some(address);
        }
        let Some((&previous, insn)) = analysis.instructions.range(..address).next_back() else {
            return Some(address);
        };
        if insn.next_address != address
            || is_block_terminator(insn.flow)
            || !direct_flow.successors.contains_key(&previous)
        {
            return Some(address);
        }
        address = previous;
    }
}

/// Vivisect's `ms.msvcfunc` pass: split the `/GS` cookie-restoring tail of a
/// function off into a function of its own. See [`super::msvcfunc`].
fn run_msvc_cookie_wave(
    analysis: &mut Analysis,
    direct_flow: &DirectFlowGraph,
    function_starts: &BTreeSet<u64>,
    pending: &mut VecDeque<u64>,
) {
    if analysis.image.format != ImageFormat::Pe {
        return;
    }
    let mut cookies = BTreeSet::new();
    for &start in function_starts {
        if !msvcfunc::is_security_check_cookie(&analysis.image, start) {
            continue;
        }
        let Some(insn) = analysis.instructions.get(&start) else {
            continue;
        };
        // `msvcfunc.py` reads `op.opers[1]` and requires it to be a deref.
        // (Upstream `return`s from the whole module when it isn't; every
        // byte pattern the signature table matches starts with a two-operand
        // `cmp reg, [cookie]`, so that early-out cannot fire -- this skips
        // the one function instead, which is order-independent.)
        if insn.x86_instruction().op_count() != 2
            || insn.x86_instruction().op_kind(1) != OpKind::Memory
        {
            continue;
        }
        if let Some(cookie) = insn.memory_target {
            cookies.insert(cookie);
        }
    }
    if cookies.is_empty() {
        return;
    }

    let starts = msvcfunc::new_function_starts(
        &cookies,
        |cookie| {
            analysis
                .data_xrefs
                .get(&cookie)
                .map(|sources| sources.to_vec())
                .unwrap_or_default()
        },
        |from| {
            analysis
                .instructions
                .get(&from)
                .map(|insn| insn.x86_instruction().mnemonic())
        },
        |from| code_block_start(analysis, direct_flow, from),
    );

    for start in starts {
        if function_starts.contains(&start) || !is_executable(&analysis.image, start) {
            continue;
        }
        analysis
            .seeds
            .entry(start)
            .or_default()
            .insert(SeedKind::MsvcCookieBlock);
        // Upstream's condition is `if not vw.isFunction(va)` -- a cookie block
        // becomes a function whatever else the workspace already knows about
        // the address. Requeueing only *newly seeded* addresses silently drops
        // the ones a heuristic seed had already claimed: the main loop skips a
        // `FunctionSignature`/`Prologue`-only seed whose bytes are already
        // decoded, so such an address is neither a function nor requeueable,
        // and the deterministic seed vanishes. `function_starts` above is the
        // `isFunction` check; everything past it is queue work.
        pending.push_front(start);
    }
}

/// Vivisect's `i386.importcalls` pass: flow through every `call [<import>]`
/// encoding left in undefined space, and promote the direct call targets found
/// along the way to function seeds.
///
/// The fragment start itself never becomes a function -- upstream calls
/// `vw.makeCode`, not `vw.makeFunction`, so the recovered run stays loose code
/// exactly as it does in the reference workspace.
fn run_import_call_wave(
    analysis: &mut Analysis,
    direct_flow: &mut DirectFlowGraph,
    pending: &mut VecDeque<u64>,
    pointers: &mut super::pointers::Discovery,
    function_starts: Option<&BTreeSet<u64>>,
) -> Result<(), RecoveryError> {
    let mut known_functions = function_starts.cloned();
    let starts = {
        let instructions = &analysis.instructions;
        importcalls::fragment_starts(&analysis.image, &|address| {
            instructions
                .range(..=address)
                .next_back()
                .map(|(start, insn)| (*start, insn.next_address))
                .filter(|(_, end)| address < *end)
                .map(|(_, end)| end)
                .or_else(|| {
                    function_starts?;
                    // `generic.relocations.analyze` makes pointer locations
                    // at undefined PE relocation slots before importcalls.
                    // findPointers skips these locations even when the slot
                    // happens to encode the operand of an undiscovered call.
                    let slots = &analysis.image.relocation_locations;
                    let index = slots.partition_point(|source| *source <= address);
                    let source = slots.get(index.checked_sub(1)?)?;
                    let end =
                        source.checked_add(analysis.image.architecture.pointer_width() as u64)?;
                    (address < end).then_some(end)
                })
        })
    };

    for start in starts {
        // Already-walked bytes are not undiscovered space.
        if direct_flow.successors.contains_key(&start) || !is_executable(&analysis.image, start) {
            continue;
        }
        let calls = discover_flow(
            analysis,
            direct_flow,
            start,
            pointers,
            known_functions.as_mut(),
        )?;
        for target in calls.into_iter().rev() {
            if !is_executable(&analysis.image, target) {
                continue;
            }
            let is_new = !analysis.seeds.contains_key(&target);
            analysis
                .seeds
                .entry(target)
                .or_default()
                .insert(SeedKind::CallTarget);
            if is_new || direct_flow.completed_functions.contains_key(&target) {
                pending.push_front(target);
            }
        }
    }
    Ok(())
}

/// AArch64 ELF/PE PLT stubs are `adrp Xn, page; ldr Xn, [Xn, #off]; ...; br
/// Xn` -- four instructions, unlike x86's single `jmp [rip+X]`, because
/// AArch64 has no instruction whose own operand computes an absolute
/// address. `discover_direct_flow`'s generic `Flow::IndirectBranch` handling
/// already recognizes a resolved thunk by checking `memory_target` against
/// `external_bindings`, but AArch64's `br` never has a memory operand (see
/// `decoder.rs`), so it can never match that check on its own.
///
/// This wave closes the gap the other way: once ordinary recovery has
/// decoded a stub's `adrp`+`ldr` pair (reached because something called the
/// stub directly, `bl <stub>`, which is an ordinary direct call and thus an
/// ordinary function candidate), resolve the pair's GOT-slot target and, if
/// it is a known import, register the **stub's own start address** --
/// exactly what a caller's `bl` targets -- as an alias for that same import.
/// The AArch64 API-feature extraction is the intended
/// downstream reader: it can look up a call's direct target in
/// `import_locations` directly, the same way x86 feature extraction does,
/// without redoing this pattern match itself. (`noreturn.rs`'s own
/// thunk/no-return check does not depend on this wave -- it needs the GOT
/// slot address, not the stub's, and resolves the pattern independently so
/// it isn't sensitive to wave ordering across recovery passes.)
fn run_aarch64_plt_wave(analysis: &mut Analysis) {
    if analysis.image.architecture != Architecture::AArch64 {
        return;
    }
    let mut resolved: Vec<(u64, Vec<String>)> = Vec::new();
    for (&address, first) in &analysis.instructions {
        let Some(second) = analysis.instructions.get(&first.next_address) else {
            continue;
        };
        let Some(target) = decoder::aarch64_plt_got_target(first, second) else {
            continue;
        };
        let Some(names) = analysis.image.external_bindings.get(&target) else {
            continue;
        };
        resolved.push((address, names.clone()));
    }
    for (address, names) in resolved {
        analysis.image.add_external_binding(address, names.clone());
        // `*.{name}`, matching `from_elf`'s own `"*"`-library convention for
        // every ELF relocation import (`image.rs`) -- `noreturn.rs`'s
        // `matches_noreturn_api` and the AArch64 API-feature extraction
        // both key off that exact prefix, and the GOT-slot entry this is an
        // alias of already carries it. A stub resolving to more than one
        // name only happens if upstream's own symbol versioning does, so
        // this takes the first the same way `import_locations` (a single
        // `String`, not a `Vec`) already forces on that GOT-slot entry.
        if let Some(name) = names.into_iter().next() {
            analysis
                .image
                .import_locations
                .entry(address)
                .or_insert_with(|| format!("*.{name}"));
        }
    }
}

fn seed_priority(kinds: &BTreeSet<SeedKind>, evaluate_candidates: bool) -> usize {
    // The prologue scan is the weakest, most false-positive-prone seed: a
    // `push ebp; mov ebp, esp` byte pattern often falls *inside* a real
    // function (a shared tail, a loop head). Processing it last -- after all
    // authoritative and call/relocation-driven flow has claimed its
    // instructions -- lets [`analyze_image`]'s heuristic-seed guard skip such
    // spurious starts, mirroring vivisect's flow-first discovery.
    if kinds.iter().any(|kind| is_authoritative_seed(*kind)) {
        0
    } else if kinds.contains(&SeedKind::CallTarget) {
        1
    } else if kinds.contains(&SeedKind::SweepCallTarget) {
        // Preserve native recovery's existing recall without letting the raw
        // byte heuristic invent reference operands for the emucode pass.
        if evaluate_candidates {
            4
        } else {
            1
        }
    } else if !kinds.contains(&SeedKind::Prologue) && !kinds.contains(&SeedKind::FunctionSignature)
    {
        2
    } else {
        3
    }
}

fn should_isolate_overlapping_candidate(
    fallback: &SeedMap,
    seeds: &SeedMap,
    start: u64,
    already_discovered: bool,
) -> bool {
    already_discovered
        && !fallback.contains_key(&start)
        && seeds.get(&start).is_some_and(|kinds| {
            kinds.contains(&SeedKind::Relocation)
                && !kinds.contains(&SeedKind::CallTarget)
                && !kinds.contains(&SeedKind::SweepCallTarget)
                && !kinds.iter().any(|kind| is_authoritative_seed(*kind))
        })
}

type SeedMap = BTreeMap<u64, BTreeSet<SeedKind>>;
type FunctionSymbolMap = BTreeMap<u64, Vec<String>>;

fn collect_seeds(
    bytes: &[u8],
    image: &LoadedImage,
    backend: RecoveryBackend,
) -> Result<(SeedMap, FunctionSymbolMap, Vec<RecoveryDiagnostic>), RecoveryError> {
    let mut seeds = BTreeMap::new();
    let mut elf_function_symbols = BTreeMap::new();
    let mut diagnostics = image
        .load_diagnostics
        .iter()
        .map(|message| RecoveryDiagnostic {
            address: image.image_base,
            message: message.clone(),
        })
        .collect();
    if let Some(entry) = image.entry_point {
        add_seed(image, &mut seeds, entry, SeedKind::EntryPoint);
    }
    match image.format {
        ImageFormat::Pe => collect_pe_seeds(bytes, image, &mut seeds, &mut diagnostics)?,
        ImageFormat::Elf => {
            collect_elf_seeds(bytes, image, backend, &mut seeds, &mut elf_function_symbols)?
        }
        // no exports/TLS/relocations/symbol tables to seed from -- see
        // `analyze_shellcode`'s doc comment.
        ImageFormat::Sc => {}
        ImageFormat::Macho => {
            collect_macho_seeds(bytes, image, &mut seeds, &mut elf_function_symbols)?
        }
    }
    Ok((seeds, elf_function_symbols, diagnostics))
}

/// `LC_FUNCTION_STARTS` (a high-quality, linker-emitted seed table), exported
/// symbols (via the export trie), and `LC_SYMTAB`'s
/// `N_SECT` symbols landing in an executable mapping. `function_symbols`
/// (named `elf_function_symbols` on [`Analysis`] for historical reasons --
/// it now also carries Mach-O's `LC_SYMTAB` names, the same "address to
/// function-name feature" role `capa.features.extractors.elf.SymTab` plays
/// for ELF) feeds `function_features.rs`'s `FunctionName` feature exactly as
/// it does for ELF.
fn collect_macho_seeds(
    bytes: &[u8],
    image: &LoadedImage,
    seeds: &mut SeedMap,
    function_symbols: &mut FunctionSymbolMap,
) -> Result<(), RecoveryError> {
    let (slice, _resolved_arch) =
        super::image::select_macho_slice(bytes, None).map_err(|error| RecoveryError::Seeds {
            format: ImageFormat::Macho,
            context: error.to_string(),
        })?;
    let macho = MachO::parse(slice, 0).map_err(|error| RecoveryError::Seeds {
        format: ImageFormat::Macho,
        context: error.to_string(),
    })?;

    // Flat section list (address, size), independent of segment/n_sect
    // numbering -- needed below to reject `__mh_execute_header`, which
    // every Mach-O executable's `LC_SYMTAB` *and* export trie both carry:
    // an `Extern`/`N_SECT` symbol whose value is the image's load address
    // (`__TEXT`'s `vmaddr`), which sits in the Mach header and load
    // commands, *not* inside any actual section's range -- a standard
    // linker convention, not a malformed input. The AArch64 decoder has
    // no invalid-encoding fallback the way x86 does (fixed-width, dense
    // opcode space -- almost any 4 bytes decode to *something*), so seeding
    // a function there let recovery fall/branch out of the header and load
    // commands and directly into real code, manufacturing a second,
    // overlapping "function" over legitimate instructions and a spurious
    // duplicate rule match (found empirically in the AArch64 Mach-O fixture
    // acceptance, `thin-arm64-exe`, recovered a 9-block function at the
    // image base that duplicated `_main`'s own `api: malloc` match). Every
    // legitimate function/data symbol and export *does* fall inside a real
    // section, so this check costs nothing for them.
    let mut macho_sections: Vec<(u64, u64)> = Vec::new();
    for segment in &macho.segments {
        if let Ok(sections) = segment.sections() {
            for (section, _data) in sections {
                macho_sections.push((section.addr, section.size));
            }
        }
    }
    let in_a_macho_section = |address: u64| {
        macho_sections
            .iter()
            .any(|(addr, size)| address >= *addr && address < addr.saturating_add(*size))
    };

    if let Ok(exports) = macho.exports() {
        for export in &exports {
            if let Some(address) = image.image_base.checked_add(export.offset) {
                if in_a_macho_section(address) {
                    add_seed(image, seeds, address, SeedKind::Export);
                }
            }
        }
    }

    for (name, nlist) in macho.symbols().flatten() {
        if nlist.is_stab() || nlist.get_type() != goblin::mach::symbols::N_SECT {
            continue;
        }
        if in_a_macho_section(nlist.n_value) {
            add_seed(image, seeds, nlist.n_value, SeedKind::Symbol);
        }
        // Strip the Mach-O C-symbol convention's leading `_`, matching
        // `image.rs::register_macho_import`'s import/export names -- a
        // rule author writing `function-name: add` should not have to know
        // this format prefixes every C symbol with an underscore. The name
        // is still recorded even when the symbol falls outside every
        // section, so a function independently recovered at this address
        // (e.g. the entry point) can still carry whatever name the symbol
        // table offers.
        let name = name.strip_prefix('_').unwrap_or(name);
        if name.is_empty() {
            continue;
        }
        let names = function_symbols.entry(nlist.n_value).or_default();
        if !names.iter().any(|existing| existing == name) {
            names.push(name.to_string());
        }
    }

    for command in &macho.load_commands {
        if let CommandVariant::FunctionStarts(linkedit) = command.command {
            collect_macho_function_starts(
                slice,
                image.image_base,
                linkedit.dataoff,
                linkedit.datasize,
                image,
                seeds,
            );
        }
    }
    Ok(())
}

/// `LC_FUNCTION_STARTS`' payload is a sequence of ULEB128-encoded deltas,
/// cumulative from `__TEXT`'s load address (`image_base`), terminated by a
/// `0x00` byte or the end of the declared region -- `mach-o/loader.h`'s
/// `linkedit_data_command` payload for this command.
fn collect_macho_function_starts(
    slice: &[u8],
    image_base: u64,
    dataoff: u32,
    datasize: u32,
    image: &LoadedImage,
    seeds: &mut SeedMap,
) {
    let base = usize::try_from(dataoff).unwrap_or(usize::MAX);
    let size = usize::try_from(datasize).unwrap_or(usize::MAX);
    let Some(data) = base.checked_add(size).and_then(|end| slice.get(base..end)) else {
        return;
    };
    let mut address = image_base;
    let mut offset = 0usize;
    'table: while offset < data.len() {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let Some(&byte) = data.get(offset) else {
                return;
            };
            offset += 1;
            result |= u64::from(byte & 0x7f).checked_shl(shift).unwrap_or(0);
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return;
            }
        }
        if result == 0 {
            // A zero delta only ever appears as the table's own terminator
            // (alignment padding after the real entries).
            break 'table;
        }
        address = address.saturating_add(result);
        add_seed(image, seeds, address, SeedKind::MachoFunctionStarts);
    }
}

// `as_chunks` is not available on the crate's Rust 1.87 MSRV, and these
// exact-size iterators intentionally leave malformed trailing bytes out.
#[allow(clippy::chunks_exact_to_as_chunks)]
fn collect_pe_seeds(
    bytes: &[u8],
    image: &LoadedImage,
    seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>,
    diagnostics: &mut Vec<RecoveryDiagnostic>,
) -> Result<(), RecoveryError> {
    let mut options = ParseOptions::default();
    options.parse_mode = ParseMode::Permissive;
    options.parse_resources = false;
    options.parse_attribute_certificates = false;
    options.parse_tls_data = true;
    let pe = PE::parse_with_opts(bytes, &options).map_err(|error| RecoveryError::Seeds {
        format: ImageFormat::Pe,
        context: error.to_string(),
    })?;
    for export in &pe.exports {
        // vivisect/parsers/pe.py records forwarded exports as strings. Their
        // RVA names another DLL's symbol, so it is not a function entry.
        if export.reexport.is_some() {
            continue;
        }
        if let Some(address) = image.image_base.checked_add(export.rva as u64) {
            add_seed(image, seeds, address, SeedKind::Export);
        }
    }
    if let Some(tls) = &pe.tls_data {
        for callback in &tls.callbacks {
            add_seed(image, seeds, *callback, SeedKind::TlsCallback);
        }
    }
    if let Some(load_config) = &pe.load_config_data {
        if let (Some(table), Some(count)) = (
            load_config.directory.se_handler_table,
            load_config.directory.se_handler_count,
        ) {
            collect_safe_seh_seeds(bytes.len(), image, table, count, seeds, diagnostics);
        }
    }
    if let Some(directory) = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|header| header.data_directories.get_exception_table())
    {
        // Parse this optional directory directly (rather than through
        // goblin 0.10.7's `ExceptionData::functions()`, which slices with
        // unchecked PE-provided bounds and can panic on malformed input).
        // AMD64 and ARM64 both call this the "exception table"/`.pdata`,
        // but its entry layout is architecture-specific -- `RUNTIME_FUNCTION`
        // (12 bytes: three RVAs) for AMD64, `IMAGE_ARM64_RUNTIME_FUNCTION_
        // ENTRY` (8 bytes: `BeginAddress` + `UnwindData`) for ARM64 --
        // so which loop below runs is gated on `image.architecture`, not
        // format alone.
        let directory_address = image
            .image_base
            .saturating_add(u64::from(directory.virtual_address));
        let requested = usize::try_from(directory.size).unwrap_or(usize::MAX);
        let raw = image.bytes_at(directory_address, requested).unwrap_or(&[]);
        if image.architecture == Architecture::X64 {
            if raw.len() != requested || !raw.len().is_multiple_of(12) {
                diagnostics.push(RecoveryDiagnostic {
                    address: directory_address,
                    message: format!(
                        "malformed x64 exception directory: declared {} bytes, {} file-backed bytes",
                        directory.size,
                        raw.len()
                    ),
                });
            }
            // Port of vivisect/parsers/pe.py's `.pdata` walk (pe.py:513-548): seed
            // a function per AMD64 RUNTIME_FUNCTION *entry*, but skip function
            // *blocks* -- chained fragments (`UNW_FLAG_CHAININFO`) whose
            // BeginAddress is interior to the parent function. Vivisect only calls
            // `addEntryPoint()` on non-chained entries; seeding the chained ones
            // (as this code previously did) manufactures a spurious function start
            // inside every real function that has multiple unwind fragments, which
            // then truncates the real function at that address. Vivisect also
            // *bails on the whole directory* (`break`) the moment an entry's
            // UNWIND_INFO pointer is unmapped or its version is not 1, so replicate
            // that rather than skipping the single entry.
            // UNW_FLAG_CHAININFO = 0x4 (PE/__init__.py:162); the VerFlags version
            // (`& 0x7`) / flags (`>> 3`) split and break semantics are pe.py:529-548.
            const UNW_FLAG_CHAININFO: u8 = 0x4;
            for entry in raw.chunks_exact(12) {
                let (Some(begin), Some(unwind_info_rva)) = (
                    entry
                        .get(..4)
                        .and_then(|value| <[u8; 4]>::try_from(value).ok())
                        .map(u32::from_le_bytes),
                    entry
                        .get(8..12)
                        .and_then(|value| <[u8; 4]>::try_from(value).ok())
                        .map(u32::from_le_bytes),
                ) else {
                    continue;
                };
                let Some(unwind_info_va) = image.image_base.checked_add(u64::from(unwind_info_rva))
                else {
                    break;
                };
                // vivisect: `if not vw.isValidPointer(baseaddr + UnwindInfoAddress): break`
                let Some(&ver_flags) = image
                    .bytes_at(unwind_info_va, 1)
                    .and_then(|bytes| bytes.first())
                else {
                    break;
                };
                if ver_flags & 0x7 != 1 {
                    // Unwind Info Version != 1 -> vivisect bails on the whole `.pdata`.
                    break;
                }
                if ver_flags >> 3 & UNW_FLAG_CHAININFO != 0 {
                    // A function *block*, not a function *entry* -> not a start.
                    continue;
                }
                if let Some(address) = image.image_base.checked_add(u64::from(begin)) {
                    add_seed(image, seeds, address, SeedKind::Unwind);
                }
            }
        } else if image.architecture == Architecture::AArch64 {
            if raw.len() != requested || !raw.len().is_multiple_of(8) {
                diagnostics.push(RecoveryDiagnostic {
                    address: directory_address,
                    message: format!(
                        "malformed arm64 exception directory: declared {} bytes, {} file-backed bytes",
                        directory.size,
                        raw.len()
                    ),
                });
            }
            // `IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY` (winnt.h): `BeginAddress`
            // (RVA, u32) then `UnwindData` (u32 -- either packed unwind info
            // or, when its low 2 bits are 0, an RVA into `.xdata`). Unlike
            // AMD64, the ARM64 Windows ABI has no function-fragment/chaining
            // concept (every entry stands for exactly one whole function --
            // Microsoft's ARM64 exception-handling docs), so this needs
            // none of the AMD64 branch's `UNW_FLAG_CHAININFO`/version-bail
            // logic: every entry's `BeginAddress` is an authoritative
            // function start, full stop.
            for entry in raw.chunks_exact(8) {
                let Some(begin) = entry
                    .get(..4)
                    .and_then(|value| <[u8; 4]>::try_from(value).ok())
                    .map(u32::from_le_bytes)
                else {
                    continue;
                };
                if let Some(address) = image.image_base.checked_add(u64::from(begin)) {
                    add_seed(image, seeds, address, SeedKind::Unwind);
                }
            }
        }
    }
    // Targets remain candidates until pointer classification has the current
    // location map. The loader also retains the source slots as typed data.
    for &location in &image.relocation_locations {
        if let Some(target) = read_pointer(image, location) {
            add_seed(image, seeds, target, SeedKind::Relocation);
        }
    }
    Ok(())
}

fn collect_safe_seh_seeds(
    file_size: usize,
    image: &LoadedImage,
    table: u64,
    count: u64,
    seeds: &mut SeedMap,
    diagnostics: &mut Vec<RecoveryDiagnostic>,
) {
    if table == 0 || count == 0 {
        return;
    }
    // Faithful port of pinned Vivisect 1.3.2
    // `vivisect/parsers/pe.py:465-485`. Its sanity check is strictly
    // `SEHandlerCount * 4 < pe.filesize`, even though the subsequent `P`
    // format uses the workspace pointer width.
    let Some(sanity_size) = count.checked_mul(4) else {
        return;
    };
    if sanity_size >= u64::try_from(file_size).unwrap_or(u64::MAX)
        || image.bytes_at(table, 1).is_none()
    {
        return;
    }
    // SafeSEH is a 32/64-bit PE/x86 Windows exception-handling mechanism;
    // AArch64 PE uses `.pdata`/exception-directory unwind info
    // instead, so this table never applies there.
    let pointer_width = match image.architecture {
        Architecture::X86 => 4usize,
        Architecture::X64 => 8usize,
        Architecture::AArch64 => return,
    };
    let Some(byte_len) = usize::try_from(count)
        .ok()
        .and_then(|value| value.checked_mul(pointer_width))
    else {
        diagnostics.push(RecoveryDiagnostic {
            address: table,
            message: "SafeSEH table byte length overflows the host size".to_string(),
        });
        return;
    };
    let Some(raw) = image.bytes_at(table, byte_len) else {
        diagnostics.push(RecoveryDiagnostic {
            address: table,
            message: "SafeSEH table is not mapped".to_string(),
        });
        return;
    };
    if raw.len() != byte_len {
        diagnostics.push(RecoveryDiagnostic {
            address: table,
            message: format!(
                "SafeSEH table is truncated: expected {byte_len} bytes, found {}",
                raw.len()
            ),
        });
        return;
    }
    for entry in raw.chunks_exact(pointer_width) {
        let handler_rva = if pointer_width == 8 {
            let Some(value) = entry.get(..8).and_then(|value| value.try_into().ok()) else {
                return;
            };
            u64::from_le_bytes(value)
        } else {
            let Some(value) = entry.get(..4).and_then(|value| value.try_into().ok()) else {
                return;
            };
            u64::from(u32::from_le_bytes(value))
        };
        if let Some(handler) = image.image_base.checked_add(handler_rva) {
            add_seed(image, seeds, handler, SeedKind::SafeSeh);
        }
    }
}

fn plausible_relocation_function(image: &LoadedImage, address: u64) -> bool {
    // `generic.pointers` rejects free-hanging pointer targets marked by the
    // PE loader as dead data. Applying the same guard prevents legacy
    // relocation compensation from turning zero-filled `.rdata` into code.
    if image.is_dead_data(address) || !image.is_primary_code_address(address) {
        return false;
    }
    let Ok(first) = image.decode_at(address) else {
        return false;
    };
    if first.x86_instruction().mnemonic() == Mnemonic::Push {
        if first.x86_instruction().op0_kind() == OpKind::Register {
            return true;
        }
        // Pinned Vivisect 1.3.2's `analysis/i386/__init__.py` registers
        // `push imm8; push imm32; call rel32` as an i386 function-entry
        // signature for Microsoft's SEH setup sequence. Its relocation
        // analysis follows pointers to matching executable locations.
        return image.architecture == Architecture::X86
            && image
                .bytes_at(address, 8)
                .is_some_and(matches_x86_seh_entry_signature);
    }
    matches!(
        first.x86_instruction().mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Sub
            | Mnemonic::Xor
            | Mnemonic::Jmp
            | Mnemonic::Lea
            | Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Call
            | Mnemonic::Endbr32
            | Mnemonic::Endbr64
    )
}

fn plausible_sweep_function(image: &LoadedImage, address: u64) -> bool {
    image.decode_at(address).is_ok_and(|first| {
        first.x86_instruction().mnemonic() == Mnemonic::Push
            || plausible_relocation_function(image, address)
    })
}

fn collect_elf_seeds(
    bytes: &[u8],
    image: &LoadedImage,
    backend: RecoveryBackend,
    seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>,
    function_symbols: &mut BTreeMap<u64, Vec<String>>,
) -> Result<(), RecoveryError> {
    let elf = Elf::parse(bytes).map_err(|error| RecoveryError::Seeds {
        format: ImageFormat::Elf,
        context: error.to_string(),
    })?;
    collect_function_symbols(image, elf.syms.iter(), &elf.strtab, seeds, function_symbols);
    collect_function_symbols(
        image,
        elf.dynsyms.iter(),
        &elf.dynstrtab,
        seeds,
        function_symbols,
    );
    // `generic.emucode.analyze` also tries named undefined addresses. A
    // non-function symbol is a candidate, never an authoritative function.
    if matches!(image.architecture, Architecture::X86 | Architecture::X64) {
        for symbol in elf.syms.iter().chain(elf.dynsyms.iter()) {
            if symbol.st_shndx != 0
                && symbol.st_value != 0
                && symbol.st_name != 0
                && !matches!(st_type(symbol.st_info), STT_FUNC | STT_GNU_IFUNC)
            {
                if let Some(address) = symbol.st_value.checked_add(image.load_bias) {
                    add_seed(image, seeds, address, SeedKind::Emulated);
                }
            }
        }
    }
    for relocation in elf
        .dynrelas
        .iter()
        .chain(elf.dynrels.iter())
        .chain(elf.pltrelocs.iter())
    {
        let location = relocation.r_offset.saturating_add(image.load_bias);
        // Only the *unnamed* relocation branch of `vivisect/parsers/elf.py`
        // dereferences the slot (`R_386_RELATIVE`, elf.py:865-869: "ptr =
        // vw.readMemoryPtr(rlva)"). A *named* `JMP_SLOT`/`GLOB_DAT` becomes an
        // import instead (elf.py:842-845), and upstream guards the paths that
        // do read the slot with `isPLT`, whose comment is exactly this case:
        // "some toolchains like to point the GOT back at it's PLT entry".
        // Dereferencing it here seeds a function at `plt_entry + 6`, the middle
        // of the stub, instead of at the stub.
        if image.import_locations.contains_key(&location) {
            continue;
        }
        // A `0` slot means the relocation hasn't been applied to the raw file
        // bytes at all (an `R_AARCH64_RELATIVE`/`R_X86_64_RELATIVE` target
        // with no static addend baked into the slot itself, common for a
        // PIE's data/GOT entries this loader never runtime-relocates -- see
        // `run_aarch64_plt_wave`'s doc comment on the same non-relocation).
        // Rebasing a bare `0` by `load_bias` produces `load_bias` itself,
        // i.e. the image base -- almost always mapped and executable, so
        // `add_seed` would otherwise happily accept it as a real function
        // start and the CFG walk would then fall/branch through however much
        // of the image is reachable from address zero. Skip it rather than
        // rebase a value that was never a real pointer to begin with.
        if let Some(target) = read_pointer(image, location).filter(|&target| target != 0) {
            let target = if image.load_bias != 0 && !is_executable(image, target) {
                target.saturating_add(image.load_bias)
            } else {
                target
            };
            add_seed(image, seeds, target, SeedKind::Relocation);
        }
        // vivisect/parsers/elf.py:loadElfRelocs reads the stored pointer
        // for R_386_RELATIVE / R_X86_64_RELATIVE (both type 8). It does
        // not substitute the RELA addend, even when the slot is zero.
        if backend == RecoveryBackend::VivisectCompat
            && matches!(image.architecture, Architecture::X86 | Architecture::X64)
            && relocation.r_type == goblin::elf::reloc::R_X86_64_RELATIVE
        {
            continue;
        }
        if let Some(addend) = relocation
            .r_addend
            .and_then(|value| u64::try_from(value).ok())
        {
            let target = addend.saturating_add(image.load_bias);
            add_seed(image, seeds, target, SeedKind::Relocation);
        }
    }
    if let Some(main) = libc_start_main::main_address(image) {
        add_seed(image, seeds, main, SeedKind::LibcMain);
    }
    // `vivisect/parsers/elf.py:447-463` walks the *section* table as well as
    // the dynamic table: `.init`/`.fini` become functions by name, and
    // `.init_array`/`.fini_array` go through `makeFunctionTable`, which makes
    // a function of every pointer in the array. A statically linked ELF has no
    // `PT_DYNAMIC` at all, so the `DT_INIT_ARRAY` path below never fires for
    // one and these constructors are reachable only from the section headers.
    // `2f7f5fb5…elf_` is exactly that: ET_EXEC, no `.dynamic`, and a
    // 0x138-byte `.init_array` whose entries the reference names
    // `init_function_N`.
    for shdr in &elf.section_headers {
        let Some(name) = elf.shdr_strtab.get_at(shdr.sh_name) else {
            continue;
        };
        let address = shdr.sh_addr.saturating_add(image.load_bias);
        match name {
            ".init" => add_seed(image, seeds, address, SeedKind::Init),
            ".fini" => add_seed(image, seeds, address, SeedKind::Fini),
            ".init_array" => add_pointer_array_seeds(
                image,
                seeds,
                Some(address),
                shdr.sh_size,
                SeedKind::InitArray,
            )?,
            ".fini_array" => add_pointer_array_seeds(
                image,
                seeds,
                Some(address),
                shdr.sh_size,
                SeedKind::FiniArray,
            )?,
            _ => {}
        }
    }
    if let Some(dynamic) = &elf.dynamic {
        let mut init_array = None;
        let mut init_array_size = 0u64;
        let mut fini_array = None;
        let mut fini_array_size = 0u64;
        for entry in &dynamic.dyns {
            match entry.d_tag {
                DT_INIT => add_seed(
                    image,
                    seeds,
                    entry.d_val.saturating_add(image.load_bias),
                    SeedKind::Init,
                ),
                DT_FINI => add_seed(
                    image,
                    seeds,
                    entry.d_val.saturating_add(image.load_bias),
                    SeedKind::Fini,
                ),
                DT_INIT_ARRAY => init_array = Some(entry.d_val.saturating_add(image.load_bias)),
                DT_INIT_ARRAYSZ => init_array_size = entry.d_val,
                DT_FINI_ARRAY => fini_array = Some(entry.d_val.saturating_add(image.load_bias)),
                DT_FINI_ARRAYSZ => fini_array_size = entry.d_val,
                _ => {}
            }
        }
        add_pointer_array_seeds(
            image,
            seeds,
            init_array,
            init_array_size,
            SeedKind::InitArray,
        )?;
        add_pointer_array_seeds(
            image,
            seeds,
            fini_array,
            fini_array_size,
            SeedKind::FiniArray,
        )?;
    }
    Ok(())
}

fn add_pointer_array_seeds(
    image: &LoadedImage,
    seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>,
    address: Option<u64>,
    size: u64,
    kind: SeedKind,
) -> Result<(), RecoveryError> {
    let Some(address) = address else {
        return Ok(());
    };
    let width = image.architecture.pointer_width() as u64;
    if !size.is_multiple_of(width) || size / width > 65_536 {
        return Err(RecoveryError::Seeds {
            format: ImageFormat::Elf,
            context: format!("invalid pointer-array size {size:#x} at {address:#x}"),
        });
    }
    for index in 0..size / width {
        let Some(slot) = address.checked_add(index.saturating_mul(width)) else {
            continue;
        };
        let Some(raw) = image.bytes_at(slot, width as usize) else {
            continue;
        };
        let target = if width == 8 {
            let Some(bytes) = raw.get(..8).and_then(|value| value.try_into().ok()) else {
                continue;
            };
            u64::from_le_bytes(bytes)
        } else {
            let Some(bytes) = raw.get(..4).and_then(|value| value.try_into().ok()) else {
                continue;
            };
            u64::from(u32::from_le_bytes(bytes))
        };
        // See the matching guard in `collect_elf_seeds`'s relocation loop: a
        // bare `0` slot is an unrelocated PIE pointer, not a real address,
        // and rebasing it by `load_bias` would otherwise land squarely on
        // the (usually mapped, executable) image base.
        if target == 0 {
            continue;
        }
        let target = if image.load_bias != 0 && !is_executable(image, target) {
            target.saturating_add(image.load_bias)
        } else {
            target
        };
        add_seed(image, seeds, target, kind);
    }
    Ok(())
}

fn add_seed(
    image: &LoadedImage,
    seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>,
    address: u64,
    kind: SeedKind,
) {
    if is_executable(image, address) {
        seeds.entry(address).or_default().insert(kind);
    }
}

/// Seeds function starts from `STT_FUNC`/`STT_GNU_IFUNC` symbols and records
/// their names, mirroring `capa.features.extractors.elf.SymTab`'s combined
/// `.symtab`/`.dynsym` view (each table's `st_name` is only meaningful
/// against its *own* string table, so this is called once per table rather
/// than over a chained iterator).
fn collect_function_symbols(
    image: &LoadedImage,
    syms: impl Iterator<Item = goblin::elf::sym::Sym>,
    strtab: &goblin::strtab::Strtab<'_>,
    seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>,
    function_symbols: &mut BTreeMap<u64, Vec<String>>,
) {
    for symbol in syms {
        if symbol.st_shndx == 0
            || symbol.st_value == 0
            || !matches!(st_type(symbol.st_info), STT_FUNC | STT_GNU_IFUNC)
        {
            continue;
        }
        let address = symbol.st_value.saturating_add(image.load_bias);
        add_seed(image, seeds, address, SeedKind::Symbol);
        let Some(name) = strtab.get_at(symbol.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let names = function_symbols.entry(address).or_default();
        if !names.iter().any(|existing| existing == name) {
            names.push(name.to_string());
        }
    }
}

fn add_prologue_seeds(image: &LoadedImage, seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>) {
    let patterns: &[&[u8]] = match image.architecture {
        Architecture::X86 => &[
            b"\x55\x8b\xec",
            b"\x55\x89\xe5",
            b"\x8b\xff\x55\x8b\xec",
            b"\x56\x8b\xf1",
        ],
        Architecture::X64 => &[
            b"\x55\x48\x89\xe5",
            b"\x40\x53\x48\x83\xec",
            b"\x48\x89\x5c\x24",
        ],
        // AArch64 has no fixed byte signature at all -- see
        // `add_aarch64_prologue_seeds`'s own doc comment for why this is a
        // decode-based structural scan instead, not a pattern list.
        Architecture::AArch64 => &[],
    };
    if image.architecture == Architecture::AArch64 {
        add_aarch64_prologue_seeds(image, seeds);
        return;
    }
    for section in image.sections.iter().filter(|section| {
        section.permissions.execute && image.is_primary_code_address(section.address)
    }) {
        let scan_len = usize::try_from(section.file_size)
            .unwrap_or(usize::MAX)
            .min(MAX_PROLOGUE_SCAN_BYTES);
        let Some(bytes) = image.bytes_at(section.address, scan_len) else {
            continue;
        };
        let mut found = 0usize;
        let mut covered_until = 0usize;
        // `generic.funcentries` uses `maxsize = mapsize - 4` and scans while
        // `offset < maxsize`, even though some registered signatures are only
        // three bytes long.
        for offset in 0..bytes.len().saturating_sub(4) {
            if offset < covered_until {
                continue;
            }
            let Some(rest) = bytes.get(offset..) else {
                break;
            };
            if let Some(pattern_len) = patterns
                .iter()
                .filter(|pattern| rest.starts_with(pattern))
                .map(|pattern| pattern.len())
                .max()
            {
                if let Some(address) = section.address.checked_add(offset as u64) {
                    if image.decode_at(address).is_ok() {
                        seeds.entry(address).or_default().insert(SeedKind::Prologue);
                        found += 1;
                        covered_until = offset.saturating_add(pattern_len);
                    }
                }
                if found >= MAX_PROLOGUE_SEEDS_PER_SECTION {
                    break;
                }
            }
        }
    }
}

/// Not a Vivisect port (Vivisect never analysed AArch64): task 4 added this
/// once feature extraction's own fixture table showed several pinned-corpus
/// functions are reachable by no seed this loader already collects (no
/// symbol, no relocation, never a `bl` target -- apparently only found by
/// Ghidra's own function-start heuristics).
///
/// Unlike x86, there is no single dominant byte signature: the AAPCS64
/// callee-saved-register save sequence a compiler emits varies both in which
/// register pair starts it (`x29`/`x30`, the frame-pointer pair, is
/// frequently saved several stores *into* the sequence rather than first --
/// an earlier, narrower version of this heuristic that only matched
/// `stp x29, x30, [sp, #-N]!` missed every function whose save order starts
/// with a different pair) and in whether the frame is carved out by the
/// first store's own pre-indexed writeback or by a preceding
/// `sub sp, sp, #N`. So this is a decode-based structural scan instead of a
/// pattern list, reusing the same decoder and `is_formattable`-gated
/// formatter this file's feature extraction already trusts
/// (`aarch64_features::is_prologue_candidate`) rather than hand-deriving a
/// second, parallel set of bitfield offsets here.
fn add_aarch64_prologue_seeds(image: &LoadedImage, seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>) {
    for section in image.sections.iter().filter(|section| {
        section.permissions.execute && image.is_primary_code_address(section.address)
    }) {
        let scan_len = usize::try_from(section.file_size)
            .unwrap_or(usize::MAX)
            .min(MAX_PROLOGUE_SCAN_BYTES);
        let Some(bytes) = image.bytes_at(section.address, scan_len) else {
            continue;
        };
        let mut found = 0usize;
        // Every AArch64 instruction is exactly 4 bytes, unlike x86's
        // variable length -- a genuine prologue can only start on a 4-byte
        // boundary, so this steps by word rather than by byte.
        for offset in (0..bytes.len().saturating_sub(4)).step_by(4) {
            let Some(address) = section.address.checked_add(offset as u64) else {
                break;
            };
            if super::aarch64_features::is_prologue_candidate(image, address) {
                seeds.entry(address).or_default().insert(SeedKind::Prologue);
                found += 1;
                if found >= MAX_PROLOGUE_SEEDS_PER_SECTION {
                    break;
                }
            }
        }
    }
}

fn add_backend_fallback_seeds(image: &LoadedImage, backend: RecoveryBackend, seeds: &mut SeedMap) {
    // Native formats and AArch64 retain their recovery heuristics. Vivisect
    // has no AArch64 backend. Its x86 compatibility path uses registered
    // entry signatures after candidate discovery.
    if backend == RecoveryBackend::Native || image.architecture == Architecture::AArch64 {
        add_prologue_seeds(image, seeds);
        add_swept_call_seeds(image, seeds);
    }
    // Vivisect runs generic function-entry signatures after other analyses.
    add_vivisect_function_signature_seeds(image, seeds);
}

fn add_vivisect_function_signature_seeds(image: &LoadedImage, seeds: &mut SeedMap) {
    if image.architecture != Architecture::X86 {
        return;
    }
    // Exact port of pinned Vivisect 1.3.2
    // `vivisect/analysis/i386/__init__.py:addEntrySigs`. Unlike the native
    // prologue fallback, these are the complete masked signatures used by the
    // compatibility backend's late `generic.funcentries` pass.
    const SIGNATURES: &[(&[u8], &[u8])] = &[
        (b"\x55\x8b\xec", b"\xff\xff\xff"),
        (b"\x56\x8b\xf1", b"\xff\xff\xff"),
        (b"\x55\x89\xe5", b"\xff\xff\xff"),
        (b"\x8b\xff\x55\x8b\xec", b"\xff\xff\xff\xff\xff"),
        (
            b"\x6a\x00\x68\x00\x00\x00\x00\xe8",
            b"\xff\x00\xff\x00\x00\x00\x00\xff",
        ),
    ];
    for section in image.sections.iter().filter(|section| {
        section.permissions.execute && image.is_primary_code_address(section.address)
    }) {
        if image.is_uninitialized(section.address) {
            continue;
        }
        let scan_len = usize::try_from(section.virtual_size)
            .unwrap_or(usize::MAX)
            .min(MAX_PROLOGUE_SCAN_BYTES);
        let Some(bytes) = image.bytes_at(section.address, scan_len) else {
            continue;
        };
        for offset in 0..bytes.len() {
            let Some(rest) = bytes.get(offset..) else {
                continue;
            };
            let matched = SIGNATURES.iter().any(|(signature, mask)| {
                rest.get(..signature.len()).is_some_and(|candidate| {
                    candidate
                        .iter()
                        .zip(signature.iter())
                        .zip(mask.iter())
                        .all(|((&actual, &expected), &mask)| actual & mask == expected & mask)
                })
            });
            if matched {
                if let Some(address) = section.address.checked_add(offset as u64) {
                    seeds
                        .entry(address)
                        .or_default()
                        .insert(SeedKind::FunctionSignature);
                }
            }
        }
    }
}

fn matches_x86_seh_entry_signature(bytes: &[u8]) -> bool {
    bytes.first() == Some(&0x6a) && bytes.get(2) == Some(&0x68) && bytes.get(7) == Some(&0xe8)
}

/// Recover callees from otherwise unreachable code islands. This is limited
/// to images with sparse deterministic recovery and requires the target to be
/// an executable, plausibly decoded entry.
fn add_swept_call_seeds(image: &LoadedImage, seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>) {
    // Dense seed maps already cover ordinary compiler output and make raw
    // byte sweeps counterproductive. Reserve this fallback for sparse images
    // where recursive descent otherwise has almost no foothold.
    if image.format != ImageFormat::Pe || seeds.len() > 128 {
        return;
    }
    // A Go binary reaches its application code through `runtime_main`, which
    // `golang::runtime_main` seeds directly. Sweeping its dense `.text` for
    // `e8` bytes on top of that is pure guesswork: measured on
    // `49a34cfbeed733c24392c9217ef46bb6.exe_`, the sweep produced 3124
    // functions against the reference's 1709, and all 11 of that sample's
    // rule diffs were *extra* matches inside the 1553 invented ones.
    if golang::is_go_image(image) {
        return;
    }
    let mut references = BTreeMap::<u64, usize>::new();
    for section in image.sections.iter().filter(|section| {
        section.permissions.execute && image.is_primary_code_address(section.address)
    }) {
        let scan_len = usize::try_from(section.file_size)
            .unwrap_or(usize::MAX)
            .min(MAX_PROLOGUE_SCAN_BYTES);
        let Some(bytes) = image.bytes_at(section.address, scan_len) else {
            continue;
        };
        for (offset, window) in bytes.windows(5).enumerate() {
            if window.first() != Some(&0xe8) {
                continue;
            }
            let Some(raw) = window.get(1..5).and_then(|value| value.try_into().ok()) else {
                continue;
            };
            let displacement = i64::from(i32::from_le_bytes(raw));
            let Some(next) = section
                .address
                .checked_add(offset as u64)
                .and_then(|address| address.checked_add(5))
            else {
                continue;
            };
            let target = if displacement >= 0 {
                next.checked_add(displacement as u64)
            } else {
                next.checked_sub(displacement.unsigned_abs())
            };
            let Some(target) = target else {
                continue;
            };
            if is_executable(image, target) && plausible_sweep_function(image, target) {
                let count = references.entry(target).or_default();
                *count = count.saturating_add(1);
            }
        }
    }
    let mut added = 0usize;
    for (address, _count) in references {
        if added >= MAX_SWEEP_CALL_SEEDS {
            continue;
        }
        seeds
            .entry(address)
            .or_default()
            .insert(SeedKind::SweepCallTarget);
        added += 1;
    }
}

fn discover_direct_flow(
    analysis: &mut Analysis,
    direct_flow: &mut DirectFlowGraph,
    start: u64,
    pointers: &mut super::pointers::Discovery,
) -> Result<BTreeSet<u64>, RecoveryError> {
    discover_flow(analysis, direct_flow, start, pointers, None)
}

enum FlowTask {
    Path(u64),
    ResumeOpcode(u64),
    CallbackTarget(u64, SeedKind),
    FinishFunction(u64),
    FinalizeFunction(u64),
    FlirtLocal(u64),
    ReleaseDelayed(u64),
    FollowPointers(VecDeque<(DecodedInstruction, u64)>),
    ResumeCall {
        address: u64,
        next: u64,
        target: u64,
    },
}

fn delay_function_for_branch(
    pending: &VecDeque<FlowTask>,
    target: u64,
    delayed: &mut BTreeMap<u64, BTreeSet<u64>>,
    loose_root: Option<u64>,
) {
    let mut active = pending.iter().filter_map(|task| match task {
        FlowTask::FinishFunction(address) => Some(*address),
        FlowTask::Path(_)
        | FlowTask::ResumeOpcode(_)
        | FlowTask::CallbackTarget(_, _)
        | FlowTask::ResumeCall { .. }
        | FlowTask::FinalizeFunction(_)
        | FlowTask::FlirtLocal(_)
        | FlowTask::ReleaseDelayed(_)
        | FlowTask::FollowPointers(_) => None,
    });
    if let Some(current) = active.next() {
        if current != target
            && (loose_root == Some(target) || active.any(|address| address == target))
        {
            delayed.entry(current).or_default().insert(target);
        }
    }
}

fn discover_flow(
    analysis: &mut Analysis,
    direct_flow: &mut DirectFlowGraph,
    start: u64,
    pointers: &mut super::pointers::Discovery,
    mut import_functions: Option<&mut BTreeSet<u64>>,
) -> Result<BTreeSet<u64>, RecoveryError> {
    let mut pending = VecDeque::from([FlowTask::Path(start)]);
    if direct_flow.compatibility && import_functions.is_none() {
        pending.push_back(FlowTask::FinishFunction(start));
    }
    let mut calls = BTreeSet::new();
    let mut discovered = 0usize;
    // envi/codeflow.py delays the function callback when a branch enters
    // an ancestor still on the analysis stack. Its complete extent is only
    // available after that ancestor finishes.
    let mut delayed = BTreeMap::<u64, BTreeSet<u64>>::new();
    let mut released_callbacks = BTreeSet::new();
    let mut retyping_functions = BTreeSet::new();
    let mut failed_block_analysis = BTreeSet::new();
    let mut block_starts_seen = BTreeMap::<u64, BTreeSet<u64>>::new();
    let loose_root = import_functions.as_ref().map(|_| start);

    'tasks: while let Some(task) = pending.pop_front() {
        let mut resume_opcode = matches!(task, FlowTask::ResumeOpcode(_));
        let path_start = match task {
            FlowTask::Path(address) | FlowTask::ResumeOpcode(address) => address,
            FlowTask::ResumeCall {
                address,
                next,
                target,
            } => {
                if direct_flow.known_noreturn.contains(&target) {
                    analysis.noreturn_calls.insert(address);
                    remove_code_reference(analysis, address, target);
                    direct_flow.successors.insert(address, Vec::new());
                } else {
                    pending.push_front(FlowTask::Path(next));
                }
                continue;
            }
            FlowTask::FinishFunction(address) => {
                if delayed.contains_key(&address)
                    || direct_flow.completed_functions.contains_key(&address)
                {
                    continue;
                }
                let order = analysis.function_order.len();
                analysis.function_order.entry(address).or_insert(order);
                let pointer = if failed_block_analysis.remove(&address) {
                    Some(Err(()))
                } else if direct_flow.compatibility {
                    prepare_function_code(
                        analysis,
                        direct_flow,
                        pointers,
                        address,
                        block_starts_seen.entry(address).or_default(),
                    )
                } else {
                    None
                };
                if let Some(Ok(target)) = pointer {
                    retyping_functions.insert(address);
                    pending.push_front(FlowTask::FinishFunction(address));
                    pending.push_front(FlowTask::Path(target));
                    continue;
                }
                let view = if pointer.is_some() {
                    Ok(Function {
                        addr: address,
                        blocks: Vec::new(),
                    })
                } else {
                    build_function_view(analysis, direct_flow, address, false)
                };
                match view {
                    Ok(mut function) => {
                        // addCodeBlock installs blocks in address order and
                        // stops when a previously visited start was deleted
                        // by pointer reclassification during this analyzer.
                        if let Some(missing) = block_starts_seen
                            .get(&address)
                            .into_iter()
                            .flatten()
                            .find(|start| {
                                instruction_location(analysis, **start).is_none()
                                    && !pointers.has_data_location(**start)
                            })
                        {
                            function.blocks.retain(|block| block.addr < *missing);
                            analysis.diagnostics.push(RecoveryDiagnostic { address: *missing, message: format!("function {address:#x} block installation stopped at a deleted location") });
                        }
                        analysis.functions.insert(address, function.clone());
                        direct_flow
                            .completed_functions
                            .entry(address)
                            .or_insert(function);
                    }
                    Err(error) => analysis.diagnostics.push(RecoveryDiagnostic {
                        address,
                        message: format!("could not preserve function extent: {error}"),
                    }),
                }
                pointers.function_completed(analysis, address);
                pending.push_front(FlowTask::FinalizeFunction(address));
                // Calling analysis runs after codeblocks and before noret,
                // while the procedural caller is still suspended.
                if direct_flow.compatibility && super::callbacks::enabled(&analysis.image) {
                    let (targets, operands, branches) = super::callbacks::discover(
                        analysis,
                        address,
                        &direct_flow.known_noreturn,
                        pointers,
                    );
                    // generic/switchcase runs only for dispatches reached
                    // by calling emulation, after the initial codeblock pass.
                    let mut switch_targets = Vec::new();
                    for branch in branches {
                        if let Some(targets) = super::switch::targets_compat(
                            analysis,
                            &branch,
                            &direct_flow.known_noreturn,
                            &mut direct_flow.pending_table_locations,
                        ) {
                            let edges = targets
                                .iter()
                                .map(|target| {
                                    push_xref(&mut analysis.code_xrefs, *target, branch.address);
                                    Edge {
                                        target: *target,
                                        kind: EdgeKind::JumpTable,
                                    }
                                })
                                .collect();
                            direct_flow.successors.insert(branch.address, edges);
                            switch_targets.extend(targets);
                        }
                    }
                    if !switch_targets.is_empty() {
                        pending.pop_front();
                        direct_flow.completed_functions.remove(&address);
                        pending.push_front(FlowTask::FinishFunction(address));
                        for target in switch_targets.into_iter().rev() {
                            pending.push_front(FlowTask::Path(target));
                        }
                    }
                    // addAnalysisResults runs after calls discovered by the
                    // emulator have completed. Follow its operands one at a
                    // time before this function's noret and FLIRT analyses.
                    pending.push_front(FlowTask::FollowPointers(operands.into()));
                    for (target, kind) in targets.into_iter().rev() {
                        pending.push_front(FlowTask::CallbackTarget(target, kind));
                    }
                }
                continue;
            }
            FlowTask::CallbackTarget(target, kind) => {
                if (kind == SeedKind::ApiCallback && super::pointers::covered(analysis, target))
                    || direct_flow.completed_functions.contains_key(&target)
                    || pending
                        .iter()
                        .any(|task| matches!(task, FlowTask::FinishFunction(va) if *va == target))
                {
                    continue;
                }
                analysis.seeds.entry(target).or_default().insert(kind);
                calls.insert(target);
                pending.push_front(FlowTask::FinishFunction(target));
                pending.push_front(FlowTask::Path(target));
                continue;
            }
            FlowTask::FollowPointers(mut operands) => {
                while let Some((instruction, target)) = operands.pop_front() {
                    pointers.observe_instruction(analysis, &instruction, false);
                    let Some(target) = pointers.follow_observed_pointer(
                        analysis,
                        target,
                        &direct_flow.known_noreturn,
                    ) else {
                        continue;
                    };
                    if direct_flow.completed_functions.contains_key(&target)
                        || pending.iter().any(
                            |task| matches!(task, FlowTask::FinishFunction(va) if *va == target),
                        )
                    {
                        continue;
                    }
                    calls.insert(target);
                    pending.push_front(FlowTask::FollowPointers(operands));
                    pending.push_front(FlowTask::FinishFunction(target));
                    pending.push_front(FlowTask::Path(target));
                    break;
                }
                continue;
            }
            FlowTask::FinalizeFunction(address) => {
                if direct_flow.compatibility
                    && direct_flow
                        .completed_functions
                        .get(&address)
                        .is_some_and(|function| {
                            noreturn::completed_function_never_returns(
                                analysis,
                                function,
                                &direct_flow.known_noreturn,
                            )
                        })
                {
                    direct_flow.known_noreturn.insert(address);
                }
                analysis
                    .function_flirt_counts
                    .insert(address, analysis.function_order.len());
                analysis
                    .function_location_counts
                    // Retyping can delete locations, but discovery order is
                    // monotonic. FLIRT visibility uses that same sequence.
                    .insert(address, analysis.instruction_order.len());
                // addEntryPoint releases only its immediate dependents via
                // _cb_function. Those callbacks do not recursively release
                // another level of deferred functions.
                if !released_callbacks.remove(&address) {
                    pending.push_front(FlowTask::ReleaseDelayed(address));
                }
                if let Some(flirt) = direct_flow.flirt.as_mut() {
                    for target in flirt
                        .function_completed(analysis, address)?
                        .into_iter()
                        .rev()
                    {
                        pending.push_front(FlowTask::FlirtLocal(target));
                    }
                }
                continue;
            }
            FlowTask::FlirtLocal(target) => {
                if instruction_location(analysis, target).is_none()
                    && !direct_flow.completed_functions.contains_key(&target)
                {
                    analysis
                        .seeds
                        .entry(target)
                        .or_default()
                        .insert(SeedKind::FlirtLocal);
                    calls.insert(target);
                    pending.push_front(FlowTask::FinishFunction(target));
                    pending.push_front(FlowTask::Path(target));
                }
                continue;
            }
            FlowTask::ReleaseDelayed(address) => {
                analysis
                    .function_analysis_counts
                    .insert(address, analysis.function_order.len());
                let mut ready = Vec::new();
                for (&waiting, dependencies) in &mut delayed {
                    dependencies.remove(&address);
                    if dependencies.is_empty() {
                        ready.push(waiting);
                    }
                }
                for waiting in ready.into_iter().rev() {
                    delayed.remove(&waiting);
                    released_callbacks.insert(waiting);
                    pending.push_front(FlowTask::FinishFunction(waiting));
                }
                continue;
            }
        };
        let mut address = path_start;
        loop {
            // Pinned Vivisect 1.3.2 discovers opcode locations and direct code
            // references before its generic codeblocks analysis assigns those
            // locations to functions. A known function entry is not a direct
            // flow barrier. Once an instruction is present in this shared
            // graph, every later function view can traverse its recorded edges.
            if direct_flow.compatibility && pointers.orphan_pointer(analysis, address) {
                if let Some(function) = pending
                    .iter()
                    .find_map(|task| match task {
                        FlowTask::FinishFunction(function) => Some(*function),
                        _ => None,
                    })
                    .filter(|function| retyping_functions.contains(function))
                {
                    failed_block_analysis.insert(function);
                    analysis.diagnostics.push(RecoveryDiagnostic { address, message: format!("function {function:#x} codeblock analysis reached a pointer without a reference") });
                }
            }
            if !resume_opcode
                && (super::emucode::in_data(pointers.code_barriers(), address)
                    || (direct_flow.compatibility
                        && pointers.pointer_location(analysis, address).is_some())
                    || (direct_flow.compatibility
                        && super::emucode::in_import(&analysis.image, address))
                    || direct_flow.successors.contains_key(&address)
                    || (direct_flow.compatibility
                        && instruction_location(analysis, address).is_some())
                    || !is_executable(&analysis.image, address))
            {
                break;
            }
            if discovered >= MAX_INSNS_PER_FUNCTION {
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address: start,
                    message: format!(
                        "abandoned code walk: direct flow from {start:#x} exceeds {MAX_INSNS_PER_FUNCTION} instructions"
                    ),
                });
                // Keep the callees already found. Their no-return status may
                // cut this oversized walk down on the next recovery pass.
                return Ok(calls);
            }
            let decoded = if direct_flow.compatibility {
                analysis.image.decode_at_compat(address)
            } else {
                analysis.image.decode_at(address)
            };
            let insn = match decoded {
                Ok(insn) => insn,
                Err(error) => {
                    analysis.diagnostics.push(RecoveryDiagnostic {
                        address,
                        message: error.to_string(),
                    });
                    break;
                }
            };
            if !direct_flow.compatibility && insn.is_privileged_barrier() {
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address,
                    message: "stopped recovery at privileged instruction".to_string(),
                });
                break;
            }
            let next = insn.next_address;
            if let Some(target) = insn.memory_target {
                push_xref(&mut analysis.data_xrefs, target, address);
            }
            // makeOpcode records mapped non-dereferenced operands as REF_PTR.
            // These references also delimit adjacent jump tables.
            if direct_flow.compatibility {
                let op = insn.x86_instruction();
                for index in 0..op.op_count() {
                    let target = match op.op_kind(index) {
                        iced_x86::OpKind::Immediate32 => Some(u64::from(op.immediate32())),
                        iced_x86::OpKind::Immediate64 => Some(op.immediate64()),
                        iced_x86::OpKind::Immediate32to64 => Some(op.immediate32to64() as u64),
                        _ => None,
                    };
                    if let Some(target) =
                        target.filter(|target| analysis.image.section_containing(*target).is_some())
                    {
                        push_xref(&mut analysis.data_xrefs, target, address);
                    }
                }
            }
            let flow = insn.flow;
            discovered = discovered.saturating_add(1);
            analysis.instructions.entry(address).or_insert(insn.clone());
            let order = analysis.instruction_order.len();
            analysis.instruction_order.entry(address).or_insert(order);
            if direct_flow.compatibility && !resume_opcode {
                pointers.mark_code(address, next);
                if let Some(target) = pointers
                    .observe_instruction(analysis, &insn, true)
                    .and_then(|target| {
                        pointers.follow_observed_pointer(
                            analysis,
                            target,
                            &direct_flow.known_noreturn,
                        )
                    })
                {
                    if !analysis.function_order.contains_key(&target)
                        && !pending.iter().any(
                            |task| matches!(task, FlowTask::FinishFunction(va) if *va == target),
                        )
                    {
                        // makeOpcode follows a newly typed data pointer before
                        // processing this instruction's control-flow edges.
                        calls.insert(target);
                        pending.push_front(FlowTask::ResumeOpcode(address));
                        pending.push_front(FlowTask::FinishFunction(target));
                        pending.push_front(FlowTask::Path(target));
                        continue 'tasks;
                    }
                }
            }
            resume_opcode = false;
            match flow {
                Flow::Next => {
                    direct_flow.successors.insert(
                        address,
                        vec![Edge {
                            target: next,
                            kind: EdgeKind::Fallthrough,
                        }],
                    );
                    address = next;
                }
                Flow::Call | Flow::IndirectCall => {
                    // envi/codeflow.py follows BR_DEREF procedural targets
                    // immediately. Import slots are removed by _cb_opcode
                    // before that step, so call [ExitProcess] still falls through.
                    let imported = insn
                        .memory_target
                        .is_some_and(|slot| analysis.image.external_bindings.contains_key(&slot));
                    let target = if flow == Flow::Call {
                        insn.direct_target
                    } else if direct_flow.compatibility
                        && !imported
                        && insn.x86_instruction().memory_index() == iced_x86::Register::None
                    {
                        insn.memory_target
                            .and_then(|slot| read_pointer(&analysis.image, slot))
                            .filter(|target| {
                                is_executable(&analysis.image, *target)
                                    && !analysis.image.is_uninitialized(*target)
                            })
                    } else {
                        None
                    };
                    if flow == Flow::IndirectCall && target.is_none() && !imported {
                        analysis.diagnostics.push(RecoveryDiagnostic {
                            address,
                            message: "unresolved indirect call".to_string(),
                        });
                    }
                    if let Some(target) = target {
                        if flow == Flow::Call {
                            push_xref(&mut analysis.code_xrefs, target, address);
                        }
                        // Pinned Vivisect 1.3.2 `envi/codeflow.py` records a
                        // procedural target only when it differs from the
                        // instruction after the call. `call $+5` remains a
                        // code reference and instruction feature, but it is
                        // not a function candidate.
                        if target != next {
                            calls.insert(target);
                        }
                    }
                    // `envi/codeflow.py:254-256`: still inside the
                    // `if bva != nextva` guard, a procedural branch to a
                    // no-return target gets `addNoFlow(va, nextva)` -- the
                    // call site keeps its code xref but loses its fallthrough,
                    // so the caller ends here instead of absorbing whatever
                    // bytes follow.
                    let ends_flow = target.is_some_and(|target| {
                        target != next && direct_flow.known_noreturn.contains(&target)
                    });
                    if ends_flow {
                        analysis.noreturn_calls.insert(address);
                        if let Some(target) = target {
                            remove_code_reference(analysis, address, target);
                        }
                        direct_flow.successors.insert(address, Vec::new());
                    } else {
                        direct_flow.successors.insert(
                            address,
                            vec![Edge {
                                target: next,
                                kind: EdgeKind::Fallthrough,
                            }],
                        );
                    }
                    // `envi/codeflow.py:addCodeFlow` descends into procedural
                    // targets before resuming a loose import-call fragment.
                    // `base.py:_cb_function` runs codeblocks.py immediately.
                    // A callee that meets already decoded fragment code can
                    // therefore end before the fragment's later continuation.
                    // Explicit tasks preserve that timing without Rust recursion.
                    if let Some(target) = target
                        .filter(|target| *target != next && is_executable(&analysis.image, *target))
                    {
                        if import_functions.as_deref_mut().is_some_and(|known| {
                            known.len() < MAX_FUNCTIONS && known.insert(target)
                        }) && !analysis.function_order.contains_key(&target)
                            && !pending.iter().any(|task| matches!(task, FlowTask::FinishFunction(va) if *va == target))
                        {
                            // Calling analysis can create a callee while an
                            // import fragment is suspended. The import pass's
                            // seed set alone does not track those active frames.
                            // Re-entering one would freeze its unfinished body.

                            if !ends_flow {
                                pending.push_front(FlowTask::ResumeCall {
                                    address,
                                    next,
                                    target,
                                });
                            }
                            direct_flow.import_functions.insert(target);
                            pending.push_front(FlowTask::FinishFunction(target));
                            pending.push_front(FlowTask::Path(target));
                            break;
                        }
                        if direct_flow.compatibility
                            && import_functions.is_none()
                            && !analysis.function_order.contains_key(&target)
                            && !pending.iter().any(|task| {
                                matches!(task, FlowTask::FinishFunction(address) if *address == target)
                            })
                        {
                            // addEntryPoint completes a callee even when its
                            // bytes were previously reached through a jump.
                            // Only a completed or currently active function
                            // suppresses that callback.
                            if !ends_flow {
                                pending.push_front(FlowTask::ResumeCall { address, next, target });
                            }
                            pending.push_front(FlowTask::FinishFunction(target));
                            pending.push_front(FlowTask::Path(target));
                            break;
                        }
                    }
                    if ends_flow {
                        break;
                    }
                    address = next;
                }
                Flow::ConditionalBranch => {
                    let mut edges = vec![Edge {
                        target: next,
                        kind: EdgeKind::Fallthrough,
                    }];
                    if !direct_flow.compatibility && import_functions.is_none() {
                        pending.push_back(FlowTask::Path(next));
                    }
                    if let Some(target) = insn.direct_target {
                        if direct_flow.compatibility {
                            delay_function_for_branch(&pending, target, &mut delayed, loose_root);
                            delay_function_for_branch(&pending, next, &mut delayed, loose_root);
                        }
                        edges.push(Edge {
                            target,
                            kind: EdgeKind::Branch,
                        });
                        if direct_flow.compatibility || import_functions.is_some() {
                            pending.push_front(FlowTask::Path(target));
                        } else {
                            pending.push_back(FlowTask::Path(target));
                        }
                        push_xref(&mut analysis.code_xrefs, target, address);
                    }
                    if direct_flow.compatibility || import_functions.is_some() {
                        pending.push_front(FlowTask::Path(next));
                    }
                    direct_flow.successors.insert(address, edges);
                    break;
                }
                Flow::UnconditionalBranch => {
                    if let Some(target) = insn.direct_target {
                        if direct_flow.compatibility {
                            delay_function_for_branch(&pending, target, &mut delayed, loose_root);
                        }
                        // Phase 2.1: a direct unconditional jump is ordinary
                        // control flow. A seed at the target only means the
                        // target *may* be a function entry -- it does not prove
                        // that this jump is a tail call, so we no longer split
                        // the function here on `seeds.contains_key(&target)`.
                        // Follow the edge as an ordinary branch; tail-call and
                        // thunk classification happens post-recovery (Phase 5)
                        // with full graph context, matching vivisect's codeflow
                        // which follows non-procedural branches and only later
                        // reclassifies single-block wrappers as thunks.
                        direct_flow.successors.insert(
                            address,
                            vec![Edge {
                                target,
                                kind: EdgeKind::Branch,
                            }],
                        );
                        push_xref(&mut analysis.code_xrefs, target, address);
                        if direct_flow.compatibility || import_functions.is_some() {
                            pending.push_front(FlowTask::Path(target));
                        } else {
                            pending.push_back(FlowTask::Path(target));
                        }
                    } else {
                        direct_flow.successors.insert(address, Vec::new());
                    }
                    break;
                }
                Flow::IndirectBranch => {
                    // `jmp [<import slot>]` is the tail of a PLT/IAT thunk, not
                    // a jump table. `_cb_opcode` (`vivisect/base.py:820`) drops
                    // every branch whose target is a `LOC_IMPORT` before
                    // codeflow inspects the branch list, so the reference never
                    // flows through one -- and never mistakes the neighbouring
                    // import slots for table entries either. Without this the
                    // lazy-binding initial value of a GOT slot (which points
                    // back at its own PLT stub) reads as a resolved table.
                    if insn.memory_target.is_some_and(|target| {
                        analysis.image.external_bindings.contains_key(&target)
                    }) {
                        direct_flow.successors.insert(address, Vec::new());
                        break;
                    }
                    let targets = if direct_flow.compatibility
                        && insn.memory_target.is_some()
                        && insn.x86_instruction().memory_index() != iced_x86::Register::None
                    {
                        Some(jump_table_targets_compat(
                            analysis,
                            &insn,
                            &direct_flow.known_noreturn,
                        ))
                    } else if direct_flow.compatibility
                        && !super::callbacks::enabled(&analysis.image)
                    {
                        super::switch::targets_compat(
                            analysis,
                            &insn,
                            &direct_flow.known_noreturn,
                            &mut direct_flow.pending_table_locations,
                        )
                    } else if direct_flow.compatibility {
                        // Register-based RVA switches are resolved by the
                        // calling emulator after function codeblocks exist.
                        None
                    } else {
                        super::switch::targets(analysis, &insn)
                    }
                    .unwrap_or_else(|| {
                        if direct_flow.compatibility {
                            jump_table_targets_compat(analysis, &insn, &direct_flow.known_noreturn)
                        } else {
                            jump_table_targets(&analysis.image, &insn)
                        }
                    });
                    if direct_flow.compatibility {
                        split_adjacent_tables(analysis, direct_flow, &insn, &targets);
                        for &target in &targets {
                            delay_function_for_branch(&pending, target, &mut delayed, loose_root);
                        }
                    }
                    // codeblocks.py excludes BR_DEREF xrefs from a function's
                    // extent. A plain pointer jump can discover loose code,
                    // but does not own the pointed-to function or inherit its
                    // no-return status. Indexed jump-table arms do belong to
                    // the dispatching function.
                    if !targets.is_empty() && is_pointer_jump(&analysis.image, &insn) {
                        for target in targets {
                            if direct_flow.compatibility || import_functions.is_some() {
                                pending.push_front(FlowTask::Path(target));
                            } else {
                                pending.push_back(FlowTask::Path(target));
                            }
                            push_xref(&mut analysis.code_xrefs, target, address);
                        }
                        direct_flow.successors.insert(address, Vec::new());
                        break;
                    }
                    // base.py:_cb_branchtable defines pointer locations for
                    // table entries. Without them, emucode may later accept
                    // the table bytes as another function.
                    if direct_flow.compatibility && !targets.is_empty() {
                        if let Some(base) = insn.memory_target {
                            let width = analysis.image.architecture.pointer_width();
                            let entries = analysis
                                .image
                                .bytes_at(base, usize::MAX)
                                .map_or(0, |bytes| bytes.len() / width);
                            for index in 0..entries {
                                let Some(slot) = base.checked_add((index * width) as u64) else {
                                    break;
                                };
                                if !read_pointer(&analysis.image, slot)
                                    .is_some_and(|target| targets.contains(&target))
                                {
                                    break;
                                }
                                direct_flow.pending_table_locations.push((slot, width));
                            }
                        }
                    }
                    if targets.is_empty() {
                        analysis.diagnostics.push(RecoveryDiagnostic {
                            address,
                            message: "unresolved indirect branch".to_string(),
                        });
                    } else {
                        // envi/codeflow.py completes every branch path before
                        // invoking the function callback. Queue switch arms
                        // ahead of FinishFunction in table order.
                        if direct_flow.compatibility || import_functions.is_some() {
                            for &target in targets.iter().rev() {
                                pending.push_front(FlowTask::Path(target));
                            }
                        } else {
                            for &target in &targets {
                                pending.push_back(FlowTask::Path(target));
                            }
                        }
                        let edges: Vec<_> = targets
                            .into_iter()
                            .map(|target| {
                                push_xref(&mut analysis.code_xrefs, target, address);
                                Edge {
                                    target,
                                    kind: EdgeKind::JumpTable,
                                }
                            })
                            .collect();
                        direct_flow.successors.insert(address, edges);
                    }
                    direct_flow.successors.entry(address).or_default();
                    break;
                }
                Flow::Return | Flow::Terminal => {
                    direct_flow.successors.insert(address, Vec::new());
                    break;
                }
            }
        }
    }

    direct_flow
        .delayed_functions
        .extend(delayed.keys().copied());
    Ok(calls)
}

// codeblocks.py deletes a stale pointer before trying to decode its suffix.
// locmap resolves that deletion through the current location at the pointer's
// original start, so the overlapping opcode is removed instead. The stale
// suffix remains orphaned; revisiting it aborts block analysis.
fn prepare_function_code(
    analysis: &mut Analysis,
    graph: &DirectFlowGraph,
    pointers: &mut super::pointers::Discovery,
    start: u64,
    block_starts_seen: &mut BTreeSet<u64>,
) -> Option<Result<u64, ()>> {
    let mut pending = vec![start];
    let mut done = BTreeSet::new();
    while let Some(mut address) = pending.pop() {
        if !done.insert(address) {
            continue;
        }
        let block_start = address;
        if instruction_location(analysis, address).is_some() {
            block_starts_seen.insert(address);
        }
        loop {
            let Some(location) = instruction_location(analysis, address) else {
                if let Some((pointer, end)) = pointers.pointer_location(analysis, address) {
                    if let Some(opcode) =
                        instruction_location(analysis, pointer).map(|insn| insn.address)
                    {
                        analysis.instructions.remove(&opcode);
                        pointers.remove_pointer_reference(pointer);
                        for sources in analysis.code_xrefs.values_mut() {
                            sources.retain(|source| *source != pointer);
                        }
                        analysis.code_xrefs.retain(|_, sources| !sources.is_empty());
                        analysis.diagnostics.push(RecoveryDiagnostic {
                            address,
                            message: format!(
                                "function {start:#x} has an overlapping pointer at {pointer:#x}"
                            ),
                        });
                        break;
                    }
                    if pointers.orphan_pointer(analysis, address) {
                        return Some(Err(()));
                    }
                    pointers.mark_code(pointer, end);
                    return Some(Ok(address));
                }
                break;
            };
            if analysis.image.decode_at_compat(address).is_err() {
                block_starts_seen.remove(&block_start);
                break;
            }
            let Some(next) = address.checked_add(location.bytes.len() as u64) else {
                break;
            };
            let branches: Vec<_> = graph
                .successors
                .get(&address)
                .into_iter()
                .flatten()
                .filter(|edge| edge.kind != EdgeKind::Fallthrough)
                .map(|edge| edge.target)
                .collect();
            pending.extend(branches.iter().copied());
            if matches!(
                location.flow,
                Flow::UnconditionalBranch | Flow::IndirectBranch | Flow::Return | Flow::Terminal
            ) || analysis.noreturn_calls.contains(&location.address)
            {
                break;
            }
            if !branches.is_empty() || analysis.code_xrefs.contains_key(&next) {
                pending.push(next);
                break;
            }
            address = next;
        }
    }
    None
}

fn build_function_view(
    analysis: &Analysis,
    direct_flow: &DirectFlowGraph,
    start: u64,
    isolate_start: bool,
) -> Result<Function, RecoveryError> {
    if direct_flow.compatibility {
        return build_compatibility_view(analysis, direct_flow, start);
    }
    let mut reachable = BTreeSet::new();
    let mut pending = VecDeque::from([start]);
    while let Some(address) = pending.pop_front() {
        if !analysis.instructions.contains_key(&address) || !reachable.insert(address) {
            continue;
        }
        if reachable.len() > MAX_INSNS_PER_FUNCTION {
            return Err(RecoveryError::Limit(format!(
                "function {start:#x} exceeds {MAX_INSNS_PER_FUNCTION} instructions"
            )));
        }
        if !isolate_start {
            let Some(edges) = direct_flow.successors.get(&address) else {
                continue;
            };
            for edge in edges {
                // A non-chained PE unwind entry is a linker-provided function
                // start. Falling into it must not merge two function scopes.
                // Explicit branches may still share tails or chained code.
                if edge.kind == EdgeKind::Fallthrough
                    && edge.target != start
                    && analysis
                        .seeds
                        .get(&edge.target)
                        .is_some_and(|kinds| kinds.contains(&SeedKind::Unwind))
                {
                    continue;
                }
                pending.push_back(edge.target);
            }
        }
    }

    let mut block_starts = BTreeSet::from([start]);
    // Intersect from the smaller side so small functions do not scan every
    // code-reference target in the image. Both paths retain address order.
    if reachable.len() < analysis.code_xrefs.len() {
        block_starts.extend(
            reachable
                .iter()
                .filter(|address| analysis.code_xrefs.contains_key(address))
                .copied(),
        );
    } else {
        block_starts.extend(
            analysis
                .code_xrefs
                .keys()
                .filter(|address| reachable.contains(address))
                .copied(),
        );
    }
    for &address in &reachable {
        let Some(insn) = analysis.instructions.get(&address) else {
            continue;
        };
        if is_block_terminator(insn.flow) {
            block_starts.extend(
                direct_flow
                    .successors
                    .get(&address)
                    .into_iter()
                    .flatten()
                    .filter(|edge| reachable.contains(&edge.target))
                    .map(|edge| edge.target),
            );
        }
    }

    let mut blocks = Vec::new();
    for &block_start in &block_starts {
        if !reachable.contains(&block_start) {
            continue;
        }
        let mut insns = Vec::new();
        let mut address = block_start;
        let succs = loop {
            let Some(insn) = analysis.instructions.get(&address) else {
                break Vec::new();
            };
            insns.push(insn.clone());
            let flow = insn.flow;
            let edges: Vec<Edge> = direct_flow
                .successors
                .get(&address)
                .into_iter()
                .flatten()
                .filter(|edge| reachable.contains(&edge.target))
                .copied()
                .collect();
            if is_block_terminator(flow) {
                break edges;
            }
            let next = insn.next_address;
            if next != block_start && block_starts.contains(&next) {
                break vec![Edge {
                    target: next,
                    kind: EdgeKind::Fallthrough,
                }];
            }
            if !reachable.contains(&next) {
                break Vec::new();
            }
            address = next;
        };
        blocks.push(BasicBlock {
            addr: block_start,
            insns,
            succs,
        });
    }
    blocks.sort_by_key(|block| block.addr);
    Ok(Function {
        addr: start,
        blocks,
    })
}

fn split_adjacent_tables(
    analysis: &mut Analysis,
    graph: &mut DirectFlowGraph,
    branch: &DecodedInstruction,
    targets: &[u64],
) {
    let (Some(base), Some(first)) = (branch.memory_target, targets.first()) else {
        return;
    };
    // makeJumpTable splits a previous table when this table's first arm
    // already has a reference from an earlier indexed dispatch.
    let previous: Vec<_> = analysis
        .code_xrefs
        .get(first)
        .into_iter()
        .flatten()
        .filter_map(|source| analysis.instructions.get(source))
        .filter(|insn| {
            insn.address != branch.address
                && insn.flow == Flow::IndirectBranch
                && insn.x86_instruction().memory_index() != iced_x86::Register::None
                && insn.memory_target.is_some_and(|previous| previous < base)
        })
        .map(|insn| insn.address)
        .collect();
    if previous.is_empty() {
        return;
    }
    let affected: Vec<_> = graph
        .completed_functions
        .iter()
        .filter(|(_, function)| {
            function.blocks.iter().any(|block| {
                block
                    .insns
                    .iter()
                    .any(|insn| previous.contains(&insn.address))
            })
        })
        .map(|(&address, _)| address)
        .collect();
    for source in previous {
        if let Some(edges) = graph.successors.get_mut(&source) {
            edges.retain(|edge| !targets.contains(&edge.target));
        }
        for target in targets {
            if let Some(sources) = analysis.code_xrefs.get_mut(target) {
                sources.retain(|address| *address != source);
            }
        }
    }
    // splitJumpTable removes the former owner's case blocks. Refresh scopes
    // whose dispatch edges changed so they no longer retain those arms.
    for target in targets {
        let owner = graph
            .completed_functions
            .iter()
            .filter(|(_, function)| function.blocks.iter().any(|block| block.addr == *target))
            .max_by_key(|(address, _)| analysis.function_order.get(address).copied().unwrap_or(0))
            .map(|(&address, _)| address);
        if let Some(function) = owner.and_then(|owner| graph.completed_functions.get_mut(&owner)) {
            function.blocks.retain(|block| block.addr != *target);
        }
    }
    for address in affected {
        match build_function_view(analysis, graph, address, false) {
            Ok(function) => {
                graph.completed_functions.insert(address, function);
            }
            Err(error) => analysis.diagnostics.push(RecoveryDiagnostic {
                address,
                message: format!("could not rebuild function after splitting its table: {error}"),
            }),
        }
    }
}

fn instruction_location(analysis: &Analysis, address: u64) -> Option<&DecodedInstruction> {
    // VivWorkspace.locmap overwrites each covered byte when a later opcode
    // overlaps an earlier one. A location can start at most fourteen bytes
    // before this address because x86 instructions are at most fifteen bytes.
    analysis
        .instructions
        .range(address.saturating_sub(14)..=address)
        .filter(|(_, insn)| address < insn.next_address)
        .max_by_key(|(start, _)| analysis.instruction_order.get(start).copied().unwrap_or(0))
        .map(|(_, insn)| insn)
}

/// Vivisect 1.3.2 generic/codeblocks.py advances by the existing location's
/// size, even when a branch enters its interior. viv_utils.BasicBlock then
/// decodes the resulting byte interval independently of those locations.
fn build_compatibility_view(
    analysis: &Analysis,
    graph: &DirectFlowGraph,
    start: u64,
) -> Result<Function, RecoveryError> {
    let mut pending = vec![start];
    let mut done = BTreeSet::new();
    let mut blocks = Vec::new();
    let mut count = 0usize;
    while let Some(block_start) = pending.pop() {
        if !done.insert(block_start) {
            continue;
        }
        let mut address = block_start;
        let mut succs = Vec::new();
        while let Some(location) = instruction_location(analysis, address) {
            count += 1;
            if count > MAX_INSNS_PER_FUNCTION {
                return Err(RecoveryError::Limit(format!(
                    "function {start:#x} exceeds {MAX_INSNS_PER_FUNCTION} instructions"
                )));
            }
            if !analysis.instructions.contains_key(&address)
                && analysis.image.decode_at_compat(address).is_err()
            {
                // A decoder exception leaves blocks[start] at zero upstream.
                // Only an existing block survives a failed reanalysis.
                address = graph
                    .completed_functions
                    .get(&start)
                    .and_then(|function| {
                        function
                            .blocks
                            .iter()
                            .find(|block| block.addr == block_start)
                    })
                    .and_then(|block| block.insns.last())
                    .map_or(block_start, |last| last.next_address);
                break;
            }
            let Some(next) = address.checked_add(location.bytes.len() as u64) else {
                break;
            };
            let edges = graph.successors.get(&address);
            let branches: Vec<_> = edges
                .into_iter()
                .flatten()
                .filter(|edge| edge.kind != EdgeKind::Fallthrough)
                .copied()
                .collect();
            pending.extend(branches.iter().map(|edge| edge.target));
            let nofall = matches!(
                location.flow,
                Flow::UnconditionalBranch | Flow::IndirectBranch | Flow::Return | Flow::Terminal
            ) || analysis.noreturn_calls.contains(&location.address);
            address = next;
            if nofall {
                succs = branches;
                break;
            }
            // vivisect/analysis/generic/codeblocks.py follows fallthrough
            // across other function entries, including PE unwind roots.
            // Unwind metadata seeds discovery but is not a flow barrier.
            if !branches.is_empty() || analysis.code_xrefs.contains_key(&next) {
                succs = branches;
                succs.push(Edge {
                    target: next,
                    kind: EdgeKind::Fallthrough,
                });
                pending.push(next);
                break;
            }
        }
        let mut insns = Vec::new();
        let mut cursor = block_start;
        while cursor < address {
            let decoded = analysis
                .instructions
                .get(&cursor)
                .cloned()
                .map(Ok)
                .unwrap_or_else(|| analysis.image.decode_at_compat(cursor));
            let Ok(insn) = decoded else {
                break;
            };
            cursor = insn.next_address;
            insns.push(insn);
        }
        if !insns.is_empty() {
            blocks.push(BasicBlock {
                addr: block_start,
                insns,
                succs,
            });
        }
    }
    blocks.sort_by_key(|block| block.addr);
    Ok(Function {
        addr: start,
        blocks,
    })
}

fn is_block_terminator(flow: Flow) -> bool {
    !matches!(flow, Flow::Next | Flow::Call | Flow::IndirectCall)
}

fn rebuild_call_indexes(analysis: &mut Analysis) {
    let mut callers = BTreeMap::<u64, BTreeSet<u64>>::new();
    let mut callees = BTreeMap::<u64, BTreeSet<u64>>::new();
    for (&function_address, function) in &analysis.functions {
        let mut seen = BTreeSet::new();
        for insn in function.blocks.iter().flat_map(|block| &block.insns) {
            if !seen.insert(insn.address) || insn.flow != Flow::Call {
                continue;
            }
            let Some(target) = insn.direct_target else {
                continue;
            };
            callees.entry(function_address).or_default().insert(target);
            callers.entry(target).or_default().insert(function_address);
        }
    }
    analysis.callers = callers;
    analysis.callees = callees;
}

fn is_authoritative_seed(kind: SeedKind) -> bool {
    matches!(
        kind,
        SeedKind::EntryPoint
            | SeedKind::Export
            | SeedKind::TlsCallback
            | SeedKind::SafeSeh
            | SeedKind::Unwind
            | SeedKind::Symbol
            | SeedKind::Init
            | SeedKind::Fini
            | SeedKind::InitArray
            | SeedKind::FiniArray
            | SeedKind::LibcMain
            | SeedKind::GoRuntimeMain
            | SeedKind::MsvcCookieBlock
            | SeedKind::MachoFunctionStarts
    )
}

/// Thin accessor over the pre-computed [`DecodedInstruction::direct_target`],
/// kept as a free function so callers outside this module (e.g.
/// `basicblock_features.rs`, `libc_start_main.rs`) read unchanged.
pub(crate) fn direct_target(insn: &DecodedInstruction) -> Option<u64> {
    insn.direct_target
}

/// Thin accessor over the pre-computed [`DecodedInstruction::memory_target`],
/// kept as a free function so callers outside this module (e.g.
/// `noreturn.rs`, `libc_start_main.rs`) read unchanged.
pub(crate) fn memory_target(insn: &DecodedInstruction) -> Option<u64> {
    insn.memory_target
}

pub(crate) fn jump_table_targets(image: &LoadedImage, insn: &DecodedInstruction) -> Vec<u64> {
    let mut targets = scan_jump_table(image, insn, |_, _| true);
    targets.sort_unstable();
    targets.dedup();
    targets
}

fn jump_table_targets_compat(
    analysis: &mut Analysis,
    insn: &DecodedInstruction,
    noreturn: &BTreeSet<u64>,
) -> Vec<u64> {
    if is_pointer_jump(&analysis.image, insn) {
        return jump_table_targets(&analysis.image, insn);
    }
    let Some(base) = insn.memory_target else {
        return Vec::new();
    };
    let width = analysis.image.architecture.pointer_width() as u64;
    let candidates = scan_jump_table(&analysis.image, insn, |_, _| true);
    let mut targets = Vec::new();
    for (index, target) in candidates.into_iter().enumerate() {
        let Some(slot) = base.checked_add((index as u64).saturating_mul(width)) else {
            break;
        };
        if Some(slot) != insn.memory_target
            && (analysis.code_xrefs.contains_key(&slot) || analysis.data_xrefs.contains_key(&slot))
        {
            break;
        }
        let signature = analysis
            .seeds
            .get(&target)
            .is_some_and(|kinds| kinds.contains(&SeedKind::FunctionSignature));
        if !signature && !targets.contains(&target) {
            match super::emucode::evaluate_candidate(analysis, target, noreturn, &[]) {
                super::emucode::Verdict::NotCode => break,
                super::emucode::Verdict::Inconclusive { address, reason } => {
                    analysis.diagnostics.push(RecoveryDiagnostic {
                        address,
                        message: format!(
                            "switch {:#x} arm {target:#x} candidate evaluation inconclusive: {reason}",
                            insn.address
                        ),
                    });
                    break;
                }
                super::emucode::Verdict::Code => {}
            }
        }
        // _cb_branchtable records each reference before evaluating the
        // next entry. Subsequent candidate traces see that partial table.
        push_xref(&mut analysis.code_xrefs, target, insn.address);
        targets.push(target);
    }
    let mut seen = BTreeSet::new();
    targets.retain(|target| seen.insert(*target));
    targets
}

fn scan_jump_table(
    image: &LoadedImage,
    insn: &DecodedInstruction,
    mut accept: impl FnMut(u64, u64) -> bool,
) -> Vec<u64> {
    let Some(base) = insn.memory_target else {
        return Vec::new();
    };
    // `i386Opcode.getBranches` only labels scale-four SIB operands as
    // BR_TABLE. Other indexed operands have no static address without an
    // emulator. In particular, scanning an unbounded x64 scale-eight table
    // absorbs adjacent tables and prevents later pointer discovery.
    if image.architecture != Architecture::AArch64
        && insn.x86_instruction().memory_index() != iced_x86::Register::None
        && insn.x86_instruction().memory_index_scale() != 4
    {
        return Vec::new();
    }
    let width = image.architecture.pointer_width();
    // envi/archs/i386/__init__.py distinguishes BR_DEREF from BR_TABLE:
    // a plain memory jump dereferences one pointer, while an indexed jump
    // selects among table entries. Adjacent pointers are not its successors.
    let entries = if is_pointer_jump(image, insn) {
        1
    } else {
        // VivWorkspace.iterJumpTable scans until a table boundary, including
        // switches with more than 256 cases. Mapped bytes bound the scan.
        image
            .bytes_at(base, usize::MAX)
            .map_or(0, |bytes| bytes.len() / width)
    };
    let mut targets = Vec::new();
    for index in 0..entries {
        let Some(slot) = base.checked_add((index.saturating_mul(width)) as u64) else {
            break;
        };
        let Some(raw) = image.bytes_at(slot, width) else {
            break;
        };
        let target = if width == 8 {
            let Some(value) = raw.get(..8).and_then(|value| value.try_into().ok()) else {
                break;
            };
            u64::from_le_bytes(value)
        } else {
            let Some(value) = raw.get(..4).and_then(|value| value.try_into().ok()) else {
                break;
            };
            u64::from(u32::from_le_bytes(value))
        };
        if !is_executable(image, target) || !accept(slot, target) {
            break;
        }
        targets.push(target);
    }
    targets
}

fn is_pointer_jump(image: &LoadedImage, insn: &DecodedInstruction) -> bool {
    image.architecture != Architecture::AArch64
        && insn.memory_target.is_some()
        && insn.x86_instruction().memory_index() == iced_x86::Register::None
}

pub(crate) fn is_executable(image: &LoadedImage, address: u64) -> bool {
    image.is_executable_address(address)
}

pub(crate) fn read_pointer(image: &LoadedImage, address: u64) -> Option<u64> {
    let width = image.architecture.pointer_width();
    let raw = image.bytes_at(address, width)?;
    if width == 8 {
        let value = raw.get(..8)?.try_into().ok()?;
        Some(u64::from_le_bytes(value))
    } else {
        let value = raw.get(..4)?.try_into().ok()?;
        Some(u64::from(u32::from_le_bytes(value)))
    }
}

fn remove_code_reference(analysis: &mut Analysis, source: u64, target: u64) {
    if let Some(sources) = analysis.code_xrefs.get_mut(&target) {
        sources.retain(|address| *address != source);
        if sources.is_empty() {
            analysis.code_xrefs.remove(&target);
        }
    }
}

fn push_xref(index: &mut BTreeMap<u64, Vec<u64>>, target: u64, source: u64) {
    let sources = index.entry(target).or_default();
    if !sources.contains(&source) {
        sources.push(source);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::extract::image::{ImageFormat, MappedSection, Permissions, SHELLCODE_BASE};

    fn callback_image(bytes: &[u8], architecture: Architecture, api: &str) -> Analysis {
        let mut image = LoadedImage::for_test(
            ImageFormat::Pe,
            architecture,
            0x1000,
            vec![MappedSection {
                name: ".text".into(),
                address: 0x1000,
                virtual_size: bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len() as u64,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
            BTreeMap::new(),
            bytes.to_vec(),
        );
        image.import_locations.insert(0x2000, api.into());
        image.external_bindings.insert(0x2000, vec![api.into()]);
        analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .expect("synthetic callback recovery succeeds")
    }

    #[test]
    fn flirt_local_code_precedes_fallback_function_entries() {
        let mut bytes = vec![0xe8, 0x1b, 0, 0, 0, 0xc3];
        bytes.resize(0x20, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
        bytes.resize(0x40, 0xcc);
        bytes.extend_from_slice(&[0xe9, 0x3b, 0, 0, 0]);
        bytes.resize(0x80, 0xcc);
        bytes.extend_from_slice(&[0x55, 0x8b, 0xec, 0x5d, 0xc3]);
        bytes.resize(0x100, 0xcc);
        let image = noreturn_test_image(&bytes);
        let path = std::env::temp_dir().join(format!("capa-x-local-{}.pat", std::process::id()));
        let pattern = format!(
            "31C0C3{} 00 0000 0040 :0000 root :0020@ local\n---",
            "..".repeat(29)
        );
        std::fs::write(&path, pattern).unwrap();
        let signatures = super::super::flirt::Signatures::from_path(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let analysis = analyze_seeded_image_with_signatures(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
            Some(&signatures),
        )
        .unwrap();
        assert!(analysis.functions.contains_key(&0x1040));
        assert!(analysis.instructions.contains_key(&0x1080));
        assert!(!analysis.functions.contains_key(&0x1080));
        let libraries =
            super::super::flirt::identify_library_functions(&analysis, &signatures).unwrap();
        assert_eq!(libraries.get(&0x1040).map(String::as_str), Some("local"));
    }

    #[test]
    fn flirt_public_names_include_functions_created_by_its_local_symbols() {
        let mut bytes = vec![0xe8, 0x1b, 0, 0, 0, 0xc3];
        bytes.resize(0x20, 0xcc);
        bytes.push(0xc3);
        bytes.resize(0x40, 0xcc);
        bytes.extend_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]);
        bytes.resize(0x60, 0xcc);
        bytes.extend_from_slice(&[0x90, 0xc3]);
        bytes.resize(0x80, 0xcc);
        bytes.extend_from_slice(&[0x90, 0xc3]);
        bytes.resize(0x100, 0xcc);
        let path = std::env::temp_dir().join(format!("capa-x-public-{}.pat", std::process::id()));
        let pattern = format!(
            "C3{} 00 0000 0080 :0000 root :0020@ local :0040 created :0060 later\n---",
            "..".repeat(31)
        );
        std::fs::write(&path, pattern).unwrap();
        let signatures = super::super::flirt::Signatures::from_path(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let analysis = analyze_seeded_image_with_signatures(
            noreturn_test_image(&bytes),
            RecoveryBackend::VivisectCompat,
            SeedMap::from([
                (0x1000, BTreeSet::from([SeedKind::EntryPoint])),
                (0x1080, BTreeSet::from([SeedKind::Export])),
            ]),
            BTreeMap::new(),
            Vec::new(),
            Some(&signatures),
        )
        .unwrap();
        let libraries =
            super::super::flirt::identify_library_functions(&analysis, &signatures).unwrap();
        assert_eq!(libraries.get(&0x1060).map(String::as_str), Some("created"));
        assert!(analysis.functions.contains_key(&0x1080));
        assert!(!libraries.contains_key(&0x1080));
    }

    #[test]
    fn branch_into_loose_import_root_keeps_its_function_callback_deferred() {
        let mut bytes = vec![0xc3];
        bytes.resize(0x1e, 0xcc);
        bytes.extend_from_slice(&[
            0x75, 0x10, // 0x101e: jnz 0x1030; fallthrough enters loose root
            0xff, 0x15, 0, 0x20, 0, 0, // 0x1020: call [import]
            0xe8, 0x25, 0, 0, 0, 0xc3, // call 0x1050; ret
        ]);
        bytes.resize(0x30, 0xcc);
        bytes.push(0xc3);
        bytes.resize(0x50, 0xcc);
        bytes.extend_from_slice(&[0xe8, 0xc9, 0xff, 0xff, 0xff, 0xc3]); // call 0x101e
        bytes.resize(0x1100, 0);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        assert!(analysis.instructions.contains_key(&0x101e));
        assert!(analysis.functions.contains_key(&0x1050));
        assert!(!analysis.functions.contains_key(&0x101e));
    }

    #[test]
    fn import_call_functions_keep_the_extent_at_creation() {
        let mut bytes = vec![0xc3];
        bytes.resize(0x10, 0xcc);
        // An unreferenced function, with an exit reachable independently of
        // the import-call fragment that first discovers its recursive call.
        bytes.extend_from_slice(&[0x31, 0xc0, 0x74, 0x2c]);
        bytes.resize(0x20, 0x90);
        bytes.extend_from_slice(&[
            0xff, 0x15, 0, 0x20, 0, 0, // 0x1020: call [import]
            0xe8, 0xe5, 0xff, 0xff, 0xff, // 0x1026: call 0x1010
            0xe8, 0x20, 0, 0, 0, // 0x102b: call 0x1050
            0xc3,
        ]);
        bytes.resize(0x40, 0xcc);
        bytes.push(0xc3);
        bytes.resize(0x50, 0xcc);
        bytes.push(0xc3);
        // Keep the synthetic IAT inside a mapped region for findPointers.
        bytes.resize(0x1100, 0);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        let function = &analysis.functions[&0x1010];
        let owned: BTreeSet<_> = function
            .blocks
            .iter()
            .flat_map(|block| block.insns.iter().map(|insn| insn.address))
            .collect();
        assert!(owned.contains(&0x1026));
        assert!(owned.contains(&0x1040));
        assert!(!owned.contains(&0x102b));
        assert!(analysis.instructions.contains_key(&0x102b));
        assert!(analysis.functions.contains_key(&0x1050));
        assert!(!analysis.is_noreturn_va(0x1010));

        let native = analyze_seeded_image(
            analysis.image.clone(),
            RecoveryBackend::Native,
            SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(native.functions[&0x1010]
            .blocks
            .iter()
            .flat_map(|block| &block.insns)
            .any(|insn| insn.address == 0x102b));

        let mut relocated = analysis.image.clone();
        relocated.relocation_locations.push(0x1022);
        let relocated = analyze_seeded_image(
            relocated,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(
            !relocated.instructions.contains_key(&0x1020),
            "a typed relocation operand is not an undefined import-call candidate"
        );
        assert!(!relocated.functions.contains_key(&0x1010));
    }

    #[test]
    fn api_callbacks_recover_nonreturning_targets_from_computed_arguments() {
        // CreateThread's third argument is an absolute LEA, so it provides
        // no static REF_PTR. The callback never returns, so it cannot pass
        // candidate evaluation either. Only the API type establishes a root.
        let mut bytes = vec![
            0x6a, 0, 0x6a, 0, 0x6a, 0, // last three arguments
            0x8d, 0x05, 0x40, 0x10, 0, 0, // lea eax, [0x1040]
            0x50, 0x6a, 0, 0x6a, 0, // callback, size, attributes
            0x89, 0x43, 8, // mov [ebx+8], eax: unknown destination, not the stack
            0xff, 0x15, 0, 0x20, 0, 0, // call [CreateThread]
            0xc3,
        ];
        bytes.resize(0x40, 0xcc);
        bytes.extend_from_slice(&[0xeb, 0xfe]);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.CreateThread");
        assert!(analysis.functions.contains_key(&0x1040));
        assert!(analysis.seeds[&0x1040].contains(&SeedKind::ApiCallback));
        let ordinary = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        assert!(!ordinary.functions.contains_key(&0x1040));
    }

    #[test]
    fn recursive_callbacks_in_import_fragments_finish_before_finalization() {
        let mut bytes = vec![0xc3];
        bytes.resize(0x10, 0xcc);
        bytes.extend_from_slice(&[
            0xff, 0x15, 0, 0x20, 0, 0, // loose call [import]
            0xe8, 0x25, 0, 0, 0, 0xc3, // call 0x1040; ret
        ]);
        bytes.resize(0x40, 0xcc);
        bytes.extend_from_slice(&[0xb8, 0x80, 0x10, 0, 0, 0xff, 0xd0, 0xc3]);
        bytes.resize(0x80, 0xcc);
        bytes.extend_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]); // call 0x10a0; ret
        bytes.resize(0xa0, 0xcc);
        bytes.extend_from_slice(&[0xe8, 0xdb, 0xff, 0xff, 0xff, 0xc3]); // call 0x1080; ret
        bytes.resize(0x1100, 0);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        for start in [0x1080, 0x10a0] {
            assert!(!analysis.is_noreturn_va(start));
            assert!(analysis.functions[&start]
                .blocks
                .iter()
                .flat_map(|block| &block.insns)
                .any(|insn| insn.address == start + 5));
        }
    }

    #[test]
    fn callbacks_discovered_inside_import_fragments_become_functions() {
        let mut bytes = vec![0xc3];
        bytes.resize(0x10, 0xcc);
        bytes.extend_from_slice(&[
            0xff, 0x15, 0, 0x20, 0, 0, // loose call [CreateThread]
            0xe8, 0x25, 0, 0, 0, // call 0x1040
            0xc3,
        ]);
        bytes.resize(0x40, 0xcc);
        bytes.extend_from_slice(&[
            0x6a, 0, 0x6a, 0, 0x6a, 0, 0x8d, 0x05, 0xa0, 0x10, 0, 0, // lea eax,[0x10a0]
            0x50, 0x6a, 0, 0x6a, 0, 0xff, 0x15, 0, 0x20, 0, 0, 0xc3,
        ]);
        bytes.resize(0xa0, 0xcc);
        bytes.extend_from_slice(&[0xeb, 0xfe]);
        bytes.resize(0x1100, 0);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.CreateThread");
        assert!(analysis.functions.contains_key(&0x1040));
        assert!(analysis.functions.contains_key(&0x10a0));
        assert!(analysis.seeds[&0x10a0].contains(&SeedKind::ApiCallback));
    }

    #[test]
    fn seh3_scope_tables_contribute_filter_and_handler_candidates() {
        let mut bytes = vec![
            0x6a, 0, // local allocation
            0x68, 0x80, 0x10, 0, 0, // scope table
            0xe8, 0x34, 0, 0, 0, // call seh3_prolog at 0x1040
            0xc3,
        ];
        bytes.resize(0x40, 0xcc);
        bytes.extend_from_slice(&[0x68, 0, 0, 0, 0, 0x64, 0xa1, 0, 0, 0, 0, 0x50, 0xc3]);
        bytes.resize(0x80, 0xcc);
        for value in [u32::MAX, 0x10c0, 0x10d0] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.resize(0xc0, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
        bytes.resize(0xd0, 0xcc);
        bytes.extend_from_slice(&[0x49, 0x75, 0xfd, 0xc3]);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        for address in [0x10c0, 0x10d0] {
            assert!(analysis.functions.contains_key(&address));
            assert!(analysis.seeds[&address].contains(&SeedKind::Emulated));
        }
        assert!(!analysis.instructions.contains_key(&0x1080));
    }

    #[test]
    fn callee_data_references_stop_the_callers_later_code_flow() {
        let mut bytes = vec![0xe8, 0x0b, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0xeb, 0xfe];
        bytes.resize(0x10, 0xcc);
        bytes.push(0xa1); // mov eax,[base+5]
        bytes.extend_from_slice(&((SHELLCODE_BASE + 5) as u32).to_le_bytes());
        bytes.push(0xc3);
        let analysis = analyze_shellcode(&bytes, Architecture::X86).unwrap();
        assert!(!analysis.instructions.contains_key(&(SHELLCODE_BASE + 5)));
        assert_eq!(
            function_instruction_addrs(&analysis.functions[&SHELLCODE_BASE]).len(),
            1
        );
        assert!(analysis.functions.contains_key(&(SHELLCODE_BASE + 0x10)));
    }

    #[test]
    fn candidate_traces_follow_previously_resolved_indirect_branches() {
        let mut analysis = analyze_noreturn_test_image(&[0xff, 0xe0, 0xc3]);
        assert_eq!(
            super::super::emucode::evaluate_candidate(&analysis, 0x1000, &BTreeSet::new(), &[]),
            super::super::emucode::Verdict::NotCode
        );
        let target = analysis.image.decode_at_compat(0x1002).unwrap();
        analysis.instructions.insert(0x1002, target);
        analysis.code_xrefs.insert(0x1002, vec![0x1000]);
        assert_eq!(
            super::super::emucode::evaluate_candidate(&analysis, 0x1000, &BTreeSet::new(), &[]),
            super::super::emucode::Verdict::Code
        );
    }

    #[test]
    fn candidate_table_references_require_a_defined_code_block() {
        let mut bytes = vec![0xff, 0x24, 0x85, 0x10, 0x10, 0, 0];
        bytes.resize(0x10, 0xcc);
        bytes.extend_from_slice(&0x1020u32.to_le_bytes());
        bytes.resize(0x20, 0xcc);
        bytes.push(0xc3);
        let mut analysis = analyze_noreturn_test_image(&bytes);
        let target = analysis.image.decode_at_compat(0x1020).unwrap();
        analysis.functions.clear();
        analysis.instructions.insert(0x1020, target.clone());
        analysis.code_xrefs.insert(0x1020, vec![0x1000]);
        assert_eq!(
            super::super::emucode::evaluate_candidate(&analysis, 0x1000, &BTreeSet::new(), &[]),
            super::super::emucode::Verdict::NotCode
        );
        analysis.functions.insert(
            0x1020,
            Function {
                addr: 0x1020,
                blocks: vec![BasicBlock {
                    addr: 0x1020,
                    insns: vec![target],
                    succs: Vec::new(),
                }],
            },
        );
        assert_eq!(
            super::super::emucode::evaluate_candidate(&analysis, 0x1000, &BTreeSet::new(), &[]),
            super::super::emucode::Verdict::Code
        );
    }

    #[test]
    fn rejected_emucode_strings_become_code_barriers() {
        let mut bytes = vec![0xc3];
        bytes.resize(0x40, 0xcc);
        bytes.extend_from_slice(b"hello world\0");
        let mut analysis = analyze_noreturn_test_image(&bytes);
        analysis
            .seeds
            .insert(0x1040, BTreeSet::from([SeedKind::Emulated]));
        let mut discovery = super::super::pointers::Discovery::new(&mut analysis, true);
        assert_eq!(discovery.next(&mut analysis, &BTreeSet::new()), None);
        assert!(super::super::emucode::in_data(
            discovery.code_barriers(),
            0x1045
        ));
    }

    #[test]
    fn compatibility_preserves_jump_table_order_and_deduplicates_arms() {
        let mut bytes = vec![0xff, 0x24, 0x85, 0x20, 0x10, 0, 0];
        bytes.resize(0x20, 0xcc);
        for target in [0x1080u32, 0x1040, 0x1080, 0x1060] {
            bytes.extend_from_slice(&target.to_le_bytes());
        }
        bytes.resize(0x90, 0xcc);
        for offset in [0x40, 0x60, 0x80] {
            bytes[offset] = 0xc3;
        }
        let mut analysis = analyze_noreturn_test_image(&bytes);
        let branch = analysis.instructions[&0x1000].clone();
        assert_eq!(
            jump_table_targets_compat(&mut analysis, &branch, &BTreeSet::new()),
            [0x1080, 0x1040, 0x1060]
        );
        assert_eq!(
            jump_table_targets(&analysis.image, &branch),
            [0x1040, 0x1060, 0x1080]
        );
    }

    #[test]
    fn compatibility_stops_a_table_at_an_unsupported_candidate() {
        let mut bytes = vec![0xff, 0x24, 0x85, 0x20, 0x10, 0, 0];
        bytes.resize(0x20, 0xcc);
        for target in [0x1040u32, 0x1050, 0x1060] {
            bytes.extend_from_slice(&target.to_le_bytes());
        }
        bytes.resize(0x61, 0xcc);
        bytes[0x40] = 0xc3;
        bytes[0x50..0x55].copy_from_slice(&[0xf2, 0x0f, 0x5e, 0xc0, 0xc3]); // divsd; ret
        bytes[0x60] = 0xc3;
        let mut analysis = analyze_noreturn_test_image(&bytes);
        let branch = analysis.instructions[&0x1000].clone();
        assert_eq!(
            jump_table_targets_compat(&mut analysis, &branch, &BTreeSet::new()),
            [0x1040]
        );
        assert!(analysis
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("Divsd")));
    }

    #[test]
    fn compatibility_recovers_switch_arms_beyond_256_entries() {
        let mut bytes = vec![0xff, 0x24, 0x85, 0x20, 0x10, 0, 0];
        bytes.resize(0x20, 0xcc);
        for _ in 0..256 {
            bytes.extend_from_slice(&0x1500u32.to_le_bytes());
        }
        bytes.extend_from_slice(&0x1510u32.to_le_bytes());
        bytes.resize(0x500, 0xcc);
        bytes.push(0xc3);
        bytes.resize(0x510, 0xcc);
        bytes.extend_from_slice(&[0x49, 0x75, 0xfd, 0xc3]);
        let mut analysis = analyze_noreturn_test_image(&bytes);
        let branch = analysis.instructions[&0x1000].clone();
        assert_eq!(
            jump_table_targets_compat(&mut analysis, &branch, &BTreeSet::new()),
            [0x1500, 0x1510]
        );
        assert!(analysis.functions[&0x1000]
            .blocks
            .iter()
            .any(|block| block.addr == 0x1510));
        assert!(!analysis.functions.contains_key(&0x1510));
        assert!(analysis.code_xrefs[&0x1510].contains(&0x1000));
    }

    #[test]
    fn calling_trace_follows_reference_far_pointer_fallthrough() {
        let mut bytes = vec![
            0xff, 0x6a, 0x00, // jmp far [edx]: unsupported six-byte read
            0xe8, 0x18, 0, 0, 0, // call 0x1020 in loose bytes
            0xc3,
        ];
        bytes.resize(0x20, 0xcc);
        bytes.extend_from_slice(&[0x49, 0x75, 0xfd, 0xc3]);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        assert!(analysis.functions.contains_key(&0x1020));
        assert!(!analysis.instructions.contains_key(&0x1003));
    }

    #[test]
    fn calling_trace_finds_callees_after_a_computed_jump() {
        let mut bytes = vec![
            0xc7, 0x05, 0x40, 0x10, 0, 0, 0x60, 0x10, 0, 0, // mov [0x1040],0x1060
            0x8d, 0x05, 0x40, 0x10, 0, 0, // lea eax,[0x1040]
            0xff, 0x20, // jmp [eax]
        ];
        bytes.resize(0x60, 0);
        bytes.extend_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]); // call 0x1080; ret
        bytes.resize(0x80, 0xcc);
        bytes.extend_from_slice(&[0xeb, 0xfe]); // a callee that cannot pass candidate evaluation
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        assert!(analysis.functions.contains_key(&0x1080));
        assert!(analysis.seeds[&0x1080].contains(&SeedKind::CallTarget));
    }

    #[test]
    fn calling_trace_continues_past_a_noreturn_call_only_at_its_entry() {
        for prefix in [false, true] {
            let mut bytes = Vec::new();
            if prefix {
                bytes.push(0x90);
            }
            for target in [0x40u32, 0x50] {
                let next = bytes.len() as u32 + 5;
                bytes.push(0xe8);
                bytes.extend_from_slice(&(target - next).to_le_bytes());
            }
            bytes.push(0xc3);
            bytes.resize(0x50, 0xcc);
            bytes.push(0xc3);
            let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
            assert!(analysis.noreturn.contains(&0x1040));
            assert_eq!(analysis.functions.contains_key(&0x1050), !prefix);
            assert!(
                analysis.functions[&0x1000]
                    .blocks
                    .iter()
                    .flat_map(|block| &block.insns)
                    .all(|insn| insn.address < 0x1005 + u64::from(prefix)),
                "calling analysis must not expand the captured code scope"
            );
        }
    }

    #[test]
    fn calling_trace_stops_on_the_reference_bad_opcode() {
        let mut bytes = vec![
            0xe8, 0x3b, 0, 0, 0, // call nonreturning function at 0x1040
            0, 0, // bad opcode rejected by the calling monitor
            0xe8, 0x44, 0, 0, 0, // call 0x1050
            0xc3,
        ];
        bytes.resize(0x50, 0xcc);
        bytes.push(0xc3);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        assert!(analysis.noreturn.contains(&0x1040));
        assert!(!analysis.functions.contains_key(&0x1050));
    }

    #[test]
    fn calling_trace_does_not_treat_import_contents_as_a_callee() {
        let mut bytes = vec![0xff, 0x15, 0, 0x20, 0, 0, 0xc3];
        bytes.resize(0x40, 0xcc);
        bytes.extend_from_slice(&[0xeb, 0xfe]);
        bytes.resize(0x1000, 0);
        bytes.extend_from_slice(&0x1040u32.to_le_bytes());
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        assert!(!analysis.functions.contains_key(&0x1040));
    }

    #[test]
    fn calling_trace_preserves_concrete_nonvolatile_function_pointers_across_calls() {
        let mut bytes = vec![
            0xbd, 0x40, 0x10, 0, 0, // mov ebp,0x1040
            0xff, 0x15, 0, 0x20, 0, 0, // call [OtherApi]
            0xff, 0xd5, 0xc3, // call ebp; ret
        ];
        bytes.resize(0x40, 0xcc);
        bytes.extend_from_slice(&[0xeb, 0xfe]);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        assert!(analysis.functions.contains_key(&0x1040));
        assert!(analysis.seeds[&0x1040].contains(&SeedKind::CallTarget));
    }

    #[test]
    fn elf_calling_analysis_recovers_concrete_register_calls() {
        let mut bytes = vec![0xb8, 0x20, 0x10, 0, 0, 0xff, 0xd0, 0xc3];
        bytes.resize(0x20, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
        let mut image = noreturn_test_image(&bytes);
        image.format = ImageFormat::Elf;
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(analysis.seeds[&0x1020].contains(&SeedKind::CallTarget));
        assert!(analysis.functions.contains_key(&0x1020));
    }

    #[test]
    fn referenced_data_strings_do_not_create_embedded_pointer_functions() {
        let mut bytes = vec![0xb8, 0, 0, 0x50, 0, 0xc3];
        bytes.resize(0x41, 0xcc);
        bytes.push(0xc3);
        let data_offset = bytes.len() as u64;
        bytes.extend_from_slice(b"helloAAA\0\0\0\0\0");
        let image = LoadedImage::for_test(
            ImageFormat::Elf,
            Architecture::X86,
            0x414100,
            vec![
                MappedSection {
                    name: ".text".into(),
                    address: 0x414100,
                    virtual_size: data_offset,
                    file_offset: 0,
                    file_size: data_offset,
                    permissions: Permissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                },
                MappedSection {
                    name: ".rodata".into(),
                    address: 0x500000,
                    virtual_size: 13,
                    file_offset: data_offset,
                    file_size: 13,
                    permissions: Permissions {
                        read: true,
                        write: false,
                        execute: false,
                    },
                },
            ],
            BTreeMap::new(),
            bytes,
        );
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(0x414100, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(!analysis.functions.contains_key(&0x414141));
    }

    #[test]
    fn completed_function_padding_stops_later_callback_flow() {
        let mut bytes = vec![
            0xe8, 0x3b, 0, 0, 0, // call 0x1040, which types its preceding pad
            0xe8, 0x16, 0, 0, 0, // call 0x1020
            0xc3,
        ];
        bytes.resize(0x20, 0xcc);
        bytes.extend_from_slice(&[0xff, 0x15, 0, 0x20, 0, 0]);
        bytes.resize(0x40, 0x90);
        bytes.push(0xc3);
        let analysis = analyze_noreturn_test_image(&bytes);
        assert!(!analysis.instructions.contains_key(&0x1026));
        assert!(analysis.functions[&0x1020]
            .blocks
            .iter()
            .all(|block| block.addr < 0x1040));
    }

    #[test]
    fn concrete_callees_finish_in_emulator_encounter_order() {
        let mut bytes = vec![
            0xb8, 0x60, 0x10, 0, 0, 0xff, 0xd0, 0xb8, 0x40, 0x10, 0, 0, 0xff, 0xd0, 0xc3,
        ];
        bytes.resize(0x40, 0xcc);
        bytes.push(0xc3);
        bytes.resize(0x60, 0xcc);
        bytes.push(0xc3);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        assert!(analysis.function_order[&0x1060] < analysis.function_order[&0x1040]);
    }

    #[test]
    fn callbacks_recheck_locations_after_each_target_finishes() {
        let mut bytes = Vec::new();
        for target in [0x1080u32, 0x1081] {
            bytes.extend_from_slice(&[0x6a, 0, 0x6a, 0, 0x6a, 0, 0x68]);
            bytes.extend_from_slice(&target.to_le_bytes());
            bytes.extend_from_slice(&[0x6a, 0, 0x6a, 0, 0xff, 0x15, 0, 0x20, 0, 0]);
        }
        bytes.push(0xc3);
        bytes.resize(0x80, 0xcc);
        bytes.extend_from_slice(&[0x90, 0xc3]);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.CreateThread");
        assert!(analysis.functions.contains_key(&0x1080));
        assert!(!analysis.functions.contains_key(&0x1081));
    }

    #[test]
    fn calling_analysis_follows_data_pointers_before_resuming_its_caller() {
        for opcode in [0x8b, 0x8d] {
            // MOV and the i386 monitor's LEA hook
            let mut bytes = vec![
                0xe8, 0x1b, 0, 0, 0, // call 0x1020
                0xe8, 0x36, 0, 0, 0, // call 0x1040
                0xc3,
            ];
            bytes.resize(0x20, 0xcc);
            bytes.extend_from_slice(&[opcode, 0x05, 0x80, 0x10, 0, 0, 0xc3]);
            bytes.resize(0x40, 0xcc);
            bytes.push(0xc3);
            bytes.resize(0x60, 0xcc);
            bytes.push(0xc3);
            bytes.resize(0x80, 0xcc);
            bytes.extend_from_slice(&0x1060u32.to_le_bytes());
            let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
            if opcode == 0x8b {
                assert!(analysis.function_order[&0x1060] < analysis.function_order[&0x1020]);
            } else {
                assert!(analysis.function_order[&0x1020] < analysis.function_order[&0x1060]);
            }
            assert!(analysis.function_order[&0x1060] < analysis.function_order[&0x1040]);
            assert!(analysis.seeds[&0x1060].contains(&SeedKind::PointerTarget));
        }
    }

    #[test]
    fn calling_trace_follows_resolved_switches_with_unknown_selectors() {
        let mut bytes = vec![0xff, 0x24, 0x8d, 0x80, 0x10, 0, 0];
        bytes.resize(0x20, 0xcc);
        bytes.extend_from_slice(&[0xbf, 0x40, 0x10, 0, 0, 0xff, 0xd7, 0xc3]);
        bytes.resize(0x30, 0xcc);
        bytes.push(0xc3);
        bytes.resize(0x40, 0xcc);
        bytes.extend_from_slice(&[0xeb, 0xfe]);
        bytes.resize(0x80, 0xcc);
        for target in [0x1020u32, 0x1030, 0] {
            bytes.extend_from_slice(&target.to_le_bytes());
        }
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        assert!(analysis.functions.contains_key(&0x1040));
        assert!(analysis.seeds[&0x1040].contains(&SeedKind::CallTarget));
    }

    #[test]
    fn calling_trace_preserves_stack_function_pointers_across_calls() {
        let mut bytes = vec![
            0x68, 0x40, 0x10, 0, 0, // push 0x1040
            0xff, 0x15, 0, 0x20, 0, 0, // call [OtherApi]
            0x5f, 0xff, 0xd7, 0xc3, // pop edi; call edi; ret
        ];
        bytes.resize(0x40, 0xcc);
        bytes.extend_from_slice(&[0xeb, 0xfe]);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        assert!(analysis.functions.contains_key(&0x1040));
        assert!(analysis.seeds[&0x1040].contains(&SeedKind::CallTarget));
    }

    #[test]
    fn api_callbacks_preserve_import_registers_but_forget_volatile_values() {
        let mut bytes = vec![
            0x8b, 0x35, 0, 0x20, 0, 0, // mov esi, [CreateThread]
            0xff, 0x15, 0, 0x30, 0, 0, // unknown call
            0x6a, 0, 0x6a, 0, 0x6a, 0, 0x8d, 0x05, 0x40, 0x10, 0, 0, // lea eax, [0x1040]
            0x50, 0x6a, 0, 0x6a, 0, 0xff, 0xd6, // call esi
            0xc3,
        ];
        bytes.resize(0x40, 0xcc);
        bytes.extend_from_slice(&[0xeb, 0xfe]);
        for (load, call) in [(0x35, 0xd6), (0x2d, 0xd5)] {
            // Both ESI and EBP can hold an import across an unknown call.
            bytes[1] = load;
            bytes[30] = call;
            assert!(
                callback_image(&bytes, Architecture::X86, "kernel32.CreateThread")
                    .functions
                    .contains_key(&0x1040)
            );
        }
        // The same import held in EAX must be invalidated by the unknown call.
        bytes[1] = 0x05;
        bytes[30] = 0xd0;
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.CreateThread");
        // EAX no longer identifies CreateThread. The later LEA instead
        // makes CALL EAX a concrete call to 0x1040, not an API callback.
        assert!(!analysis.seeds[&0x1040].contains(&SeedKind::ApiCallback));
        assert!(analysis.seeds[&0x1040].contains(&SeedKind::CallTarget));
    }

    #[test]
    fn api_callbacks_use_windows_x64_register_and_stack_arguments() {
        for (api, setup) in [
            (
                "kernel32.CreateThread",
                vec![0x49, 0xc7, 0xc0, 0x40, 0x10, 0, 0],
            ),
            (
                "msvcrt.bsearch",
                vec![0x48, 0xc7, 0x44, 0x24, 0x20, 0x40, 0x10, 0, 0],
            ),
        ] {
            let mut bytes = setup;
            // RIP-relative import call, displacement from the call's end.
            let displacement = 0x2000i32 - (0x1000 + bytes.len() as i32 + 6);
            bytes.extend_from_slice(&[0xff, 0x15]);
            bytes.extend_from_slice(&displacement.to_le_bytes());
            bytes.push(0xc3);
            bytes.resize(0x40, 0xcc);
            bytes.extend_from_slice(&[0xeb, 0xfe]);
            let analysis = callback_image(&bytes, Architecture::X64, api);
            assert!(
                analysis.seeds[&0x1040].contains(&SeedKind::ApiCallback),
                "{api}"
            );
        }
    }

    #[test]
    fn api_callbacks_do_not_promote_unknown_arguments_or_instruction_interiors() {
        for target in [None, Some(0x1001), Some(0x9000)] {
            let mut bytes = vec![0x6a, 0, 0x6a, 0, 0x6a, 0];
            if let Some(target) = target {
                bytes.extend_from_slice(&[0x8d, 0x05]);
                bytes.extend_from_slice(&u32::to_le_bytes(target));
            }
            bytes.extend_from_slice(&[0x50, 0x6a, 0, 0x6a, 0, 0xff, 0x15, 0, 0x20, 0, 0, 0xc3]);
            let analysis = callback_image(&bytes, Architecture::X86, "kernel32.CreateThread");
            assert!(!analysis
                .seeds
                .values()
                .any(|kinds| kinds.contains(&SeedKind::ApiCallback)));
        }
    }

    #[test]
    fn emucode_recovers_instruction_references_without_a_prologue() {
        let target = SHELLCODE_BASE + 32;
        let mut bytes = vec![0xb8]; // mov eax, candidate; ret
        bytes.extend_from_slice(&(target as u32).to_le_bytes());
        bytes.push(0xc3);
        bytes.resize(32, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0xc3]);
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(analysis.functions.contains_key(&target));
        assert!(analysis.seeds[&target].contains(&SeedKind::Emulated));
    }

    #[test]
    fn x86_lea_monitor_follows_a_data_pointer_without_promoting_its_slot() {
        let slot = SHELLCODE_BASE + 32;
        let target = SHELLCODE_BASE + 64;
        let mut bytes = vec![0x8d, 0x05]; // lea eax, [slot]
        bytes.extend_from_slice(&(slot as u32).to_le_bytes());
        bytes.push(0xc3);
        bytes.resize(32, 0xcc);
        bytes.extend_from_slice(&(target as u32).to_le_bytes());
        bytes.resize(64, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0xc3]);
        let analysis = analyze_seeded_image(
            LoadedImage::from_shellcode(&bytes, Architecture::X86),
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(!analysis.functions.contains_key(&slot));
        assert!(analysis.functions.contains_key(&target));
        assert!(analysis.seeds[&target].contains(&SeedKind::PointerTarget));
    }

    #[test]
    fn pointer_candidates_do_not_split_existing_instructions() {
        let mut bytes = vec![0xb8, 0x31, 0xc0, 0xc3, 0, 0xc3]; // ret bytes inside an immediate
        bytes.resize(32, 0xcc);
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([
                (SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint])),
                (SHELLCODE_BASE + 1, BTreeSet::from([SeedKind::Relocation])),
            ]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(!analysis.functions.contains_key(&(SHELLCODE_BASE + 1)));
    }

    #[test]
    fn entry_signatures_skip_instruction_interiors() {
        let bytes = [0xb8, 0x55, 0x8b, 0xec, 0, 0xc3];
        let analysis = analyze_seeded_image(
            LoadedImage::from_shellcode(&bytes, Architecture::X86),
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(!analysis.functions.contains_key(&(SHELLCODE_BASE + 1)));
        assert!(analysis.functions.contains_key(&SHELLCODE_BASE));
    }

    #[test]
    fn only_rip_relative_lea_provides_a_static_candidate_reference() {
        let target = SHELLCODE_BASE + 32;
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut bytes = if architecture == Architecture::X64 {
                vec![0x48, 0x8d, 0x05, 25, 0, 0, 0]
            } else {
                let mut bytes = vec![0x8d, 0x05];
                bytes.extend_from_slice(&(target as u32).to_le_bytes());
                bytes
            };
            bytes.push(0xc3);
            bytes.resize(32, 0xcc);
            bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
            let image = LoadedImage::from_shellcode(&bytes, architecture);
            let analysis = analyze_seeded_image(
                image,
                RecoveryBackend::VivisectCompat,
                SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
                BTreeMap::new(),
                Vec::new(),
            )
            .unwrap();
            assert_eq!(
                analysis.functions.contains_key(&target),
                architecture == Architecture::X64
            );
        }
    }

    #[test]
    fn relocation_targets_are_followed_before_later_slots_are_typed() {
        let target = SHELLCODE_BASE + 32;
        let mut bytes = vec![0xc3];
        bytes.resize(16, 0xcc);
        bytes.extend_from_slice(&(target as u32).to_le_bytes());
        bytes.resize(32, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0xc3]);
        let mut image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        image.format = ImageFormat::Pe;
        image.relocation_locations = vec![SHELLCODE_BASE + 16, target];
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(analysis.functions.contains_key(&target));
        assert!(analysis.seeds[&target].contains(&SeedKind::PointerTarget));
    }

    #[test]
    fn partially_overwritten_pointer_stops_code_flow_at_its_remaining_bytes() {
        for pointer_offset in [0, 1] {
            let mut bytes = vec![0xc3];
            bytes.resize(32, 0xcc);
            bytes.extend_from_slice(&[0x83, 0xc0, 1, 0x60, 0x61, 0xc3]);
            let mut analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
            let start = 0x1020;
            let mut pointers = super::super::pointers::Discovery::new(&mut analysis, true);
            pointers.mark_data(start + pointer_offset, 4);
            let mut graph = DirectFlowGraph {
                compatibility: true,
                ..DirectFlowGraph::default()
            };
            discover_flow(
                &mut analysis,
                &mut graph,
                start,
                &mut pointers,
                Some(&mut BTreeSet::new()),
            )
            .unwrap();
            assert_eq!(
                analysis.instructions.contains_key(&start),
                pointer_offset != 0
            );
            assert!(!analysis.instructions.contains_key(&(start + 3)));
            // An existing pointer stops codeflow. Starting before its prefix
            // creates one opcode, then stops at the surviving pointer suffix.
        }
    }

    #[test]
    fn pointer_retyping_deletes_the_covering_opcode_and_preserves_its_suffix() {
        let mut bytes = vec![0xc3];
        bytes.resize(32, 0xcc);
        bytes.extend_from_slice(&[0x83, 0xc0, 1, 0x60, 0x61, 0xc3]);
        let mut analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        let mut pointers = super::super::pointers::Discovery::new(&mut analysis, true);
        pointers.mark_data(0x1021, 4);
        let mut graph = DirectFlowGraph {
            compatibility: true,
            ..DirectFlowGraph::default()
        };
        discover_flow(
            &mut analysis,
            &mut graph,
            0x1020,
            &mut pointers,
            Some(&mut BTreeSet::new()),
        )
        .unwrap();
        let mut starts = BTreeSet::new();
        assert_eq!(
            prepare_function_code(&mut analysis, &graph, &mut pointers, 0x1020, &mut starts),
            None
        );
        assert!(!analysis.instructions.contains_key(&0x1020));
        assert!(starts.contains(&0x1020));
        assert!(pointers.orphan_pointer(&analysis, 0x1023));
        assert_eq!(
            prepare_function_code(&mut analysis, &graph, &mut pointers, 0x1023, &mut starts),
            Some(Err(()))
        );
    }

    #[test]
    fn deleted_locations_do_not_hide_later_signature_references() {
        let mut bytes = vec![0xc3];
        bytes.resize(32, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
        let mut analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        analysis.instructions.remove(&0x1000);
        let mut pointers = super::super::pointers::Discovery::new(&mut analysis, true);
        let mut graph = DirectFlowGraph {
            compatibility: true,
            ..DirectFlowGraph::default()
        };
        discover_flow(&mut analysis, &mut graph, 0x1020, &mut pointers, None).unwrap();
        let visible = analysis.function_location_counts[&0x1020];
        assert!(analysis.instruction_order[&0x1022] < visible);
        assert!(analysis.instructions.len() < visible);
    }

    #[test]
    fn elf_register_thunks_require_the_first_callers_add() {
        let mut bytes = vec![0xe8, 27, 0, 0, 0, 0x83, 0xc3, 4, 0xc3];
        bytes.resize(32, 0xcc);
        bytes.extend_from_slice(&[0x8b, 0x1c, 0x24, 0xc3]);
        let mut analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        assert!(!super::super::callbacks::is_register_thunk(
            &analysis, 0x1020
        ));
        analysis.image.format = ImageFormat::Elf;
        assert!(super::super::callbacks::is_register_thunk(
            &analysis, 0x1020
        ));
        analysis.code_xrefs.insert(0x1020, vec![0x1008, 0x1000]);
        assert!(!super::super::callbacks::is_register_thunk(
            &analysis, 0x1020
        ));
    }

    #[test]
    fn calls_complete_previously_decoded_jump_targets_before_the_caller() {
        let mut bytes = vec![0xe8, 27, 0, 0, 0, 0xe8, 38, 0, 0, 0, 0xc3];
        bytes.resize(32, 0xcc);
        bytes.extend_from_slice(&[0xeb, 14]);
        bytes.resize(48, 0xcc);
        bytes.push(0xc3);
        let analysis = analyze_seeded_image(
            LoadedImage::from_shellcode(&bytes, Architecture::X86),
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        let order = &analysis.function_order;
        assert!(order[&(SHELLCODE_BASE + 32)] < order[&(SHELLCODE_BASE + 48)]);
        assert!(order[&(SHELLCODE_BASE + 48)] < order[&SHELLCODE_BASE]);
    }

    #[test]
    fn pe_entry_point_precedes_lower_address_export_roots() {
        let mut image = LoadedImage::from_shellcode(&[0xc3, 0xc3], Architecture::X86);
        image.format = ImageFormat::Pe;
        image.entry_point = Some(SHELLCODE_BASE + 1);
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([
                (SHELLCODE_BASE, BTreeSet::from([SeedKind::Export])),
                (SHELLCODE_BASE + 1, BTreeSet::from([SeedKind::EntryPoint])),
            ]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(
            analysis.function_order[&(SHELLCODE_BASE + 1)]
                < analysis.function_order[&SHELLCODE_BASE]
        );
    }

    #[test]
    fn pe_exports_and_handlers_precede_lower_address_unwind_roots() {
        let mut image = LoadedImage::from_shellcode(&[0xc3; 4], Architecture::X64);
        image.format = ImageFormat::Pe;
        image.entry_point = Some(SHELLCODE_BASE + 3);
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([
                (SHELLCODE_BASE, BTreeSet::from([SeedKind::Unwind])),
                (SHELLCODE_BASE + 1, BTreeSet::from([SeedKind::SafeSeh])),
                (
                    SHELLCODE_BASE + 2,
                    BTreeSet::from([SeedKind::Export, SeedKind::Unwind]),
                ),
                (SHELLCODE_BASE + 3, BTreeSet::from([SeedKind::EntryPoint])),
            ]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        let order = &analysis.function_order;
        assert!(order[&(SHELLCODE_BASE + 3)] < order[&(SHELLCODE_BASE + 2)]);
        assert!(order[&(SHELLCODE_BASE + 2)] < order[&(SHELLCODE_BASE + 1)]);
        assert!(order[&(SHELLCODE_BASE + 1)] < order[&SHELLCODE_BASE]);
    }

    #[test]
    fn pointer_candidates_cannot_branch_into_a_completed_functions_hotpatch_padding() {
        let mut bytes = vec![0xe8, 27, 0, 0, 0, 0xc3];
        bytes.resize(16, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0x40, 0x40, 0xeb, 4]);
        bytes.resize(32, 0x90);
        bytes.push(0xc3);
        bytes.resize(48, 0xcc);
        bytes.extend_from_slice(&((SHELLCODE_BASE + 16) as u32).to_le_bytes());
        let mut image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        image.format = ImageFormat::Pe;
        image.relocation_locations = vec![SHELLCODE_BASE + 48];
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(analysis.functions.contains_key(&(SHELLCODE_BASE + 32)));
        assert!(!analysis.functions.contains_key(&(SHELLCODE_BASE + 16)));
    }

    #[test]
    fn static_indirect_callees_complete_before_their_callers() {
        let slot = SHELLCODE_BASE + 16;
        let target = SHELLCODE_BASE + 32;
        let mut bytes = vec![0xff, 0x15];
        bytes.extend_from_slice(&(slot as u32).to_le_bytes());
        bytes.push(0xc3);
        bytes.resize(16, 0xcc);
        bytes.extend_from_slice(&(target as u32).to_le_bytes());
        bytes.resize(32, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
        let analysis = analyze_seeded_image(
            LoadedImage::from_shellcode(&bytes, Architecture::X86),
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(analysis.functions.contains_key(&target));
        assert!(analysis.seeds[&target].contains(&SeedKind::CallTarget));
        assert!(analysis.function_order[&target] < analysis.function_order[&SHELLCODE_BASE]);
    }

    #[test]
    fn forwarded_pe_exports_do_not_seed_functions() {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/testfiles/kernel32.dll_"),
        )
        .unwrap();
        let image = LoadedImage::parse(&bytes).unwrap();
        let mut seeds = SeedMap::new();
        collect_pe_seeds(&bytes, &image, &mut seeds, &mut Vec::new()).unwrap();
        let pe = PE::parse(&bytes).unwrap();
        let forwarded: Vec<_> = pe.exports.iter().filter(|e| e.reexport.is_some()).collect();
        assert!(!forwarded.is_empty());
        for export in forwarded {
            assert!(!seeds.contains_key(&(image.image_base + export.rva as u64)));
        }
        assert!(seeds
            .values()
            .any(|kinds| kinds.contains(&SeedKind::Export)));
    }

    #[test]
    fn relocated_instruction_operands_do_not_bypass_candidate_evaluation() {
        let target = SHELLCODE_BASE + 32;
        for source_is_code in [true, false] {
            let mut bytes = vec![0xb8];
            bytes.extend_from_slice(&(target as u32).to_le_bytes());
            bytes.push(0xc3);
            bytes.resize(16, 0xcc);
            bytes.extend_from_slice(&(target as u32).to_le_bytes());
            bytes.resize(32, 0xcc);
            bytes.extend_from_slice(&[0x55, 0x8b, 0xec, 0x0f, 0x0b]);
            let mut image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
            image.format = ImageFormat::Pe;
            image.relocation_locations = vec![SHELLCODE_BASE + if source_is_code { 1 } else { 16 }];
            let analysis = analyze_seeded_image(
                image,
                RecoveryBackend::VivisectCompat,
                SeedMap::from([
                    (SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint])),
                    (target, BTreeSet::from([SeedKind::Relocation])),
                ]),
                BTreeMap::new(),
                Vec::new(),
            )
            .unwrap();
            // A data pointer may use isProbablyCode's signature shortcut.
            // A relocated immediate is a REF_PTR for emucode, which must
            // reject this trace before the later function-signature pass.
            assert_eq!(
                analysis.seeds[&target].contains(&SeedKind::PointerTarget),
                !source_is_code
            );
            assert!(!analysis.seeds[&target].contains(&SeedKind::Emulated));
        }
    }

    #[test]
    fn pe_does_not_scan_arbitrary_data_as_function_pointers() {
        for format in [ImageFormat::Pe, ImageFormat::Elf] {
            let target = SHELLCODE_BASE + 32;
            let mut bytes = vec![0xc3];
            bytes.resize(16, 0xcc);
            bytes.extend_from_slice(&(target as u32).to_le_bytes());
            bytes.resize(32, 0xcc);
            bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0xc3]);
            let mut image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
            image.format = format;
            let analysis = analyze_seeded_image(
                image,
                RecoveryBackend::VivisectCompat,
                SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
                BTreeMap::new(),
                Vec::new(),
            )
            .unwrap();
            assert_eq!(
                analysis.functions.contains_key(&target),
                format == ImageFormat::Elf
            );
        }
    }

    #[test]
    fn late_signatures_do_not_restart_the_emucode_pass() {
        let target = SHELLCODE_BASE + 64;
        let mut bytes = vec![0xc3];
        bytes.resize(16, 0xcc);
        bytes.extend_from_slice(&[0x55, 0x8b, 0xec, 0xb8]);
        bytes.extend_from_slice(&(target as u32).to_le_bytes());
        bytes.extend_from_slice(&[0xc9, 0xc3]);
        bytes.resize(64, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0xc3]);
        let mut image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        image.format = ImageFormat::Pe;
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(analysis.functions.contains_key(&(SHELLCODE_BASE + 16)));
        assert!(!analysis.functions.contains_key(&target));
    }

    #[test]
    fn dereferenced_data_is_not_promoted_by_a_relocation() {
        let target = SHELLCODE_BASE + 16;
        let mut bytes = vec![0xa1]; // mov eax, [data]; ret
        bytes.extend_from_slice(&(target as u32).to_le_bytes());
        bytes.push(0xc3);
        bytes.resize(16, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0xc3]);
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([
                (SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint])),
                (target, BTreeSet::from([SeedKind::Relocation])),
            ]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(!analysis.functions.contains_key(&target));
    }

    #[test]
    fn later_noreturn_signatures_cannot_validate_an_earlier_candidate() {
        let target = SHELLCODE_BASE + 16;
        let mut bytes = vec![0xb8];
        bytes.extend_from_slice(&(target as u32).to_le_bytes());
        bytes.push(0xc3);
        bytes.resize(16, 0xcc);
        bytes.extend_from_slice(&[0xeb, 0x0e]); // jmp late signature
        bytes.resize(32, 0xcc);
        bytes.extend_from_slice(&[0x55, 0x8b, 0xec, 0x0f, 0x0b]);
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(analysis.functions.contains_key(&(SHELLCODE_BASE + 32)));
        assert!(!analysis.functions.contains_key(&target));
    }

    /// A walk past `MAX_INSNS_PER_FUNCTION` abandons that walk and records
    /// why; it does not fail the image. Upstream Vivisect has no per-walk
    /// instruction budget at all, so this limit is a statement about
    /// capa-x's guard rail, and a guard rail that discards every result
    /// the run already produced is worse than the runaway it prevents. This
    /// is why mapping `0cd2b334`'s resource-hosted
    /// code is the faithful loader behaviour, and it was revertible only
    /// because the budget turned one long walk into a hard error.
    #[test]
    fn a_walk_past_the_instruction_budget_is_abandoned_not_fatal() {
        // Single-byte `nop`s so the walk is one straight line, one past the
        // budget, then `ret`.
        let mut bytes = vec![0x90u8; MAX_INSNS_PER_FUNCTION + 1];
        bytes.push(0xc3);

        let analysis = analyze_shellcode(&bytes, Architecture::X86)
            .expect("a runaway walk must not fail the image");

        let abandoned: Vec<&RecoveryDiagnostic> = analysis
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.message.contains("abandoned code walk"))
            .collect();
        assert_eq!(
            abandoned.len(),
            1,
            "expected exactly one abandoned-walk diagnostic, got {:?}",
            analysis.diagnostics
        );
        assert!(
            abandoned[0].message.contains("exceeds"),
            "the diagnostic must say what budget was exceeded: {}",
            abandoned[0].message
        );
        // The walk is abandoned, not the run: what it decoded before hitting
        // the budget is still there to extract features from.
        assert!(
            analysis.instructions.len() >= MAX_INSNS_PER_FUNCTION,
            "decoded instructions should be kept, got {}",
            analysis.instructions.len()
        );
    }

    #[test]
    fn a_budgeted_walk_keeps_discovered_callees() {
        let mut bytes = vec![0x90; MAX_INSNS_PER_FUNCTION + 16];
        let target = bytes.len() - 1;
        bytes[0] = 0xe8;
        bytes[1..5].copy_from_slice(&((target - 5) as i32).to_le_bytes());
        bytes[target] = 0xc3;
        let analysis = analyze_shellcode(&bytes, Architecture::X86).unwrap();
        assert!(analysis
            .functions
            .contains_key(&(SHELLCODE_BASE + target as u64)));
        assert!(analysis
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("abandoned code walk")));
    }

    #[test]
    fn later_overlapping_opcodes_replace_the_covered_location() {
        let mut analysis = analyze_noreturn_test_image(&[0xe9, 0, 0, 0, 0, 0xc3]);
        let interior = analysis.image.decode_at_compat(0x1002).unwrap();
        analysis.instructions.insert(0x1002, interior);
        analysis.instruction_order.insert(0x1002, 0);
        analysis.instruction_order.insert(0x1000, 1);
        assert_eq!(
            instruction_location(&analysis, 0x1002).unwrap().address,
            0x1000
        );
        assert_eq!(
            instruction_location(&analysis, 0x1004).unwrap().address,
            0x1000
        );
        assert_eq!(
            instruction_location(&analysis, 0x1005).unwrap().address,
            0x1005
        );
    }

    #[test]
    fn compatibility_blocks_decode_inside_existing_instruction_locations() {
        let code = [
            0x68, 0x00, 0x64, 0xff, 0x30, // push immediate
            0x64, 0x89, 0x20, // fs: mov [eax],esp
            0x75, 0xf7, // jnz into the push's immediate
            0xc3, 0x90, 0x90, 0x90, 0x90,
        ];
        let analysis = analyze_seeded_image(
            noreturn_test_image(&code),
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(!analysis.instructions.contains_key(&0x1001));
        let block = analysis.functions[&0x1000]
            .blocks
            .iter()
            .find(|block| block.addr == 0x1001)
            .unwrap();
        assert_eq!(block.insns[0].x86_instruction().mnemonic(), Mnemonic::Add);
        assert_eq!(
            block.insns[0].x86_instruction().memory_displacement64(),
            0x30
        );
        assert!(block.insns.iter().any(|insn| insn.address == 0x1005));
    }

    #[test]
    fn compatibility_codeflow_continues_through_string_io() {
        for backend in [RecoveryBackend::VivisectCompat, RecoveryBackend::Native] {
            let analysis = analyze_seeded_image(
                noreturn_test_image(&[0x6c, 0x31, 0xc0, 0xc3]),
                backend,
                SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
                BTreeMap::new(),
                Vec::new(),
            )
            .unwrap();
            assert_eq!(
                analysis.instructions.contains_key(&0x1003),
                backend == RecoveryBackend::VivisectCompat
            );
        }
    }

    #[test]
    fn compatibility_halt_ends_codeflow_before_later_bytes() {
        let analysis = analyze_seeded_image(
            noreturn_test_image(&[0xf4, 0x60, 0x61, 0xc3]),
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(analysis.instructions[&0x1000].flow, Flow::Terminal);
        assert!(!analysis.instructions.contains_key(&0x1001));
        assert_eq!(analysis.functions[&0x1000].blocks[0].insns.len(), 1);
    }

    #[test]
    fn compatibility_unwind_entries_preserve_fallthrough_and_shared_tails() {
        for (code, expected) in [
            (
                vec![0x90, 0x90, 0x90, 0xc3],
                BTreeSet::from([0x1000, 0x1001, 0x1002, 0x1003]),
            ),
            (
                vec![0xeb, 0x00, 0x90, 0xc3],
                BTreeSet::from([0x1000, 0x1002, 0x1003]),
            ),
        ] {
            let analysis = analyze_seeded_image(
                noreturn_test_image(&code),
                RecoveryBackend::VivisectCompat,
                SeedMap::from([
                    (0x1000, BTreeSet::from([SeedKind::Unwind])),
                    (0x1002, BTreeSet::from([SeedKind::Unwind])),
                ]),
                BTreeMap::new(),
                Vec::new(),
            )
            .unwrap();
            assert_eq!(
                function_instruction_addrs(&analysis.functions[&0x1000]),
                expected
            );
            assert!(!analysis.is_noreturn_va(0x1000));
            assert_eq!(
                function_instruction_addrs(&analysis.functions[&0x1002]),
                BTreeSet::from([0x1002, 0x1003])
            );
        }
    }

    #[test]
    fn plain_memory_jumps_do_not_absorb_adjacent_pointer_targets() {
        for (opcode, expected_offsets) in [
            (vec![0xff, 0x25], vec![]),
            (vec![0xff, 0x24, 0x85], vec![0x20, 0x21]),
        ] {
            let mut bytes = opcode;
            bytes.extend_from_slice(&((SHELLCODE_BASE + 0x10) as u32).to_le_bytes());
            bytes.resize(0x10, 0xcc);
            bytes.extend_from_slice(&((SHELLCODE_BASE + 0x20) as u32).to_le_bytes());
            bytes.extend_from_slice(&((SHELLCODE_BASE + 0x21) as u32).to_le_bytes());
            bytes.resize(0x20, 0xcc);
            bytes.extend_from_slice(&[0xc3, 0xc3]);
            let analysis = analyze_shellcode(&bytes, Architecture::X86).unwrap();
            let mut expected = BTreeSet::from([SHELLCODE_BASE]);
            expected.extend(
                expected_offsets
                    .into_iter()
                    .map(|offset| SHELLCODE_BASE + offset),
            );
            assert_eq!(
                function_instruction_addrs(&analysis.functions[&SHELLCODE_BASE]),
                expected
            );
            assert!(analysis.instructions.contains_key(&(SHELLCODE_BASE + 0x20)));
            assert_eq!(
                analysis.instructions.contains_key(&(SHELLCODE_BASE + 0x21)),
                analysis.instructions[&SHELLCODE_BASE]
                    .x86_instruction()
                    .memory_index()
                    != iced_x86::Register::None
            );
            assert!(!analysis.is_noreturn_va(SHELLCODE_BASE));
        }
    }

    #[test]
    fn unresolved_pointer_jump_keeps_a_diagnostic() {
        let analysis = analyze_noreturn_test_image(&[0xff, 0x25, 0x00, 0x30, 0x00, 0x00]);
        assert!(!analysis.is_noreturn_va(0x1000));
        assert!(analysis.diagnostics.iter().any(|diagnostic| {
            diagnostic.address == 0x1000 && diagnostic.message == "unresolved indirect branch"
        }));
    }

    #[test]
    fn safe_seh_table_entries_become_authoritative_seeds() {
        let image_base = 0x1000;
        let table = 0x2000;
        let code = 0x1100;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x100u32.to_le_bytes());
        bytes.extend_from_slice(&0x101u32.to_le_bytes());
        bytes.extend_from_slice(&[0xc3, 0xc3]);
        let image = LoadedImage::for_test(
            ImageFormat::Pe,
            Architecture::X86,
            image_base,
            vec![
                MappedSection {
                    name: ".sxdata".to_string(),
                    address: table,
                    virtual_size: 8,
                    file_offset: 0,
                    file_size: 8,
                    permissions: Permissions {
                        read: true,
                        write: false,
                        execute: false,
                    },
                },
                MappedSection {
                    name: ".text".to_string(),
                    address: code,
                    virtual_size: 2,
                    file_offset: 8,
                    file_size: 2,
                    permissions: Permissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                },
            ],
            BTreeMap::new(),
            bytes,
        );
        let mut seeds = SeedMap::new();
        let mut diagnostics = Vec::new();

        collect_safe_seh_seeds(64, &image, table, 2, &mut seeds, &mut diagnostics);

        assert!(diagnostics.is_empty());
        assert_eq!(seeds.get(&code), Some(&BTreeSet::from([SeedKind::SafeSeh])));
        assert_eq!(
            seeds.get(&code.saturating_add(1)),
            Some(&BTreeSet::from([SeedKind::SafeSeh]))
        );
    }

    #[test]
    fn compat_uses_only_pinned_x86_function_signatures() {
        let x86 = [0xc3, 0x55, 0x8b, 0xec, 0xc3];
        let x86_image = LoadedImage::from_shellcode(&x86, Architecture::X86);
        let x86_analysis = analyze_image(&x86, x86_image, RecoveryBackend::VivisectCompat)
            .expect("compatibility recovery succeeds");
        assert_eq!(
            x86_analysis.seeds.get(&SHELLCODE_BASE.saturating_add(1)),
            Some(&BTreeSet::from([SeedKind::FunctionSignature]))
        );

        let x64 = [0xc3, 0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0xc3];
        let x64_image = LoadedImage::from_shellcode(&x64, Architecture::X64);
        let x64_analysis = analyze_image(&x64, x64_image, RecoveryBackend::VivisectCompat)
            .expect("compatibility recovery succeeds");
        assert!(!x64_analysis
            .seeds
            .contains_key(&SHELLCODE_BASE.saturating_add(1)));
    }

    #[test]
    fn raw_call_sweep_is_only_a_native_fallback() {
        let bytes = [
            0xc3, 0xe8, 0x04, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x53, 0xc3,
        ];
        let target = 0x1000u64.saturating_add(10);
        let image = LoadedImage::for_test(
            ImageFormat::Pe,
            Architecture::X86,
            0x1000,
            vec![MappedSection {
                name: ".text".to_string(),
                address: 0x1000,
                virtual_size: bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len() as u64,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
            BTreeMap::new(),
            bytes.to_vec(),
        );
        let mut compat = SeedMap::new();
        add_backend_fallback_seeds(&image, RecoveryBackend::VivisectCompat, &mut compat);
        assert!(!compat
            .get(&target)
            .is_some_and(|kinds| kinds.contains(&SeedKind::SweepCallTarget)));

        let mut native = SeedMap::new();
        add_backend_fallback_seeds(&image, RecoveryBackend::Native, &mut native);
        assert!(native
            .get(&target)
            .is_some_and(|kinds| kinds.contains(&SeedKind::SweepCallTarget)));
    }

    #[test]
    fn msvc_cookie_reference_block_becomes_its_own_function() {
        // `vivisect/analysis/ms/msvcfunc.py`: a `/GS` cookie check is
        // byte-signature-matched, and every code block whose `mov`
        // references that cookie becomes a function.
        //
        //   0x401000: call 0x401010          (the cookie check)
        //   0x401005: jmp  0x401020          (into the cookie-restoring tail)
        //   0x401010: cmp ecx, [0x403000]    \
        //   0x401016: jne 0x40101a            | signature row 1, 32-bit
        //   0x401018: rep ret                 | VS 2005..2013
        //   0x40101a: jmp 0x40101f           /
        //   0x40101f: ret
        //   0x401020: mov eax, [0x403000]    <- the split point
        //   0x401025: ret
        let base = 0x401000u64;
        let bytes = vec![
            0xe8, 0x0b, 0x00, 0x00, 0x00, // call 0x401010
            0xeb, 0x19, // jmp 0x401020
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // padding
            0x3b, 0x0d, 0x00, 0x30, 0x40, 0x00, // cmp ecx, [0x403000]
            0x75, 0x02, // jne 0x40101a
            0xf3, 0xc3, // rep ret
            0xe9, 0x00, 0x00, 0x00, 0x00, // jmp 0x40101f
            0xc3, // ret
            0xa1, 0x00, 0x30, 0x40, 0x00, // mov eax, [0x403000]
            0xc3, // ret
        ];
        let image = LoadedImage::for_test(
            ImageFormat::Pe,
            Architecture::X86,
            base,
            vec![MappedSection {
                name: ".text".to_string(),
                address: base,
                virtual_size: bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len() as u64,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
            BTreeMap::new(),
            bytes.clone(),
        );
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(base, BTreeSet::from([SeedKind::EntryPoint]))]),
            FunctionSymbolMap::new(),
            Vec::new(),
        )
        .expect("synthetic recovery succeeds");

        let split = base.saturating_add(0x20);
        assert_eq!(
            analysis.seeds.get(&split),
            Some(&BTreeSet::from([SeedKind::MsvcCookieBlock]))
        );
        assert!(analysis.functions.contains_key(&split));
        // the enclosing function still flows through it, as in vivisect --
        // this splits ownership, it does not cut the edge.
        let entry = analysis
            .functions
            .get(&base)
            .expect("entry function recovered");
        assert!(function_instruction_addrs(entry).contains(&split));
    }

    #[test]
    fn msvc_cookie_wave_ignores_a_non_mov_reference() {
        // Same shape, but the tail reads the cookie with `cmp`, which
        // `msvcfunc.py`'s `op.mnem == 'mov'` rejects.
        let base = 0x401000u64;
        let bytes = vec![
            0xe8, 0x0b, 0x00, 0x00, 0x00, //
            0xeb, 0x19, //
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, //
            0x3b, 0x0d, 0x00, 0x30, 0x40, 0x00, //
            0x75, 0x02, //
            0xf3, 0xc3, //
            0xe9, 0x00, 0x00, 0x00, 0x00, //
            0xc3, //
            0x3b, 0x05, 0x00, 0x30, 0x40, 0x00, // cmp eax, [0x403000]
            0xc3, //
        ];
        let image = LoadedImage::for_test(
            ImageFormat::Pe,
            Architecture::X86,
            base,
            vec![MappedSection {
                name: ".text".to_string(),
                address: base,
                virtual_size: bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len() as u64,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
            BTreeMap::new(),
            bytes.clone(),
        );
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(base, BTreeSet::from([SeedKind::EntryPoint]))]),
            FunctionSymbolMap::new(),
            Vec::new(),
        )
        .expect("synthetic recovery succeeds");
        assert!(!analysis.functions.contains_key(&base.saturating_add(0x20)));
    }

    #[test]
    fn direct_call_target_inside_recovered_region_gets_function_scope() {
        // call base+0xa; five nops; ret. The entry-point walk reaches and
        // owns base+0xa before the discovered call target is processed.
        let bytes = [
            0xe8, 0x05, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3,
        ];
        let analysis = analyze_shellcode(&bytes, Architecture::X86)
            .expect("synthetic shellcode recovery succeeds");

        assert!(analysis.functions.contains_key(&SHELLCODE_BASE));
        assert!(analysis
            .functions
            .contains_key(&SHELLCODE_BASE.saturating_add(0xa)));
    }

    #[test]
    fn call_plus_five_does_not_create_function_candidate() {
        // Pinned Vivisect's `envi/codeflow.py` explicitly excludes a
        // procedural target equal to the next instruction. The xref remains
        // visible so capa can still extract `characteristic: call $+5`.
        let bytes = [0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0xc3];
        let analysis = analyze_shellcode(&bytes, Architecture::X86)
            .expect("synthetic shellcode recovery succeeds");

        let next = SHELLCODE_BASE.saturating_add(0x5);
        assert!(!analysis.seeds.contains_key(&next));
        assert!(!analysis.functions.contains_key(&next));
        assert_eq!(analysis.code_xrefs.get(&next), Some(&vec![SHELLCODE_BASE]));
        assert!(function_instruction_addrs(
            analysis
                .functions
                .get(&SHELLCODE_BASE)
                .expect("entry function recovered")
        )
        .contains(&next));
    }

    #[test]
    fn overlapping_call_targets_get_distinct_shared_graph_views() {
        // Both calls target instructions that entry-point discovery reaches
        // first by fallthrough. Each target must still become a function view
        // over the shared direct-flow graph, without cloning blocks from an
        // already-materialized function.
        //   base+0x0: e8 06 00 00 00  call base+0xb
        //   base+0x5: e8 03 00 00 00  call base+0xd
        //   base+0xa: 90              nop
        //   base+0xb: 90 90           nop; nop
        //   base+0xd: c3              ret
        let bytes = [
            0xe8, 0x06, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xc3,
        ];
        let analysis = analyze_shellcode(&bytes, Architecture::X86)
            .expect("synthetic shellcode recovery succeeds");

        let first_target = SHELLCODE_BASE.saturating_add(0xb);
        let second_target = SHELLCODE_BASE.saturating_add(0xd);
        let entry_addrs = function_instruction_addrs(
            analysis
                .functions
                .get(&SHELLCODE_BASE)
                .expect("entry function recovered"),
        );
        let first_addrs = function_instruction_addrs(
            analysis
                .functions
                .get(&first_target)
                .expect("first overlapping target recovered"),
        );
        let second_addrs = function_instruction_addrs(
            analysis
                .functions
                .get(&second_target)
                .expect("second overlapping target recovered"),
        );

        assert!(entry_addrs.contains(&first_target));
        assert!(entry_addrs.contains(&second_target));
        assert_eq!(
            first_addrs,
            BTreeSet::from([first_target, first_target.saturating_add(1), second_target])
        );
        assert_eq!(second_addrs, BTreeSet::from([second_target]));
    }

    fn function_instruction_addrs(function: &Function) -> BTreeSet<u64> {
        function
            .blocks
            .iter()
            .flat_map(|block| block.insns.iter().map(|insn| insn.address))
            .collect()
    }

    #[test]
    fn direct_jump_to_call_seeded_target_stays_in_flowing_function() {
        // Phase 2.1: `call base+0xb` (seeds base+0xb as a call target), then
        // `jmp base+0xb`. A seed at the jump target must NOT split the function
        // -- the flowing function keeps flowing through the jump. Pre-2.1 the
        // seed made this a TailCall that ended the entry function short.
        //   base+0x0: e8 06 00 00 00  call base+0xb
        //   base+0x5: eb 04           jmp  base+0xb
        //   base+0x7: 90 90 90 90     nop x4
        //   base+0xb: c3              ret
        let bytes = [
            0xe8, 0x06, 0x00, 0x00, 0x00, 0xeb, 0x04, 0x90, 0x90, 0x90, 0x90, 0xc3,
        ];
        let analysis = analyze_shellcode(&bytes, Architecture::X86)
            .expect("synthetic shellcode recovery succeeds");

        let target = SHELLCODE_BASE.saturating_add(0xb);
        let entry = analysis
            .functions
            .get(&SHELLCODE_BASE)
            .expect("entry function recovered");
        // The jump followed into the seeded target: it belongs to the caller.
        assert!(function_instruction_addrs(entry).contains(&target));
        // ...and the call target still gets its own (overlapping) function.
        assert!(analysis.functions.contains_key(&target));
    }

    #[test]
    fn direct_jump_to_prologue_seeded_target_stays_in_flowing_function() {
        // Phase 2.1: `jmp` to a `push ebp; mov ebp, esp` prologue pattern. The
        // prologue scan seeds that address, but a seed is not proof of a tail
        // call -- the caller must still flow through it.
        //   base+0x0: eb 03        jmp base+0x5
        //   base+0x2: 90 90 90     nop x3
        //   base+0x5: 55           push ebp
        //   base+0x6: 8b ec        mov ebp, esp
        //   base+0x8: c3           ret
        let bytes = [0xeb, 0x03, 0x90, 0x90, 0x90, 0x55, 0x8b, 0xec, 0xc3];
        let analysis = analyze_shellcode(&bytes, Architecture::X86)
            .expect("synthetic shellcode recovery succeeds");

        let target = SHELLCODE_BASE.saturating_add(0x5);
        let entry = analysis
            .functions
            .get(&SHELLCODE_BASE)
            .expect("entry function recovered");
        assert!(function_instruction_addrs(entry).contains(&target));
    }

    #[test]
    fn called_signature_seed_is_walked_before_lower_signature_seeds() {
        // An MSVC hot-patch thunk in miniature: the entry calls the *higher*
        // of two `mov edi, edi; push ebp; mov ebp, esp` prologue hits, and
        // that one jumps down into the *lower* one. Both are signature seeds,
        // so the initial priority sort would walk the lower (body) one first
        // and give it a function of its own -- which vivisect never does,
        // because codeflow from the call has already claimed those bytes by
        // the time `generic/funcentries.py` scans for prologues.
        //   base+0x00: e8 08 00 00 00  call base+0xd
        //   base+0x05: c3              ret
        //   base+0x06: 8b ff           mov edi, edi   <- body
        //   base+0x08: 55              push ebp
        //   base+0x09: 8b ec           mov ebp, esp
        //   base+0x0b: 5d              pop ebp
        //   base+0x0c: c3              ret
        //   base+0x0d: 8b ff           mov edi, edi   <- thunk
        //   base+0x0f: 55              push ebp
        //   base+0x10: 8b ec           mov ebp, esp
        //   base+0x12: 5d              pop ebp
        //   base+0x13: e9 ee ff ff ff  jmp base+0x6
        let bytes = [
            0xe8, 0x08, 0x00, 0x00, 0x00, 0xc3, 0x8b, 0xff, 0x55, 0x8b, 0xec, 0x5d, 0xc3, 0x8b,
            0xff, 0x55, 0x8b, 0xec, 0x5d, 0xe9, 0xee, 0xff, 0xff, 0xff,
        ];
        let analysis = analyze_shellcode(&bytes, Architecture::X86)
            .expect("synthetic shellcode recovery succeeds");

        let body = SHELLCODE_BASE.saturating_add(0x6);
        let thunk = SHELLCODE_BASE.saturating_add(0xd);
        let thunk_view = analysis
            .functions
            .get(&thunk)
            .expect("the called thunk is a function");
        assert!(function_instruction_addrs(thunk_view).contains(&body));
        assert!(
            !analysis.functions.contains_key(&body),
            "the jump target is the thunk's body, not a function of its own"
        );
    }

    #[test]
    fn call_target_view_can_flow_into_authoritative_entry() {
        // The entry calls base+6 and returns. The callee jumps back to the
        // authoritative entry. Discovery must record that jump before function
        // ownership is constructed, so the callee view can include the entry.
        //   base+0x0: e8 01 00 00 00  call base+0x6
        //   base+0x5: c3              ret
        //   base+0x6: eb f8           jmp base+0x0
        let bytes = [0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xeb, 0xf8];
        let analysis = analyze_shellcode(&bytes, Architecture::X86)
            .expect("synthetic shellcode recovery succeeds");

        let callee_address = SHELLCODE_BASE.saturating_add(0x6);
        let callee = analysis
            .functions
            .get(&callee_address)
            .expect("call target function recovered");
        let owned = function_instruction_addrs(callee);
        assert!(owned.contains(&callee_address));
        assert!(owned.contains(&SHELLCODE_BASE));
        assert!(owned.contains(&SHELLCODE_BASE.saturating_add(0x5)));
    }

    #[test]
    fn overlapping_relocation_candidate_stays_isolated() {
        let address = SHELLCODE_BASE.saturating_add(0x10);
        let mut seeds = SeedMap::new();
        seeds
            .entry(address)
            .or_default()
            .insert(SeedKind::Relocation);
        let mut fallback = SeedMap::new();

        assert!(should_isolate_overlapping_candidate(
            &fallback, &seeds, address, true
        ));
        assert!(!should_isolate_overlapping_candidate(
            &fallback, &seeds, address, false
        ));

        seeds
            .entry(address)
            .or_default()
            .insert(SeedKind::CallTarget);
        assert!(!should_isolate_overlapping_candidate(
            &fallback, &seeds, address, true
        ));
        if let Some(kinds) = seeds.get_mut(&address) {
            kinds.remove(&SeedKind::CallTarget);
        }

        seeds.entry(address).or_default().insert(SeedKind::Export);
        assert!(!should_isolate_overlapping_candidate(
            &fallback, &seeds, address, true
        ));

        if let Some(kinds) = seeds.get_mut(&address) {
            kinds.remove(&SeedKind::Export);
        }
        fallback
            .entry(address)
            .or_default()
            .insert(SeedKind::Prologue);
        assert!(!should_isolate_overlapping_candidate(
            &fallback, &seeds, address, true
        ));
    }

    /// A hand-built x86 PE-shaped image: `.text` at `TEXT_BASE`, plus a
    /// non-executable one-slot import table at `IAT` bound to
    /// `kernel32.ExitProcess` -- one of the literal no-return APIs the pinned
    /// PE loader registers (`vivisect/parsers/pe.py:417`).
    fn noreturn_test_image(code: &[u8]) -> LoadedImage {
        const TEXT_BASE: u64 = 0x1000;
        const IAT: u64 = 0x2000;
        let mut bytes = code.to_vec();
        let iat_offset = bytes.len() as u64;
        // An unbound IAT slot: not an executable address, so an indirect
        // branch through it stays unresolved, exactly as in a real unloaded PE.
        bytes.extend_from_slice(&0u32.to_le_bytes());
        LoadedImage::for_test(
            ImageFormat::Pe,
            Architecture::X86,
            TEXT_BASE,
            vec![
                MappedSection {
                    name: ".text".to_string(),
                    address: TEXT_BASE,
                    virtual_size: code.len() as u64,
                    file_offset: 0,
                    file_size: code.len() as u64,
                    permissions: Permissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                },
                MappedSection {
                    name: ".idata".to_string(),
                    address: IAT,
                    virtual_size: 4,
                    file_offset: iat_offset,
                    file_size: 4,
                    permissions: Permissions {
                        read: true,
                        write: false,
                        execute: false,
                    },
                },
            ],
            BTreeMap::new(),
            bytes,
        )
        .with_import_location(IAT, "kernel32.ExitProcess")
    }

    /// Run the full no-return fixpoint over a hand-built image, seeding only
    /// its entry point (a synthetic image has no parseable PE directories for
    /// [`collect_seeds`] to walk).
    fn analyze_noreturn_test_image(code: &[u8]) -> Analysis {
        let image = noreturn_test_image(code);
        let mut seeds = SeedMap::new();
        if let Some(entry) = image.entry_point {
            add_seed(&image, &mut seeds, entry, SeedKind::EntryPoint);
        }
        analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            seeds,
            BTreeMap::new(),
            Vec::new(),
        )
        .expect("synthetic no-return recovery succeeds")
    }

    /// `0x1010: jmp [0x2000]` -- a one-instruction import thunk, preceded by
    /// `code` and padded out so the thunk always lands at `0x1010`.
    fn thunk_at_0x1010(code: &[u8]) -> Vec<u8> {
        let mut bytes = code.to_vec();
        bytes.resize(0x10, 0xcc);
        bytes.extend_from_slice(&[0xff, 0x25, 0x00, 0x20, 0x00, 0x00]);
        bytes
    }

    #[test]
    fn elf_plt_loose_code_finishes_callees_before_image_entry() {
        let mut bytes = vec![0xc3];
        bytes.resize(0x20, 0xcc);
        bytes.extend_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]);
        bytes.resize(0x40, 0xcc);
        bytes.push(0xc3);
        let mut image = noreturn_test_image(&bytes);
        image.format = ImageFormat::Elf;
        image.elf_plt_ranges.push((0x1020, 0x1026));
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(analysis.function_order[&0x1040] < analysis.function_order[&0x1000]);
        assert!(!analysis.functions.contains_key(&0x1020));
    }

    #[test]
    fn cet_plt_thunks_propagate_no_return_only_in_plt_sections() {
        for in_plt in [false, true] {
            let mut code = vec![0xe8, 0x0b, 0, 0, 0, 0x90, 0xc3];
            code.resize(0x10, 0xcc);
            code.extend_from_slice(&[0xf3, 0x0f, 0x1e, 0xfb, 0xff, 0x25, 0, 0x20, 0, 0]);
            let mut image =
                noreturn_test_image(&code).with_import_location(0x2000, "*.__stack_chk_fail");
            image.format = ImageFormat::Elf;
            if in_plt {
                image.elf_plt_ranges.push((0x1010, 0x1020));
            }
            let analysis = analyze_seeded_image(
                image,
                RecoveryBackend::VivisectCompat,
                SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
                BTreeMap::new(),
                Vec::new(),
            )
            .unwrap();
            assert_eq!(analysis.is_noreturn_va(0x1010), in_plt);
            assert_eq!(analysis.noreturn_calls.contains(&0x1000), in_plt);
        }
    }

    #[test]
    fn call_through_a_noreturn_import_keeps_its_fallthrough() {
        // Vivisect does *not* stop here, even though the IAT slot is a
        // registered no-return VA: `_cb_opcode` (`vivisect/base.py:820`) drops
        // branches to `LOC_IMPORT` targets before codeflow's `BR_DEREF`
        // no-return check can see them. Verified on `Practical Malware
        // Analysis Lab 17-02.dll_`, where all ten `call [no-return import]`
        // sites keep their fallthrough.
        //   0x1000: ff 15 00 20 00 00   call [0x2000]   ; kernel32.ExitProcess
        //   0x1006: 90                  nop
        //   0x1007: c3                  ret
        let analysis =
            analyze_noreturn_test_image(&[0xff, 0x15, 0x00, 0x20, 0x00, 0x00, 0x90, 0xc3]);

        assert!(analysis.noreturn.contains(&0x2000));
        assert!(analysis.noreturn_calls.is_empty());
        let entry = analysis
            .functions
            .get(&0x1000)
            .expect("entry function recovered");
        assert_eq!(
            function_instruction_addrs(entry),
            BTreeSet::from([0x1000, 0x1006, 0x1007])
        );
    }

    #[test]
    fn noreturn_status_propagates_through_an_import_thunk() {
        //   0x1000: e8 0b 00 00 00      call 0x1010
        //   0x1005: 90                  nop             ; unreachable
        //   0x1006: c3                  ret             ; unreachable
        //   0x1010: ff 25 00 20 00 00   jmp [0x2000]    ; ExitProcess thunk
        let analysis =
            analyze_noreturn_test_image(&thunk_at_0x1010(&[0xe8, 0x0b, 0, 0, 0, 0x90, 0xc3]));

        // The thunk inherits the import's no-return status
        // (`VivWorkspace.checkNoRetApi`), which then truncates its caller --
        // reached only by re-running discovery with the enlarged set.
        assert!(analysis.noreturn.contains(&0x1010));
        assert!(analysis.noreturn_calls.contains(&0x1000));
        // addEntryPoint completes even a known no-return callee before the
        // caller's fallthrough is suppressed on subsequent recovery sweeps.
        assert!(analysis.function_order[&0x1010] < analysis.function_order[&0x1000]);
        let entry = analysis
            .functions
            .get(&0x1000)
            .expect("entry function recovered");
        assert_eq!(function_instruction_addrs(entry), BTreeSet::from([0x1000]));
        // The bytes after the call were never even decoded.
        assert!(!analysis.instructions.contains_key(&0x1005));
        // ...and a function whose only leaf ends in a no-return call is itself
        // no-return (`vivisect/analysis/generic/noret.py`).
        assert!(analysis.is_noreturn_va(0x1000));
    }

    #[test]
    fn noreturn_call_mid_function_keeps_the_rest_of_the_function() {
        // The no-return call is *not* the last instruction: its own
        // fallthrough disappears, but the branch target block is still part of
        // the same function, and the function still returns.
        //   0x1000: 85 c0               test eax, eax
        //   0x1002: 74 0b               je 0x100f
        //   0x1004: e8 07 00 00 00      call 0x1010     ; ExitProcess thunk
        //   0x1009: 90 x6                               ; unreachable
        //   0x100f: c3                  ret
        //   0x1010: ff 25 00 20 00 00   jmp [0x2000]
        let analysis = analyze_noreturn_test_image(&thunk_at_0x1010(&[
            0x85, 0xc0, 0x74, 0x0b, 0xe8, 0x07, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3,
        ]));

        assert!(analysis.noreturn_calls.contains(&0x1004));
        let entry = analysis
            .functions
            .get(&0x1000)
            .expect("entry function recovered");
        assert_eq!(
            function_instruction_addrs(entry),
            BTreeSet::from([0x1000, 0x1002, 0x1004, 0x100f])
        );
        assert!(!analysis.instructions.contains_key(&0x1009));
        // A leaf ending in `ret` means the function itself still returns.
        assert!(!analysis.is_noreturn_va(0x1000));
    }

    #[test]
    fn a_callee_whose_only_leaf_stops_on_undecodable_bytes_is_noreturn() {
        // `noret.py` sets `hasret` only for a leaf ending in `IF_RET` or an
        // unresolved `IF_BRANCH`. A block that simply stops -- here because
        // the bytes after `xor edx, edx` do not decode -- is neither, so the
        // function is no-return and its caller's fallthrough disappears. This
        // is the shape behind `0596c4ea`'s `inject thread`: three functions
        // deep, the reference ends the chain's first block on an invalid
        // `0f c7 c8` and every caller inherits it.
        //   0x1000: e8 03 00 00 00      call 0x1008
        //   0x1005: 90 90               nop, nop        ; unreachable
        //   0x1007: c3                  ret             ; unreachable
        //   0x1008: 31 d2               xor edx, edx
        //   0x100a: 0f c7 c8            (invalid)
        let analysis = analyze_noreturn_test_image(&[
            0xe8, 0x03, 0, 0, 0, 0x90, 0x90, 0xc3, 0x31, 0xd2, 0x0f, 0xc7, 0xc8,
        ]);

        assert!(analysis.is_noreturn_va(0x1008));
        assert!(analysis.noreturn_calls.contains(&0x1000));
        let entry = analysis
            .functions
            .get(&0x1000)
            .expect("entry function recovered");
        assert_eq!(function_instruction_addrs(entry), BTreeSet::from([0x1000]));
        // The caller's own leaf is now a suppressed call, so it too is
        // no-return -- the propagation that used to stop at the decode gap.
        assert!(analysis.is_noreturn_va(0x1000));
    }

    #[test]
    fn unresolved_jump_does_not_truncate_its_caller() {
        // call 0x1008; nop; nop; ret; jmp 0x1100 (outside the image).
        let analysis = analyze_noreturn_test_image(&[
            0xe8, 0x03, 0, 0, 0, 0x90, 0x90, 0xc3, 0xe9, 0xf3, 0, 0, 0,
        ]);
        assert!(!analysis.is_noreturn_va(0x1008));
        assert!(analysis.noreturn_calls.is_empty());
        assert_eq!(
            function_instruction_addrs(&analysis.functions[&0x1000]),
            BTreeSet::from([0x1000, 0x1005, 0x1006, 0x1007])
        );
    }

    #[test]
    fn conflicting_instruction_stream_does_not_truncate_its_caller() {
        // An unresolved ELF relocation can point a call into its own operand:
        // call 0x1001; nop; ret. The alternate stream is cld; invalid ff.
        // Its decode gap cannot establish that this call never returns.
        let analysis = analyze_noreturn_test_image(&[0xe8, 0xfc, 0xff, 0xff, 0xff, 0x90, 0xc3]);
        assert!(!analysis.is_noreturn_va(0x1001));
        assert!(analysis.noreturn_calls.is_empty());
        assert_eq!(
            function_instruction_addrs(&analysis.functions[&0x1000]),
            BTreeSet::from([0x1000, 0x1005, 0x1006])
        );
    }

    #[test]
    fn call_to_an_ordinary_import_thunk_keeps_its_fallthrough() {
        // The same shape as `noreturn_status_propagates_through_an_import_thunk`
        // but through an import that is *not* on the pinned no-return list:
        // suppression must be name-driven, not "any thunk".
        let image = noreturn_test_image(&thunk_at_0x1010(&[0xe8, 0x0b, 0, 0, 0, 0x90, 0xc3]))
            .with_import_location(0x2000, "kernel32.CreateFileA");
        let mut seeds = SeedMap::new();
        if let Some(entry) = image.entry_point {
            add_seed(&image, &mut seeds, entry, SeedKind::EntryPoint);
        }
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            seeds,
            BTreeMap::new(),
            Vec::new(),
        )
        .expect("synthetic recovery succeeds");

        assert!(analysis.noreturn.is_empty());
        assert!(analysis.noreturn_calls.is_empty());
        let entry = analysis
            .functions
            .get(&0x1000)
            .expect("entry function recovered");
        assert_eq!(
            function_instruction_addrs(entry),
            BTreeSet::from([0x1000, 0x1005, 0x1006])
        );
    }

    #[test]
    fn recognizes_vivisect_x86_seh_entry_signature() {
        assert!(matches_x86_seh_entry_signature(&[
            0x6a, 0x38, 0x68, 0x10, 0x23, 0x4b, 0x00, 0xe8,
        ]));
        assert!(!matches_x86_seh_entry_signature(&[
            0x6a, 0x38, 0x68, 0x10, 0x23, 0x4b, 0x00, 0x90,
        ]));
    }

    /// A hand-built AArch64 image: `bl <stub>` at the entry point, and at
    /// `stub` the AAPCS64 lazy-PLT shape (`adrp x16, page(got); ldr x17,
    /// [x16, #off]; br x17`) whose `adrp`+`ldr` pair resolves to `got` --
    /// bound, via `with_import_location`/`external_bindings`, to `exit`, one
    /// of the pinned ELF no-return APIs (`ELF_NORETURN_APIS`). Encodings
    /// independently verified in Python against `aarch64_plt_got_target`'s
    /// own formulas before being hand-transcribed here.
    #[test]
    fn aarch64_plt_stub_resolves_to_its_got_import_and_propagates_noreturn() {
        const ENTRY: u64 = 0x400000;
        const STUB: u64 = 0x400100;
        const GOT: u64 = 0x500000;

        let mut code = vec![0x90u8; (STUB - ENTRY) as usize];
        code[0..4].copy_from_slice(&0x9400_0040u32.to_le_bytes()); // bl STUB
        let stub_offset = code.len();
        code.extend_from_slice(&0x9000_0810u32.to_le_bytes()); // adrp x16, page(GOT)
        code.extend_from_slice(&0xf940_0211u32.to_le_bytes()); // ldr x17, [x16, #off]
        code.extend_from_slice(&0xd61f_0220u32.to_le_bytes()); // br x17
        assert_eq!(ENTRY + stub_offset as u64, STUB);

        let image = LoadedImage::for_test(
            ImageFormat::Elf,
            Architecture::AArch64,
            ENTRY,
            vec![MappedSection {
                name: ".text".to_string(),
                address: ENTRY,
                virtual_size: code.len() as u64,
                file_offset: 0,
                file_size: code.len() as u64,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
            BTreeMap::from([(GOT, vec!["exit".to_string()])]),
            code,
        )
        .with_import_location(GOT, "*.exit");

        let mut seeds = SeedMap::new();
        add_seed(&image, &mut seeds, ENTRY, SeedKind::EntryPoint);
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            seeds,
            BTreeMap::new(),
            Vec::new(),
        )
        .expect("synthetic AArch64 recovery succeeds");

        assert_eq!(
            analysis
                .image
                .import_locations
                .get(&STUB)
                .map(String::as_str),
            Some("*.exit"),
            "the stub's own start address should alias the GOT slot's import name"
        );
        assert!(
            analysis
                .image
                .external_bindings
                .get(&STUB)
                .is_some_and(|names| names.iter().any(|name| name == "exit")),
            "external_bindings should carry the same alias"
        );
        // `exit` is a pinned ELF no-return API (`ELF_NORETURN_APIS`); once
        // the stub's address is a known import location, the no-return
        // fixpoint (which re-seeds from `import_locations` each pass) should
        // propagate that status to the stub itself.
        assert!(
            analysis.noreturn.contains(&STUB),
            "a stub resolving to a no-return API should itself be no-return"
        );
    }
}
