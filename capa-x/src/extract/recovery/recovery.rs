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
const MAX_JUMP_TABLE_ENTRIES: usize = 256;
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

#[derive(Debug, Default)]
struct DirectFlowGraph {
    successors: BTreeMap<u64, Vec<Edge>>,
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
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
    let image = LoadedImage::parse(bytes)?;
    analyze_image(bytes, image, backend)
}

/// `-f sc32`/`sc64`. Function seeds come only from the entry point
/// (seeded generically below), call-target discovery, and the prologue
/// scan -- there are no format-specific seeds (no exports/TLS/relocations/
/// symbol tables) for a raw blob, mirrored by [`collect_seeds`]'s `Sc` arm.
pub fn analyze_shellcode(
    bytes: &[u8],
    architecture: Architecture,
) -> Result<Analysis, RecoveryError> {
    let image = LoadedImage::from_shellcode(bytes, architecture);
    // Shellcode remains experimental and its contract explicitly includes
    // prologue and call sweeps because it has no container-provided seeds.
    analyze_image(bytes, image, RecoveryBackend::Native)
}

/// `-f macho`. `RecoveryBackend::Native`, same reasoning as
/// [`analyze_shellcode`]: there is no pinned-Vivisect baseline to reproduce
/// for a format Vivisect never loaded, so "Vivisect-compatible" isn't a
/// meaningful mode here.
pub fn analyze_macho(bytes: &[u8], arch: Option<&str>) -> Result<Analysis, RecoveryError> {
    let image = LoadedImage::from_macho(bytes, arch)?;
    analyze_image(bytes, image, RecoveryBackend::Native)
}

fn analyze_image(
    bytes: &[u8],
    image: LoadedImage,
    backend: RecoveryBackend,
) -> Result<Analysis, RecoveryError> {
    let (seeds, elf_function_symbols, diagnostics) = collect_seeds(bytes, &image)?;
    analyze_seeded_image(image, backend, seeds, elf_function_symbols, diagnostics)
}

fn analyze_seeded_image(
    image: LoadedImage,
    backend: RecoveryBackend,
    mut seeds: SeedMap,
    elf_function_symbols: FunctionSymbolMap,
    diagnostics: Vec<RecoveryDiagnostic>,
) -> Result<Analysis, RecoveryError> {
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
            analysis.instructions.clear();
            analysis.code_xrefs.clear();
            analysis.data_xrefs.clear();
            analysis.noreturn_calls.clear();
        }
        recover_functions(&mut analysis, &fallback, &noreturn)?;
        let next = noreturn::propagate(&analysis, &noreturn_seed);
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
) -> Result<(), RecoveryError> {
    let mut initial: Vec<u64> = analysis.seeds.keys().copied().collect();
    initial.sort_by_key(|address| {
        let priority = analysis
            .seeds
            .get(address)
            .map(seed_priority)
            .unwrap_or(usize::MAX);
        (priority, *address)
    });
    let mut pending: VecDeque<u64> = initial.into();
    let mut function_starts = BTreeSet::new();
    let mut isolated_starts = BTreeSet::new();
    let mut direct_flow = DirectFlowGraph::default();
    let mut late_waves_done = false;
    let mut function_budget_reported = false;
    loop {
        let Some(start) = pending.pop_front() else {
            if late_waves_done {
                break;
            }
            // Vivisect's `i386.importcalls` only fires on space no earlier
            // analysis has defined, and by the time it runs (analysis module
            // 6) its location database already covers everything reachable
            // from the entry points. capa-x's nearest equivalent to "still
            // undefined" is "no seed's flow ever walked it", which is only
            // known once the queue is empty -- so the wave runs last, and
            // whatever it seeds is drained by the same loop.
            //
            // Firing it earlier, at the boundary before the entry-signature
            // seeds, reproduces upstream's module order but not its coverage:
            // measured on `6f99a2c8944cb02ff28c6f9ced59b161.exe_` it found 645
            // fragments where vivisect finds 0, because 641 of those sites sit
            // in code capa-x had not yet walked. Claiming them as loose
            // code suppressed three signature-seeded functions vivisect keeps.
            //
            // The Go pass shares the timing for a different reason: it reads
            // the *recovered* entry function's basic blocks, so it cannot run
            // until that function's flow exists.
            late_waves_done = true;
            run_go_runtime_main_wave(analysis, &direct_flow, &mut pending)?;
            run_import_call_wave(analysis, &mut direct_flow, &mut pending, noreturn)?;
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
        let late_signature_only = analysis.seeds.get(&start).is_some_and(|kinds| {
            kinds
                .iter()
                .all(|kind| matches!(kind, SeedKind::FunctionSignature | SeedKind::Prologue))
        });
        if function_starts.contains(&start)
            || (late_signature_only && analysis.instructions.contains_key(&start))
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
            // Relocation candidates are a native recovery heuristic, not a
            // pinned Vivisect function source. Until backend selection moves
            // them out of compatibility mode, keep an overlapping candidate
            // isolated at its entry instruction. This preserves the previous
            // containment rule and prevents a speculative seed from claiming
            // an entire shared graph after ownership becomes a second stage.
            isolated_starts.insert(start);
        }
        function_starts.insert(start);
        // Same rule as the import-call wave below: upstream has no per-walk
        // instruction budget, so a walk that blows past capa-x's is a
        // statement about this backend's guard rail, not about the image.
        // Keep what the walk did discover and record why it stopped, rather
        // than failing the whole image on one runaway start.
        let calls = match discover_direct_flow(analysis, &mut direct_flow, start, noreturn) {
            Ok(calls) => calls,
            Err(RecoveryError::Limit(message)) => {
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address: start,
                    message: format!("abandoned code walk: {message}"),
                });
                BTreeSet::new()
            }
            Err(error) => return Err(error),
        };
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
                        matches!(kind, SeedKind::FunctionSignature | SeedKind::Prologue)
                    })
                });
            analysis
                .seeds
                .entry(target)
                .or_default()
                .insert(SeedKind::CallTarget);
            if is_new || (was_heuristic_only && !function_starts.contains(&target)) {
                pending.push_front(target);
            }
        }
    }
    for start in function_starts {
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
    Ok(())
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
    noreturn: &BTreeSet<u64>,
) -> Result<(), RecoveryError> {
    let starts = {
        let instructions = &analysis.instructions;
        importcalls::fragment_starts(&analysis.image, &|address| {
            instructions
                .range(..=address)
                .next_back()
                .map(|(start, insn)| (*start, insn.next_address))
                .filter(|(_, end)| address < *end)
                .map(|(_, end)| end)
        })
    };

    for start in starts {
        // Already-walked bytes are not undiscovered space.
        if direct_flow.successors.contains_key(&start) || !is_executable(&analysis.image, start) {
            continue;
        }
        let calls = match discover_direct_flow(analysis, direct_flow, start, noreturn) {
            Ok(calls) => calls,
            // Upstream has no per-run instruction budget here. A fragment that
            // blows past capa-x's is loose code either way, so record why
            // it was abandoned rather than failing the whole image on it.
            Err(RecoveryError::Limit(message)) => {
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address: start,
                    message: format!("abandoned import-call code fragment: {message}"),
                });
                continue;
            }
            Err(error) => return Err(error),
        };
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
            if is_new {
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

fn seed_priority(kinds: &BTreeSet<SeedKind>) -> usize {
    // The prologue scan is the weakest, most false-positive-prone seed: a
    // `push ebp; mov ebp, esp` byte pattern often falls *inside* a real
    // function (a shared tail, a loop head). Processing it last -- after all
    // authoritative and call/relocation-driven flow has claimed its
    // instructions -- lets [`analyze_image`]'s heuristic-seed guard skip such
    // spurious starts, mirroring vivisect's flow-first discovery.
    if kinds.iter().any(|kind| is_authoritative_seed(*kind)) {
        0
    } else if kinds.contains(&SeedKind::CallTarget) || kinds.contains(&SeedKind::SweepCallTarget) {
        1
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
        ImageFormat::Elf => collect_elf_seeds(bytes, image, &mut seeds, &mut elf_function_symbols)?,
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
    // This legacy relocation candidate path remains in compatibility mode for
    // now. Removing it loses previously exact corpus samples, so Phase 3's
    // no-regression policy requires a faithful Vivisect pointer-analysis
    // replacement before it can move to Native.
    if let Some(relocations) = &pe.relocation_data {
        for block in relocations.blocks() {
            let block = match block {
                Ok(block) => block,
                Err(error) => {
                    diagnostics.push(RecoveryDiagnostic {
                        address: image.image_base,
                        message: format!("stopped parsing malformed PE relocations: {error}"),
                    });
                    break;
                }
            };
            for word in block.words() {
                let word = match word {
                    Ok(word) => word,
                    Err(error) => {
                        diagnostics.push(RecoveryDiagnostic {
                            address: image.image_base.saturating_add(u64::from(block.rva)),
                            message: format!(
                                "stopped parsing malformed PE relocation block: {error}"
                            ),
                        });
                        break;
                    }
                };
                if word.reloc_type() == 0 {
                    continue;
                }
                if let Some(location) = image
                    .image_base
                    .checked_add(u64::from(block.rva))
                    .and_then(|value| value.checked_add(u64::from(word.offset())))
                {
                    if let Some(target) = read_pointer(image, location) {
                        if plausible_relocation_function(image, target) {
                            add_seed(image, seeds, target, SeedKind::Relocation);
                        }
                    }
                }
            }
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
    // PE compatibility follows Vivisect's exact entry signatures. ELF remains
    // experimental and retains its established broad scan; the public
    // shellcode path explicitly selects the native backend above.
    if backend == RecoveryBackend::Native || image.format == ImageFormat::Elf {
        add_prologue_seeds(image, seeds);
        add_swept_call_seeds(image, seeds);
    } else {
        // Preserve the legacy raw-call sweep's density decision without
        // promoting its broad prologue candidates into compatibility-mode
        // functions. Previously exact sparse PEs depend on this fallback,
        // while enabling it for dense compiler output creates false loops.
        let mut legacy_density = SeedMap::new();
        add_prologue_seeds(image, &mut legacy_density);
        if legacy_density.len() <= 128 {
            add_swept_call_seeds(image, seeds);
        }
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
    noreturn: &BTreeSet<u64>,
) -> Result<BTreeSet<u64>, RecoveryError> {
    let mut pending = VecDeque::from([start]);
    let mut calls = BTreeSet::new();
    let mut discovered = 0usize;

    while let Some(path_start) = pending.pop_front() {
        let mut address = path_start;
        loop {
            // Pinned Vivisect 1.3.2 discovers opcode locations and direct code
            // references before its generic codeblocks analysis assigns those
            // locations to functions. A known function entry is not a direct
            // flow barrier. Once an instruction is present in this shared
            // graph, every later function view can traverse its recorded edges.
            if direct_flow.successors.contains_key(&address)
                || !is_executable(&analysis.image, address)
            {
                break;
            }
            if discovered >= MAX_INSNS_PER_FUNCTION {
                return Err(RecoveryError::Limit(format!(
                    "direct flow from {start:#x} exceeds {MAX_INSNS_PER_FUNCTION} instructions"
                )));
            }
            let insn = match analysis.image.decode_at(address) {
                Ok(insn) => insn,
                Err(error) => {
                    analysis.diagnostics.push(RecoveryDiagnostic {
                        address,
                        message: error.to_string(),
                    });
                    break;
                }
            };
            if insn.is_privileged_barrier() {
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
            let flow = insn.flow;
            discovered = discovered.saturating_add(1);
            analysis.instructions.entry(address).or_insert(insn.clone());
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
                Flow::Call => {
                    let target = insn.direct_target;
                    if let Some(target) = target {
                        push_xref(&mut analysis.code_xrefs, target, address);
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
                    if target.is_some_and(|target| target != next && noreturn.contains(&target)) {
                        analysis.noreturn_calls.insert(address);
                        direct_flow.successors.insert(address, Vec::new());
                        break;
                    }
                    direct_flow.successors.insert(
                        address,
                        vec![Edge {
                            target: next,
                            kind: EdgeKind::Fallthrough,
                        }],
                    );
                    address = next;
                }
                Flow::IndirectCall => {
                    if insn.memory_target.is_none_or(|target| {
                        !analysis.image.external_bindings.contains_key(&target)
                    }) {
                        analysis.diagnostics.push(RecoveryDiagnostic {
                            address,
                            message: "unresolved indirect call".to_string(),
                        });
                    }
                    // NOTE: `call [ExitProcess]` keeps its fallthrough, even
                    // though the IAT slot is in the no-return set. Vivisect's
                    // `BR_DEREF` no-return check (`envi/codeflow.py:218-220`)
                    // is unreachable for imports: `_cb_opcode`
                    // (`vivisect/base.py:820`) drops every branch whose target
                    // is a `LOC_IMPORT` -- "dont code flow through import
                    // calls" -- before codeflow ever inspects the branch list.
                    // Measured on `Practical Malware Analysis Lab 17-02.dll_`:
                    // all 35 of its `NoReturnCalls` sites are direct calls, and
                    // all 10 `call [no-return import]` sites keep their
                    // fallthrough. Imports reach the no-return set only through
                    // a thunk (`checkNoRetApi`), which is a *direct* call.
                    direct_flow.successors.insert(
                        address,
                        vec![Edge {
                            target: next,
                            kind: EdgeKind::Fallthrough,
                        }],
                    );
                    address = next;
                }
                Flow::ConditionalBranch => {
                    let mut edges = vec![Edge {
                        target: next,
                        kind: EdgeKind::Fallthrough,
                    }];
                    pending.push_back(next);
                    if let Some(target) = insn.direct_target {
                        edges.push(Edge {
                            target,
                            kind: EdgeKind::Branch,
                        });
                        pending.push_back(target);
                        push_xref(&mut analysis.code_xrefs, target, address);
                    }
                    direct_flow.successors.insert(address, edges);
                    break;
                }
                Flow::UnconditionalBranch => {
                    if let Some(target) = insn.direct_target {
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
                        pending.push_back(target);
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
                    let targets = jump_table_targets(&analysis.image, &insn);
                    if targets.is_empty() {
                        analysis.diagnostics.push(RecoveryDiagnostic {
                            address,
                            message: "unresolved indirect branch".to_string(),
                        });
                    } else {
                        let edges: Vec<_> = targets
                            .into_iter()
                            .map(|target| {
                                pending.push_back(target);
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

    Ok(calls)
}

fn build_function_view(
    analysis: &Analysis,
    direct_flow: &DirectFlowGraph,
    start: u64,
    isolate_start: bool,
) -> Result<Function, RecoveryError> {
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
                pending.push_back(edge.target);
            }
        }
    }

    let mut block_starts = BTreeSet::from([start]);
    block_starts.extend(
        analysis
            .code_xrefs
            .keys()
            .filter(|address| reachable.contains(address))
            .copied(),
    );
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
    let Some(base) = insn.memory_target else {
        return Vec::new();
    };
    let width = image.architecture.pointer_width();
    let mut targets = Vec::new();
    for index in 0..MAX_JUMP_TABLE_ENTRIES {
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
        if !is_executable(image, target) {
            break;
        }
        targets.push(target);
    }
    targets.sort_unstable();
    targets.dedup();
    targets
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

    /// A walk past `MAX_INSNS_PER_FUNCTION` abandons that walk and records
    /// why; it does not fail the image. Upstream Vivisect has no per-walk
    /// instruction budget at all, so this limit is a statement about
    /// capa-x's guard rail, and a guard rail that discards every result
    /// the run already produced is worse than the runaway it prevents. This
    /// is the mechanism behind KD-011: mapping `0cd2b334`'s resource-hosted
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
    fn raw_call_sweep_remains_in_compat_until_replacement() {
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
        assert!(compat
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
