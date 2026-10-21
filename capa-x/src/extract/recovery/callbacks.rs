//! Bounded callback and concrete-callee discovery, following AnalysisMonitor.apicall.
//! Argument positions come from Vivisect 1.3.2's impapi/windows tables.

use std::collections::BTreeSet;

use iced_x86::{Mnemonic, OpKind, Register};

use super::decoder::{DecodedInstruction, Flow};
use super::emucode::State;
use super::image::{Architecture, ImageFormat, LoadedImage};
use super::{Analysis, RecoveryDiagnostic, SeedKind};

// Local resource bounds, independent of the upstream emulator's limits.
const MAX_STEPS: usize = 8192;
const MAX_PATHS: usize = 256;
const MAX_THUNKS: usize = 8;

fn callback_api(name: &str, architecture: Architecture) -> Option<(usize, &'static [usize], bool)> {
    let name = name.to_ascii_lowercase();
    // The pinned amd64 API dictionary has no msvcr71 callback definitions.
    if architecture == Architecture::X64 && name.starts_with("msvcr71.") {
        return None;
    }
    // (argument count, zero-based funcptr arguments, x86 callee cleanup).
    // Derived from vivisect/impapi/windows/{i386,amd64}.py and their imported
    // *_32.py / *_64.py dictionaries. Preserve even unusual upstream entries.
    Some(match name.as_str() {
        "advapi32.registertraceguidsa" => (8, &[0], true),
        "advapi32.registertraceguidsw" => (8, &[0], true),
        "advapi32.wmireceivenotificationsa" => (4, &[2], true),
        "advapi32.wmireceivenotificationsw" => (4, &[2], true),
        "gdi32.enumenhmetafile" => (5, &[2], true),
        "gdi32.enumfontfamiliesa" => (4, &[2], true),
        "gdi32.enumfontfamiliesexa" => (5, &[2], true),
        "gdi32.enumfontfamiliesexw" => (5, &[2], true),
        "gdi32.enumfontfamiliesw" => (4, &[2], true),
        "gdi32.enumfontsa" => (4, &[2], true),
        "gdi32.enumfontsw" => (4, &[2], true),
        "gdi32.enumicmprofilesa" => (3, &[1], true),
        "gdi32.enumicmprofilesw" => (3, &[1], true),
        "gdi32.enummetafile" => (4, &[2], true),
        "gdi32.enumobjects" => (4, &[2], true),
        "gdi32.linedda" => (6, &[4], true),
        "kernel32.createthread" => (6, &[2], true),
        "kernel32.enumcalendarinfoa" => (4, &[0], true),
        "kernel32.enumcalendarinfoexa" => (4, &[0], true),
        "kernel32.enumcalendarinfoexw" => (4, &[0], true),
        "kernel32.enumcalendarinfow" => (4, &[0], true),
        "kernel32.enumdateformatsa" => (3, &[0], true),
        "kernel32.enumdateformatsexa" => (3, &[0], true),
        "kernel32.enumdateformatsexw" => (3, &[0], true),
        "kernel32.enumdateformatsw" => (3, &[0], true),
        "kernel32.enumlanguagegrouplocalesa" => (4, &[0], true),
        "kernel32.enumlanguagegrouplocalesw" => (4, &[0], true),
        "kernel32.enumresourcelanguagesa" => (5, &[3], true),
        "kernel32.enumresourcelanguagesw" => (5, &[3], true),
        "kernel32.enumresourcenamesa" => (4, &[2], true),
        "kernel32.enumresourcenamesw" => (4, &[2], true),
        "kernel32.enumresourcetypesa" => (3, &[1], true),
        "kernel32.enumresourcetypesw" => (3, &[1], true),
        "kernel32.enumsystemcodepagesa" => (2, &[0], true),
        "kernel32.enumsystemcodepagesw" => (2, &[0], true),
        "kernel32.enumsystemgeoid" => (3, &[2], true),
        "kernel32.enumsystemlanguagegroupsa" => (3, &[0], true),
        "kernel32.enumsystemlanguagegroupsw" => (3, &[0], true),
        "kernel32.enumsystemlocalesa" => (2, &[0], true),
        "kernel32.enumsystemlocalesw" => (2, &[0], true),
        "kernel32.enumtimeformatsa" => (3, &[0], true),
        "kernel32.enumtimeformatsw" => (3, &[0], true),
        "kernel32.enumuilanguagesa" => (3, &[0], true),
        "kernel32.enumuilanguagesw" => (3, &[0], true),
        "msvcr100.bsearch" => (5, &[4], false),
        "msvcr110.bsearch" => (5, &[4], false),
        "msvcr120.bsearch" => (5, &[4], false),
        "msvcr71.__cxxcallunwinddtor" => (2, &[0], false),
        "msvcr71.__cxxcallunwindvecdtor" => (5, &[0], false),
        "msvcr71._lfind" => (5, &[4], false),
        "msvcr71._lsearch" => (5, &[4], false),
        "msvcr71.bsearch" => (5, &[4], false),
        "msvcr71.qsort" => (40, &[2], true),
        "msvcr80.bsearch" => (5, &[4], false),
        "msvcr90.bsearch" => (5, &[4], false),
        "msvcrt.__cxxcallunwinddtor" => (2, &[0], false),
        "msvcrt._lfind" => (5, &[4], false),
        "msvcrt._lsearch" => (5, &[4], false),
        "msvcrt.bsearch" => (5, &[4], false),
        "msvcrt.qsort" => (40, &[0, 3], true),
        "mswsock.migratewinsockconfiguration" => (3, &[1], true),
        "ntdll._lfind" => (5, &[4], false),
        "ntdll.bsearch" => (5, &[4], false),
        "ntdll.ldrenumerateloadedmodules" => (3, &[1], true),
        "ntdll.ldrverifyimagematcheschecksum" => (4, &[1], true),
        "ntdll.qsort" => (40, &[0, 3], true),
        "ntdll.rtlenumerategenerictablelikeadirectory" => (7, &[1], true),
        "ntdll.rtlenumprocessheaps" => (2, &[0], true),
        "ntdll.rtlfindrange" => (12, &[10], true),
        "ntdll.rtlisrangeavailable" => (10, &[8], true),
        "ntdll.rtlpapplylengthfunction" => (4, &[3], true),
        "user32.drawstatea" => (10, &[2], true),
        "user32.drawstatew" => (10, &[2], true),
        "user32.enumchildwindows" => (3, &[1], true),
        "user32.enumdesktopsa" => (3, &[1], true),
        "user32.enumdesktopsw" => (3, &[1], true),
        "user32.enumdesktopwindows" => (3, &[1], true),
        "user32.enumpropsa" => (2, &[1], true),
        "user32.enumpropsexa" => (3, &[1], true),
        "user32.enumpropsexw" => (3, &[1], true),
        "user32.enumpropsw" => (2, &[1], true),
        "user32.enumthreadwindows" => (3, &[1], true),
        "user32.enumwindows" => (2, &[0], true),
        "user32.enumwindowstationsa" => (2, &[0], true),
        "user32.enumwindowstationsw" => (2, &[0], true),
        "user32.graystringa" => (9, &[2], true),
        "user32.graystringw" => (9, &[2], true),
        "user32.registermessagepumphook" => (1, &[0], true),
        "wsock32.migratewinsockconfiguration" => (3, &[1], true),
        _ => return None,
    })
}

fn import_at(image: &LoadedImage, mut target: u64) -> Option<&str> {
    // Imports are often called through one or more direct jump thunks.
    for _ in 0..MAX_THUNKS {
        if let Some(name) = image.import_locations.get(&target) {
            return Some(name);
        }
        let insn = image.decode_at(target).ok()?;
        target = match insn.flow {
            Flow::UnconditionalBranch => insn.direct_target?,
            Flow::IndirectBranch if insn.x86_instruction().memory_index() == Register::None => {
                insn.memory_target?
            }
            _ => return None,
        };
    }
    None
}

fn call_import<'a>(
    image: &'a LoadedImage,
    state: &State,
    insn: &DecodedInstruction,
) -> Option<&'a str> {
    let op = insn.x86_instruction();
    let target = if op.op0_kind() == OpKind::Memory {
        state.address(op, image.architecture)?
    } else {
        state.operand(image, op, 0)?
    };
    import_at(image, target)
}

// WindowsMixin's dynamic-library hooks call execCallReturn directly,
// without checkCall's safe-memory fallback for an invalid return address.
pub(super) fn import_hook_arguments(
    image: &LoadedImage,
    state: &State,
    insn: &DecodedInstruction,
) -> Option<usize> {
    if image.format != ImageFormat::Pe {
        return None;
    }
    Some(
        match call_import(image, state, insn)?
            .to_ascii_lowercase()
            .as_str()
        {
            "kernel32.loadlibrarya"
            | "kernel32.loadlibraryw"
            | "kernel32.getmodulehandlea"
            | "kernel32.getmodulehandlew" => 1,
            "kernel32.getprocaddress" => 2,
            "kernel32.loadlibraryexa"
            | "kernel32.loadlibraryexw"
            | "kernel32.getmodulehandleexa"
            | "kernel32.getmodulehandleexw" => 3,
            _ => return None,
        },
    )
}

fn argument(image: &LoadedImage, state: &State, index: usize) -> Option<u64> {
    let width = image.architecture.pointer_width();
    if image.architecture == Architecture::X64 {
        if let Some(register) =
            [Register::RCX, Register::RDX, Register::R8, Register::R9].get(index)
        {
            return state.register(*register);
        }
    }
    // State is sampled before CALL pushes the return address. On Windows x64
    // the four register arguments are followed by the 32-byte home area.
    let offset = index.checked_mul(width)? as u64;
    let address = state.register(Register::RSP)?.checked_add(offset)?;
    state.read(image, address, width)
}

pub(super) fn enabled(image: &LoadedImage) -> bool {
    // analysis/__init__.py installs calling/emulation for both formats.
    matches!(image.format, ImageFormat::Pe | ImageFormat::Elf)
        && matches!(image.architecture, Architecture::X86 | Architecture::X64)
}

pub(super) type DiscoveryResults = (
    Vec<(u64, SeedKind)>,
    Vec<(DecodedInstruction, u64)>,
    Vec<DecodedInstruction>,
);

pub(super) fn is_register_thunk(analysis: &Analysis, target: u64) -> bool {
    let image = &analysis.image;
    if image.format != ImageFormat::Elf
        || image.architecture != Architecture::X86
        || !analysis.functions.contains_key(&target)
    {
        return false;
    }
    // vivisect/analysis/i386/thunk_reg.py recognizes these seven MOV/RET
    // signatures only when the first caller is immediately followed by ADD.
    if !matches!(
        image.bytes_at(target, 4),
        Some([
            0x8b,
            0x04 | 0x0c | 0x14 | 0x1c | 0x2c | 0x34 | 0x3c,
            0x24,
            0xc3
        ])
    ) {
        return false;
    }
    analysis
        .code_xrefs
        .get(&target)
        .and_then(|sources| sources.first())
        .and_then(|source| image.decode_at_compat(*source).ok())
        .and_then(|call| image.decode_at_compat(call.next_address).ok())
        .is_some_and(|next| next.x86_instruction().mnemonic() == Mnemonic::Add)
}

pub(super) fn discover(
    analysis: &mut Analysis,
    start: u64,
    noreturn: &BTreeSet<u64>,
    pointers: &mut super::pointers::Discovery,
) -> DiscoveryResults {
    let image = &analysis.image;
    let mut targets = Vec::<(u64, SeedKind)>::new();
    let mut pending = vec![(start, State::entry())];
    let mut visited = BTreeSet::new();
    let mut observed_pointers = Vec::new();
    let mut unresolved_switches = Vec::new();
    while let Some((mut address, mut state)) = pending.pop() {
        loop {
            if !visited.insert(address) {
                break;
            }
            if visited.len() > MAX_STEPS || pending.len() > MAX_PATHS {
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address,
                    message: format!("callback trace at {start:#x} exceeded its budget"),
                });
                return (targets, observed_pointers, unresolved_switches);
            }
            if image.section_containing(address).is_none() || image.is_uninitialized(address) {
                break;
            }
            // The calling-analysis emulator can follow a computed jump into
            // bytes that static codeflow has not decoded yet. It discovers
            // calls there without assigning that loose code to the function.
            let decoded;
            let insn = if let Some(insn) = analysis.instructions.get(&address) {
                insn
            } else {
                decoded = match image.decode_at_compat(address) {
                    Ok(insn) => insn,
                    Err(error) => {
                        analysis.diagnostics.push(RecoveryDiagnostic {
                            address,
                            message: format!("calling trace at {start:#x}: {error}"),
                        });
                        break;
                    }
                };
                &decoded
            };
            // i386/calling.py:AnalysisMonitor.prehook rejects the decoder's
            // all-zero bad opcode before executing it or following more calls.
            if insn.bytes.as_slice() == [0, 0] {
                break;
            }
            let op = insn.x86_instruction();
            if op.memory_index() == Register::None
                && !matches!(insn.flow, Flow::IndirectCall | Flow::IndirectBranch)
                && (op.memory_size().size() == image.architecture.pointer_width()
                    || (op.mnemonic() == Mnemonic::Lea && image.architecture == Architecture::X86))
            {
                if let Some(target) = insn
                    .memory_target
                    .and_then(|slot| super::read_pointer(image, slot))
                {
                    observed_pointers.push((insn.clone(), target));
                }
            }
            match insn.flow {
                Flow::Call | Flow::IndirectCall => {
                    // checkCall enters registered PIC thunks. runFunction
                    // stops at their RET rather than resuming this caller.
                    if state
                        .operand(image, op, 0)
                        .is_some_and(|target| is_register_thunk(analysis, target))
                    {
                        break;
                    }
                    // addAnalysisResults restores the reference for calls
                    // actually reached by the emulator. _cb_noflow removed
                    // the original reference when replacing the location.
                    if let Some(target) = insn.direct_target {
                        let sources = analysis.code_xrefs.entry(target).or_default();
                        if !sources.contains(&address) {
                            sources.push(address);
                        }
                    }
                    if image.architecture == Architecture::X86
                        && insn
                            .direct_target
                            .is_some_and(|target| super::msvcfunc::is_seh3_prolog(image, target))
                    {
                        if let Some(table) = argument(image, &state, 0)
                            .filter(|address| image.section_containing(*address).is_some())
                        {
                            if let Some(diagnostic) = pointers.seh3_scope_table(analysis, table) {
                                analysis.diagnostics.push(diagnostic);
                            }
                        }
                    }
                    let imported = call_import(image, &state, insn);
                    // impemu/monitor.py:AnalysisMonitor.apicall creates
                    // concrete callees found while emulating a function.
                    // Known imports use loader identities, never raw IAT
                    // contents, which may point back into the input image.
                    if let Some(target) = state.operand(image, op, 0).filter(|target| {
                        imported.is_none()
                            && *target != start
                            && *target != insn.next_address
                            && image.is_executable_address(*target)
                            && !analysis.function_order.contains_key(target)
                    }) {
                        if !targets.iter().any(|(address, _)| *address == target) {
                            targets.push((target, SeedKind::CallTarget));
                        }
                    }
                    let api = imported.and_then(|name| callback_api(name, image.architecture));
                    if let Some((_, indexes, _)) = api {
                        for &index in indexes {
                            // apicall uses explicit type evidence rather than
                            // isProbablyCode. A section marked as dead data
                            // can still contain an executable callback.
                            if let Some(target) = argument(image, &state, index).filter(|target| {
                                image.is_executable_address(*target)
                                    && !super::pointers::covered(analysis, *target)
                            }) {
                                if let Some((_, kind)) =
                                    targets.iter_mut().find(|(address, _)| *address == target)
                                {
                                    *kind = SeedKind::ApiCallback;
                                } else {
                                    targets.push((target, SeedKind::ApiCallback));
                                }
                            }
                        }
                    }
                    // WorkspaceEmulator.runFunction permits the first opcode
                    // even when it is a no-return call. The calling monitor
                    // can discover concrete callees in the loose bytes after
                    // that call without expanding the function's code blocks.
                    if address != start
                        && (noreturn.contains(&address)
                            || analysis.noreturn_calls.contains(&address))
                    {
                        break;
                    }
                    if let Some(count) = import_hook_arguments(image, &state, insn) {
                        let Some(next) = state.hooked_call_return(image, insn.next_address, count)
                        else {
                            break;
                        };
                        address = next;
                        continue;
                    }
                    if let Some((count, _, callee_clean)) = api {
                        if image.architecture == Architecture::X86 && callee_clean {
                            let sp = state
                                .register(Register::ESP)
                                .and_then(|sp| sp.checked_add((count * 4) as u64));
                            state.set_register(Register::ESP, sp);
                        }
                        state.clobber_call();
                    } else {
                        // checkCall skips the callee and replaces only the
                        // return register. Its private frame and other values
                        // remain available for subsequent computed calls.
                        state.clobber_call();
                    }
                    address = insn.next_address;
                }
                Flow::ConditionalBranch => {
                    pending.push((insn.next_address, state.clone()));
                    let Some(target) = insn.direct_target else {
                        break;
                    };
                    address = target;
                }
                Flow::UnconditionalBranch | Flow::IndirectBranch => {
                    // i386Emulator.readMemValue has no six/ten-byte case.
                    // i_jmp returns None for these far pointers, which makes
                    // executeOpcode advance to the next instruction.
                    if op.op0_kind() == OpKind::Memory && matches!(op.memory_size().size(), 6 | 10)
                    {
                        address = insn.next_address;
                        continue;
                    }
                    // checkBranches follows already resolved indirect edges,
                    // independently of the selector's concrete value. Table
                    // arms must belong to a defined code block at this point.
                    if insn.flow == Flow::IndirectBranch {
                        let table = op.op0_kind() == OpKind::Memory && op.memory_index_scale() == 4;
                        let mut found = false;
                        for (&target, sources) in &analysis.code_xrefs {
                            if !sources.contains(&address) {
                                continue;
                            }
                            if table
                                && !analysis.functions.values().any(|function| {
                                    function.blocks.iter().any(|block| {
                                        block.addr <= target
                                            && block
                                                .insns
                                                .last()
                                                .is_some_and(|last| target < last.next_address)
                                    })
                                })
                            {
                                continue;
                            }
                            pending.push((target, state.clone()));
                            found = true;
                        }
                        if found {
                            break;
                        }
                        // i386SibOper.getBranches(emu) scans unresolved
                        // scale-four tables independently of their selector.
                        if table
                            && !analysis
                                .code_xrefs
                                .values()
                                .any(|sources| sources.contains(&address))
                        {
                            if let Some(base) = state.register(op.memory_base()) {
                                let base = base.wrapping_add(op.memory_displacement64());
                                let width = op.memory_size().size();
                                let mut branches = Vec::new();
                                for index in 0..=MAX_PATHS {
                                    let Some(slot) = base.checked_add((index * width) as u64)
                                    else {
                                        break;
                                    };
                                    let Some(target) = state.read(image, slot, width) else {
                                        break;
                                    };
                                    if image.section_containing(target).is_none() {
                                        break;
                                    }
                                    if index == MAX_PATHS {
                                        analysis.diagnostics.push(RecoveryDiagnostic {
                                            address,
                                            message: format!(
                                                "callback table at {start:#x} exceeded its budget"
                                            ),
                                        });
                                        return (targets, observed_pointers, unresolved_switches);
                                    }
                                    branches.push(target);
                                }
                                if branches.len() > 1 {
                                    let mut seen = BTreeSet::new();
                                    for target in branches {
                                        if seen.insert(target) {
                                            pending.push((target, state.clone()));
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                        if image.architecture == Architecture::X64
                            && op.op0_kind() == OpKind::Register
                        {
                            unresolved_switches.push(insn.clone());
                        }
                    }
                    let Some(target) = state.operand(image, op, 0) else {
                        break;
                    };
                    address = target;
                }
                Flow::Next => {
                    let import_slot = if op.mnemonic() == Mnemonic::Mov
                        && op.op0_kind() == OpKind::Register
                        && op.op1_kind() == OpKind::Memory
                        && op.op0_register().size() == image.architecture.pointer_width()
                        && op.memory_size().size() == image.architecture.pointer_width()
                    {
                        state
                            .address(op, image.architecture)
                            .filter(|slot| image.import_locations.contains_key(slot))
                    } else {
                        None
                    };
                    if let Err(reason) = state.step(image, op) {
                        analysis.diagnostics.push(RecoveryDiagnostic {
                            address,
                            message: format!(
                                "callback trace at {start:#x}: {reason}: {:?}",
                                op.mnemonic()
                            ),
                        });
                        break;
                    }
                    // The loader supplies import identity separately from the
                    // on-disk IAT value. Preserve it through register calls.
                    if let Some(slot) = import_slot {
                        state.set_register(op.op0_register(), Some(slot));
                    }
                    if address != start && noreturn.contains(&address) {
                        break;
                    }
                    address = insn.next_address;
                }
                _ => break,
            }
        }
    }
    (targets, observed_pointers, unresolved_switches)
}
