//! Bounded static switch dispatch, without a workspace emulator.
//!
//! The x64 shape corresponds to Vivisect 1.3.2's
//! analysis/generic/switchcase.py:getSwitchBase (load, add base, jump),
//! including its optional byte selector table. Native recovery requires a
//! guard; compatibility also accepts proven image-relative MOV/ADD/JMP tables.
//! AArch64's BinExport2 reference supplies already-resolved CFG edges; its
//! native counterpart recognizes ADRP/ADD/LDRSW/ADD/BR with the same guard.
//! Unsupported sequences keep the existing unresolved-branch diagnostic.

use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use super::decoder::{self, Flow};
use super::image::{Architecture, DecodedInstruction, LoadedImage};
use super::Analysis;

#[cfg(test)]
#[path = "switch_tests.rs"]
mod tests;

// Local analysis budgets, not upstream constants. Exceeding a budget rejects
// the dispatch; compatibility may stop earlier at a reference table boundary.
const MAX_CASES: u64 = 256;
const MAX_DISPATCH_INSNS: usize = 10;

pub(super) fn targets(analysis: &Analysis, branch: &DecodedInstruction) -> Option<Vec<u64>> {
    targets_with_policy(analysis, branch, None, &mut Vec::new(), &mut Vec::new())
}

pub(super) fn targets_compat(
    analysis: &mut Analysis,
    branch: &DecodedInstruction,
    noreturn: &std::collections::BTreeSet<u64>,
    table_locations: &mut Vec<(u64, usize)>,
) -> Option<Vec<u64>> {
    let mut diagnostics = Vec::new();
    let mut locations = Vec::new();
    let targets = targets_with_policy(
        analysis,
        branch,
        Some(noreturn),
        &mut diagnostics,
        &mut locations,
    )
    .or_else(|| {
        compatibility_rva_targets(analysis, branch, noreturn, &mut diagnostics, &mut locations)
    });
    analysis.diagnostics.extend(diagnostics);
    if targets.is_some() {
        table_locations.extend(locations);
    }
    targets
}

/// generic/switchcase.py:getSwitchBase recognizes a MOV/ADD/JMP dispatch
/// without requiring a nearby bounds check. This fallback proves the image
/// base statically; unresolved register values retain the branch diagnostic.
fn compatibility_rva_targets(
    analysis: &Analysis,
    branch: &DecodedInstruction,
    noreturn: &std::collections::BTreeSet<u64>,
    diagnostics: &mut Vec<super::RecoveryDiagnostic>,
    table_locations: &mut Vec<(u64, usize)>,
) -> Option<Vec<u64>> {
    if analysis.image.architecture != Architecture::X64 {
        return None;
    }
    let register = reg_operand(branch.x86_instruction(), 0)?;
    let add = previous(analysis, branch.address)?;
    // getSwitchBase/findOp searches past unrelated instructions, including
    // an image-base LEA placed between the table load and the ADD.
    let mut load = previous(analysis, add.address)?;
    let mut remaining = MAX_DISPATCH_INSNS;
    while !reg_operand(load.x86_instruction(), 0)
        .is_some_and(|dest| dest.full_register() == register)
    {
        if remaining == 0 || load.flow != Flow::Next || has_entry(analysis, load.address) {
            return None;
        }
        remaining -= 1;
        load = previous(analysis, load.address)?;
    }
    let sum = add.x86_instruction();
    let mov = load.x86_instruction();
    let base_register = reg_operand(sum, 1)?;
    if branch.x86_instruction().mnemonic() != Mnemonic::Jmp
        || sum.mnemonic() != Mnemonic::Add
        || base_register == register
        || reg_operand(sum, 0) != Some(register)
        || mov.mnemonic() != Mnemonic::Mov
        || !reg_operand(mov, 0)
            .is_some_and(|dest| dest.size() == 4 && dest.full_register() == register)
        || !indexed_load(mov, mov.memory_base(), mov.memory_index(), 4, 4)
        || mov.memory_index() == Register::None
        || constant_before(analysis, add.address, base_register)? != analysis.image.image_base
        || constant_before(analysis, load.address, mov.memory_base())? != analysis.image.image_base
    {
        return None;
    }
    let base = analysis.image.image_base;
    let table = base.checked_add_signed(mov.memory_displacement64() as i64)?;
    let mut targets = Vec::new();
    for index in 0..=MAX_CASES {
        let slot = table.checked_add(index.checked_mul(4)?)?;
        if index != 0
            && (analysis.code_xrefs.contains_key(&slot) || analysis.data_xrefs.contains_key(&slot))
        {
            break;
        }
        let Some(raw) = read_u32(&analysis.image, slot) else {
            break;
        };
        // VivWorkspace.iterJumpTable rebases only values below the image base.
        let raw = u64::from(raw);
        let target = if raw < base {
            base.checked_add(raw)?
        } else {
            raw
        };
        if !analysis.image.is_executable_address(target) {
            break;
        }
        if index == MAX_CASES {
            diagnostics.push(super::RecoveryDiagnostic {
                address: branch.address,
                message: format!("RVA switch exceeds {MAX_CASES} entries"),
            });
            return None;
        }
        match super::emucode::evaluate_candidate(analysis, target, noreturn, &[]) {
            super::emucode::Verdict::NotCode => break,
            super::emucode::Verdict::Inconclusive { address, reason } => {
                diagnostics.push(super::RecoveryDiagnostic {
                    address,
                    message: format!(
                        "switch {:#x} arm {target:#x} candidate evaluation inconclusive: {reason}",
                        branch.address
                    ),
                });
                break;
            }
            super::emucode::Verdict::Code => {}
        }
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    table_locations.push((table, analysis.image.architecture.pointer_width()));
    Some(targets)
}

fn targets_with_policy(
    analysis: &Analysis,
    branch: &DecodedInstruction,
    noreturn: Option<&std::collections::BTreeSet<u64>>,
    diagnostics: &mut Vec<super::RecoveryDiagnostic>,
    table_locations: &mut Vec<(u64, usize)>,
) -> Option<Vec<u64>> {
    let sequence = guarded_sequence(analysis, branch)?;
    let (compare, rest) = sequence.split_first()?;
    let (guard, body) = rest.split_first()?;
    let mut targets = match analysis.image.architecture {
        Architecture::AArch64 => arm_targets(analysis, compare, guard, body)?,
        Architecture::X64 => {
            absolute_targets(analysis, compare, guard, body, noreturn, diagnostics).or_else(
                || {
                    x64_targets(
                        analysis,
                        compare,
                        guard,
                        body,
                        noreturn,
                        diagnostics,
                        table_locations,
                    )
                },
            )?
        }
        Architecture::X86 => {
            absolute_targets(analysis, compare, guard, body, noreturn, diagnostics)?
        }
    };
    // An arm must not re-enter the guarded computation with an unchecked
    // selector. AArch64 targets also have to be instruction-aligned.
    if targets.iter().any(|target| {
        (*target >= compare.next_address && *target <= branch.address)
            || !analysis.image.is_executable_address(*target)
            || (analysis.image.architecture == Architecture::AArch64 && target % 4 != 0)
            || match analysis.image.decode_at(*target) {
                Ok(insn) => {
                    analysis.image.architecture == Architecture::AArch64
                        && decoder::aarch64_opcode(&insn).is_none()
                }
                Err(_) => true,
            }
    }) {
        return None;
    }
    if noreturn.is_some() {
        // makeJumpTable and codeflow preserve the first occurrence of each
        // arm in the table. Address sorting changes discovery order.
        let mut seen = std::collections::BTreeSet::new();
        targets.retain(|target| seen.insert(*target));
    } else {
        targets.sort_unstable();
        targets.dedup();
    }
    Some(targets)
}

fn absolute_targets(
    analysis: &Analysis,
    compare: &DecodedInstruction,
    guard: &DecodedInstruction,
    body: &[&DecodedInstruction],
    noreturn: Option<&std::collections::BTreeSet<u64>>,
    diagnostics: &mut Vec<super::RecoveryDiagnostic>,
) -> Option<Vec<u64>> {
    let (branch, setup) = body.split_last()?;
    let op = branch.x86_instruction();
    let cmp = compare.x86_instruction();
    let width = analysis.image.architecture.pointer_width();
    let index = reg_operand(cmp, 0)?;
    if cmp.mnemonic() != Mnemonic::Cmp
        || op.mnemonic() != Mnemonic::Jmp
        || op.op0_kind() != OpKind::Memory
        || op.memory_base() != Register::None
        || op.memory_size().size() != width
        || matches!(op.memory_segment(), Register::FS | Register::GS)
        || op.memory_index().full_register() != index.full_register()
        || op.memory_index_scale() as usize != width
        || !matches!(index.size(), 4 | 8)
    {
        return None;
    }
    let count = case_count(
        immediate(cmp)?,
        match guard.x86_instruction().mnemonic() {
            Mnemonic::Ja => true,
            Mnemonic::Jae => false,
            _ => return None,
        },
    )?;
    // Unlike the legacy sequential pointer scan, this must stop at the
    // selector's bound even when another table follows immediately.
    // A 32-bit guard on a 64-bit index needs an explicit zero extension.
    // Compilers emit `mov ecx, ecx` for this absolute-table shape.
    let zero_extended = match setup {
        [] => false,
        [mov] => {
            let mov = mov.x86_instruction();
            if mov.mnemonic() != Mnemonic::Mov
                || reg_operand(mov, 0)? != index
                || reg_operand(mov, 1)? != index
            {
                return None;
            }
            index.size() == 4
        }
        _ => return None,
    };
    if op.memory_index().size() == 8 && index.size() == 4 && !zero_extended {
        return None;
    }
    let base = branch.memory_target?;
    let mut targets = Vec::new();
    for index in 0..count {
        let slot = base.checked_add(index * width as u64)?;
        if let Some(noreturn) = noreturn {
            // VivWorkspace.iterJumpTable stops at a referenced next slot,
            // or at the first arm rejected by isProbablyCode.
            if index != 0
                && (analysis.code_xrefs.contains_key(&slot)
                    || analysis.data_xrefs.contains_key(&slot))
            {
                break;
            }
            let target = super::read_pointer(&analysis.image, slot)?;
            let signature = analysis
                .seeds
                .get(&target)
                .is_some_and(|kinds| kinds.contains(&super::SeedKind::FunctionSignature));
            if !signature {
                match super::emucode::evaluate_candidate(analysis, target, noreturn, &[]) {
                    super::emucode::Verdict::NotCode => break,
                    super::emucode::Verdict::Inconclusive { address, reason } => {
                        diagnostics.push(super::RecoveryDiagnostic {
                            address,
                            message: format!("switch {:#x} arm {target:#x} candidate evaluation inconclusive: {reason}", branch.address),
                        });
                        break;
                    }
                    super::emucode::Verdict::Code => {}
                }
            }
            targets.push(target);
        } else {
            targets.push(super::read_pointer(&analysis.image, slot)?);
        }
    }
    Some(targets)
}

fn previous(analysis: &Analysis, address: u64) -> Option<&DecodedInstruction> {
    let (_, insn) = analysis.instructions.range(..address).next_back()?;
    (insn.next_address == address).then_some(insn)
}

/// Resolve a base carried between guarded dispatches. Every reaching
/// definition must be the same constant; calls and unknown writes stop the
/// proof. The bound is local, not an upstream emulator limit.
fn constant_before(analysis: &Analysis, address: u64, register: Register) -> Option<u64> {
    let mut pending = vec![address];
    let mut visited = std::collections::BTreeSet::new();
    let mut value = None;
    let mut info = InstructionInfoFactory::new();
    while let Some(address) = pending.pop() {
        if !visited.insert(address) {
            continue;
        }
        if visited.len() > 8192 {
            return None;
        }
        let mut predecessors = Vec::new();
        if let Some(prior) = previous(analysis, address) {
            if matches!(
                prior.flow,
                Flow::Next | Flow::Call | Flow::IndirectCall | Flow::ConditionalBranch
            ) && !analysis.noreturn_calls.contains(&prior.address)
            {
                predecessors.push(prior);
            }
        }
        for source in analysis.code_xrefs.get(&address).into_iter().flatten() {
            if let Some(prior) = analysis.instructions.get(source) {
                if !matches!(prior.flow, Flow::Call | Flow::IndirectCall) {
                    predecessors.push(prior);
                }
            }
        }
        if predecessors.is_empty() {
            return None;
        }
        for prior in predecessors {
            let op = prior.x86_instruction();
            if matches!(prior.flow, Flow::Call | Flow::IndirectCall)
                && matches!(
                    register,
                    Register::RAX
                        | Register::RCX
                        | Register::RDX
                        | Register::R8
                        | Register::R9
                        | Register::R10
                        | Register::R11
                )
            {
                return None;
            }
            let writes = info.info(op).used_registers().iter().any(|used| {
                used.register().full_register() == register
                    && matches!(
                        used.access(),
                        OpAccess::Write
                            | OpAccess::CondWrite
                            | OpAccess::ReadWrite
                            | OpAccess::ReadCondWrite
                    )
            });
            if writes {
                let found = if op.mnemonic() == Mnemonic::Lea
                    && reg_operand(op, 0) == Some(register)
                    && op.is_ip_rel_memory_operand()
                {
                    op.ip_rel_memory_address()
                } else {
                    return None;
                };
                if value.is_some_and(|value| value != found) {
                    return None;
                }
                value = Some(found);
            } else {
                pending.push(prior.address);
            }
        }
    }
    value
}

fn guarded_sequence<'a>(
    analysis: &'a Analysis,
    branch: &'a DecodedInstruction,
) -> Option<Vec<&'a DecodedInstruction>> {
    let mut reverse = vec![branch];
    let mut current = branch;
    for _ in 0..MAX_DISPATCH_INSNS {
        // Reject known entries that bypass the guard or redefine a value in
        // the middle of this straight-line sequence.
        if has_entry(analysis, current.address) {
            return None;
        }
        let prior = previous(analysis, current.address)?;
        reverse.push(prior);
        if prior.flow == Flow::ConditionalBranch {
            if has_entry(analysis, prior.address) {
                return None;
            }
            let default = prior.direct_target?;
            if default >= prior.next_address && default <= branch.address {
                return None;
            }
            let compare = previous(analysis, prior.address)?;
            if compare.flow != Flow::Next {
                return None;
            }
            reverse.push(compare);
            reverse.reverse();
            return Some(reverse);
        }
        if prior.flow != Flow::Next {
            return None;
        }
        current = prior;
    }
    None
}

fn has_entry(analysis: &Analysis, address: u64) -> bool {
    analysis.code_xrefs.contains_key(&address) || analysis.seeds.contains_key(&address)
}

fn read_u32(image: &LoadedImage, address: u64) -> Option<u32> {
    Some(u32::from_le_bytes(
        image.bytes_at(address, 4)?.try_into().ok()?,
    ))
}

fn case_count(limit: u64, inclusive: bool) -> Option<u64> {
    let count = limit.checked_add(u64::from(inclusive))?;
    (count > 0 && count <= MAX_CASES).then_some(count)
}

fn arm_word(insn: &DecodedInstruction) -> Option<u32> {
    decoder::aarch64_opcode(insn)?;
    Some(u32::from_le_bytes(insn.bytes.as_slice().try_into().ok()?))
}

fn arm_targets(
    analysis: &Analysis,
    compare: &DecodedInstruction,
    guard: &DecodedInstruction,
    body: &[&DecodedInstruction],
) -> Option<Vec<u64>> {
    let [page, base_add, load, target_add, branch] = body else {
        return None;
    };
    let cmp = arm_word(compare)?;
    let cond = arm_word(guard)?;
    // ARM DDI 0487: SUBS (immediate), Rd == ZR is CMP; B.cond
    // conditions HI and CS/HS select unsigned > and >= respectively.
    if cmp & 0x7f80_001f != 0x7100_001f || cond & 0xff00_0010 != 0x5400_0000 {
        return None;
    }
    let inclusive = match cond & 0xf {
        8 => true,
        2 => false,
        _ => return None,
    };
    let limit = u64::from((cmp >> 10) & 0xfff) << if cmp & (1 << 22) != 0 { 12 } else { 0 };
    let count = case_count(limit, inclusive)?;
    let index = (cmp >> 5) & 31;
    let adrp = arm_word(page)?;
    let add = arm_word(base_add)?;
    let ldr = arm_word(load)?;
    let sum = arm_word(target_add)?;
    let br = arm_word(branch)?;
    // ARM DDI 0487: ADRP, ADD (64-bit immediate), LDRSW (register
    // offset, scaled by 4), ADD (64-bit shifted register, unshifted), BR.
    if adrp & 0x9f00_0000 != 0x9000_0000
        || add & 0xff80_0000 != 0x9100_0000
        || ldr & 0xffe0_1c00 != 0xb8a0_1800
        || sum & 0xffe0_fc00 != 0x8b00_0000
        || br & 0xffff_fc1f != 0xd61f_0000
    {
        return None;
    }
    let base = adrp & 31;
    let loaded = ldr & 31;
    let result = sum & 31;
    let extension = (ldr >> 13) & 7;
    if base == 31
        || index == 31
        || loaded == 31
        || result == 31
        || base == index
        || loaded == base
        || add & 31 != base
        || (add >> 5) & 31 != base
        || (ldr >> 5) & 31 != base
        || (ldr >> 16) & 31 != index
        || (br >> 5) & 31 != result
        || !(((sum >> 5) & 31 == loaded && (sum >> 16) & 31 == base)
            || ((sum >> 5) & 31 == base && (sum >> 16) & 31 == loaded))
    {
        return None;
    }
    match extension {
        // UXTW/SXTW: the bounded selector fits in positive signed 32 bits.
        2 | 6 if cmp >> 31 == 0 => {}
        3 if cmp >> 31 != 0 => {}
        // A W-register comparison does not clear its X-register's high
        // bits. Require a preceding W ADD/SUB that does, before LSL Xindex.
        3 if !has_entry(analysis, compare.address)
            && arm_word(previous(analysis, compare.address)?)
                .is_some_and(|word| word & 0x9f80_0000 == 0x1100_0000 && word & 31 == index) => {}
        _ => return None,
    }
    let immediate = ((adrp >> 5) & 0x7ffff) << 2 | ((adrp >> 29) & 3);
    let signed = i64::from((immediate as i32) << 11 >> 11) << 12;
    let page_address = (page.address & !0xfff).checked_add_signed(signed)?;
    let offset = u64::from((add >> 10) & 0xfff) << if add & (1 << 22) != 0 { 12 } else { 0 };
    let table = page_address.checked_add(offset)?;
    (0..count)
        .map(|index| {
            let raw = read_u32(&analysis.image, table.checked_add(index.checked_mul(4)?)?)?;
            table.checked_add_signed(i64::from(raw as i32))
        })
        .collect()
}

fn reg_operand(insn: &Instruction, operand: u32) -> Option<Register> {
    (insn.op_kind(operand) == OpKind::Register).then(|| insn.op_register(operand))
}

fn immediate(insn: &Instruction) -> Option<u64> {
    match insn.op1_kind() {
        OpKind::Immediate8 => Some(u64::from(insn.immediate8())),
        OpKind::Immediate8to32 => u64::try_from(insn.immediate8to32()).ok(),
        OpKind::Immediate8to64 => u64::try_from(insn.immediate8to64()).ok(),
        OpKind::Immediate32 => Some(u64::from(insn.immediate32())),
        OpKind::Immediate32to64 => u64::try_from(insn.immediate32to64()).ok(),
        _ => None,
    }
}

fn x64_targets(
    analysis: &Analysis,
    compare: &DecodedInstruction,
    guard: &DecodedInstruction,
    body: &[&DecodedInstruction],
    noreturn: Option<&std::collections::BTreeSet<u64>>,
    diagnostics: &mut Vec<super::RecoveryDiagnostic>,
    table_locations: &mut Vec<(u64, usize)>,
) -> Option<Vec<u64>> {
    let cmp = compare.x86_instruction();
    if cmp.mnemonic() != Mnemonic::Cmp {
        return None;
    }
    let selector = reg_operand(cmp, 0)?;
    if !matches!(selector.size(), 4 | 8) {
        return None;
    }
    let inclusive = match guard.x86_instruction().mnemonic() {
        Mnemonic::Ja => true,
        Mnemonic::Jae => false,
        _ => return None,
    };
    let count = case_count(immediate(cmp)?, inclusive)?;
    let (first, remaining) = body.split_first()?;
    // MSVC can establish the image base immediately before CMP, or after
    // the guard. Both keep the base definition on the guarded path.
    let (base_reg, base, mut rest) = if first.x86_instruction().mnemonic() == Mnemonic::Lea {
        let lea = first.x86_instruction();
        if !lea.is_ip_rel_memory_operand() {
            return None;
        }
        (reg_operand(lea, 0)?, lea.ip_rel_memory_address(), remaining)
    } else {
        let load = body.iter().map(|insn| insn.x86_instruction()).find(|op| {
            matches!(
                op.mnemonic(),
                Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsxd
            ) && op.op1_kind() == OpKind::Memory
        })?;
        let register = load.memory_base();
        (
            register,
            constant_before(analysis, compare.address, register)?,
            body,
        )
    };
    if base_reg.size() != 8 || base_reg == selector.full_register() {
        return None;
    }
    let mut index = selector.full_register();
    let sign_extend = rest.first().is_some_and(|insn| {
        let op = insn.x86_instruction();
        if op.mnemonic() == Mnemonic::Cdqe && index == Register::RAX {
            return true;
        }
        if op.mnemonic() == Mnemonic::Movsxd
            && reg_operand(op, 1) == Some(selector)
            && reg_operand(op, 0).is_some_and(|dest| dest.size() == 8 && dest != base_reg)
        {
            index = op.op0_register();
            return true;
        }
        false
    });
    if sign_extend {
        rest = rest.get(1..)?;
    }
    // CMP r32 does not clear the upper half of the register. CDQE or an
    // immediately preceding 32-bit assignment must establish it.
    if noreturn.is_none() && selector.size() == 4 && !sign_extend {
        if has_entry(analysis, compare.address) {
            return None;
        }
        let prior = previous(analysis, compare.address)?.x86_instruction();
        let zero_extended = matches!(
            prior.mnemonic(),
            Mnemonic::Lea | Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Sub | Mnemonic::Add
        ) && reg_operand(prior, 0) == Some(selector);
        // A signed dword load before the unsigned guard also establishes
        // the full index. Negative values fail CMP r32 against this bounded
        // case count, leaving only nonnegative, correctly extended values.
        let sign_extended = prior.mnemonic() == Mnemonic::Movsxd
            && reg_operand(prior, 0) == Some(selector.full_register())
            && (reg_operand(prior, 1).is_some_and(|source| source.size() == 4)
                || prior.op1_kind() == OpKind::Memory && prior.memory_size().size() == 4);
        if !zero_extended && !sign_extended {
            return None;
        }
    }
    let mut indexes: Vec<u64> = (0..count).collect();
    if let Some(remap) = rest.first().map(|insn| insn.x86_instruction()) {
        if remap.mnemonic() == Mnemonic::Movzx {
            let dest = reg_operand(remap, 0)?;
            if !matches!(dest.size(), 4 | 8)
                || dest.full_register() == base_reg
                || !indexed_load(remap, base_reg, index, 1, 1)
            {
                return None;
            }
            let table = base.checked_add_signed(remap.memory_displacement64() as i64)?;
            indexes = indexes
                .into_iter()
                .map(|i| {
                    Some(u64::from(
                        *analysis.image.bytes_at(table.checked_add(i)?, 1)?.first()?,
                    ))
                })
                .collect::<Option<Vec<_>>>()?;
            index = dest.full_register();
            rest = rest.get(1..)?;
        }
    }
    let [load, add, branch] = rest else {
        return None;
    };
    let load = load.x86_instruction();
    let add = add.x86_instruction();
    let jump = branch.x86_instruction();
    let loaded = reg_operand(load, 0)?;
    let signed = load.mnemonic() == Mnemonic::Movsxd && loaded.size() == 8;
    // generic/switchcase.py:getSwitchBase requires a MOV of an unsigned
    // RVA and an addition of the image base. Table-relative MOVSXD shapes
    // belong to native recovery; the pinned reference does not resolve them.
    if noreturn.is_some() && (signed || base != analysis.image.image_base) {
        return None;
    }
    if !(signed || load.mnemonic() == Mnemonic::Mov && loaded.size() == 4)
        || loaded.full_register() == base_reg
        || !indexed_load(load, base_reg, index, 4, 4)
        || add.mnemonic() != Mnemonic::Add
        || reg_operand(add, 0)? != loaded.full_register()
        || reg_operand(add, 1)? != base_reg
        || jump.mnemonic() != Mnemonic::Jmp
        || reg_operand(jump, 0)? != loaded.full_register()
    {
        return None;
    }
    let table = base.checked_add_signed(load.memory_displacement64() as i64)?;
    // Vivisect 1.3.2 iterJumpTable tests consecutive entries using
    // isProbablyCode and stops at the first rejected arm. The selector
    // remap does not allow it to skip that entry. Keep the guard as a
    // resource bound and reproduce definite candidate rejections.
    if let Some(noreturn) = noreturn.filter(|_| base == analysis.image.image_base && !signed) {
        let limit = indexes.iter().copied().max()?.checked_add(1)?;
        for index in 0..limit {
            let slot = table.checked_add(index.checked_mul(4)?)?;
            let target = base.checked_add(u64::from(read_u32(&analysis.image, slot)?))?;
            match super::emucode::evaluate_candidate(analysis, target, noreturn, &[]) {
                super::emucode::Verdict::NotCode => {
                    indexes.retain(|value| *value < index);
                    break;
                }
                super::emucode::Verdict::Inconclusive { address, reason } => {
                    diagnostics.push(super::RecoveryDiagnostic {
                        address,
                        message: format!(
                            "switch {:#x} arm {target:#x} candidate evaluation inconclusive: {reason}",
                            branch.address
                        ),
                    });
                    indexes.retain(|value| *value < index);
                    break;
                }
                super::emucode::Verdict::Code => {}
            }
        }
    }
    // generic/switchcase.py:analyzeJmp makes a pointer at the RVA table
    // base before makeJumpTable. Its size is the workspace pointer width,
    // even though the relative entries themselves are four bytes wide.
    if noreturn.is_some() && !signed && base == analysis.image.image_base {
        table_locations.push((table, analysis.image.architecture.pointer_width()));
    }
    indexes
        .into_iter()
        .map(|index| {
            let raw = read_u32(&analysis.image, table.checked_add(index.checked_mul(4)?)?)?;
            if signed {
                base.checked_add_signed(i64::from(raw as i32))
            } else {
                base.checked_add(u64::from(raw))
            }
        })
        .collect()
}

fn indexed_load(
    insn: &Instruction,
    base: Register,
    index: Register,
    scale: u32,
    size: usize,
) -> bool {
    insn.op1_kind() == OpKind::Memory
        && insn.memory_base() == base
        && insn.memory_index() == index
        && insn.memory_index_scale() == scale
        && insn.memory_size().size() == size
        && insn.segment_prefix() == Register::None
}
