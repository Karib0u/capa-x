//! Candidate sources for `generic.pointers`, `pointertables`, and `emucode`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::{Mnemonic, OpKind, Register};

use super::emucode::{self, Verdict};
use super::image::{Architecture, ImageFormat};
use super::{Analysis, RecoveryDiagnostic, SeedKind};

// Local bounds for scanning hostile input, independent of upstream.
const MAX_SCAN_BYTES: usize = 32 * 1024 * 1024;
const MAX_CANDIDATES: usize = 32768;
// vivisect.defconfig: pointertables requires more than table_min_len entries.
const POINTER_TABLE_MIN_LEN: usize = 4;

pub(super) fn covered(analysis: &Analysis, address: u64) -> bool {
    analysis
        .instructions
        .range(..=address)
        .next_back()
        .is_some_and(|(_, insn)| address < insn.next_address)
}

pub(super) struct Discovery {
    candidates: BTreeSet<(SeedKind, u64)>,
    emulated_ready: BTreeSet<u64>,
    pointer_tables: VecDeque<(u64, u64)>,
    late_pointers: VecDeque<(u64, u64)>,
    tried: BTreeSet<(SeedKind, u64)>,
    examined_instructions: BTreeSet<u64>,
    examined_functions: BTreeSet<u64>,
    scanned: bool,
    emucode_active: bool,
    data_locations: Vec<(u64, u64)>,
    pointer_locations: BTreeMap<u64, u64>,
    code_barriers: Vec<(u64, u64)>,
    candidate_limit_hit: bool,
    relocation_index: usize,
}

impl Discovery {
    pub(super) fn new(analysis: &mut Analysis, enabled: bool) -> Self {
        let mut candidates = BTreeSet::new();
        if enabled {
            let have_pe_slots = !analysis.image.relocation_locations.is_empty();
            analysis.seeds.retain(|address, kinds| {
                if kinds.remove(&SeedKind::Relocation) {
                    // PE slots are reconsidered after entry-point code flow.
                    // A relocation inside an instruction is not a pointer
                    // location; its operand contributes a REF_PTR instead.
                    if !have_pe_slots {
                        candidates.insert((SeedKind::PointerTarget, *address));
                    }
                }
                if kinds.remove(&SeedKind::Emulated) {
                    candidates.insert((SeedKind::Emulated, *address));
                }
                !kinds.is_empty()
            });
        }
        Self {
            candidates,
            emulated_ready: BTreeSet::new(),
            pointer_tables: VecDeque::new(),
            late_pointers: VecDeque::new(),
            tried: BTreeSet::new(),
            examined_instructions: BTreeSet::new(),
            examined_functions: BTreeSet::new(),
            scanned: !enabled,
            emucode_active: enabled,
            data_locations: Vec::new(),
            pointer_locations: BTreeMap::new(),
            code_barriers: Vec::new(),
            candidate_limit_hit: false,
            relocation_index: 0,
        }
    }

    pub(super) fn finish_emucode(&mut self) {
        // PE runs emucode before importcalls and funcentries. New REF_PTR
        // operands discovered by those later passes are not another emucode
        // wave. Dereferenced data pointers still go through followPointer.
        self.emucode_active = false;
        self.candidates
            .retain(|(kind, _)| *kind != SeedKind::Emulated);
    }

    fn add(&mut self, analysis: &Analysis, target: u64, kind: SeedKind) {
        if (kind != SeedKind::Emulated || self.emucode_active)
            && analysis.image.is_executable_address(target)
            && (kind != SeedKind::Emulated || !analysis.image.is_dead_data(target))
            && !covered(analysis, target)
            && !self.tried.contains(&(kind, target))
        {
            if self.candidates.len() >= MAX_CANDIDATES {
                self.candidate_limit_hit = true;
            } else {
                self.candidates.insert((kind, target));
            }
        }
    }

    pub(super) fn code_barriers(&self) -> &[(u64, u64)] {
        &self.code_barriers
    }

    pub(super) fn is_pointer_tail(&self, analysis: &Analysis, address: u64) -> bool {
        // locmap retains the uncovered suffix when an opcode overwrites the
        // beginning of a pointer. _cb_opcode stops at that suffix. During
        // codeblocks analysis, delLocation(pointer_start) removes the
        // overlapping opcode instead of freeing the suffix for more code.
        self.pointer_locations
            .range(..address)
            .next_back()
            .is_some_and(|(&start, &end)| {
                address < end
                    && analysis
                        .instructions
                        .range(..=start)
                        .next_back()
                        .is_some_and(|(&opcode, insn)| opcode < start && start < insn.next_address)
                    && !covered(analysis, address)
            })
    }

    pub(super) fn mark_data(&mut self, start: u64, size: usize) {
        insert_location(&mut self.data_locations, start, size);
        if let Some(end) = start.checked_add(size as u64) {
            self.pointer_locations.insert(start, end);
        }
    }

    fn mark_noncode(&mut self, start: u64, size: usize) {
        self.mark_data(start, size);
        insert_location(&mut self.code_barriers, start, size);
    }

    #[allow(clippy::chunks_exact_to_as_chunks)] // Keep the Rust 1.87 MSRV.
    pub(super) fn seh3_scope_table(
        &mut self,
        analysis: &Analysis,
        address: u64,
    ) -> Option<RecoveryDiagnostic> {
        if covered(analysis, address) || emucode::in_data(&self.data_locations, address) {
            return None;
        }
        // vstruct.defs.win32.SEH3_SCOPETABLE contains a four-byte level,
        // followed by FilterFunction and HandlerFunction pointers.
        let Some(bytes) = analysis
            .image
            .bytes_at(address, 12)
            .filter(|bytes| bytes.len() == 12)
        else {
            return Some(RecoveryDiagnostic {
                address,
                message: "SEH3 scope table is not fully mapped (requires 12 bytes)".into(),
            });
        };
        self.mark_noncode(address, 12);
        for field in bytes.chunks_exact(4).skip(1) {
            if let Ok(raw) = <[u8; 4]>::try_from(field) {
                // makeStructure adds REF_PTR references. generic.emucode
                // evaluates these targets later, without a signature bypass.
                self.add(
                    analysis,
                    u64::from(u32::from_le_bytes(raw)),
                    SeedKind::Emulated,
                );
            }
        }
        None
    }

    fn collect(&mut self, analysis: &mut Analysis) {
        if !self.scanned && analysis.image.format == ImageFormat::Elf {
            self.scanned = true;
            // `VivWorkspace.findPointers`: unaligned pointers are allowed on
            // x86, but their source must still be undefined. `pointertables`
            // visits the same sources, so a single scan covers both passes.
            let mut remaining = MAX_SCAN_BYTES;
            let mut found = Vec::new();
            for section in &analysis.image.sections {
                if analysis.image.is_uninitialized(section.address) {
                    continue;
                }
                let bytes = analysis
                    .image
                    .bytes_at(section.address, remaining)
                    .unwrap_or_default();
                let width = analysis.image.architecture.pointer_width();
                let mut offset = 0usize;
                while let Some(raw) = bytes.get(offset..offset.saturating_add(width)) {
                    let Some(source) = section.address.checked_add(offset as u64) else {
                        break;
                    };
                    if covered(analysis, source)
                        || analysis.image.import_locations.contains_key(&source)
                        || emucode::in_data(&self.data_locations, source)
                    {
                        offset += 1;
                        continue;
                    }
                    let target = raw.iter().enumerate().fold(0u64, |value, (index, byte)| {
                        value | (u64::from(*byte) << (index * 8))
                    });
                    if analysis.image.section_containing(target).is_some() {
                        if found.len() < MAX_CANDIDATES {
                            found.push((source, target));
                        } else {
                            self.candidate_limit_hit = true;
                        }
                    }
                    // Upstream skips a whole pointer when its value is mapped.
                    offset += if analysis.image.section_containing(target).is_some() {
                        width
                    } else {
                        1
                    };
                }
                remaining = remaining.saturating_sub(bytes.len());
                if remaining == 0 {
                    analysis.diagnostics.push(RecoveryDiagnostic {
                        address: section.address,
                        message: format!("pointer scan stopped at {MAX_SCAN_BYTES} bytes"),
                    });
                    break;
                }
            }
            // pointertables follows contiguous arrays before emucode.
            // generic.pointers follows the remaining sources afterward.
            // Both visit source addresses in order and type one slot at a
            // time, since following it can expose code over later slots.
            let width = analysis.image.architecture.pointer_width() as u64;
            let mut first = 0;
            while first < found.len() {
                let mut end = first + 1;
                while found.get(end).zip(found.get(end - 1)).is_some_and(
                    |((source, _), (previous, _))| previous.checked_add(width) == Some(*source),
                ) {
                    end += 1;
                }
                if let Some(run) = found.get(first..end) {
                    if run.len() > POINTER_TABLE_MIN_LEN {
                        self.pointer_tables.extend(run.iter().copied());
                    } else {
                        self.late_pointers.extend(run.iter().copied());
                    }
                }
                first = end;
            }
        }
        // PE's amodlist has `generic.relocations` and `ms.vftables`, not
        // `generic.pointers/pointertables`. vftables only inspects pointers to
        // existing functions; it never promotes arbitrary raw values to code.
        self.scanned = true;
        // `base._cb_opcode/guessDataPointer` also contributes immediate and
        // dereferenced operand targets. Repeat after new functions are walked.
        for instruction in analysis.instructions.values() {
            self.observe_instruction(analysis, instruction, false);
        }
        if self.candidate_limit_hit {
            analysis.diagnostics.push(RecoveryDiagnostic {
                address: analysis.image.image_base,
                message: format!("pointer discovery stopped adding candidates at {MAX_CANDIDATES}"),
            });
            self.candidate_limit_hit = false;
        }
    }

    pub(super) fn observe_instruction(
        &mut self,
        analysis: &Analysis,
        instruction: &super::image::DecodedInstruction,
        during_flow: bool,
    ) {
        if during_flow && instruction.x86_instruction().mnemonic() == Mnemonic::Lea {
            return;
        }
        if !self.examined_instructions.insert(instruction.address) {
            return;
        }
        let op = instruction.x86_instruction();
        for index in 0..op.op_count() {
            let target = match op.op_kind(index) {
                OpKind::Immediate32 => Some(u64::from(op.immediate32())),
                OpKind::Immediate64 => Some(op.immediate64()),
                OpKind::Immediate32to64 => Some(op.immediate32to64() as u64),
                _ => None,
            };
            if let Some(target) = target {
                self.add(analysis, target, SeedKind::Emulated);
            }
        }
        if let Some(target) = instruction.memory_target {
            // A SIB operand needs an index value. envi's getOperAddr
            // returns None without an emulator, so its displacement
            // alone is neither a pointer nor a defined data location.
            if op.memory_index() != Register::None {
                return;
            }
            if op.mnemonic() == Mnemonic::Lea {
                // `i386ImmMemOper.getOperValue` returns None without an
                // emulator, even for an absolute LEA. Amd64RipRelOper
                // supplies the static address and does create REF_PTR.
                if op.is_ip_rel_memory_operand() {
                    self.add(analysis, target, SeedKind::Emulated);
                }
                // i386/calling.py:AnalysisMonitor.prehook explicitly
                // records LEA operands despite isDeref being false.
                // addAnalysisResults then calls guessDataPointer on the
                // source slot. The amd64 monitor has no such LEA hook.
                if analysis.image.architecture != Architecture::X86 {
                    return;
                }
            }
            if !covered(analysis, target)
                && !emucode::in_data(&self.data_locations, target)
                && !analysis.image.import_locations.contains_key(&target)
            {
                let size = if op.mnemonic() == Mnemonic::Lea {
                    op.op0_register().size()
                } else {
                    op.memory_size().size()
                };
                if size == 0 || analysis.image.bytes_at(target, size).is_none() {
                    return;
                }
                if matches!(
                    instruction.flow,
                    super::decoder::Flow::IndirectCall | super::decoder::Flow::IndirectBranch
                ) {
                    // makeOpcode creates a pointer for BR_DEREF, without
                    // following it or interpreting its bytes as a number.
                    self.mark_data(target, analysis.image.architecture.pointer_width());
                    return;
                }
                if let Some(size) = string_size(analysis, target) {
                    self.mark_noncode(target, size);
                    return;
                }
                let pointer = (size == analysis.image.architecture.pointer_width())
                    .then(|| super::read_pointer(&analysis.image, target))
                    .flatten()
                    .filter(|value| analysis.image.section_containing(*value).is_some());
                if let Some(value) = pointer {
                    self.mark_data(target, size);
                    self.add(analysis, value, SeedKind::PointerTarget);
                } else {
                    // guessDataPointer creates LOC_NUMBER for a scalar.
                    // Code flow cannot reclassify that location as code.
                    self.mark_noncode(target, size);
                }
            }
        }
    }

    pub(super) fn next(
        &mut self,
        analysis: &mut Analysis,
        noreturn: &BTreeSet<u64>,
    ) -> Option<u64> {
        if analysis.image.architecture == Architecture::AArch64 {
            return None;
        }
        if let Some(address) = self.next_emulated(analysis) {
            return Some(address);
        }
        if analysis.image.format == ImageFormat::Pe {
            // ms/hotpatch.py:analyzeFunction marks a run of at least five
            // identical NOP or INT3 bytes immediately before a new function.
            // It runs before generic.emucode evaluates remaining candidates.
            for &function in analysis.function_order.keys() {
                if !self.examined_functions.insert(function) {
                    continue;
                }
                let Some(section) = analysis.image.section_containing(function) else {
                    continue;
                };
                let Some(size) = function
                    .checked_sub(section.address)
                    .and_then(|size| usize::try_from(size).ok())
                else {
                    continue;
                };
                let Some(bytes) = analysis.image.bytes_at(section.address, size) else {
                    continue;
                };
                let Some(&padding @ (0x90 | 0xcc)) = bytes.last() else {
                    continue;
                };
                let count = bytes
                    .iter()
                    .rev()
                    .take_while(|&&byte| byte == padding)
                    .count();
                let start = function.saturating_sub(count as u64);
                if count >= 5 && !covered(analysis, start) {
                    self.mark_noncode(start, count);
                }
            }
        }
        // Drain this candidate batch before rescanning operands. Walking one
        // new function per call must not rescan the whole instruction map.
        if self.relocation_index >= analysis.image.relocation_locations.len()
            && (!self.scanned || self.candidates.is_empty())
        {
            self.collect(analysis);
        }
        if self.tried.len() >= MAX_CANDIDATES {
            if !self.candidates.is_empty() {
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address: analysis.image.image_base,
                    message: format!("pointer evaluation stopped at {MAX_CANDIDATES} candidates"),
                });
                self.candidates.clear();
            }
            return None;
        }
        loop {
            // generic.relocations follows each pointer before typing the next
            // slot. A later relocation can lie inside the code just discovered.
            let candidate = if let Some(&source) = analysis
                .image
                .relocation_locations
                .get(self.relocation_index)
            {
                self.relocation_index += 1;
                if covered(analysis, source) {
                    continue;
                }
                self.mark_data(source, analysis.image.architecture.pointer_width());
                super::read_pointer(&analysis.image, source)
                    .map(|target| (target, SeedKind::PointerTarget))
            } else {
                // Pointer analysis precedes the generic.emucode wave.
                // A lower-addressed immediate candidate must not absorb a
                // function that the earlier pointer pass would create.
                let source = if self
                    .candidates
                    .first()
                    .is_some_and(|(kind, _)| *kind == SeedKind::PointerTarget)
                {
                    None
                } else {
                    self.pointer_tables.pop_front().or_else(|| {
                        if self.emucode_active {
                            None
                        } else {
                            self.late_pointers.pop_front()
                        }
                    })
                };
                if let Some((source, target)) = source {
                    if covered(analysis, source) || emucode::in_data(&self.data_locations, source) {
                        continue;
                    }
                    self.mark_data(source, analysis.image.architecture.pointer_width());
                    Some((target, SeedKind::PointerTarget))
                } else {
                    self.candidates
                        .pop_first()
                        .map(|(kind, address)| (address, kind))
                }
            };
            let Some((address, kind)) = candidate else {
                if self.relocation_index < analysis.image.relocation_locations.len() {
                    continue;
                }
                break;
            };
            if kind == SeedKind::PointerTarget {
                // makePointer adds REF_PTR even when followPointer rejects
                // code. generic.emucode has its own tried set and revisits
                // that reference after the pointer pass finishes.
                self.add(analysis, address, SeedKind::Emulated);
            }

            if self.tried.len() >= MAX_CANDIDATES {
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address,
                    message: format!("pointer evaluation stopped at {MAX_CANDIDATES} candidates"),
                });
                self.candidates.clear();
                return None;
            }
            if !analysis.image.is_executable_address(address)
                || !self.tried.insert((kind, address))
                || covered(analysis, address)
                || emucode::in_data(&self.data_locations, address)
                || emucode::in_import(&analysis.image, address)
                || (kind == SeedKind::Emulated && analysis.image.is_dead_data(address))
            {
                continue;
            }
            if kind == SeedKind::PointerTarget {
                if let Some(size) = string_size(analysis, address) {
                    // analyzePointer/followPointer creates a string location.
                    // Later traces must reject branches into these bytes.
                    self.mark_noncode(address, size);
                    continue;
                }
            }
            // `isProbablyCode` accepts a registered entry signature before
            // running the watcher. The signature scanner already populated
            // this map; emucode's named/REF_PTR wave has no such shortcut.
            let signature = kind == SeedKind::PointerTarget
                && analysis
                    .seeds
                    .get(&address)
                    .is_some_and(|kinds| kinds.contains(&SeedKind::FunctionSignature));
            let verdict = if signature {
                Verdict::Code
            } else {
                emucode::evaluate_candidate(analysis, address, noreturn, &self.data_locations)
            };
            match verdict {
                Verdict::Code => {
                    if kind == SeedKind::Emulated {
                        // generic.emucode evaluates the whole current wave
                        // before creating any function. A newly accepted
                        // function must not alter another candidate's verdict.
                        self.emulated_ready.insert(address);
                        continue;
                    }
                    analysis.seeds.entry(address).or_default().insert(kind);
                    return Some(address);
                }
                Verdict::Inconclusive {
                    address: stopped,
                    reason,
                } => {
                    analysis.diagnostics.push(RecoveryDiagnostic {
                        address,
                        message: format!("candidate evaluation stopped at {stopped:#x}: {reason}"),
                    });
                }
                Verdict::NotCode => {
                    if kind == SeedKind::Emulated {
                        // generic.emucode types rejected string candidates
                        // before creating the accepted functions in this wave.
                        if let Some(size) = string_size(analysis, address) {
                            self.mark_noncode(address, size);
                        }
                    }
                }
            }
        }
        if let Some(address) = self.next_emulated(analysis) {
            return Some(address);
        }
        if !self.scanned || self.examined_instructions.len() < analysis.instructions.len() {
            return self.next(analysis, noreturn);
        }
        None
    }

    fn next_emulated(&mut self, analysis: &mut Analysis) -> Option<u64> {
        while let Some(address) = self.emulated_ready.pop_first() {
            if !covered(analysis, address) && !emucode::in_data(&self.data_locations, address) {
                analysis
                    .seeds
                    .entry(address)
                    .or_default()
                    .insert(SeedKind::Emulated);
                return Some(address);
            }
        }
        None
    }
}

#[allow(clippy::chunks_exact_to_as_chunks)] // Keep the Rust 1.87 MSRV.
fn string_size(analysis: &Analysis, address: u64) -> Option<usize> {
    // `VivWorkspace.analyzePointer` checks strings before code. Keep this
    // bounded and require the same printable ASCII and NUL terminator.
    let bytes = analysis.image.bytes_at(address, 4096)?;
    let printable = |byte: u8| byte.is_ascii_graphic() || byte == b' ' || matches!(byte, 9..=13);
    for (count, &byte) in bytes.iter().enumerate() {
        if byte == 0 {
            if count >= 4 {
                return Some(count + 1);
            }
            break;
        }
        if !printable(byte) {
            break;
        }
    }
    let &charset = bytes.get(1)?;
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let (&first, rest) = pair.split_first()?;
        if first == 0 {
            return (index > 4).then_some((index + 1) * 2);
        }
        if !printable(first) || rest.first() != Some(&charset) {
            return None;
        }
    }
    None
}

fn insert_location(locations: &mut Vec<(u64, u64)>, start: u64, size: usize) {
    let end = start.saturating_add(size as u64);
    let first = locations.partition_point(|(_, end)| *end < start);
    let last = locations.partition_point(|(start, _)| *start <= end);
    let start = locations
        .get(first)
        .filter(|_| first < last)
        .map_or(start, |(previous, _)| start.min(*previous));
    let end = last
        .checked_sub(1)
        .and_then(|index| locations.get(index))
        .filter(|_| first < last)
        .map_or(end, |(_, previous)| end.max(*previous));
    locations.splice(first..last, [(start, end)]);
}
