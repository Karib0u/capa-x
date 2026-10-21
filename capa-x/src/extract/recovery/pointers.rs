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
    collected_instruction_count: usize,
    examined_functions: BTreeSet<u64>,
    scanned: bool,
    emucode_active: bool,
    data_locations: Vec<(u64, u64)>,
    pointer_locations: BTreeMap<u64, u64>,
    orphan_pointers: BTreeSet<u64>,
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
            collected_instruction_count: 0,
            examined_functions: BTreeSet::new(),
            scanned: !enabled,
            emucode_active: enabled,
            data_locations: Vec::new(),
            pointer_locations: BTreeMap::new(),
            orphan_pointers: BTreeSet::new(),
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
            && analysis
                .image
                .section_containing(target)
                .is_some_and(|section| section.permissions.read)
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

    pub(super) fn mark_code(&mut self, start: u64, end: u64) {
        // codeblocks deletes a pointer starting at the next opcode before
        // decoding it. An opcode starting before a pointer instead overwrites
        // only its covered bytes in Vivisect's location map.
        let end = self
            .pointer_locations
            .remove(&start)
            .map_or(end, |old_end| end.max(old_end));
        let first = self
            .data_locations
            .partition_point(|(_, stop)| *stop <= start);
        let last = self
            .data_locations
            .partition_point(|(begin, _)| *begin < end);
        if first >= last {
            return;
        }
        let mut remaining = Vec::new();
        if let Some(&(begin, _)) = self.data_locations.get(first) {
            if begin < start {
                remaining.push((begin, start));
            }
        }
        if let Some(&(_, stop)) = self.data_locations.get(last - 1) {
            if end < stop {
                remaining.push((end, stop));
            }
        }
        self.data_locations.splice(first..last, remaining);
    }

    pub(super) fn orphan_pointer(&self, analysis: &Analysis, address: u64) -> bool {
        self.pointer_location(analysis, address)
            .is_some_and(|(start, _)| self.orphan_pointers.contains(&start))
    }

    pub(super) fn remove_pointer_reference(&mut self, start: u64) {
        self.orphan_pointers.insert(start);
    }

    pub(super) fn has_data_location(&self, address: u64) -> bool {
        emucode::in_data(&self.data_locations, address)
    }

    pub(super) fn pointer_location(&self, analysis: &Analysis, address: u64) -> Option<(u64, u64)> {
        if covered(analysis, address) || !emucode::in_data(&self.data_locations, address) {
            return None;
        }
        self.pointer_locations
            .range(..=address)
            .next_back()
            .and_then(|(&start, &end)| (address < end).then_some((start, end)))
    }

    pub(super) fn mark_data(&mut self, start: u64, size: usize) {
        self.orphan_pointers.remove(&start);
        insert_location(&mut self.data_locations, start, size);
        if let Some(end) = start.checked_add(size as u64) {
            self.pointer_locations.insert(start, end);
        }
    }

    fn mark_noncode(&mut self, start: u64, size: usize) {
        insert_location(&mut self.data_locations, start, size);
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
            self.observe_instruction(
                analysis,
                instruction,
                super::callbacks::enabled(&analysis.image),
            );
        }
        self.collected_instruction_count = analysis.instructions.len();
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
    ) -> Option<u64> {
        if during_flow
            && analysis.image.architecture == Architecture::X86
            && instruction.x86_instruction().mnemonic() == Mnemonic::Lea
        {
            return None;
        }
        if !self.examined_instructions.insert(instruction.address) {
            return None;
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
                return None;
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
                    return None;
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
                    return None;
                }
                if matches!(
                    instruction.flow,
                    super::decoder::Flow::IndirectCall | super::decoder::Flow::IndirectBranch
                ) {
                    // makeOpcode creates a pointer for BR_DEREF, without
                    // following it or interpreting its bytes as a number.
                    self.mark_data(target, analysis.image.architecture.pointer_width());
                    return None;
                }
                if let Some(size) = string_size(analysis, target, &self.data_locations) {
                    self.mark_noncode(target, size);
                    return None;
                }
                let pointer = (size == analysis.image.architecture.pointer_width())
                    .then(|| super::read_pointer(&analysis.image, target))
                    .flatten()
                    .filter(|value| analysis.image.section_containing(*value).is_some());
                if let Some(value) = pointer {
                    self.mark_data(target, size);
                    self.add(analysis, value, SeedKind::PointerTarget);
                    return Some(value);
                } else {
                    // guessDataPointer creates LOC_NUMBER for a scalar.
                    // Code flow cannot reclassify that location as code.
                    self.mark_noncode(target, size);
                }
            }
        }
        None
    }

    pub(super) fn follow_observed_pointer(
        &mut self,
        analysis: &mut Analysis,
        target: u64,
        noreturn: &BTreeSet<u64>,
    ) -> Option<u64> {
        // AnalysisMonitor.addAnalysisResults follows each newly typed data
        // pointer before the containing function's noret/FLIRT passes run.
        if !self.candidates.remove(&(SeedKind::PointerTarget, target)) {
            return None;
        }
        if self.tried.len() >= MAX_CANDIDATES {
            analysis.diagnostics.push(RecoveryDiagnostic {
                address: target,
                message: format!("pointer evaluation stopped at {MAX_CANDIDATES} candidates"),
            });
            return None;
        }
        self.add(analysis, target, SeedKind::Emulated);
        if !self.tried.insert((SeedKind::PointerTarget, target))
            || covered(analysis, target)
            || emucode::in_data(&self.data_locations, target)
            || emucode::in_import(&analysis.image, target)
        {
            return None;
        }
        if let Some(size) = string_size(analysis, target, &self.data_locations) {
            self.mark_noncode(target, size);
            return None;
        }
        let signature = analysis
            .seeds
            .get(&target)
            .is_some_and(|kinds| kinds.contains(&SeedKind::FunctionSignature));
        let verdict = if signature {
            Verdict::Code
        } else {
            emucode::evaluate_candidate(analysis, target, noreturn, &self.data_locations)
        };
        match verdict {
            Verdict::Code => {
                analysis
                    .seeds
                    .entry(target)
                    .or_default()
                    .insert(SeedKind::PointerTarget);
                Some(target)
            }
            Verdict::Inconclusive { address, reason } => {
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address: target,
                    message: format!("candidate evaluation stopped at {address:#x}: {reason}"),
                });
                None
            }
            Verdict::NotCode => None,
        }
    }

    pub(super) fn function_completed(&mut self, analysis: &Analysis, function: u64) {
        // ms/hotpatch.py runs after codeblocks and before calling analysis.
        if analysis.image.format != ImageFormat::Pe || !self.examined_functions.insert(function) {
            return;
        }
        let Some(section) = analysis.image.section_containing(function) else {
            return;
        };
        let Some(size) = function
            .checked_sub(section.address)
            .and_then(|size| usize::try_from(size).ok())
        else {
            return;
        };
        let Some(bytes) = analysis.image.bytes_at(section.address, size) else {
            return;
        };
        let Some(&padding @ (0x90 | 0xcc)) = bytes.last() else {
            return;
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
                // generic.relocations skips every existing location, including
                // structures and strings created by function analysis.
                if covered(analysis, source) || emucode::in_data(&self.data_locations, source) {
                    continue;
                }
                self.mark_data(source, analysis.image.architecture.pointer_width());
                super::read_pointer(&analysis.image, source).map(|target| {
                    let sources = analysis.data_xrefs.entry(target).or_default();
                    if !sources.contains(&source) {
                        sources.push(source);
                    }
                    (target, SeedKind::PointerTarget)
                })
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
                    let sources = analysis.data_xrefs.entry(target).or_default();
                    if !sources.contains(&source) {
                        sources.push(source);
                    }
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
            if !self.tried.insert((kind, address))
                || covered(analysis, address)
                || emucode::in_data(&self.data_locations, address)
                || emucode::in_import(&analysis.image, address)
                || (kind == SeedKind::Emulated && analysis.image.is_dead_data(address))
            {
                continue;
            }
            let executable = analysis.image.is_executable_address(address);
            if kind == SeedKind::PointerTarget || !executable {
                if let Some(size) = string_size(analysis, address, &self.data_locations) {
                    // analyzePointer/followPointer creates a string location.
                    // Later traces must reject branches into these bytes.
                    self.mark_noncode(address, size);
                    continue;
                }
            }
            if !executable {
                continue;
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
                    // An emulator anomaly rejects code upstream but still
                    // allows the emucode pass to recognize a string.
                    if kind == SeedKind::Emulated {
                        if let Some(size) = string_size(analysis, address, &self.data_locations) {
                            self.mark_noncode(address, size);
                        }
                    }
                }
                Verdict::NotCode => {
                    if kind == SeedKind::Emulated {
                        // generic.emucode types rejected string candidates
                        // before creating the accepted functions in this wave.
                        if let Some(size) = string_size(analysis, address, &self.data_locations) {
                            self.mark_noncode(address, size);
                        }
                    }
                }
            }
        }
        if let Some(address) = self.next_emulated(analysis) {
            return Some(address);
        }
        if !self.scanned || self.collected_instruction_count < analysis.instructions.len() {
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
fn string_size(analysis: &Analysis, address: u64, data_locations: &[(u64, u64)]) -> Option<usize> {
    // `VivWorkspace.analyzePointer` checks strings before code. Keep this
    // bounded and require the same printable ASCII and NUL terminator.
    let bytes = analysis.image.bytes_at(address, 4096)?;
    // detectString also accepts short Pascal/Delphi strings when the
    // preceding two- or four-byte length agrees with the NUL terminator.
    let prefixed_length = |width: usize| {
        let start = address.checked_sub(width as u64)?;
        let bytes = analysis.image.bytes_at(start, width)?;
        (bytes.len() == width).then(|| {
            bytes.iter().enumerate().fold(0u64, |value, (index, byte)| {
                value | (u64::from(*byte) << (index * 8))
            })
        })
    };
    let pascal_length = prefixed_length(2);
    let delphi_length = prefixed_length(4);
    let printable = |byte: u8| byte.is_ascii_graphic() || byte == b' ' || matches!(byte, 9..=13);
    let blocked = |offset: usize| {
        offset > 0
            && address.checked_add(offset as u64).is_none_or(|va| {
                covered(analysis, va)
                    || emucode::in_data(data_locations, va)
                    || emucode::in_import(&analysis.image, va)
            })
    };
    for (count, &byte) in bytes.iter().enumerate() {
        if blocked(count) {
            break;
        }
        if byte == 0 {
            if count > 0
                && (count >= 4
                    || pascal_length == Some(count as u64)
                    || delphi_length == Some(count as u64))
            {
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
        if blocked(index * 2) {
            return None;
        }
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn observed_pointers_respect_the_candidate_budget() {
        let mut analysis = super::super::analyze_shellcode(&[0xc3], Architecture::X86).unwrap();
        let target = analysis.image.image_base;
        let mut discovery = Discovery::new(&mut analysis, true);
        discovery.tried = (0..MAX_CANDIDATES as u64)
            .map(|address| (SeedKind::PointerTarget, address))
            .collect();
        discovery
            .candidates
            .insert((SeedKind::PointerTarget, target));
        assert_eq!(
            discovery.follow_observed_pointer(&mut analysis, target, &BTreeSet::new()),
            None
        );
        assert_eq!(discovery.tried.len(), MAX_CANDIDATES);
        assert!(analysis
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.address == target
                && diagnostic.message.contains("pointer evaluation stopped")));
    }

    #[test]
    fn string_candidates_stop_at_existing_locations() {
        let bytes = b"\xc3\xcc\xcc\xccHello\0W\0o\0r\0l\0d\0\0\0";
        let mut analysis = super::super::analyze_shellcode(bytes, Architecture::X86).unwrap();
        let start = analysis.image.image_base;
        assert_eq!(string_size(&analysis, start + 4, &[]), Some(6));
        assert_eq!(string_size(&analysis, start + 10, &[]), Some(12));
        assert_eq!(
            string_size(&analysis, start + 4, &[(start + 6, start + 10)]),
            None
        );
        assert_eq!(
            string_size(&analysis, start + 10, &[(start + 14, start + 18)]),
            None
        );
        let instruction = analysis.image.decode_at_compat(start + 6).unwrap();
        analysis.instructions.insert(start + 6, instruction);
        assert_eq!(string_size(&analysis, start + 4, &[]), None);
    }

    #[test]
    fn relocations_do_not_follow_previously_typed_structure_members() {
        let mut bytes = vec![0xc3];
        bytes.resize(16, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
        bytes.resize(32, 0xcc);
        let mut analysis = super::super::analyze_shellcode(&bytes, Architecture::X86).unwrap();
        let start = analysis.image.image_base;
        let slot = start + 24;
        // Use the same mapped image helper as recovery, with a relocation
        // pointing at a valid but otherwise undiscovered function.
        bytes[24..28].copy_from_slice(&((start + 16) as u32).to_le_bytes());
        analysis.image =
            super::super::image::LoadedImage::from_shellcode(&bytes, Architecture::X86);
        analysis.image.relocation_locations.push(slot);
        let mut discovery = Discovery::new(&mut analysis, true);
        discovery.mark_noncode(slot - 4, 12);
        assert_eq!(discovery.next(&mut analysis, &BTreeSet::new()), None);
        assert!(!analysis.seeds.contains_key(&(start + 16)));
    }

    #[test]
    fn length_prefixed_short_strings_are_data() {
        let bytes = [
            0xc3, 0xcc, 0xcc, 0xcc, 2, 0, 0, 0, b'y', b'y', 0, 0xcc, 0xff, 0xff, 3, 0, b'A', b'p',
            b'r', 0, 0xff, 0xff, 0xff, 0xff, b'n', b'o', 0,
        ];
        let analysis = super::super::analyze_shellcode(&bytes, Architecture::X86).unwrap();
        let start = analysis.image.image_base;
        assert_eq!(string_size(&analysis, start + 8, &[]), Some(3));
        assert_eq!(string_size(&analysis, start + 16, &[]), Some(4));
        assert_eq!(string_size(&analysis, start + 24, &[]), None);
    }
}
