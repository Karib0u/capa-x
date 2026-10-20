//! Candidate sources for `generic.pointers`, `pointertables`, and `emucode`.

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Mnemonic, OpKind, Register};

use super::emucode::{self, Verdict};
use super::image::{Architecture, ImageFormat};
use super::{Analysis, RecoveryDiagnostic, SeedKind};

// Local bounds for scanning hostile input, independent of upstream.
const MAX_SCAN_BYTES: usize = 32 * 1024 * 1024;
const MAX_CANDIDATES: usize = 32768;

pub(super) fn covered(analysis: &Analysis, address: u64) -> bool {
    analysis
        .instructions
        .range(..=address)
        .next_back()
        .is_some_and(|(_, insn)| address < insn.next_address)
}

pub(super) struct Discovery {
    candidates: BTreeMap<u64, SeedKind>,
    tried: BTreeSet<u64>,
    examined_instructions: BTreeSet<u64>,
    examined_functions: BTreeSet<u64>,
    scanned: bool,
    emucode_active: bool,
    data_locations: Vec<(u64, u64)>,
    candidate_limit_hit: bool,
    relocation_index: usize,
}

impl Discovery {
    pub(super) fn new(analysis: &mut Analysis, enabled: bool) -> Self {
        let mut candidates = BTreeMap::new();
        if enabled {
            let have_pe_slots = !analysis.image.relocation_locations.is_empty();
            analysis.seeds.retain(|address, kinds| {
                if kinds.remove(&SeedKind::Relocation) {
                    // PE slots are reconsidered after entry-point code flow.
                    // A relocation inside an instruction is not a pointer
                    // location; its operand contributes a REF_PTR instead.
                    if !have_pe_slots {
                        candidates.insert(*address, SeedKind::PointerTarget);
                    }
                }
                if kinds.remove(&SeedKind::Emulated) {
                    candidates.insert(*address, SeedKind::Emulated);
                }
                !kinds.is_empty()
            });
        }
        Self {
            candidates,
            tried: BTreeSet::new(),
            examined_instructions: BTreeSet::new(),
            examined_functions: BTreeSet::new(),
            scanned: !enabled,
            emucode_active: enabled,
            data_locations: Vec::new(),
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
            .retain(|_, kind| *kind != SeedKind::Emulated);
    }

    fn add(&mut self, analysis: &Analysis, target: u64, kind: SeedKind) {
        if (kind != SeedKind::Emulated || self.emucode_active)
            && analysis.image.is_executable_address(target)
            && (kind != SeedKind::Emulated || !analysis.image.is_dead_data(target))
            && !covered(analysis, target)
            && !self.tried.contains(&target)
        {
            if self.candidates.len() >= MAX_CANDIDATES {
                self.candidate_limit_hit = true;
            } else {
                self.candidates.entry(target).or_insert(kind);
            }
        }
    }

    fn mark_data(&mut self, start: u64, size: usize) {
        let end = start.saturating_add(size as u64);
        let first = self.data_locations.partition_point(|(_, end)| *end < start);
        let last = self
            .data_locations
            .partition_point(|(start, _)| *start <= end);
        let start = self
            .data_locations
            .get(first)
            .filter(|_| first < last)
            .map_or(start, |(previous, _)| start.min(*previous));
        let end = last
            .checked_sub(1)
            .and_then(|index| self.data_locations.get(index))
            .filter(|_| first < last)
            .map_or(end, |(_, previous)| end.max(*previous));
        self.data_locations.splice(first..last, [(start, end)]);
    }

    fn collect(&mut self, analysis: &mut Analysis) {
        if !self.scanned && analysis.image.format == ImageFormat::Elf {
            self.scanned = true;
            // `VivWorkspace.findPointers`: unaligned pointers are allowed on
            // x86, but their source must still be undefined. `pointertables`
            // visits the same sources, so a single scan covers both passes.
            let mut remaining = MAX_SCAN_BYTES;
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
                    {
                        offset += 1;
                        continue;
                    }
                    let target = raw.iter().enumerate().fold(0u64, |value, (index, byte)| {
                        value | (u64::from(*byte) << (index * 8))
                    });
                    self.add(analysis, target, SeedKind::PointerTarget);
                    if analysis.image.section_containing(target).is_some() {
                        self.mark_data(source, width);
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
        }
        // PE's amodlist has `generic.relocations` and `ms.vftables`, not
        // `generic.pointers/pointertables`. vftables only inspects pointers to
        // existing functions; it never promotes arbitrary raw values to code.
        self.scanned = true;
        // `base._cb_opcode/guessDataPointer` also contributes immediate and
        // dereferenced operand targets. Repeat after new functions are walked.
        for instruction in analysis.instructions.values() {
            if !self.examined_instructions.insert(instruction.address) {
                continue;
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
                    continue;
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
                        continue;
                    }
                }
                if !covered(analysis, target) {
                    let size = if op.mnemonic() == Mnemonic::Lea {
                        op.op0_register().size()
                    } else {
                        op.memory_size().size()
                    };
                    if let Some(size) = string_size(analysis, target) {
                        self.mark_data(target, size);
                        continue;
                    }
                    self.mark_data(target, size);
                    if size == analysis.image.architecture.pointer_width()
                        && !analysis.image.import_locations.contains_key(&target)
                    {
                        if let Some(target) = super::read_pointer(&analysis.image, target) {
                            self.add(analysis, target, SeedKind::PointerTarget);
                        }
                    }
                }
            }
        }
        if self.candidate_limit_hit {
            analysis.diagnostics.push(RecoveryDiagnostic {
                address: analysis.image.image_base,
                message: format!("pointer discovery stopped adding candidates at {MAX_CANDIDATES}"),
            });
            self.candidate_limit_hit = false;
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
                    self.mark_data(start, count);
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
                self.candidates.pop_first()
            };
            let Some((address, kind)) = candidate else {
                if self.relocation_index < analysis.image.relocation_locations.len() {
                    continue;
                }
                break;
            };

            if self.tried.len() >= MAX_CANDIDATES {
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address,
                    message: format!("pointer evaluation stopped at {MAX_CANDIDATES} candidates"),
                });
                self.candidates.clear();
                return None;
            }
            if !analysis.image.is_executable_address(address)
                || !self.tried.insert(address)
                || covered(analysis, address)
                || emucode::in_data(&self.data_locations, address)
                || (kind == SeedKind::Emulated && analysis.image.is_dead_data(address))
            {
                continue;
            }
            if kind == SeedKind::PointerTarget {
                if let Some(size) = string_size(analysis, address) {
                    // analyzePointer/followPointer creates a string location.
                    // Later traces must reject branches into these bytes.
                    self.mark_data(address, size);
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
                emucode::evaluate(&analysis.image, address, noreturn, &self.data_locations)
            };
            match verdict {
                Verdict::Code => {
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
                Verdict::NotCode => {}
            }
        }
        if !self.scanned || self.examined_instructions.len() < analysis.instructions.len() {
            return self.next(analysis, noreturn);
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
