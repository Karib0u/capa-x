//! Bounded candidate evaluation for Vivisect's `generic.emucode` watcher.
//!
//! This is an abstract interpreter, not a sample execution environment.
//! Unknown input registers and unreadable memory stay unknown. Writes are
//! private to each path. Calls return an unknown value without executing the
//! callee, and conditional branches explore both successors, as in
//! `vivisect/impemu/emulator.py:runFunction/checkBranches/checkCall`.

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use super::decoder::Flow;
use super::image::{Architecture, LoadedImage};

// Local resource limits, not upstream constants. A budget cannot establish code.
const MAX_STEPS: usize = 8192;
const MAX_PATHS: usize = 256;
const STACK_BASE: u64 = 0x7fff_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Verdict {
    Code,
    NotCode,
    Inconclusive { address: u64, reason: String },
}

#[derive(Clone, Default)]
pub(super) struct State {
    registers: BTreeMap<Register, u64>,
    memory: BTreeMap<u64, Option<u8>>,
    backwards: bool,
}

fn mask(size: usize) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

fn high_byte(register: Register) -> bool {
    matches!(
        register,
        Register::AH | Register::BH | Register::CH | Register::DH
    )
}

impl State {
    pub(super) fn entry() -> Self {
        let mut state = Self::default();
        state.set_register(Register::RSP, Some(STACK_BASE));
        state
    }

    pub(super) fn register(&self, register: Register) -> Option<u64> {
        if register == Register::None {
            return Some(0);
        }
        if register.size() > 8 {
            return None;
        }
        let value = *self.registers.get(&register.full_register())?;
        Some((value >> if high_byte(register) { 8 } else { 0 }) & mask(register.size()))
    }

    pub(super) fn set_register(&mut self, register: Register, value: Option<u64>) {
        let full = register.full_register();
        let size = register.size();
        let value = value.filter(|_| size <= 8).map(|value| value & mask(size));
        // Writes to a 32-bit GPR zero extend. Narrower writes preserve the
        // other bits, so they cannot manufacture a known full pointer.
        let merged = if size >= 4 {
            value
        } else {
            self.registers
                .get(&full)
                .copied()
                .zip(value)
                .map(|(old, value)| {
                    let shift = if high_byte(register) { 8 } else { 0 };
                    (old & !(mask(size) << shift)) | (value << shift)
                })
        };
        if let Some(value) = merged {
            self.registers.insert(full, value);
        } else {
            self.registers.remove(&full);
        }
    }

    pub(super) fn address(&self, op: &Instruction, architecture: Architecture) -> Option<u64> {
        if matches!(op.memory_segment(), Register::FS | Register::GS) {
            return None;
        }
        if op.is_ip_rel_memory_operand() {
            return Some(op.ip_rel_memory_address());
        }
        let base = self.register(op.memory_base())?;
        let index = self.register(op.memory_index())?;
        let address = base
            .wrapping_add(index.wrapping_mul(u64::from(op.memory_index_scale())))
            .wrapping_add(op.memory_displacement64());
        let size = if architecture == Architecture::X86
            || op.memory_base().size() == 4
            || op.memory_index().size() == 4
        {
            4
        } else {
            8
        };
        Some(address & mask(size))
    }

    pub(super) fn read(&self, image: &LoadedImage, address: u64, size: usize) -> Option<u64> {
        if !(1..=8).contains(&size) {
            return None;
        }
        let mut value = 0;
        for offset in 0..size {
            let address = address.checked_add(offset as u64)?;
            let byte = match self.memory.get(&address) {
                Some(byte) => (*byte)?,
                None => *image.bytes_at(address, 1)?.first()?,
            };
            value |= u64::from(byte) << (8 * offset);
        }
        Some(value)
    }

    fn write(&mut self, address: u64, size: usize, value: Option<u64>) {
        for offset in 0..size.min(64) {
            if let Some(address) = address.checked_add(offset as u64) {
                self.memory.insert(
                    address,
                    value
                        .filter(|_| size <= 8)
                        .map(|value| (value >> (offset * 8)) as u8),
                );
            }
        }
    }

    pub(super) fn operand(&self, image: &LoadedImage, op: &Instruction, index: u32) -> Option<u64> {
        match op.op_kind(index) {
            OpKind::Register => self.register(op.op_register(index)),
            OpKind::Memory => self.read(
                image,
                self.address(op, image.architecture)?,
                op.memory_size().size(),
            ),
            OpKind::Immediate8 => Some(u64::from(op.immediate8())),
            OpKind::Immediate16 => Some(u64::from(op.immediate16())),
            OpKind::Immediate32 => Some(u64::from(op.immediate32())),
            OpKind::Immediate64 => Some(op.immediate64()),
            OpKind::Immediate8to16 => Some(op.immediate8to16() as u64),
            OpKind::Immediate8to32 => Some(op.immediate8to32() as u64),
            OpKind::Immediate8to64 => Some(op.immediate8to64() as u64),
            OpKind::Immediate32to64 => Some(op.immediate32to64() as u64),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Some(op.near_branch_target())
            }
            _ => None,
        }
    }

    fn assign(&mut self, image: &LoadedImage, op: &Instruction, index: u32, value: Option<u64>) {
        match op.op_kind(index) {
            OpKind::Register => self.set_register(op.op_register(index), value),
            OpKind::Memory => {
                if let Some(address) = self.address(op, image.architecture) {
                    self.write(address, op.memory_size().size(), value);
                }
                // impemu/emulator.py:writeMemory ignores writes through
                // unmapped taint addresses in safe_mem mode. An unknown
                // destination must not erase concrete stack arguments.
            }
            _ => {}
        }
    }

    pub(super) fn step(
        &mut self,
        image: &LoadedImage,
        op: &Instruction,
    ) -> Result<(), &'static str> {
        use Mnemonic::*;
        let left = self.operand(image, op, 0);
        let right = if op.op_count() > 1 {
            self.operand(image, op, 1)
        } else {
            None
        };
        let width = image.architecture.pointer_width();
        let sp = if width == 4 {
            Register::ESP
        } else {
            Register::RSP
        };
        let bp = if width == 4 {
            Register::EBP
        } else {
            Register::RBP
        };
        let value = match op.mnemonic() {
            Mov | Movzx | Movd | Movq => right,
            // Vector state is deliberately unknown, including after a move.
            // These operations are supported by envi's i_mov aliases.
            Movaps | Movapd | Movups | Movupd | Movdqa | Movdqu | Movss => None,
            Movsx | Movsxd => {
                let size = if op.op1_kind() == OpKind::Register {
                    op.op1_register().size()
                } else {
                    op.memory_size().size()
                };
                right.map(|value| {
                    let shift = 64 - size.clamp(1, 8) * 8;
                    (((value << shift) as i64) >> shift) as u64
                })
            }
            Lea => self.address(op, image.architecture),
            Xor | Sub
                if op.op0_kind() == OpKind::Register
                    && op.op1_kind() == OpKind::Register
                    && op.op0_register() == op.op1_register() =>
            {
                Some(0)
            }
            Add => left.zip(right).map(|(a, b)| a.wrapping_add(b)),
            Sub => left.zip(right).map(|(a, b)| a.wrapping_sub(b)),
            Xor => left.zip(right).map(|(a, b)| a ^ b),
            And if right == Some(0) => Some(0),
            And => left.zip(right).map(|(a, b)| a & b),
            Or => left.zip(right).map(|(a, b)| a | b),
            Bt => return Ok(()),
            Bts | Btr | Btc => {
                // envi/archs/i386/emu.py:doBitTest reduces the index modulo
                // the destination width, including for memory operands.
                let size = if op.op0_kind() == OpKind::Register {
                    op.op0_register().size()
                } else {
                    op.memory_size().size()
                };
                left.zip(right).map(|(value, index)| {
                    let bit = 1u64 << (index % (size.clamp(1, 8) as u64 * 8));
                    match op.mnemonic() {
                        Bts => value | bit,
                        Btr => value & !bit,
                        _ => value ^ bit,
                    }
                })
            }
            Inc => left.map(|value| value.wrapping_add(1)),
            Dec => left.map(|value| value.wrapping_sub(1)),
            Neg => left.map(u64::wrapping_neg),
            Not => left.map(|value| !value),
            Shl | Shr | Sar => {
                let size = if op.op0_kind() == OpKind::Register {
                    op.op0_register().size()
                } else {
                    op.memory_size().size()
                };
                left.zip(right).map(|(a, b)| {
                    let bits = size.clamp(1, 8) * 8;
                    let count = (b & if bits == 64 { 63 } else { 31 }) as u32;
                    match op.mnemonic() {
                        Shl => a.wrapping_shl(count),
                        Shr => (a & mask(size)).wrapping_shr(count),
                        _ => {
                            let signed = ((a << (64 - bits)) as i64) >> (64 - bits);
                            signed.wrapping_shr(count) as u64
                        }
                    }
                })
            }
            Imul if op.op_count() > 1 => {
                if op.op_count() == 3 {
                    right
                        .zip(self.operand(image, op, 2))
                        .map(|(a, b)| a.wrapping_mul(b))
                } else {
                    left.zip(right).map(|(a, b)| a.wrapping_mul(b))
                }
            }
            Push => {
                let size = if op.op0_kind() == OpKind::Register {
                    op.op0_register().size()
                } else {
                    width
                };
                let address = self
                    .register(sp)
                    .map(|value| value.wrapping_sub(size as u64));
                self.set_register(sp, address);
                if let Some(address) = self.register(sp) {
                    self.write(address, size, left);
                }
                return Ok(());
            }
            Pop => {
                let size = if op.op0_kind() == OpKind::Register {
                    op.op0_register().size()
                } else {
                    width
                };
                let address = self.register(sp);
                let value = address.and_then(|address| self.read(image, address, size));
                self.set_register(sp, address.map(|value| value.wrapping_add(size as u64)));
                self.assign(image, op, 0, value);
                return Ok(());
            }
            Pushad | Popad => {
                let registers = [
                    Register::EAX,
                    Register::ECX,
                    Register::EDX,
                    Register::EBX,
                    Register::ESP,
                    Register::EBP,
                    Register::ESI,
                    Register::EDI,
                ];
                let original = self.register(Register::ESP);
                if op.mnemonic() == Pushad {
                    for register in registers {
                        let value = if register == Register::ESP {
                            original
                        } else {
                            self.register(register)
                        };
                        let address = self
                            .register(Register::ESP)
                            .map(|value| value.wrapping_sub(4));
                        self.set_register(Register::ESP, address);
                        if let Some(address) = self.register(Register::ESP) {
                            self.write(address, 4, value);
                        }
                    }
                } else {
                    for register in registers.into_iter().rev() {
                        let address = self.register(Register::ESP);
                        let value = address.and_then(|address| self.read(image, address, 4));
                        self.set_register(
                            Register::ESP,
                            address.map(|value| value.wrapping_add(4)),
                        );
                        if register != Register::ESP {
                            self.set_register(register, value);
                        }
                    }
                }
                return Ok(());
            }
            Pushfd | Pushfq | Popfd | Popfq => {
                let push = matches!(op.mnemonic(), Pushfd | Pushfq);
                let address = self.register(sp).map(|value| {
                    if push {
                        value.wrapping_sub(width as u64)
                    } else {
                        value.wrapping_add(width as u64)
                    }
                });
                self.set_register(sp, address);
                if push {
                    if let Some(address) = address {
                        self.write(address, width, None);
                    }
                }
                return Ok(());
            }
            Enter => {
                // `envi/archs/i386/emu.py:i_enter` only implements nesting 0.
                if op.immediate8_2nd() != 0 {
                    return Err("unsupported nested enter");
                }
                let address = self
                    .register(sp)
                    .map(|value| value.wrapping_sub(width as u64));
                if let Some(address) = address {
                    self.write(address, width, self.register(bp));
                }
                self.set_register(bp, address);
                self.set_register(
                    sp,
                    address.map(|value| value.wrapping_sub(u64::from(op.immediate16()))),
                );
                return Ok(());
            }
            Leave => {
                let address = self.register(bp);
                self.set_register(
                    bp,
                    address.and_then(|address| self.read(image, address, width)),
                );
                self.set_register(sp, address.map(|value| value.wrapping_add(width as u64)));
                return Ok(());
            }
            Xchg => {
                self.assign(image, op, 0, right);
                self.assign(image, op, 1, left);
                return Ok(());
            }
            Xadd => {
                // envi/archs/i386/emu.py:i_xadd exchanges the original
                // destination into the source, then writes their sum.
                // Capture a memory destination before changing its base.
                let address = self.address(op, image.architecture);
                let sum = left.zip(right).map(|(a, b)| a.wrapping_add(b));
                self.assign(image, op, 1, left);
                if op.op0_kind() == OpKind::Memory {
                    if let Some(address) = address {
                        self.write(address, op.memory_size().size(), sum);
                    }
                } else {
                    self.assign(image, op, 0, sum);
                }
                return Ok(());
            }
            Cmp | Test | Nop | Endbr32 | Endbr64 | Clc | Stc | Cmc | Sahf | Lfence | Clflush
            | Prefetchw => return Ok(()),
            Cld | Std => {
                self.backwards = op.mnemonic() == Std;
                return Ok(());
            }
            // Upstream intentionally ignores these four FPU instructions
            // (`envi/archs/i386/emu.py:i_fldz/i_fld/i_fild/i_fstp`).
            Fldz | Fld | Fild | Fstp => return Ok(()),
            Stosb | Stosw | Stosd | Stosq | Movsb | Movsw | Movsd | Movsq | Lodsb | Lodsw
            | Lodsd | Lodsq | Cmpsb | Cmpsw | Cmpsd | Cmpsq | Scasb | Scasw | Scasd | Scasq => {
                return self.string_step(image, op);
            }
            Rdtsc => {
                // Deterministic values from `envi/archs/i386/emu.py:i_rdtsc`.
                self.set_register(Register::EDX, Some(0));
                self.set_register(Register::EAX, Some(0x414141));
                return Ok(());
            }
            Cpuid => {
                for register in [Register::RAX, Register::RBX, Register::RCX, Register::RDX] {
                    self.set_register(register, None);
                }
                return Ok(());
            }
            Cdq | Cqo | Cwd => {
                self.set_register(Register::RDX, None);
                return Ok(());
            }
            Cbw | Cwde | Cdqe => {
                self.set_register(Register::RAX, None);
                return Ok(());
            }
            // Flags are abstract: conditional results cannot become pointers.
            Adc | Sbb | Rcl | Rcr | Rol | Ror | Shld | Shrd | Cmova | Cmovae | Cmovb | Cmovbe
            | Cmove | Cmovg | Cmovge | Cmovl | Cmovle | Cmovne | Cmovno | Cmovnp | Cmovns
            | Cmovo | Cmovp | Cmovs | Seta | Setae | Setb | Setbe | Sete | Setg | Setge | Setl
            | Setle | Setne | Setno | Setnp | Setns | Seto | Setp | Sets | Bsf | Bsr | Bswap => {
                None
            }
            Mul | Imul | Div | Idiv => {
                if matches!(op.mnemonic(), Div | Idiv) && left == Some(0) {
                    return Err("division by zero");
                }
                self.set_register(Register::RAX, None);
                self.set_register(Register::RDX, None);
                return Ok(());
            }
            _ => return Err("unsupported instruction"),
        };
        self.assign(image, op, 0, value);
        Ok(())
    }

    pub(super) fn clobber_call(&mut self) {
        for register in [
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
        ] {
            self.set_register(register, None);
        }
        for value in self.memory.values_mut() {
            *value = None;
        }
    }

    fn string_step(&mut self, image: &LoadedImage, op: &Instruction) -> Result<(), &'static str> {
        use Mnemonic::*;
        if matches!(op.mnemonic(), Movsd | Cmpsd)
            && op
                .op_kinds()
                .any(|kind| matches!(kind, OpKind::Register | OpKind::Memory))
        {
            return Err("unsupported scalar vector operation");
        }
        let size = match op.mnemonic() {
            Stosb | Movsb | Lodsb | Cmpsb | Scasb => 1,
            Stosw | Movsw | Lodsw | Cmpsw | Scasw => 2,
            Stosd | Movsd | Lodsd | Cmpsd | Scasd => 4,
            _ => 8,
        };
        let is64 = image.architecture == Architecture::X64;
        let src = if is64 { Register::RSI } else { Register::ESI };
        let dst = if is64 { Register::RDI } else { Register::EDI };
        let counter = if is64 { Register::RCX } else { Register::ECX };
        let accumulator = match size {
            1 => Register::AL,
            2 => Register::AX,
            4 => Register::EAX,
            _ => Register::RAX,
        };
        let repeated = op.has_rep_prefix() || op.has_repne_prefix();
        if repeated && self.register(counter) == Some(0) {
            return Ok(());
        }
        let source = self.register(src);
        let destination = self.register(dst);
        let loads = matches!(op.mnemonic(), Lodsb | Lodsw | Lodsd | Lodsq);
        let stores = matches!(op.mnemonic(), Stosb | Stosw | Stosd | Stosq);
        let moves = matches!(op.mnemonic(), Movsb | Movsw | Movsd | Movsq);
        let compares = matches!(op.mnemonic(), Cmpsb | Cmpsw | Cmpsd | Cmpsq);
        if moves || stores {
            let value = if stores {
                self.register(accumulator)
            } else {
                source.and_then(|address| self.read(image, address, size))
            };
            if let Some(address) = destination {
                self.write(address, size, value);
            }
        }
        if loads {
            self.set_register(
                accumulator,
                source.and_then(|address| self.read(image, address, size)),
            );
        }
        let advance = |address: u64| {
            if self.backwards {
                address.wrapping_sub(size as u64)
            } else {
                address.wrapping_add(size as u64)
            }
        };
        let next_source = source.map(advance);
        let next_destination = destination.map(advance);
        if moves || loads || compares {
            self.set_register(src, next_source);
        }
        if !loads {
            self.set_register(dst, next_destination);
        }
        if repeated {
            // `i386WorkspaceEmulator` sets `i386:repmax` to one.
            self.set_register(
                counter,
                self.register(counter).map(|value| value.wrapping_sub(1)),
            );
        }
        Ok(())
    }
}

fn good_distribution(counts: &BTreeMap<Mnemonic, usize>, total: usize) -> bool {
    // `generic/emucode.py:watcher.looksgood`: round(count / total, 3)
    // must be below .67 for traces longer than four instructions.
    total <= 4
        || counts
            .values()
            .all(|count| (count * 1000 + total / 2) / total < 670)
}

pub(super) fn in_data(locations: &[(u64, u64)], address: u64) -> bool {
    locations
        .partition_point(|(start, _)| *start <= address)
        .checked_sub(1)
        .and_then(|index| locations.get(index))
        .is_some_and(|(_, end)| address < *end)
}

pub(super) fn evaluate(
    image: &LoadedImage,
    start: u64,
    noreturn: &BTreeSet<u64>,
    data_locations: &[(u64, u64)],
) -> Verdict {
    if !matches!(image.architecture, Architecture::X86 | Architecture::X64) {
        return Verdict::NotCode;
    }
    if in_data(data_locations, start) {
        return Verdict::NotCode;
    }
    let state = State::entry();
    let mut pending = vec![(start, state)];
    let mut visited = BTreeSet::new();
    let mut counts = BTreeMap::new();
    let mut incomplete = None;
    while let Some((mut address, mut state)) = pending.pop() {
        loop {
            if !visited.insert(address) {
                break;
            }
            if visited.len() > MAX_STEPS || pending.len() > MAX_PATHS {
                return Verdict::Inconclusive {
                    address,
                    reason: "candidate trace budget exceeded".into(),
                };
            }
            if !image.is_executable_address(address) {
                break;
            }
            // watcher.prehook checks the location type at every instruction.
            // A branch into an existing pointer or string invalidates a trace,
            // even if the candidate's first byte was undefined.
            if in_data(data_locations, address) {
                return Verdict::NotCode;
            }
            // runFunction logs a decoder exception as an anomaly; the
            // watcher's badcode flag rejects the entire candidate, even
            // when another queued branch could reach a return.
            let Ok(decoded) = image.decode_at_compat(address) else {
                return Verdict::NotCode;
            };
            let op = decoded.x86_instruction();
            // `envi.ArchitectureModule.archGetBadOps` decodes all-zero bytes
            // as add [eax/rax], al. `watcher.prehook` stops on that opcode.
            if decoded.bytes.as_slice() == [0, 0]
                || matches!(
                    op.mnemonic(),
                    Mnemonic::Out | Mnemonic::Outsb | Mnemonic::Outsw | Mnemonic::Outsd
                )
            {
                return Verdict::NotCode;
            }
            // envi decodes CET landing pads as a prefixed nop.
            let mnemonic = match op.mnemonic() {
                Mnemonic::Endbr32 | Mnemonic::Endbr64 => Mnemonic::Nop,
                mnemonic => mnemonic,
            };
            *counts.entry(mnemonic).or_default() += 1;
            let total = counts.values().sum();
            if decoded.flow == Flow::Return
                || (image.architecture == Architecture::X86
                    && op.mnemonic() == Mnemonic::Int
                    && state.register(Register::EAX) == Some(1))
            {
                return if good_distribution(&counts, total) {
                    Verdict::Code
                } else {
                    Verdict::NotCode
                };
            }
            // Only a call to a known no-return target establishes an exit
            // below. A previous pass's function label at this instruction
            // cannot validate this candidate (or one of its shared tails).
            match decoded.flow {
                Flow::Call | Flow::IndirectCall => {
                    // iced groups system transfers with calls. envi supports
                    // syscall as a no-op, but has no sysenter implementation.
                    if op.mnemonic() == Mnemonic::Sysenter {
                        incomplete = Some((address, "unsupported instruction: Sysenter".into()));
                        break;
                    }
                    let target = state.operand(image, op, 0);
                    if target.is_some_and(|target| noreturn.contains(&target)) {
                        return if good_distribution(&counts, total) {
                            Verdict::Code
                        } else {
                            Verdict::NotCode
                        };
                    }
                    // Unknown return and caller-saved registers. Callee writes
                    // cannot leave a trusted private memory value behind.
                    state.clobber_call();
                    address = decoded.next_address;
                }
                Flow::ConditionalBranch => {
                    // envi emits fallthrough first; runFunction's LIFO queue
                    // therefore visits the taken edge first.
                    pending.push((decoded.next_address, state.clone()));
                    if let Some(target) = decoded.direct_target {
                        address = target;
                    } else {
                        break;
                    }
                }
                Flow::UnconditionalBranch | Flow::IndirectBranch => {
                    if let Some(target) = state.operand(image, op, 0) {
                        address = target;
                    } else {
                        incomplete = Some((address, "unresolved indirect branch".to_owned()));
                        break;
                    }
                }
                Flow::Next => {
                    if let Err(reason) = state.step(image, op) {
                        if reason == "division by zero" {
                            return Verdict::NotCode;
                        }
                        incomplete = Some((address, format!("{reason}: {:?}", op.mnemonic())));
                        break;
                    }
                    address = decoded.next_address;
                }
                _ => break,
            }
        }
    }
    if let Some((address, reason)) = incomplete {
        Verdict::Inconclusive { address, reason }
    } else {
        Verdict::NotCode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(bytes: &[u8]) -> Verdict {
        let image = LoadedImage::from_shellcode(bytes, Architecture::X86);
        evaluate(&image, image.image_base, &BTreeSet::new(), &[])
    }

    #[test]
    fn supports_bit_tests_used_by_trap_flag_checks() {
        assert_eq!(
            verdict(&[0x0f, 0xba, 0x2c, 0x24, 0x08, 0xc3]),
            Verdict::Code
        );
    }

    #[test]
    fn rejects_a_trace_that_branches_into_defined_data() {
        let image = LoadedImage::from_shellcode(&[0xeb, 0x02, 0xcc, 0xcc, 0xc3], Architecture::X86);
        let start = image.image_base;
        assert_eq!(
            evaluate(&image, start, &BTreeSet::new(), &[]),
            Verdict::Code
        );
        assert_eq!(
            evaluate(&image, start, &BTreeSet::new(), &[(start + 4, start + 5)]),
            Verdict::NotCode
        );
    }

    #[test]
    fn requires_a_return_and_rejects_padding_and_dominant_mnemonics() {
        assert_eq!(verdict(&[0x31, 0xc0, 0x40, 0xc3]), Verdict::Code);
        assert_eq!(verdict(&[0xeb, 0xfe]), Verdict::NotCode);
        assert_eq!(verdict(&[0, 0, 0xc3]), Verdict::NotCode);
        assert_eq!(verdict(&[0x90, 0x90, 0x90, 0x90, 0xc3]), Verdict::NotCode);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn xadd_preserves_the_original_memory_address_and_register_aliasing() {
        let image = LoadedImage::from_shellcode(
            &[0x0f, 0xc1, 0x00, 0x0f, 0xc1, 0xc0], // xadd [eax], eax; xadd eax, eax
            Architecture::X86,
        );
        let mut state = State::entry();
        state.set_register(Register::EAX, Some(0x2000));
        state.write(0x2000, 4, Some(3));
        let first = image.decode_at(image.image_base).unwrap();
        state.step(&image, first.x86_instruction()).unwrap();
        assert_eq!(state.register(Register::EAX), Some(3));
        assert_eq!(state.read(&image, 0x2000, 4), Some(0x2003));
        let second = image.decode_at(first.next_address).unwrap();
        state.step(&image, second.x86_instruction()).unwrap();
        assert_eq!(state.register(Register::EAX), Some(6));
    }

    #[test]
    fn explores_other_branch_when_one_path_is_unsupported() {
        assert_eq!(verdict(&[0x74, 0x01, 0xc3, 0x0f, 0x0b]), Verdict::Code);
    }

    #[test]
    fn invalid_instruction_on_taken_path_rejects_candidate_despite_return_path() {
        // JZ takes the invalid FE /7 path first. The fallthrough RET cannot
        // undo the watcher's decoder anomaly.
        assert_eq!(verdict(&[0x74, 0x01, 0xc3, 0xfe, 0xff]), Verdict::NotCode);
        assert_eq!(verdict(&[0x74, 0x01, 0xc3, 0xe6, 0x80]), Verdict::NotCode);
        assert_eq!(verdict(&[0x74, 0x01, 0xc3, 0x6e]), Verdict::NotCode);
    }

    #[test]
    fn unsupported_operations_are_explicit() {
        assert!(matches!(
            verdict(&[0x66, 0x0f, 0x38, 0xdc, 0xc0, 0xc3]),
            Verdict::Inconclusive { .. }
        ));
    }

    #[test]
    fn known_zero_divisor_is_an_anomaly() {
        assert_eq!(verdict(&[0x31, 0xc9, 0xf7, 0xf1, 0xc3]), Verdict::NotCode);
    }

    #[test]
    fn register_aliases_do_not_keep_stale_pointers() {
        let mut state = State::default();
        state.set_register(Register::RAX, Some(0x1234_5678_9abc_def0));
        state.set_register(Register::AH, Some(0x42));
        assert_eq!(state.register(Register::AX), Some(0x42f0));
        state.set_register(Register::EAX, Some(0x1234));
        assert_eq!(state.register(Register::RAX), Some(0x1234));
        state.set_register(Register::AL, None);
        assert_eq!(state.register(Register::RAX), None);
    }

    #[test]
    fn follows_computed_register_and_stack_targets() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let base = LoadedImage::from_shellcode(&[], architecture).image_base;
            let mut bytes = if architecture == Architecture::X64 {
                vec![0x48, 0xb8]
            } else {
                vec![0xb8]
            };
            let target = base + 32;
            bytes.extend_from_slice(&target.to_le_bytes()[..architecture.pointer_width()]);
            bytes.extend_from_slice(&[0x50, 0x59, 0xff, 0xe1]); // push ax; pop cx; jmp cx
            bytes.resize(32, 0xcc);
            bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
            let image = LoadedImage::from_shellcode(&bytes, architecture);
            assert_eq!(evaluate(&image, base, &BTreeSet::new(), &[]), Verdict::Code);
        }
    }

    #[test]
    fn unresolved_jump_and_budget_do_not_establish_code() {
        assert!(matches!(
            verdict(&[0xff, 0xe0]),
            Verdict::Inconclusive { .. }
        ));
        let mut bytes = vec![0x90; MAX_STEPS + 1];
        bytes.push(0xc3);
        assert!(matches!(verdict(&bytes), Verdict::Inconclusive { .. }));
    }

    #[test]
    fn noreturn_calls_and_linux_exit_terminate_successfully() {
        let image = LoadedImage::from_shellcode(&[0xe8, 0, 0, 0, 0], Architecture::X86);
        let base = image.image_base;
        assert_eq!(
            evaluate(&image, base, &BTreeSet::from([base + 5]), &[]),
            Verdict::Code
        );
        assert_eq!(verdict(&[0xb8, 1, 0, 0, 0, 0xcd, 0x80]), Verdict::Code);
    }

    #[test]
    fn cet_landing_pads_and_string_initialization_can_reach_return() {
        assert_eq!(
            verdict(&[0xf3, 0x0f, 0x1e, 0xfb, 0x31, 0xc0, 0xf3, 0xaa, 0xc3]),
            Verdict::Code
        );
    }

    #[test]
    fn mnemonic_threshold_uses_upstream_rounding() {
        assert!(!good_distribution(
            &BTreeMap::from([(Mnemonic::Mov, 1339), (Mnemonic::Add, 661)]),
            2000
        ));
        assert!(good_distribution(
            &BTreeMap::from([(Mnemonic::Mov, 1338), (Mnemonic::Add, 662)]),
            2000
        ));
    }
}
