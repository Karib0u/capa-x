//! Port of pinned Vivisect 1.3.2 `vivisect/analysis/elf/libc_start_main.py`.
//!
//! A dynamically linked glibc program's ELF entry point is `_start`, a short
//! compiler-generated stub whose only job is to hand `main` to
//! `__libc_start_main` and never return. Nothing calls `main` directly, so a
//! backend that misses this hand-off never reaches the program's own code at
//! all -- measured on `294b8db1...elf_`, that one function start is the root of
//! 79 of the reference's functions and 15 of its 30 rule matches.
//!
//! Upstream reads the argument with the emulator: it runs `_start` until the
//! call whose target is the `__libc_start_main` import, then asks the calling
//! convention for argument 0 (`libc_start_main.py:33-52`). The value itself is
//! a link-time constant in the stub -- `mov rdi, <main>` on x86-64, `push
//! <main>` on i386 -- so this port reads that constant directly rather than
//! emulating to it. It deliberately recognises only the stub shape: an
//! immediate that no instruction in `_start` has recomputed.

use iced_x86::{FlowControl, Mnemonic, OpKind, Register};

use super::engine::{direct_target, memory_target};
use super::image::{Architecture, ImageFormat, LoadedImage};

/// glibc's `_start` is ~12 instructions. The cap only stops a runaway walk
/// through a stub that is not one.
const MAX_STUB_INSNS: usize = 64;

/// Import name upstream keys on (`getMainVas`, via the `__libc_start_main`
/// import location vivisect's ELF parser creates).
const LIBC_START_MAIN: &str = "__libc_start_main";

/// The address `_start` passes as `__libc_start_main`'s first argument, i.e.
/// `main`.
///
/// Returns `None` for anything that is not a recognisable dynamically-linked
/// glibc entry stub -- a static binary, a non-ELF image, or a packed entry
/// point.
pub fn main_address(image: &LoadedImage) -> Option<u64> {
    if image.format != ImageFormat::Elf {
        return None;
    }
    // x86/x64-only: this reads `mov rdi, <main>`/`push <main>` off the
    // decoded `iced_x86::Instruction` below, which panics by design if
    // called against an AArch64 image (`DecodedInstruction::x86_instruction`).
    // AArch64's own `_start` shape (typically `adrp`/`add x0, ...; bl
    // __libc_start_main`) is not yet ported -- see `golang::is_go_image`'s
    // identical gate for the same reason.
    if !matches!(image.architecture, Architecture::X86 | Architecture::X64) {
        return None;
    }
    let entry = image.entry_point?;

    // Argument 0 under both ABIs upstream's `getPreCallArgs` covers: SysV
    // amd64 passes it in `rdi`, i386 cdecl on the stack, so the last `push` of
    // an immediate before the call is the one `main` was pushed by.
    let mut candidate: Option<u64> = None;

    let mut address = entry;
    for _ in 0..MAX_STUB_INSNS {
        let insn = image.decode_at(address).ok()?;
        let instruction = insn.x86_instruction();
        match instruction.flow_control() {
            FlowControl::Call => {
                let target = direct_target(&insn)?;
                if calls_libc_start_main(image, target) {
                    return candidate;
                }
                // A different call in the stub would have clobbered the
                // argument registers; upstream's emulator would carry its
                // effects, and this port cannot.
                return None;
            }
            FlowControl::Next => {}
            // `_start` is straight-line up to the hand-off. Anything else is
            // not the stub this pass recognises.
            _ => return None,
        }

        if image.architecture == Architecture::X64 {
            if instruction.mnemonic() == Mnemonic::Mov
                && matches!(instruction.op0_register(), Register::RDI | Register::EDI)
            {
                candidate = immediate(instruction);
            } else if instruction.mnemonic() == Mnemonic::Lea
                && instruction.op0_register() == Register::RDI
            {
                candidate = memory_target(&insn);
            } else if writes_register(instruction, Register::RDI) {
                // Some other instruction produced `rdi`; its value is not a
                // constant this pass can read.
                candidate = None;
            }
        } else if instruction.mnemonic() == Mnemonic::Push {
            candidate = immediate(instruction);
        }

        address = instruction.next_ip();
    }
    None
}

/// True when `target` is a direct call to the `__libc_start_main` import,
/// including through its PLT stub (`jmp [<got slot>]`), which is how every
/// dynamically linked call site reaches it.
fn calls_libc_start_main(image: &LoadedImage, target: u64) -> bool {
    if is_libc_start_main_slot(image, target) {
        return true;
    }
    let Ok(stub) = image.decode_at(target) else {
        return false;
    };
    if stub.x86_instruction().flow_control() != FlowControl::IndirectBranch {
        return false;
    }
    memory_target(&stub).is_some_and(|slot| is_libc_start_main_slot(image, slot))
}

fn is_libc_start_main_slot(image: &LoadedImage, slot: u64) -> bool {
    image.import_locations.get(&slot).is_some_and(|name| {
        name.rsplit('.')
            .next()
            .is_some_and(|symbol| symbol == LIBC_START_MAIN)
    })
}

/// The instruction's immediate operand, widened to an address.
fn immediate(instruction: &iced_x86::Instruction) -> Option<u64> {
    (0..instruction.op_count()).find_map(|index| match instruction.op_kind(index) {
        OpKind::Immediate32to64 | OpKind::Immediate64 | OpKind::Immediate32 => {
            Some(instruction.immediate(index))
        }
        _ => None,
    })
}

fn writes_register(instruction: &iced_x86::Instruction, register: Register) -> bool {
    (0..instruction.op_count()).any(|index| {
        instruction.op_kind(index) == OpKind::Register
            && instruction.op_register(index).full_register() == register.full_register()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::extract::image::{MappedSection, Permissions};

    const TEXT: u64 = 0x1000;
    const PLT: u64 = 0x1100;
    const GOT: u64 = 0x2000;
    const MAIN: u64 = 0x1234;

    fn image_with(architecture: Architecture, entry: &[u8], plt: &[u8]) -> LoadedImage {
        let mut bytes = entry.to_vec();
        bytes.resize(0x100, 0x90);
        bytes.extend_from_slice(plt);
        bytes.resize(0x200, 0x90);
        let mut image = LoadedImage::for_test(
            ImageFormat::Elf,
            architecture,
            TEXT,
            vec![
                MappedSection {
                    name: ".text".to_string(),
                    address: TEXT,
                    virtual_size: 0x200,
                    file_offset: 0,
                    file_size: 0x200,
                    permissions: Permissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                },
                MappedSection {
                    name: ".got.plt".to_string(),
                    address: GOT,
                    virtual_size: 0x20,
                    file_offset: 0x200,
                    file_size: 0x20,
                    permissions: Permissions {
                        read: true,
                        write: true,
                        execute: false,
                    },
                },
            ],
            BTreeMap::new(),
            bytes,
        )
        .with_import_location(GOT, "*.__libc_start_main");
        image.entry_point = Some(TEXT);
        image
    }

    /// `jmp qword [rip + disp]` at [`PLT`], resolving to [`GOT`].
    fn plt_stub_x64() -> Vec<u8> {
        let disp = (GOT as i64) - (PLT as i64 + 6);
        let mut stub = vec![0xff, 0x25];
        stub.extend_from_slice(&(disp as i32).to_le_bytes());
        stub
    }

    #[test]
    fn reads_main_from_the_x86_64_entry_stub() {
        // xor ebp, ebp; mov rdi, MAIN; call PLT
        let mut entry = vec![0x31, 0xed];
        entry.extend_from_slice(&[0x48, 0xc7, 0xc7]);
        entry.extend_from_slice(&(MAIN as u32).to_le_bytes());
        let call_site = TEXT + entry.len() as u64;
        entry.push(0xe8);
        entry.extend_from_slice(&((PLT as i64 - (call_site as i64 + 5)) as i32).to_le_bytes());

        let image = image_with(Architecture::X64, &entry, &plt_stub_x64());
        assert_eq!(main_address(&image), Some(MAIN));
    }

    #[test]
    fn reads_main_from_the_i386_entry_stub() {
        // push 0x0; push MAIN; call PLT -- arg0 is the last push.
        let mut entry = vec![0x6a, 0x00, 0x68];
        entry.extend_from_slice(&(MAIN as u32).to_le_bytes());
        let call_site = TEXT + entry.len() as u64;
        entry.push(0xe8);
        entry.extend_from_slice(&((PLT as i64 - (call_site as i64 + 5)) as i32).to_le_bytes());

        // jmp dword [GOT]
        let mut stub = vec![0xff, 0x25];
        stub.extend_from_slice(&(GOT as u32).to_le_bytes());

        let image = image_with(Architecture::X86, &entry, &stub);
        assert_eq!(main_address(&image), Some(MAIN));
    }

    #[test]
    fn ignores_a_call_to_something_else() {
        let mut entry = vec![0x48, 0xc7, 0xc7];
        entry.extend_from_slice(&(MAIN as u32).to_le_bytes());
        let call_site = TEXT + entry.len() as u64;
        entry.push(0xe8);
        // Call a plain `ret` rather than the import's PLT stub.
        let elsewhere = TEXT + 0x80;
        entry
            .extend_from_slice(&((elsewhere as i64 - (call_site as i64 + 5)) as i32).to_le_bytes());

        let image = image_with(Architecture::X64, &entry, &plt_stub_x64());
        assert_eq!(main_address(&image), None);
    }

    #[test]
    fn ignores_a_recomputed_argument_register() {
        // mov rdi, MAIN; xor edi, edi; call PLT -- `rdi` is no longer the
        // constant, and only the emulator upstream uses could say what it is.
        let mut entry = vec![0x48, 0xc7, 0xc7];
        entry.extend_from_slice(&(MAIN as u32).to_le_bytes());
        entry.extend_from_slice(&[0x31, 0xff]);
        let call_site = TEXT + entry.len() as u64;
        entry.push(0xe8);
        entry.extend_from_slice(&((PLT as i64 - (call_site as i64 + 5)) as i32).to_le_bytes());

        let image = image_with(Architecture::X64, &entry, &plt_stub_x64());
        assert_eq!(main_address(&image), None);
    }
}
