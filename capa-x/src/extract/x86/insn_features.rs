//! Instruction-scope feature extraction, ported function-by-
//! function from `capa/features/extractors/viv/insn.py` (v9.4.0, see
//! PINNED.md). Also covers `capa/features/extractors/viv/indirect_calls.py`
//! (`resolve_indirect_call`/`find_definition`, a plain backward dataflow
//! scan with no vivisect dependency) and the ELF/FLIRT/thunk-chain parts of
//! `get_imports`.
//!
//! By deliberate design, vivisect internals (xrefs,
//! "is this a valid pointer", "is there a string at this address", ...) are
//! not ported; each is replaced by the equivalent query against
//! [`super::recovery::Analysis`]/[`super::image::LoadedImage`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::{
    FlowControl, FormatMnemonicOptions, Formatter, Instruction, MasmFormatter, OpKind, Register,
};

use crate::address::Address;
use crate::features::{Feature, NumberValue, StringFeature};

use super::helpers::all_zeros;
use super::image::{ImageFormat, LoadedImage};
use super::operand::{classify_operand, Operand};
use super::recovery::{self, Analysis, BasicBlock, Function};
use super::strings;

/// capa/features/common.py: THUNK_CHAIN_DEPTH_DELTA
const THUNK_CHAIN_DEPTH_DELTA: usize = 5;
/// capa/features/insn.py: MAX_STRUCTURE_SIZE
const MAX_STRUCTURE_SIZE: i64 = 0x10000;
/// capa/features/extractors/viv/insn.py: SECURITY_COOKIE_BYTES_DELTA
const SECURITY_COOKIE_BYTES_DELTA: u64 = 0x40;
/// Not an upstream constant: a bound on how many bytes to fetch when
/// probing for a string at a dereferenced address (we deliberately don't port
/// vivisect's `detectString`/`detectUnicode`, decide our own equivalent).
///
/// `detectString` bounds itself only by the containing memory map
/// (`maxlen = len(bytez) - offset`, `vivisect/__init__.py:1033`), and
/// `capa/features/extractors/viv/insn.py:read_string` calls it with no length
/// of its own, so any fixed window here is a divergence by construction: a
/// string longer than the window is truncated, and a rule needing content past
/// it cannot match. That was KD-013, on a 5,006-byte string.
///
/// The window is now large enough that `LoadedImage::bytes_at`'s clamp to the
/// end of the containing section is what actually bounds the read, which *is*
/// `detectString`'s rule. It is kept finite rather than removed because the
/// scanners hand back an owned `String`, so the bound also caps one
/// allocation.
///
/// Widening it is close to free, which the old value's "costs extraction time
/// on every dereferenced operand" reasoning had wrong: `detect_string` is a
/// `take_while(printable).count()` and `detect_unicode` stops at the first zero
/// low byte, so both cost the length of the run they find, not the length of
/// the window, and `bytes_at` is O(1). Measured over `corpus-outer.txt` with
/// `--no-rust-cache`: 1136.6s at `0x400` against 1148.7s here, +1.1%, at the
/// level of run-to-run variance. It buys `schedule task via at` on
/// `5789181c…`, whose string is 5,006 bytes.
const STRING_SCAN_WINDOW: usize = 0x10000;
/// capa/features/common.py: MAX_BYTES_FEATURE_SIZE
const MAX_BYTES_FEATURE_SIZE: usize = 0x100;

/// envi's `DESTRUCTIVE_MNEMONICS` (`viv/indirect_calls.py`).
const DESTRUCTIVE_MNEMONICS: [&str; 4] = ["mov", "lea", "pop", "xor"];

pub struct InsnContext<'a> {
    pub analysis: &'a Analysis,
    /// FLIRT-recognized library function names by address
    /// (`identify_library_functions`'s result).
    pub libraries: &'a BTreeMap<u64, String>,
    pub function: &'a Function,
    pub block: &'a BasicBlock,
}

fn addr(insn: &super::image::DecodedInstruction) -> Address {
    Address::Absolute(insn.address)
}

/// capa/features/extractors/viv/insn.py: `extract_features` /
/// `INSTRUCTION_HANDLERS`. Order matters -- it's the insertion order into
/// this instruction's `FeatureSet`.
pub fn extract_features(
    ctx: &InsnContext,
    insn: &super::image::DecodedInstruction,
) -> Vec<(Address, Feature)> {
    let mnemonic = mnemonic_text(insn);
    let mut out = Vec::new();
    out.extend(extract_insn_api_features(ctx, insn, &mnemonic));
    out.extend(extract_insn_bytes_features(ctx, insn, &mnemonic));
    out.extend(extract_insn_nzxor_characteristic_features(
        ctx, insn, &mnemonic,
    ));
    out.push((addr(insn), Feature::Mnemonic(mnemonic.clone())));
    out.extend(extract_insn_obfs_call_plus_5_characteristic_features(
        insn, &mnemonic,
    ));
    out.extend(extract_insn_peb_access_characteristic_features(
        insn, &mnemonic,
    ));
    out.extend(extract_insn_cross_section_cflow(ctx, insn, &mnemonic));
    out.extend(extract_insn_segment_access_features(insn));
    out.extend(extract_function_calls_from(
        insn,
        ctx.function.addr,
        &mnemonic,
    ));
    out.extend(extract_function_indirect_call_characteristic_features(
        insn, &mnemonic,
    ));
    out.extend(extract_operand_features(ctx, insn, &mnemonic));
    out
}

/// capa/features/extractors/viv/insn.py: `extract_insn_mnemonic_features`,
/// via a masm-flavor `iced_x86::Formatter` (no formatting feature was
/// otherwise needed before this). `NO_PREFIXES` matches envi's
/// `insn.mnem`, which excludes `rep`/`lock`/segment-override prefixes --
/// those are covered separately by `extract_insn_segment_access_features`.
pub(crate) fn mnemonic_text(insn: &super::image::DecodedInstruction) -> String {
    if let Some(mnemonic) = insn.mnemonic_override {
        // envi decoded an opcode iced-x86 rejects; `insn.x86_instruction()` is only
        // a carrier there, so formatting it would name the wrong instruction.
        return mnemonic.to_string();
    }
    let mut formatter = MasmFormatter::new();
    let mut output = String::new();
    formatter.format_mnemonic_options(
        insn.x86_instruction(),
        &mut output,
        FormatMnemonicOptions::NO_PREFIXES,
    );
    output.make_ascii_lowercase();
    output
}

/// A function consisting of exactly one unconditional-jump instruction --
/// stand-in for `viv_utils`' `Thunk` function-metadata flag (viv's thunk
/// classifier itself is heuristic and not reproduced here; this covers the
/// common single-instruction jump-stub case it's meant to catch).
fn is_thunk_function(function: &Function) -> bool {
    let mut insns = function.blocks.iter().flat_map(|block| block.insns.iter());
    let Some(only) = insns.next() else {
        return false;
    };
    if insns.next().is_some() {
        return false;
    }
    matches!(
        only.x86_instruction().flow_control(),
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
    )
}

/// Stand-in for "the first `REF_CODE` xref whose origin is `va`"
/// (`viv/helpers.py:get_coderef_from`), restricted to actual control-flow
/// instructions so it never treats a `mov`/`lea`'s memory operand as a code
/// reference the way [`super::operand::classify_operand`] alone would.
fn code_ref_from(analysis: &Analysis, va: u64) -> Option<u64> {
    let insn = analysis.instructions.get(&va)?;
    match insn.x86_instruction().flow_control() {
        // A conditional branch has exactly one `REF_CODE` xref -- its taken
        // target. `makeOpcode` (`vivisect/__init__.py:1420`) skips
        // `BR_FALL`: "vivisect does NOT create REF_CODE entries for
        // instruction fall through". The thunk-chain walk in
        // `extract_insn_api_features` really does step through these; on
        // `9b7ccaa2…dll_` the chain to `CryptBinaryToStringW` runs
        // `jmp` -> `jz` -> `call [<import>]`.
        FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
            recovery::direct_target(insn).or_else(|| recovery::memory_target(insn))
        }
        FlowControl::IndirectCall | FlowControl::IndirectBranch => recovery::memory_target(insn),
        _ => None,
    }
}

/// port of `viv/indirect_calls.py:get_previous_instructions`. Upstream
/// calls `vw.getPrevLocation(va, adjacent=True)` twice in a row (`loc` then
/// `ploc`) with identical arguments -- a deterministic call, so `ploc` is
/// always exactly `loc`; this is ported as the single lookup that produces,
/// not two.
fn get_previous_instructions(analysis: &Analysis, va: u64) -> Vec<u64> {
    let mut out = Vec::new();
    if let Some((&prev_addr, prev_insn)) = analysis.instructions.range(..va).next_back() {
        let end = prev_addr.saturating_add(prev_insn.bytes.len() as u64);
        if end == va && falls_through(prev_insn.x86_instruction()) {
            out.push(prev_addr);
        }
    }
    if let Some(sources) = analysis.code_xrefs.get(&va) {
        for &source in sources {
            // envi's FAR_BRANCH_MASK excludes calls ("ignore any calls");
            // approximated here as "the source instruction is itself a
            // call", since a callee's return address isn't a meaningful
            // predecessor for local register-definition analysis.
            let is_call = analysis
                .instructions
                .get(&source)
                .is_some_and(|source_insn| {
                    matches!(
                        source_insn.x86_instruction().flow_control(),
                        FlowControl::Call | FlowControl::IndirectCall
                    )
                });
            if !is_call {
                out.push(source);
            }
        }
    }
    out
}

/// stand-in for envi's `IF_NOFALL` flag: does control reach the next
/// instruction after this one, absent an explicit incoming branch?
fn falls_through(instruction: &Instruction) -> bool {
    !matches!(
        instruction.flow_control(),
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch | FlowControl::Return
    )
}

/// port of `viv/indirect_calls.py:find_definition` (backward dataflow scan
/// for the last assignment to `reg` reaching `va`). Upstream returns
/// `(address, Optional[value])` and raises `NotFoundError` if the search is
/// exhausted; both "not found" and "found but not a resolvable constant"
/// leave the caller with nothing to yield, so this collapses to `Option`.
fn find_definition(analysis: &Analysis, va: u64, reg: Register) -> Option<u64> {
    let mut queue: VecDeque<u64> = get_previous_instructions(analysis, va).into();
    let mut seen = BTreeSet::new();
    while let Some(cur) = queue.pop_front() {
        if !seen.insert(cur) {
            continue;
        }
        let Some(insn) = analysis.instructions.get(&cur) else {
            continue;
        };
        if insn.x86_instruction().op_count() == 0 {
            queue.extend(get_previous_instructions(analysis, cur));
            continue;
        }
        let mnemonic = mnemonic_text(insn);
        let is_destructive_to_reg = matches!(classify_operand(insn.x86_instruction(), 0), Operand::Reg(r) if r == reg)
            && DESTRUCTIVE_MNEMONICS.contains(&mnemonic.as_str());
        if !is_destructive_to_reg {
            queue.extend(get_previous_instructions(analysis, cur));
            continue;
        }
        if mnemonic != "mov" {
            return None;
        }
        return match classify_operand(insn.x86_instruction(), 1) {
            Operand::Imm(v) => Some(v as u64),
            Operand::ImmMem(v) => Some(v),
            Operand::RipRel(v) => Some(v),
            _ => None,
        };
    }
    None
}

/// port of `viv/insn.py:derefs`: recursively follow a pointer chain,
/// stopping at an invalid pointer, a self-loop, depth 10, or once a
/// qualifying string is found at the current address (that address is
/// still yielded, matching upstream's `yield p` before the string check).
fn derefs(image: &LoadedImage, start: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut p = start;
    let mut depth = 0;
    loop {
        if !is_valid_pointer(image, p) {
            break;
        }
        out.push(p);
        let window = image.bytes_at(p, STRING_SCAN_WINDOW).unwrap_or(&[]);
        if strings::is_probably_string(window) {
            break;
        }
        let Some(next) = recovery::read_pointer(image, p) else {
            break;
        };
        if next == p {
            break;
        }
        depth += 1;
        if depth > 10 {
            break;
        }
        p = next;
    }
    out
}

/// stand-in for `vw.isValidPointer`/`vw.probeMemory(v, 1, MM_READ)`: is
/// `address` inside a mapped, readable region of the image? Address values
/// derived from operand fields are reinterpreted as an unsigned VA (same as
/// passing a Python int, however computed, straight into `probeMemory`).
fn is_valid_pointer(image: &LoadedImage, address: u64) -> bool {
    image
        .section_containing(address)
        .is_some_and(|section| section.permissions.read)
}

fn is_probably_mapped_address(image: &LoadedImage, value: i128) -> bool {
    // `probeMemory` takes whatever integer the operand produced; anything
    // wider than a VA simply isn't mapped.
    u64::try_from(value).is_ok_and(|address| is_valid_pointer(image, address))
}

/// capa/features/extractors/viv/insn.py: `extract_insn_api_features`.
fn extract_insn_api_features(
    ctx: &InsnContext,
    insn: &super::image::DecodedInstruction,
    mnemonic: &str,
) -> Vec<(Address, Feature)> {
    let mut out = Vec::new();
    if mnemonic != "call" && mnemonic != "jmp" {
        return out;
    }
    if mnemonic == "jmp" && is_thunk_function(ctx.function) {
        return out;
    }

    let push_api_names = |out: &mut Vec<(Address, Feature)>, target: u64| {
        if let Some(names) = ctx.analysis.image.external_bindings.get(&target) {
            for name in names {
                out.push((addr(insn), Feature::Api(name.clone())));
            }
        }
    };

    match classify_operand(insn.x86_instruction(), 0) {
        // traditional call via IAT: `call dword [0x00473038]`
        Operand::ImmMem(target) => push_api_names(&mut out, target),
        // call via import on x64: `call qword [rip+X]`
        Operand::RipRel(target) => push_api_names(&mut out, target),
        // indirect call, e.g. `call eax`
        Operand::Reg(reg) => {
            if let Some(target) = find_definition(ctx.analysis, insn.address, reg) {
                push_api_names(&mut out, target);
            }
        }
        _ if is_near_branch(insn.x86_instruction()) => {
            // call/jmp via thunk on x86, or to an internal function on x64.
            let Some(mut target) = code_ref_from(ctx.analysis, insn.address) else {
                return out;
            };

            if ctx.analysis.image.format == ImageFormat::Elf {
                if let Some(names) = ctx.analysis.elf_function_symbols.get(&target) {
                    for name in names {
                        out.push((addr(insn), Feature::Api(name.clone())));
                    }
                }
            }

            if let Some(name) = ctx.libraries.get(&target) {
                out.push((addr(insn), Feature::Api(name.clone())));
                if let Some(unmangled) = name.strip_prefix('_') {
                    out.push((addr(insn), Feature::Api(unmangled.to_string())));
                }
                return out;
            }

            for _ in 0..THUNK_CHAIN_DEPTH_DELTA {
                push_api_names(&mut out, target);

                // if the jump leads to an ENDBRANCH instruction, skip it.
                if ctx
                    .analysis
                    .image
                    .bytes_at(target, 3)
                    .is_some_and(|bytes| bytes == [0xf3, 0x0f, 0x1e])
                {
                    target = target.wrapping_add(4);
                }

                let Some(next_target) = code_ref_from(ctx.analysis, target) else {
                    return out;
                };
                target = next_target;
            }
        }
        _ => {}
    }
    out
}

fn is_near_branch(instruction: &Instruction) -> bool {
    matches!(
        instruction.op_kind(0),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

/// port of `viv/insn.py:read_bytes` + `extract_insn_bytes_features`. Unlike
/// upstream's manual segment-end clamp, [`LoadedImage::bytes_at`] already
/// bounds reads to the containing mapping.
fn extract_insn_bytes_features(
    ctx: &InsnContext,
    insn: &super::image::DecodedInstruction,
    mnemonic: &str,
) -> Vec<(Address, Feature)> {
    let mut out = Vec::new();
    if mnemonic == "call" {
        return out;
    }
    for i in 0..insn.x86_instruction().op_count() {
        // note: `ImmMemOper` is deliberately absent here (matches upstream)
        // -- absolute-address memory operands don't feed the bytes feature.
        let v: u64 = match classify_operand(insn.x86_instruction(), i) {
            Operand::Imm(v) => v as u64,
            Operand::RegMem { disp, .. } => disp as u64,
            // `oper.imm` (matches upstream's `i386SibOper` branch), not
            // `.disp` -- see `Operand::Sib`'s doc comment.
            Operand::Sib { imm: Some(imm), .. } => imm,
            Operand::RipRel(addr) => addr,
            _ => continue,
        };
        for candidate in derefs(&ctx.analysis.image, v) {
            let Some(buf) = ctx
                .analysis
                .image
                .bytes_at(candidate, MAX_BYTES_FEATURE_SIZE)
            else {
                continue;
            };
            if all_zeros(buf) {
                continue;
            }
            if strings::is_probably_string(buf) {
                continue;
            }
            out.push((addr(insn), Feature::Bytes(buf.to_vec())));
        }
    }
    out
}

/// port of `viv/insn.py:is_security_cookie`.
fn is_security_cookie(
    function: &Function,
    block: &BasicBlock,
    insn: &super::image::DecodedInstruction,
) -> bool {
    if insn.x86_instruction().op_count() >= 2 {
        if let Operand::Reg(reg) = classify_operand(insn.x86_instruction(), 1) {
            if !matches!(
                reg,
                Register::ESP | Register::EBP | Register::RBP | Register::RSP
            ) {
                return false;
            }
        }
    }
    let Some(first_block) = function.blocks.first() else {
        return false;
    };
    if block.addr == first_block.addr
        && insn.address < block.addr.wrapping_add(SECURITY_COOKIE_BYTES_DELTA)
    {
        return true;
    }
    if let Some(last) = block.insns.last() {
        if last.x86_instruction().flow_control() == FlowControl::Return {
            let block_end = last.address.saturating_add(last.bytes.len() as u64);
            let block_size = block_end.saturating_sub(block.addr);
            if insn.address
                > block
                    .addr
                    .wrapping_add(block_size)
                    .wrapping_sub(SECURITY_COOKIE_BYTES_DELTA)
            {
                return true;
            }
        }
    }
    false
}

/// port of `viv/insn.py:extract_insn_nzxor_characteristic_features`.
fn extract_insn_nzxor_characteristic_features(
    ctx: &InsnContext,
    insn: &super::image::DecodedInstruction,
    mnemonic: &str,
) -> Vec<(Address, Feature)> {
    if !matches!(mnemonic, "xor" | "xorpd" | "xorps" | "pxor") {
        return Vec::new();
    }
    if insn.x86_instruction().op_count() >= 2
        && classify_operand(insn.x86_instruction(), 0)
            == classify_operand(insn.x86_instruction(), 1)
    {
        return Vec::new();
    }
    if is_security_cookie(ctx.function, ctx.block, insn) {
        return Vec::new();
    }
    vec![(addr(insn), Feature::Characteristic("nzxor".to_string()))]
}

/// port of `viv/insn.py:extract_insn_obfs_call_plus_5_characteristic_features`.
fn extract_insn_obfs_call_plus_5_characteristic_features(
    insn: &super::image::DecodedInstruction,
    mnemonic: &str,
) -> Vec<(Address, Feature)> {
    if mnemonic != "call" {
        return Vec::new();
    }
    let expected = insn.address.wrapping_add(5);
    let hit = if is_near_branch(insn.x86_instruction()) {
        insn.x86_instruction().near_branch_target() == expected
    } else {
        matches!(
            classify_operand(insn.x86_instruction(), 0),
            Operand::ImmMem(target) | Operand::RipRel(target) if target == expected
        )
    };
    if hit {
        vec![(addr(insn), Feature::Characteristic("call $+5".to_string()))]
    } else {
        Vec::new()
    }
}

/// port of `viv/insn.py:extract_insn_peb_access_characteristic_features`.
fn extract_insn_peb_access_characteristic_features(
    insn: &super::image::DecodedInstruction,
    mnemonic: &str,
) -> Vec<(Address, Feature)> {
    let mut out = Vec::new();
    if mnemonic != "push" && mnemonic != "mov" {
        return out;
    }
    let segment = insn.x86_instruction().segment_prefix();
    for i in 0..insn.x86_instruction().op_count() {
        let hits = matches!(
            (segment, classify_operand(insn.x86_instruction(), i)),
            (Register::FS, Operand::RegMem { disp: 0x30, .. })
                | (Register::FS, Operand::ImmMem(0x30))
                | (Register::GS, Operand::RegMem { disp: 0x60, .. })
                | (
                    Register::GS,
                    Operand::Sib {
                        imm: Some(0x60),
                        ..
                    }
                )
                | (Register::GS, Operand::ImmMem(0x60))
        );
        if hits {
            out.push((
                addr(insn),
                Feature::Characteristic("peb access".to_string()),
            ));
        }
    }
    out
}

/// port of `viv/insn.py:extract_insn_segment_access_features`.
fn extract_insn_segment_access_features(
    insn: &super::image::DecodedInstruction,
) -> Vec<(Address, Feature)> {
    match insn.x86_instruction().segment_prefix() {
        Register::FS => vec![(addr(insn), Feature::Characteristic("fs access".to_string()))],
        Register::GS => vec![(addr(insn), Feature::Characteristic("gs access".to_string()))],
        _ => Vec::new(),
    }
}

/// port of `viv/insn.py:extract_insn_cross_section_cflow`.
fn extract_insn_cross_section_cflow(
    ctx: &InsnContext,
    insn: &super::image::DecodedInstruction,
    mnemonic: &str,
) -> Vec<(Address, Feature)> {
    let mut out = Vec::new();
    for target in branch_targets(ctx.analysis, insn) {
        if mnemonic == "call" {
            let calls_import = match classify_operand(insn.x86_instruction(), 0) {
                Operand::ImmMem(a) | Operand::RipRel(a) => {
                    ctx.analysis.image.external_bindings.contains_key(&a)
                }
                _ => false,
            };
            if calls_import {
                continue;
            }
        }
        let Some(source_section) = ctx.analysis.image.section_containing(insn.address) else {
            continue;
        };
        let Some(target_section) = ctx.analysis.image.section_containing(target) else {
            continue;
        };
        if source_section.address != target_section.address {
            out.push((
                addr(insn),
                Feature::Characteristic("cross section flow".to_string()),
            ));
        }
    }
    out
}

fn branch_targets(analysis: &Analysis, insn: &super::image::DecodedInstruction) -> Vec<u64> {
    match insn.x86_instruction().flow_control() {
        FlowControl::Call
        | FlowControl::UnconditionalBranch
        | FlowControl::ConditionalBranch
        | FlowControl::XbeginXabortXend => recovery::direct_target(insn).into_iter().collect(),
        FlowControl::IndirectCall => recovery::memory_target(insn).into_iter().collect(),
        FlowControl::IndirectBranch => recovery::jump_table_targets(&analysis.image, insn),
        _ => Vec::new(),
    }
}

/// port of `viv/insn.py:extract_function_calls_from`. Note the location is
/// the *target*, not the instruction address.
fn extract_function_calls_from(
    insn: &super::image::DecodedInstruction,
    function_addr: u64,
    mnemonic: &str,
) -> Vec<(Address, Feature)> {
    if mnemonic != "call" {
        return Vec::new();
    }
    let target = match classify_operand(insn.x86_instruction(), 0) {
        Operand::ImmMem(target) => Some(target),
        Operand::RipRel(target) => Some(target),
        _ if is_near_branch(insn.x86_instruction()) => {
            Some(insn.x86_instruction().near_branch_target())
        }
        _ => None,
    };
    let Some(target) = target else {
        return Vec::new();
    };
    let mut out = vec![(
        Address::Absolute(target),
        Feature::Characteristic("calls from".to_string()),
    )];
    if target == function_addr {
        out.push((
            Address::Absolute(target),
            Feature::Characteristic("recursive call".to_string()),
        ));
    }
    out
}

/// port of `viv/insn.py:extract_function_indirect_call_characteristic_features`.
fn extract_function_indirect_call_characteristic_features(
    insn: &super::image::DecodedInstruction,
    mnemonic: &str,
) -> Vec<(Address, Feature)> {
    if mnemonic != "call" {
        return Vec::new();
    }
    match classify_operand(insn.x86_instruction(), 0) {
        Operand::Reg(_) | Operand::RegMem { .. } | Operand::Sib { .. } => {
            vec![(
                addr(insn),
                Feature::Characteristic("indirect call".to_string()),
            )]
        }
        _ => Vec::new(),
    }
}

/// port of `viv/insn.py:extract_operand_features` / `OPERAND_HANDLERS`.
fn extract_operand_features(
    ctx: &InsnContext,
    insn: &super::image::DecodedInstruction,
    mnemonic: &str,
) -> Vec<(Address, Feature)> {
    let mut out = Vec::new();
    for i in 0..insn.x86_instruction().op_count() {
        out.extend(extract_op_number_features(ctx, insn, mnemonic, i));
        out.extend(extract_op_offset_features(ctx, insn, mnemonic, i));
        out.extend(extract_op_string_features(ctx, insn, i));
    }
    out
}

/// envi's `i386ImmOper.getOperValue()` (feeding `Number`/`OperandNumber`)
/// reports the raw N-bit pattern of an immediate operand as an unsigned
/// magnitude -- e.g. `cmp eax, -1` (`83 f8 ff`, a `cmp r/m32, imm8`
/// sign-extending its one-byte encoding to fill the 32-bit destination) is
/// `Number(0xFFFFFFFF)`, never `Number(-1)`. iced-x86's `immediate()`
/// sign-extends the 8to16/8to32/8to64/32to64 kinds to the full 64-bit `u64`
/// return type regardless of the operand's actual width (`i32 as u64` et
/// al. sign-extend under Rust's numeric cast rules), so truncate back down
/// to that width to recover envi's convention. Scoped to this call site
/// only -- other `Operand::Imm` consumers (e.g. indirect-call pointer
/// resolution) want iced's natively sign-extended value instead.
fn immediate_number_value(instruction: &Instruction, index: u32) -> i128 {
    let raw = instruction.immediate(index);
    let width_bits = match instruction.op_kind(index) {
        OpKind::Immediate8 | OpKind::Immediate8_2nd => 8,
        OpKind::Immediate16 | OpKind::Immediate8to16 => 16,
        // envi's amd64 table is not uniform for a 32-bit immediate in a
        // 64-bit operand: `add rax, imm32` and `push imm32` report the
        // sign-extended 64-bit pattern, while `cmp`/`and`/`test`/`mov
        // rm64, imm32` report the bare 32-bit one. Only the sign bit can
        // tell them apart at all, and this takes the majority form. A
        // *positive* imm32 -- the overwhelmingly common case -- is
        // identical either way.
        OpKind::Immediate32 | OpKind::Immediate8to32 | OpKind::Immediate32to64 => 32,
        // Immediate64/Immediate8to64.
        _ => 64,
    };
    if width_bits >= 64 {
        // unsigned: `mov rcx, 0xcbbb9d5dc1059ed8` (SHA-384's H(0)0) is
        // `Number(0xcbbb9d5dc1059ed8)` upstream, not its negative i64
        // reinterpretation.
        i128::from(raw)
    } else {
        i128::from(raw & ((1u64 << width_bits) - 1))
    }
}

/// port of `viv/insn.py:extract_op_number_features`.
fn extract_op_number_features(
    ctx: &InsnContext,
    insn: &super::image::DecodedInstruction,
    mnemonic: &str,
    i: u32,
) -> Vec<(Address, Feature)> {
    let value: i128 = match classify_operand(insn.x86_instruction(), i) {
        Operand::Imm(_) => immediate_number_value(insn.x86_instruction(), i),
        Operand::ImmMem(v) => i128::from(v),
        _ => return Vec::new(),
    };
    if is_probably_mapped_address(&ctx.analysis.image, value) {
        // looks like a valid address; assume it's not also a constant.
        return Vec::new();
    }
    // capa/features/extractors/viv/insn.py only excludes `add esp, N`
    // (32-bit `REG_ESP`) here, not `add rsp, N` on x64 -- preserved as-is.
    if mnemonic == "add"
        && matches!(
            classify_operand(insn.x86_instruction(), 0),
            Operand::Reg(Register::ESP)
        )
    {
        return Vec::new();
    }

    let mut out = vec![
        (addr(insn), Feature::Number(NumberValue::Int(value))),
        (
            addr(insn),
            Feature::OperandNumber(i as u8, NumberValue::Int(value)),
        ),
    ];
    if mnemonic == "add"
        && value > 0
        && value < i128::from(MAX_STRUCTURE_SIZE)
        && matches!(classify_operand(insn.x86_instruction(), i), Operand::Imm(_))
    {
        // bounded by MAX_STRUCTURE_SIZE just above, so this can't truncate.
        let offset = value as i64;
        out.push((addr(insn), Feature::Offset(offset)));
        out.push((addr(insn), Feature::OperandOffset(i as u8, offset)));
    }
    out
}

/// port of `viv/insn.py:extract_op_offset_features`.
fn extract_op_offset_features(
    ctx: &InsnContext,
    insn: &super::image::DecodedInstruction,
    mnemonic: &str,
    i: u32,
) -> Vec<(Address, Feature)> {
    let mut out = Vec::new();
    match classify_operand(insn.x86_instruction(), i) {
        Operand::RegMem { base, disp } => {
            // capa/features/extractors/viv/insn.py excludes ESP/EBP/RBP
            // only for i386RegMemOper. ESP/RSP encodings classified as
            // i386SibOper take the branch below instead.
            if matches!(base, Register::ESP | Register::EBP | Register::RBP) {
                return out;
            }
            out.push((addr(insn), Feature::Offset(disp)));
            out.push((addr(insn), Feature::OperandOffset(i as u8, disp)));
            if mnemonic == "lea"
                && i == 1
                && !is_probably_mapped_address(&ctx.analysis.image, i128::from(disp))
            {
                out.push((addr(insn), Feature::Number(NumberValue::Int(disp as i128))));
                out.push((
                    addr(insn),
                    Feature::OperandNumber(i as u8, NumberValue::Int(disp as i128)),
                ));
            }
        }
        Operand::Sib { disp, .. } => {
            out.push((addr(insn), Feature::Offset(disp)));
            out.push((addr(insn), Feature::OperandOffset(i as u8, disp)));
        }
        _ => {}
    }
    out
}

/// port of `viv/insn.py:extract_op_string_features`.
fn extract_op_string_features(
    ctx: &InsnContext,
    insn: &super::image::DecodedInstruction,
    i: u32,
) -> Vec<(Address, Feature)> {
    let mut out = Vec::new();
    // note: `RegMemOper` is deliberately absent here (matches upstream) --
    // `[base+disp]` operands don't feed the string feature.
    let v: u64 = match classify_operand(insn.x86_instruction(), i) {
        Operand::Imm(v) => v as u64,
        Operand::ImmMem(v) => v,
        // `oper.imm` (matches upstream's `i386SibOper` branch), not
        // `.disp` -- see `Operand::Sib`'s doc comment.
        Operand::Sib { imm: Some(imm), .. } => imm,
        Operand::RipRel(v) => v,
        _ => return out,
    };
    for candidate in derefs(&ctx.analysis.image, v) {
        let Some(buf) = ctx.analysis.image.bytes_at(candidate, STRING_SCAN_WINDOW) else {
            continue;
        };
        let Some(s) = strings::string_at(buf) else {
            continue;
        };
        if s.len() >= 4 {
            out.push((addr(insn), Feature::String(StringFeature::Plain(s))));
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::extract::image::{Architecture, DecodedInstruction, MappedSection, Permissions};

    const CODE_BASE: u64 = 0x1000;

    /// A hand-built `Analysis` + single-block `Function` for exercising one
    /// extractor at a time without a real PE/ELF sample. `regions[0]` is
    /// the function under test; any further regions/data are only there to
    /// give xref-following extractors (api thunk chains, cross-section
    /// flow) something to resolve against.
    struct Fixture {
        analysis: Analysis,
        function: Function,
    }

    impl Fixture {
        fn build(
            format: ImageFormat,
            architecture: Architecture,
            regions: Vec<(u64, Vec<u8>)>,
            data_regions: Vec<(u64, Vec<u8>)>,
            external_bindings: BTreeMap<u64, Vec<String>>,
        ) -> Self {
            let code_perms = Permissions {
                read: true,
                write: false,
                execute: true,
            };
            let data_perms = Permissions {
                read: true,
                write: false,
                execute: false,
            };
            let mut combined = Vec::new();
            let mut sections = Vec::new();
            for (address, bytes) in &regions {
                let file_offset = combined.len() as u64;
                combined.extend_from_slice(bytes);
                sections.push(MappedSection {
                    name: ".text".to_string(),
                    address: *address,
                    virtual_size: bytes.len() as u64,
                    file_offset,
                    file_size: bytes.len() as u64,
                    permissions: code_perms,
                });
            }
            for (address, bytes) in &data_regions {
                let file_offset = combined.len() as u64;
                combined.extend_from_slice(bytes);
                sections.push(MappedSection {
                    name: ".data".to_string(),
                    address: *address,
                    virtual_size: bytes.len() as u64,
                    file_offset,
                    file_size: bytes.len() as u64,
                    permissions: data_perms,
                });
            }
            let image_base = regions.first().map_or(CODE_BASE, |(a, _)| *a);
            let image = crate::extract::image::LoadedImage::for_test(
                format,
                architecture,
                image_base,
                sections,
                external_bindings,
                combined,
            );

            let mut instructions = BTreeMap::new();
            let mut decoded_regions: Vec<Vec<DecodedInstruction>> = Vec::new();
            for (start, bytes) in &regions {
                let mut insns = Vec::new();
                let mut address = *start;
                let end = start + bytes.len() as u64;
                while address < end {
                    let insn = image
                        .decode_at(address)
                        .expect("fixture region decodes cleanly");
                    address = insn.x86_instruction().next_ip();
                    instructions.insert(insn.address, insn.clone());
                    insns.push(insn);
                }
                decoded_regions.push(insns);
            }

            let function_addr = regions.first().map_or(CODE_BASE, |(a, _)| *a);
            let block = BasicBlock {
                addr: function_addr,
                insns: decoded_regions.first().cloned().unwrap_or_default(),
                succs: Vec::new(),
            };
            let function = Function {
                addr: function_addr,
                blocks: vec![block],
            };

            let analysis = Analysis {
                image,
                seeds: BTreeMap::new(),
                functions: BTreeMap::new(),
                instructions,
                code_xrefs: BTreeMap::new(),
                data_xrefs: BTreeMap::new(),
                callers: BTreeMap::new(),
                callees: BTreeMap::new(),
                diagnostics: Vec::new(),
                elf_function_symbols: BTreeMap::new(),
                noreturn: BTreeSet::new(),
                noreturn_calls: BTreeSet::new(),
            };
            Fixture { analysis, function }
        }

        fn x86(code: &[u8]) -> Self {
            Self::build(
                ImageFormat::Pe,
                Architecture::X86,
                vec![(CODE_BASE, code.to_vec())],
                Vec::new(),
                BTreeMap::new(),
            )
        }

        fn x64(code: &[u8]) -> Self {
            Self::build(
                ImageFormat::Pe,
                Architecture::X64,
                vec![(CODE_BASE, code.to_vec())],
                Vec::new(),
                BTreeMap::new(),
            )
        }

        fn with_data(code: &[u8], data_addr: u64, data: Vec<u8>) -> Self {
            Self::build(
                ImageFormat::Pe,
                Architecture::X86,
                vec![(CODE_BASE, code.to_vec())],
                vec![(data_addr, data)],
                BTreeMap::new(),
            )
        }

        fn insn(&self, index: usize) -> &DecodedInstruction {
            &self.function.blocks[0].insns[index]
        }

        fn ctx<'a>(&'a self, libraries: &'a BTreeMap<u64, String>) -> InsnContext<'a> {
            InsnContext {
                analysis: &self.analysis,
                libraries,
                function: &self.function,
                block: &self.function.blocks[0],
            }
        }
    }

    fn no_libraries() -> BTreeMap<u64, String> {
        BTreeMap::new()
    }

    // ---- mnemonic ----

    #[test]
    fn mnemonic_text_is_lowercase_and_prefix_free() {
        let fixture = Fixture::x86(&[0x90]); // nop
        assert_eq!(mnemonic_text(fixture.insn(0)), "nop");
        let fixture = Fixture::x86(&[0xff, 0xd0]); // call eax
        assert_eq!(mnemonic_text(fixture.insn(0)), "call");
    }

    // ---- api ----

    #[test]
    fn api_direct_iat_call_via_imm_mem() {
        // call dword [0x9000]
        let fixture = Fixture::build(
            ImageFormat::Pe,
            Architecture::X86,
            vec![(CODE_BASE, vec![0xff, 0x15, 0x00, 0x90, 0x00, 0x00])],
            Vec::new(),
            BTreeMap::from([(0x9000, vec!["kernel32.CreateFileA".to_string()])]),
        );
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        let out = extract_insn_api_features(&ctx, insn, &mnemonic_text(insn));
        assert_eq!(
            out,
            vec![(addr(insn), Feature::Api("kernel32.CreateFileA".to_string()))]
        );
    }

    #[test]
    fn api_x64_rip_relative_import_call() {
        // call qword [rip+0x10] -- next_ip is CODE_BASE+6, so the target is
        // CODE_BASE+6+0x10.
        let fixture = Fixture::build(
            ImageFormat::Pe,
            Architecture::X64,
            vec![(CODE_BASE, vec![0xff, 0x15, 0x10, 0x00, 0x00, 0x00])],
            Vec::new(),
            BTreeMap::from([(CODE_BASE + 6 + 0x10, vec!["ntdll.NtOpenFile".to_string()])]),
        );
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        let out = extract_insn_api_features(&ctx, insn, &mnemonic_text(insn));
        assert_eq!(
            out,
            vec![(addr(insn), Feature::Api("ntdll.NtOpenFile".to_string()))]
        );
    }

    #[test]
    fn api_indirect_call_resolved_via_backward_register_definition() {
        // mov eax, dword [0x9000]
        // call eax
        let fixture = Fixture::build(
            ImageFormat::Pe,
            Architecture::X86,
            vec![(
                CODE_BASE,
                vec![0x8b, 0x05, 0x00, 0x90, 0x00, 0x00, 0xff, 0xd0],
            )],
            Vec::new(),
            BTreeMap::from([(0x9000, vec!["ws2_32.recv".to_string()])]),
        );
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let call = fixture.insn(1);
        let out = extract_insn_api_features(&ctx, call, "call");
        assert_eq!(
            out,
            vec![(addr(call), Feature::Api("ws2_32.recv".to_string()))]
        );
    }

    #[test]
    fn api_thunk_chain_follows_jmp_through_iat() {
        // function under test: call 0x2000 (a thunk elsewhere in the image)
        // thunk: jmp dword [0x9000]
        let fixture = Fixture::build(
            ImageFormat::Pe,
            Architecture::X86,
            vec![
                (CODE_BASE, vec![0xe8, 0xfb, 0x0f, 0x00, 0x00]),
                (0x2000, vec![0xff, 0x25, 0x00, 0x90, 0x00, 0x00]),
            ],
            Vec::new(),
            BTreeMap::from([(0x9000, vec!["ntdll.RtlAllocateHeap".to_string()])]),
        );
        assert_eq!(
            fixture.insn(0).x86_instruction().near_branch_target(),
            0x2000
        );
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let call = fixture.insn(0);
        let out = extract_insn_api_features(&ctx, call, "call");
        assert_eq!(
            out,
            vec![(
                addr(call),
                Feature::Api("ntdll.RtlAllocateHeap".to_string())
            )]
        );
    }

    #[test]
    fn api_flirt_recognized_thunk_yields_library_name_and_unmangled_alias() {
        // call 0x2000, where 0x2000 is a FLIRT-recognized library function.
        let fixture = Fixture::build(
            ImageFormat::Pe,
            Architecture::X86,
            vec![(CODE_BASE, vec![0xe8, 0xfb, 0x0f, 0x00, 0x00])],
            Vec::new(),
            BTreeMap::new(),
        );
        let libraries = BTreeMap::from([(0x2000, "_recognized_thunk".to_string())]);
        let ctx = fixture.ctx(&libraries);
        let call = fixture.insn(0);
        let out = extract_insn_api_features(&ctx, call, "call");
        assert_eq!(
            out,
            vec![
                (addr(call), Feature::Api("_recognized_thunk".to_string())),
                (addr(call), Feature::Api("recognized_thunk".to_string())),
            ]
        );
    }

    #[test]
    fn api_elf_direct_call_to_stt_func_symbol() {
        let mut fixture = Fixture::build(
            ImageFormat::Elf,
            Architecture::X86,
            vec![(CODE_BASE, vec![0xe8, 0xfb, 0x0f, 0x00, 0x00])],
            Vec::new(),
            BTreeMap::new(),
        );
        fixture
            .analysis
            .elf_function_symbols
            .insert(0x2000, vec!["sym_foo".to_string()]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let call = fixture.insn(0);
        let out = extract_insn_api_features(&ctx, call, "call");
        assert_eq!(out, vec![(addr(call), Feature::Api("sym_foo".to_string()))]);
    }

    #[test]
    fn api_skipped_for_jmp_inside_a_single_instruction_thunk_function() {
        // the whole "function" is just this one jmp -- viv_utils would flag
        // it as a Thunk, and capa skips api extraction for its own jmp.
        let fixture = Fixture::build(
            ImageFormat::Pe,
            Architecture::X86,
            vec![(CODE_BASE, vec![0xff, 0x25, 0x00, 0x90, 0x00, 0x00])],
            Vec::new(),
            BTreeMap::from([(0x9000, vec!["kernel32.ExitProcess".to_string()])]),
        );
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let jmp = fixture.insn(0);
        let out = extract_insn_api_features(&ctx, jmp, "jmp");
        assert!(out.is_empty());
    }

    // ---- bytes / string ----

    #[test]
    fn bytes_feature_from_pointer_operand() {
        // push 0x9000
        let fixture = Fixture::with_data(
            &[0x68, 0x00, 0x90, 0x00, 0x00],
            0x9000,
            vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00],
        );
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        let out = extract_insn_bytes_features(&ctx, insn, "push");
        assert_eq!(
            out,
            vec![(
                addr(insn),
                Feature::Bytes(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00])
            )]
        );
    }

    #[test]
    fn bytes_feature_skips_all_zero_and_call_mnemonic() {
        let fixture = Fixture::with_data(&[0x68, 0x00, 0x90, 0x00, 0x00], 0x9000, vec![0; 8]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert!(extract_insn_bytes_features(&ctx, insn, "push").is_empty());
        assert!(extract_insn_bytes_features(&ctx, insn, "call").is_empty());
    }

    #[test]
    fn string_feature_requires_min_length_four() {
        // push 0x9000. The trailing NUL is required, not decoration:
        // `detectString` only reports a run that a `0x00` terminates.
        let fixture = Fixture::with_data(
            &[0x68, 0x00, 0x90, 0x00, 0x00],
            0x9000,
            b"ABCD\x00".to_vec(),
        );
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        let out = extract_op_string_features(&ctx, insn, 0);
        assert_eq!(
            out,
            vec![(
                addr(insn),
                Feature::String(StringFeature::Plain("ABCD".to_string()))
            )]
        );

        let fixture = Fixture::with_data(
            &[0x68, 0x00, 0x90, 0x00, 0x00],
            0x9000,
            b"AB\x00\x00".to_vec(),
        );
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert!(extract_op_string_features(&ctx, insn, 0).is_empty());
    }

    /// `detectString` is bounded by the containing memory map, not by a fixed
    /// length, so a string longer than any window we pick must still come back
    /// whole. This is KD-013: at the old `0x400` the tail was silently cut off,
    /// and `schedule task via at` -- whose second regex is only satisfied past
    /// the first kilobyte of a 5,006-byte string -- could not match.
    #[test]
    fn a_string_longer_than_the_old_window_is_not_truncated() {
        let long = 0x400 * 4;
        let mut data = vec![b'A'; long];
        data.push(0);
        // push 0x9000
        let fixture = Fixture::with_data(&[0x68, 0x00, 0x90, 0x00, 0x00], 0x9000, data);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);

        let out = extract_op_string_features(&ctx, insn, 0);

        assert_eq!(
            out,
            vec![(
                addr(insn),
                Feature::String(StringFeature::Plain("A".repeat(long)))
            )],
            "the string must come back at its full {long} bytes"
        );
    }

    // ---- number / offset ----

    #[test]
    fn number_feature_on_plain_immediate() {
        // push 0x10
        let fixture = Fixture::x86(&[0x6a, 0x10]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        let out = extract_op_number_features(&ctx, insn, "push", 0);
        assert_eq!(
            out,
            vec![
                (addr(insn), Feature::Number(NumberValue::Int(0x10))),
                (
                    addr(insn),
                    Feature::OperandNumber(0, NumberValue::Int(0x10))
                ),
            ]
        );
    }

    #[test]
    fn number_feature_on_wide_immediate_is_unsigned() {
        // mov rcx, 0xcbbb9d5dc1059ed8 -- SHA-384's H(0)0, and the reason
        // `hash data using SHA384` was missed: envi reports the raw 64-bit
        // pattern, never its negative i64 reinterpretation.
        let fixture = Fixture::x64(&[0x48, 0xb9, 0xd8, 0x9e, 0x05, 0xc1, 0x5d, 0x9d, 0xbb, 0xcb]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        let out = extract_op_number_features(&ctx, insn, "mov", 1);
        assert_eq!(
            out,
            vec![
                (
                    addr(insn),
                    Feature::Number(NumberValue::Int(0xcbbb_9d5d_c105_9ed8))
                ),
                (
                    addr(insn),
                    Feature::OperandNumber(1, NumberValue::Int(0xcbbb_9d5d_c105_9ed8))
                ),
            ]
        );
    }

    #[test]
    fn number_feature_sign_extended_immediate_fills_its_operand_width() {
        // envi widths, measured against the pinned envi: `add rax, -1`
        // (imm8 -> 64) is 0xffffffffffffffff, `add eax, -1` (imm8 -> 32) is
        // 0xffffffff.
        let fixture = Fixture::x64(&[0x48, 0x83, 0xc0, 0xff]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_op_number_features(&ctx, insn, "add", 1)[0].1,
            Feature::Number(NumberValue::Int(0xffff_ffff_ffff_ffff))
        );

        let fixture = Fixture::x86(&[0x83, 0xc0, 0xff]);
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_op_number_features(&ctx, insn, "add", 1)[0].1,
            Feature::Number(NumberValue::Int(0xffff_ffff))
        );
    }

    #[test]
    fn number_feature_skips_add_esp_adjustment() {
        // add esp, 0x10
        let fixture = Fixture::x86(&[0x83, 0xc4, 0x10]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert!(extract_op_number_features(&ctx, insn, "add", 1).is_empty());
    }

    #[test]
    fn number_feature_add_immediate_also_yields_structure_offset() {
        // add eax, 0x10
        let fixture = Fixture::x86(&[0x83, 0xc0, 0x10]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        let out = extract_op_number_features(&ctx, insn, "add", 1);
        assert_eq!(
            out,
            vec![
                (addr(insn), Feature::Number(NumberValue::Int(0x10))),
                (
                    addr(insn),
                    Feature::OperandNumber(1, NumberValue::Int(0x10))
                ),
                (addr(insn), Feature::Offset(0x10)),
                (addr(insn), Feature::OperandOffset(1, 0x10)),
            ]
        );
    }

    #[test]
    fn offset_feature_respects_reg_mem_and_sib_stack_encodings() {
        // mov eax, [ebx+4]
        let fixture = Fixture::x86(&[0x8b, 0x43, 0x04]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_op_offset_features(&ctx, insn, "mov", 1),
            vec![
                (addr(insn), Feature::Offset(4)),
                (addr(insn), Feature::OperandOffset(1, 4)),
            ]
        );

        // mov eax, [ebp-4]
        let fixture = Fixture::x86(&[0x8b, 0x45, 0xfc]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert!(extract_op_offset_features(&ctx, insn, "mov", 1).is_empty());

        // mov eax, [esp+4]
        let fixture = Fixture::x86(&[0x8b, 0x44, 0x24, 0x04]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_op_offset_features(&ctx, insn, "mov", 1),
            vec![
                (addr(insn), Feature::Offset(4)),
                (addr(insn), Feature::OperandOffset(1, 4)),
            ]
        );

        // mov rax, [rsp+8] -- upstream quirk: RSP is *not* excluded.
        let fixture = Fixture::x64(&[0x48, 0x8b, 0x44, 0x24, 0x08]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_op_offset_features(&ctx, insn, "mov", 1),
            vec![
                (addr(insn), Feature::Offset(8)),
                (addr(insn), Feature::OperandOffset(1, 8)),
            ]
        );
    }

    #[test]
    fn offset_feature_lea_pattern_also_yields_number() {
        // lea eax, [ebx+1]
        let fixture = Fixture::x86(&[0x8d, 0x43, 0x01]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_op_offset_features(&ctx, insn, "lea", 1),
            vec![
                (addr(insn), Feature::Offset(1)),
                (addr(insn), Feature::OperandOffset(1, 1)),
                (addr(insn), Feature::Number(NumberValue::Int(1))),
                (addr(insn), Feature::OperandNumber(1, NumberValue::Int(1))),
            ]
        );
    }

    #[test]
    fn offset_feature_on_sib_with_no_base() {
        // mov eax, [2*ebx + 0x401000] -- envi's `i386SibOper.disp` defaults
        // to 0 for the SIB "no base register" special case (the real value
        // lives in `.imm`, read by the bytes/string extractors instead), so
        // this yields `Offset(0)`, not `Offset(0x401000)`.
        let fixture = Fixture::x86(&[0x8b, 0x04, 0x5d, 0x00, 0x10, 0x40, 0x00]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_op_offset_features(&ctx, insn, "mov", 1),
            vec![
                (addr(insn), Feature::Offset(0)),
                (addr(insn), Feature::OperandOffset(1, 0)),
            ]
        );
    }

    // ---- characteristics ----

    #[test]
    fn nzxor_yielded_for_distinct_operands() {
        // xor eax, ebx
        let fixture = Fixture::x86(&[0x31, 0xd8]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_insn_nzxor_characteristic_features(&ctx, insn, "xor"),
            vec![(addr(insn), Feature::Characteristic("nzxor".to_string()))]
        );
    }

    #[test]
    fn nzxor_skipped_for_zeroing_idiom() {
        // xor eax, eax
        let fixture = Fixture::x86(&[0x31, 0xc0]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert!(extract_insn_nzxor_characteristic_features(&ctx, insn, "xor").is_empty());
    }

    #[test]
    fn nzxor_skipped_for_security_cookie_pattern_at_function_start() {
        // xor ecx, ebp, as the very first instruction of the function.
        let fixture = Fixture::x86(&[0x31, 0xe9]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert!(extract_insn_nzxor_characteristic_features(&ctx, insn, "xor").is_empty());
    }

    #[test]
    fn call_plus_5_detected_and_not_detected() {
        // call $+5 (rel32 == 0)
        let fixture = Fixture::x86(&[0xe8, 0x00, 0x00, 0x00, 0x00]);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_insn_obfs_call_plus_5_characteristic_features(insn, "call"),
            vec![(addr(insn), Feature::Characteristic("call $+5".to_string()))]
        );

        // call 0x2000 (not +5)
        let fixture = Fixture::x86(&[0xe8, 0xfb, 0x0f, 0x00, 0x00]);
        let insn = fixture.insn(0);
        assert!(extract_insn_obfs_call_plus_5_characteristic_features(insn, "call").is_empty());
    }

    #[test]
    fn peb_access_fs_immmem_and_gs_regmem() {
        // mov eax, fs:[0x30]
        let fixture = Fixture::x86(&[0x64, 0x8b, 0x05, 0x30, 0x00, 0x00, 0x00]);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_insn_peb_access_characteristic_features(insn, "mov"),
            vec![(
                addr(insn),
                Feature::Characteristic("peb access".to_string())
            )]
        );

        // mov rax, gs:[rbx+0x60]
        let fixture = Fixture::x64(&[0x65, 0x48, 0x8b, 0x43, 0x60]);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_insn_peb_access_characteristic_features(insn, "mov"),
            vec![(
                addr(insn),
                Feature::Characteristic("peb access".to_string())
            )]
        );
    }

    #[test]
    fn segment_access_fs_and_gs() {
        let fixture = Fixture::x86(&[0x64, 0x8b, 0x05, 0x30, 0x00, 0x00, 0x00]);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_insn_segment_access_features(insn),
            vec![(addr(insn), Feature::Characteristic("fs access".to_string()))]
        );

        let fixture = Fixture::x64(&[0x65, 0x48, 0x8b, 0x43, 0x60]);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_insn_segment_access_features(insn),
            vec![(addr(insn), Feature::Characteristic("gs access".to_string()))]
        );
    }

    #[test]
    fn cross_section_flow_detected_between_far_apart_regions() {
        // jmp 0x5000, with 0x5000 in a separate (data) section far from the
        // code section at CODE_BASE.
        let fixture = Fixture::build(
            ImageFormat::Pe,
            Architecture::X86,
            vec![(CODE_BASE, vec![0xe9, 0xfb, 0x3f, 0x00, 0x00])],
            vec![(0x5000, vec![0xc3])],
            BTreeMap::new(),
        );
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_insn_cross_section_cflow(&ctx, insn, "jmp"),
            vec![(
                addr(insn),
                Feature::Characteristic("cross section flow".to_string())
            )]
        );
    }

    #[test]
    fn cross_section_flow_not_detected_within_same_section() {
        // jmp $+2; nop; nop -- target stays inside this same code region.
        let fixture = Fixture::x86(&[0xe9, 0x02, 0x00, 0x00, 0x00, 0x90, 0x90]);
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert!(extract_insn_cross_section_cflow(&ctx, insn, "jmp").is_empty());
    }

    #[test]
    fn cross_section_flow_skips_calls_to_known_imports() {
        // call dword [0x9000], where 0x9000 is a bound import -- even
        // though there's no mapped section at 0x9000 at all (which would
        // otherwise make this an unresolvable, not just excluded, case).
        let fixture = Fixture::build(
            ImageFormat::Pe,
            Architecture::X86,
            vec![(CODE_BASE, vec![0xff, 0x15, 0x00, 0x90, 0x00, 0x00])],
            Vec::new(),
            BTreeMap::from([(0x9000, vec!["kernel32.Sleep".to_string()])]),
        );
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        assert!(extract_insn_cross_section_cflow(&ctx, insn, "call").is_empty());
    }

    #[test]
    fn calls_from_and_recursive_call() {
        // call 0x2000
        let fixture = Fixture::x86(&[0xe8, 0xfb, 0x0f, 0x00, 0x00]);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_function_calls_from(insn, 0x9999, "call"),
            vec![(
                Address::Absolute(0x2000),
                Feature::Characteristic("calls from".to_string())
            )]
        );
        assert_eq!(
            extract_function_calls_from(insn, 0x2000, "call"),
            vec![
                (
                    Address::Absolute(0x2000),
                    Feature::Characteristic("calls from".to_string())
                ),
                (
                    Address::Absolute(0x2000),
                    Feature::Characteristic("recursive call".to_string())
                ),
            ]
        );
        assert!(extract_function_calls_from(insn, 0x2000, "mov").is_empty());
    }

    #[test]
    fn indirect_call_characteristic_excludes_direct_memory_forms() {
        // call eax
        let fixture = Fixture::x86(&[0xff, 0xd0]);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_function_indirect_call_characteristic_features(insn, "call"),
            vec![(
                addr(insn),
                Feature::Characteristic("indirect call".to_string())
            )]
        );

        // call dword [ebx+4]
        let fixture = Fixture::x86(&[0xff, 0x53, 0x04]);
        let insn = fixture.insn(0);
        assert_eq!(
            extract_function_indirect_call_characteristic_features(insn, "call"),
            vec![(
                addr(insn),
                Feature::Characteristic("indirect call".to_string())
            )]
        );

        // call dword [0x9000] -- an ImmMem call target is excluded.
        let fixture = Fixture::x86(&[0xff, 0x15, 0x00, 0x90, 0x00, 0x00]);
        let insn = fixture.insn(0);
        assert!(extract_function_indirect_call_characteristic_features(insn, "call").is_empty());

        // call qword [rip+0x10] -- a RipRel call target is excluded too.
        let fixture = Fixture::x64(&[0xff, 0x15, 0x10, 0x00, 0x00, 0x00]);
        let insn = fixture.insn(0);
        assert!(extract_function_indirect_call_characteristic_features(insn, "call").is_empty());
    }

    #[test]
    fn extract_features_includes_mnemonic_exactly_once() {
        let fixture = Fixture::x86(&[0x31, 0xd8]); // xor eax, ebx
        let libraries = no_libraries();
        let ctx = fixture.ctx(&libraries);
        let insn = fixture.insn(0);
        let out = extract_features(&ctx, insn);
        let mnemonics: Vec<_> = out
            .iter()
            .filter(|(_, feature)| matches!(feature, Feature::Mnemonic(_)))
            .collect();
        assert_eq!(
            mnemonics,
            vec![&(addr(insn), Feature::Mnemonic("xor".to_string()))]
        );
        assert!(out.contains(&(addr(insn), Feature::Characteristic("nzxor".to_string()))));
    }
}
