//! AArch64 instruction-scope feature extraction, ported
//! from `capa/features/extractors/binexport2/{insn,arch/arm/insn}.py` and
//! `arch/arm/helpers.py` (v9.4.0, see PINNED.md) -- the BinExport2/Ghidra ARM
//! backend, run against this crate's own native recovery (`recovery.rs`)
//! instead of a parsed BinExport2 protobuf. See `decoder.rs`'s module doc:
//! "the features must be equal, the mechanism cannot be".
//!
//! Upstream reads every operand value pre-resolved from Ghidra's own
//! expression trees (`get_operand_immediate_expression`,
//! `get_operand_register_expression`, `is_address_mapped`, ...). We decode
//! natively and have no such tree, so this module gets its operand values
//! from `disarm64`'s own instruction formatter
//! (`disarm64::InsnDisplay::display_at`) rather than hand-rolling a bitfield
//! decoder per addressing form: [`operand_text`] renders an instruction's
//! operand list exactly as `disarm64` would disassemble it (already
//! correctly scaled/sign-extended/writeback-suffixed -- verified against
//! this crate's own `decoder.rs` tests, e.g. `ldr x17, [x16, #0xd80]`), and
//! [`split_operands`]/the `parse_*` helpers below turn that text back into
//! the same shape upstream's expression tree gives it. `disarm64::InsnClass`
//! (`ADDSUB_IMM`/`LOG_IMM`/`LOG_SHIFT`/`LDST_POS`/`LDST_IMM9`/`LOADLIT`/
//! `PCRELADDR`) stands in for upstream's own encoding-family dispatch.

use std::collections::BTreeMap;

use disarm64::{InsnDisplay, InsnOpcode, Opcode as Aarch64Opcode};
use disarm64_defn::InsnClass;

use crate::address::Address;
use crate::features::{Feature, NumberValue, StringFeature};

use super::decoder::{self, Flow};
use super::helpers::all_zeros;
use super::image::{DecodedInstruction, LoadedImage};
use super::recovery::{Analysis, BasicBlock, Function};
use super::strings;

/// capa/features/insn.py: MAX_STRUCTURE_SIZE
const MAX_STRUCTURE_SIZE: i64 = 0x10000;
/// capa/features/common.py: MAX_BYTES_FEATURE_SIZE
const MAX_BYTES_FEATURE_SIZE: usize = 0x100;
/// capa/features/extractors/strings.py: default `n` for both extractors.
const MIN_STRING_LEN: usize = 4;

/// capa/features/extractors/binexport2/arch/arm/insn.py: `OFFSET_PATTERNS`'
/// single-register mnemonics (`ldr|ldrb|ldrh|ldrsb|ldrsh|ldrex|ldrd|str|
/// strb|strh|strex|strd`). `ldrd`/`strd` are ARM32-only and `disarm64` (an
/// A64-only decoder) never produces them; kept for fidelity with the source.
const OFFSET_SINGLE_MNEMONICS: [&str; 12] = [
    "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrex", "ldrd", "str", "strb", "strh", "strex",
    "strd",
];
/// Same table's pair mnemonics (`ldp|ldpd|stp|stpd`); `ldpd`/`stpd` are not
/// real A64 mnemonics (FP-register pairs still disassemble as plain `ldp`/
/// `stp`), kept for the same reason.
const OFFSET_PAIR_MNEMONICS: [&str; 2] = ["ldp", "stp"];

pub struct InsnContext<'a> {
    pub analysis: &'a Analysis,
    pub function: &'a Function,
    /// this block's address-materialization table (task 4's bounded `adrp`+
    /// `add`/`adrp`+`ldr`/literal-load chase), keyed by the completing
    /// instruction's address -> the absolute address it materialized. See
    /// [`materialize_addresses`].
    pub materialized: &'a BTreeMap<u64, u64>,
}

fn addr(insn: &DecodedInstruction) -> Address {
    Address::Absolute(insn.address)
}

/// `recovery.rs::add_aarch64_prologue_seeds`'s structural test: does the
/// instruction at `address` look like the first instruction of a
/// callee-saved-register prologue? Three shapes, all seen in the pinned
/// corpus: a pre-indexed store of one or a pair of GPRs onto a *shrinking*
/// stack (`stp x28, x27, [sp, #-96]!`, `str x28, [sp, #-96]!` -- the
/// negative immediate is what distinguishes a genuine prologue from an
/// ordinary mid-function local-variable store using the same encoding), or a
/// plain stack-frame allocation (`sub sp, sp, #N`). See that function's own
/// doc comment for why this isn't a byte-pattern list.
pub(crate) fn is_prologue_candidate(image: &LoadedImage, address: u64) -> bool {
    let Ok(insn) = image.decode_at(address) else {
        return false;
    };
    let Some(opcode) = decoder::aarch64_opcode(&insn) else {
        return false;
    };
    let def = opcode.definition();
    if !is_formattable(def.class) {
        return false;
    }
    match (def.class, def.mnemonic) {
        (InsnClass::LDSTPAIR_INDEXED, "stp") | (InsnClass::LDST_IMM9, "str") => {
            let parts = split_operands(&operand_text(opcode, address));
            parts
                .last()
                .and_then(|addr_operand| parse_bracket_any(addr_operand))
                .is_some_and(|(base, imm)| base.trim() == "sp" && imm < 0)
        }
        (InsnClass::ADDSUB_IMM, "sub") => {
            let parts = split_operands(&operand_text(opcode, address));
            parts.first().is_some_and(|rd| rd.trim() == "sp")
                && parts.get(1).is_some_and(|rn| rn.trim() == "sp")
        }
        _ => false,
    }
}

/// capa/features/extractors/binexport2/insn.py: `extract_features` /
/// `INSTRUCTION_HANDLERS`, restricted to the arm-relevant subset (the
/// bytes/string handler is arch-independent upstream but implemented here
/// against our own materialization table instead of Ghidra's
/// `data_reference`/`string_reference` indexes).
pub fn extract_features(ctx: &InsnContext, insn: &DecodedInstruction) -> Vec<(Address, Feature)> {
    let mut out = Vec::new();
    out.extend(extract_insn_api_features(ctx, insn));
    out.extend(extract_insn_number_features(ctx, insn));
    out.extend(extract_insn_bytes_string_features(ctx, insn));
    out.extend(extract_insn_offset_features(ctx, insn));
    out.extend(extract_insn_nzxor_characteristic_features(insn));
    if let Some(opcode) = decoder::aarch64_opcode(insn) {
        out.push((
            addr(insn),
            Feature::Mnemonic(opcode.definition().mnemonic.to_string()),
        ));
    }
    out.extend(extract_function_calls_from(insn, ctx.function.addr));
    out.extend(extract_function_indirect_call_characteristic_features(insn));
    out
}

/// The only `InsnClass` values this module ever formats via `disarm64`'s
/// text formatter (see [`operand_text`]). Deliberately narrow: `disarm64`
/// 0.2.0's formatter has at least one integer-underflow panic on a SIMD
/// shift-immediate operand kind (`InsnOperandKind::IMM_VLSL`,
/// `format_insn/mod.rs`), reached by a real vector instruction in the pinned
/// corpus -- a bug in the *formatter*, unrelated to decoding, which task 2's
/// own fuzz/corpus gate already proved never panics. AGENTS.md's "no panics
/// on untrusted input" rule means the fix is to never call the formatter
/// outside instruction classes already known safe, not to `catch_unwind`
/// around a call that might not be. The cost is real but bounded and
/// root-causeable: a `Number`/`Offset` feature this port could in principle
/// extract from some other general-purpose-register class (`MOVEWIDE`,
/// `BITFIELD`, `CONDCMP_IMM`, ...) is missed rather than risking a panic --
/// a J9 divergence class, not a silent skip.
fn is_formattable(class: InsnClass) -> bool {
    matches!(
        class,
        InsnClass::PCRELADDR
            | InsnClass::ADDSUB_IMM
            | InsnClass::LOG_IMM
            | InsnClass::LOG_SHIFT
            | InsnClass::LDST_POS
            | InsnClass::LDST_IMM9
            | InsnClass::LOADLIT
            | InsnClass::LDSTPAIR_OFF
            | InsnClass::LDSTPAIR_INDEXED
            | InsnClass::MOVEWIDE
    )
}

/// Render `opcode`'s operand list only (mnemonic and the `"\t\t"` separator
/// `disarm64` always emits between mnemonic and operands stripped) -- see
/// this module's doc comment.
fn operand_text(opcode: Aarch64Opcode, pc: u64) -> String {
    format!("{}", opcode.display_at(pc))
        .split_once("\t\t")
        .map_or_else(String::new, |(_, rest)| rest.to_string())
}

/// Split a rendered operand list into its top-level operands, matching
/// upstream's per-`instruction.operand_index` granularity. Bracket-aware (an
/// addressing operand's own internal `", "` -- `[x1, #8]`, `[x1], #8` -- is
/// never a boundary) and merges a trailing shift/extend suffix
/// (`", lsl #12"`, `", uxtw"`) back into the operand it qualifies, since
/// `disarm64` writes both within one `format_operand` call with no bracket to
/// bound it.
fn split_operands(text: &str) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let parts: Vec<String> = if let Some(bracket) = text.find('[') {
        let before = text[..bracket].trim_end_matches(", ");
        let mut v: Vec<String> = if before.is_empty() {
            Vec::new()
        } else {
            before.split(", ").map(str::to_string).collect()
        };
        v.push(text[bracket..].to_string());
        v
    } else {
        text.split(", ").map(str::to_string).collect()
    };

    const SHIFT_EXTEND_PREFIXES: [&str; 11] = [
        "lsl", "lsr", "asr", "ror", "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtx",
    ];
    let mut merged: Vec<String> = Vec::new();
    for part in parts {
        if SHIFT_EXTEND_PREFIXES.iter().any(|p| part.starts_with(p)) {
            if let Some(last) = merged.last_mut() {
                *last = format!("{last}, {part}");
                continue;
            }
        }
        merged.push(part);
    }
    merged
}

fn reg_num(s: &str) -> Option<u32> {
    let n: u32 = s.trim().strip_prefix('x')?.parse().ok()?;
    (n <= 30).then_some(n)
}

/// Parse a signed decimal (`-72`) or unsigned-hex (`0x10`, never negative --
/// `disarm64` prints a negative offset in decimal, never as hex) literal, as
/// `disarm64`'s formatter renders one.
fn parse_signed(s: &str) -> Option<i64> {
    let s = s.trim();
    let (negative, rest) = s.strip_prefix('-').map_or((false, s), |r| (true, r));
    let magnitude: i64 = rest.strip_prefix("0x").map_or_else(
        || rest.parse().ok(),
        |hex| i64::from_str_radix(hex, 16).ok(),
    )?;
    Some(if negative { -magnitude } else { magnitude })
}

/// A bare `#0x..`/`#123`/`#-5` token (no leading `[`).
fn parse_hash_imm(s: &str) -> Option<i64> {
    parse_signed(s.trim().strip_prefix('#')?)
}

/// A bare hex address with no `#` -- `disarm64`'s `ADDR_ADRP`/`ADDR_PCREL19`
/// formatting (used for `adrp` and literal loads) writes the resolved
/// absolute address directly, unlike every other immediate kind.
fn parse_bare_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim().strip_prefix("0x")?, 16).ok()
}

/// A plain `#imm` operand -- rejects anything with a *nonzero* shift/extend
/// suffix (`#0x1, lsl #12`) the same way upstream's
/// `get_operand_immediate_expression` rejects a multi-node expression tree
/// (only a bare `IMMEDIATE_INT`, or one wrapped in a single `SIZE_PREFIX`,
/// ever matches). A *zero* shift is not the same case: `disarm64`'s
/// `HALF`-kind formatting (`movz`/`movn`/`movk`) unconditionally appends
/// `", lsl #0x0"` even when the shift is zero (`format_insn/mod.rs`'s
/// `InsnOperandKind::HALF` arm has no `if shift != 0` guard, unlike `AIMM`'s
/// `add`/`sub` shift, which is only ever written when genuinely nonzero) --
/// but a zero-shift `movz`/`movn` disassembles identically to a plain
/// immediate move in upstream's own text (`movz w0, #5`, no `lsl` at all),
/// which is what its BinExport2/Ghidra expression tree actually reflects,
/// so treating an explicit-zero shift as "no shift" here matches upstream
/// rather than diverging from it.
fn parse_plain_imm(s: &str) -> Option<i64> {
    let s = s.trim();
    let stripped = s
        .strip_suffix(", lsl #0x0")
        .or_else(|| s.strip_suffix(", lsl #0"));
    match stripped {
        Some(without_zero_shift) => parse_hash_imm(without_zero_shift),
        None if s.contains(',') => None,
        None => parse_hash_imm(s),
    }
}

/// Strict addressing-operand parse: requires an explicit `#imm`, matching
/// upstream's `OFFSET_PATTERNS`, none of which match a bare `[reg]` (no
/// captured immediate expression node at all).
fn parse_bracket_with_imm(s: &str) -> Option<(String, i64)> {
    let s = s.trim();
    if let Some(idx) = s.find("], #") {
        let base = s[1..idx].to_string();
        return Some((base, parse_signed(&s[idx + 4..])?));
    }
    let s = s.strip_suffix('!').unwrap_or(s);
    let inner = s.strip_prefix('[')?.strip_suffix(']')?;
    let (base, imm_str) = inner.split_once(", #")?;
    Some((base.to_string(), parse_signed(imm_str)?))
}

/// Permissive addressing-operand parse for address materialization: a bare
/// `[reg]` is `reg + 0`, same as any other addressing form -- there is no
/// upstream pattern to stay faithful to here (see [`materialize_addresses`]).
fn parse_bracket_any(s: &str) -> Option<(String, i64)> {
    let s = s.trim();
    if let Some(idx) = s.find("], #") {
        let base = s[1..idx].to_string();
        return Some((base, parse_signed(&s[idx + 4..])?));
    }
    let s = s.strip_suffix('!').unwrap_or(s);
    let inner = s.strip_prefix('[')?.strip_suffix(']')?;
    match inner.split_once(", #") {
        Some((base, imm_str)) => Some((base.to_string(), parse_signed(imm_str)?)),
        None => Some((inner.to_string(), 0)),
    }
}

/// capa/features/extractors/binexport2/helpers.py: `is_address_mapped`,
/// against our own loaded sections rather than a BinExport2 section list.
fn is_address_mapped(image: &LoadedImage, value: u64) -> bool {
    image.section_containing(value).is_some_and(|section| {
        section.permissions.read || section.permissions.write || section.permissions.execute
    })
}

/// Bounded, block-scoped address materialization for `adrp`+`add`
/// (`arch/arm/insn.py`'s stack-register exclusion has no counterpart here --
/// `add`/`sub` to `sp` is never a tracked chain start, since `sp` is never
/// `adrp`-seeded), `adrp`+`ldr` (register-relative, GOT-load shaped), and
/// PC-relative literal loads -- the three supported forms. Maps a
/// completing instruction's own address to the absolute address it
/// resolved, for [`extract_insn_bytes_string_features`] to read from.
///
/// Block-bounded, invalidated on any unmodelled write, and never propagated
/// through a call: every instruction not itself a recognized continuation of
/// a currently-tracked register -- most conservatively, *every* instruction
/// outside the three recognized forms, including `bl`/`blr` -- clears the
/// whole tracked-register table. `adrp x0 ... bl foo ... add x0, x0,
/// #lo12:sym` therefore produces nothing: the `bl` clears `x0` before the
/// `add` runs.
fn materialize_addresses(block: &BasicBlock) -> BTreeMap<u64, u64> {
    let mut known: BTreeMap<u32, u64> = BTreeMap::new();
    let mut out = BTreeMap::new();
    for insn in &block.insns {
        let matched = try_materialize_step(insn, &mut known, &mut out).is_some();
        if !matched {
            known.clear();
        }
    }
    out
}

fn try_materialize_step(
    insn: &DecodedInstruction,
    known: &mut BTreeMap<u32, u64>,
    out: &mut BTreeMap<u64, u64>,
) -> Option<()> {
    let opcode = decoder::aarch64_opcode(insn)?;
    let def = opcode.definition();
    if !is_formattable(def.class) {
        return None;
    }
    let parts = split_operands(&operand_text(opcode, insn.address));
    match def.class {
        InsnClass::PCRELADDR if def.mnemonic == "adrp" => {
            let rd = reg_num(parts.first()?)?;
            let page = parse_bare_hex(parts.get(1)?)?;
            known.insert(rd, page);
            Some(())
        }
        InsnClass::ADDSUB_IMM if def.mnemonic == "add" && parts.len() == 3 => {
            let rd = reg_num(&parts[0])?;
            let rn = reg_num(&parts[1])?;
            let imm = parse_hash_imm(&parts[2])?;
            let base = *known.get(&rn)?;
            let value = base.wrapping_add_signed(imm);
            known.insert(rd, value);
            out.insert(insn.address, value);
            Some(())
        }
        InsnClass::LDST_POS | InsnClass::LDST_IMM9 if def.mnemonic == "ldr" && parts.len() == 2 => {
            let rt = reg_num(&parts[0])?;
            let (base_reg, imm) = parse_bracket_any(&parts[1])?;
            let rn = reg_num(&base_reg)?;
            let base = *known.get(&rn)?;
            let address = base.wrapping_add_signed(imm);
            out.insert(insn.address, address);
            // a load reads a *value* from memory, not a further address, so
            // it never extends the chain -- but its destination's old
            // tracked value (if any) is definitely gone.
            known.remove(&rt);
            Some(())
        }
        InsnClass::LOADLIT if def.mnemonic == "ldr" => {
            let rt = reg_num(parts.first()?)?;
            let address = parse_bare_hex(parts.get(1)?)?;
            out.insert(insn.address, address);
            known.remove(&rt);
            Some(())
        }
        _ => None,
    }
}

/// port of `arm/insn.py:extract_insn_api_features`'s callers'-eye view: a
/// `bl` whose direct target is a known import (an ELF-relocation import
/// directly, or an AArch64 PLT stub's own start address --
/// `recovery.rs::run_aarch64_plt_wave` registers both into the same
/// `external_bindings` map D.3 already resolves). Register-indirect calls
/// (`blr`) are not statically resolved, matching upstream's own inability to
/// do so without deeper analysis.
fn extract_insn_api_features(
    ctx: &InsnContext,
    insn: &DecodedInstruction,
) -> Vec<(Address, Feature)> {
    if insn.flow != Flow::Call {
        return Vec::new();
    }
    let Some(target) = insn.direct_target else {
        return Vec::new();
    };
    match ctx.analysis.image.external_bindings.get(&target) {
        Some(names) => names
            .iter()
            .map(|name| (addr(insn), Feature::Api(name.clone())))
            .collect(),
        None => Vec::new(),
    }
}

/// port of `arch/arm/insn.py:extract_insn_number_features`.
fn extract_insn_number_features(
    ctx: &InsnContext,
    insn: &DecodedInstruction,
) -> Vec<(Address, Feature)> {
    let Some(opcode) = decoder::aarch64_opcode(insn) else {
        return Vec::new();
    };
    let def = opcode.definition();
    if !is_formattable(def.class) {
        return Vec::new();
    }
    let mut parts = split_operands(&operand_text(opcode, insn.address));
    if (def.mnemonic == "add" || def.mnemonic == "sub")
        && parts.get(1).is_some_and(|rn| rn.trim() == "sp")
    {
        // skip things like: add x0, sp, #0x8
        return Vec::new();
    }
    // `orr wd, wzr, #imm`/`orr xd, xzr, #imm` is the ARM-defined preferred
    // disassembly alias for `mov wd/xd, #imm` (ARM DDI 0487, "MOV (bitmask
    // immediate)") -- Ghidra (like every other AArch64 disassembler) shows
    // it as the 2-operand `mov`, so its expression tree, and therefore its
    // `operand_index`, never has a middle `xzr`/`wzr` register operand at
    // all. `disarm64` doesn't alias-rewrite (`def.mnemonic` is always the
    // literal `"orr"`, confirmed against the pinned corpus), so the
    // 3-operand form decoded here is reindexed down to 2 for this function's
    // own purposes to match: dropping the elided zero register turns
    // `[rd, xzr, #imm]` into `[rd, #imm]`, putting the immediate back at
    // operand index 1 the way upstream's own table expects.
    if def.mnemonic == "orr" && parts.len() == 3 && matches!(parts[1].trim(), "wzr" | "xzr") {
        parts = vec![parts[0].clone(), parts[2].clone()];
    }
    // `movn wd, #imm` (no shift) computes `wd = NOT(imm)`, and upstream's
    // own disassembly/expression tree (aliasing to `mov` when beneficial)
    // reflects that *resolved* register value, not the raw encoded
    // immediate `disarm64`'s `HALF` formatting renders -- unlike every
    // other class handled here, so it needs its own arithmetic rather than
    // the generic per-operand loop below.
    if def.mnemonic == "movn" && parts.len() == 2 {
        return extract_movn_number_features(ctx, insn, &parts);
    }

    let mut out = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let Some(value) = parse_plain_imm(part) else {
            continue;
        };
        // mask_immediate: AArch64 is always a HAS_ARCH64 member, so the
        // value is masked to the full 64-bit pattern (never narrower).
        let masked = value as u64;
        if is_address_mapped(&ctx.analysis.image, masked) {
            continue;
        }
        let number = NumberValue::Int(masked as i128);
        out.push((addr(insn), Feature::Number(number)));
        out.push((addr(insn), Feature::OperandNumber(i as u8, number)));

        if def.mnemonic == "add" && i == 2 && value > 0 && value < MAX_STRUCTURE_SIZE {
            out.push((addr(insn), Feature::Offset(value)));
            out.push((addr(insn), Feature::OperandOffset(i as u8, value)));
        }
    }
    out
}

/// `movn`'s resolved-value special case (see the caller's doc comment). Only
/// handles a zero shift, matching [`parse_plain_imm`]'s own restriction --
/// upstream's expression tree excludes a genuinely shifted immediate from
/// number extraction entirely, and there is no reason `movn` should be
/// exempt from that.
fn extract_movn_number_features(
    ctx: &InsnContext,
    insn: &DecodedInstruction,
    parts: &[String],
) -> Vec<(Address, Feature)> {
    let Some(raw) = parse_plain_imm(&parts[1]) else {
        return Vec::new();
    };
    let is_64 = parts[0].trim().starts_with('x');
    let masked = if is_64 {
        !(raw as u64)
    } else {
        u64::from(!(raw as u32))
    };
    if is_address_mapped(&ctx.analysis.image, masked) {
        return Vec::new();
    }
    let number = NumberValue::Int(masked as i128);
    vec![
        (addr(insn), Feature::Number(number)),
        (addr(insn), Feature::OperandNumber(1, number)),
    ]
}

/// port of `arch/arm/insn.py:extract_insn_offset_features` /
/// `OFFSET_PATTERNS`.
fn extract_insn_offset_features(
    ctx: &InsnContext,
    insn: &DecodedInstruction,
) -> Vec<(Address, Feature)> {
    let Some(opcode) = decoder::aarch64_opcode(insn) else {
        return Vec::new();
    };
    let def = opcode.definition();
    let expected_len = if OFFSET_SINGLE_MNEMONICS.contains(&def.mnemonic) {
        2
    } else if OFFSET_PAIR_MNEMONICS.contains(&def.mnemonic) {
        3
    } else {
        return Vec::new();
    };
    if !is_formattable(def.class) {
        return Vec::new();
    }

    let parts = split_operands(&operand_text(opcode, insn.address));
    if parts.len() != expected_len {
        return Vec::new();
    }
    let operand_index = parts.len() - 1;
    let Some((base_reg, imm)) = parse_bracket_with_imm(&parts[operand_index]) else {
        return Vec::new();
    };
    if base_reg.trim() == "sp" {
        // skip things like: str x0, [sp, #0x10]
        return Vec::new();
    }
    // mask_immediate then is_address_mapped, then (if not mapped)
    // twos_complement -- `imm` is already the final signed value
    // `disarm64`'s formatter computed, so re-deriving it via mask+twos'
    // complement would be a no-op; only the mapped-address check needs the
    // unsigned reinterpretation.
    if is_address_mapped(&ctx.analysis.image, imm as u64) {
        return Vec::new();
    }
    vec![
        (addr(insn), Feature::Offset(imm)),
        (addr(insn), Feature::OperandOffset(operand_index as u8, imm)),
    ]
}

/// port of `arch/arm/insn.py:extract_insn_nzxor_characteristic_features` /
/// `NZXOR_PATTERNS`. `LOG_IMM`'s immediate operand always differs in *type*
/// from the register at operand index 1, matching upstream's `operands[1] !=
/// operands[2]` trivially; `LOG_SHIFT`'s register form needs the actual
/// comparison, and (like upstream, whose 3-operand pattern only matches an
/// unshifted register operand) never matches when a shift/extend suffix is
/// present.
fn extract_insn_nzxor_characteristic_features(
    insn: &DecodedInstruction,
) -> Vec<(Address, Feature)> {
    let Some(opcode) = decoder::aarch64_opcode(insn) else {
        return Vec::new();
    };
    let def = opcode.definition();
    if def.mnemonic != "eor" {
        return Vec::new();
    }
    let is_nzxor = match def.class {
        InsnClass::LOG_IMM => true,
        InsnClass::LOG_SHIFT if is_formattable(def.class) => {
            let parts = split_operands(&operand_text(opcode, insn.address));
            parts.len() == 3 && !parts[2].contains(',') && parts[1].trim() != parts[2].trim()
        }
        _ => false,
    };
    if is_nzxor {
        vec![(addr(insn), Feature::Characteristic("nzxor".to_string()))]
    } else {
        Vec::new()
    }
}

/// port of `insn.py:extract_insn_bytes_features` +
/// `extract_insn_string_features`, merged since both key off the same
/// resolved reference address -- see [`materialize_addresses`]'s doc
/// comment for why our reference source differs from upstream's.
fn extract_insn_bytes_string_features(
    ctx: &InsnContext,
    insn: &DecodedInstruction,
) -> Vec<(Address, Feature)> {
    let Some(&target) = ctx.materialized.get(&insn.address) else {
        return Vec::new();
    };
    let Some(buf) = ctx.analysis.image.bytes_at(target, MAX_BYTES_FEATURE_SIZE) else {
        return Vec::new();
    };
    if all_zeros(buf) {
        return Vec::new();
    }
    // note: we *always* look only at the first candidate, matching
    // upstream's "note: we always break after the first iteration".
    if let Some(s) = strings::extract_ascii_strings(buf, MIN_STRING_LEN)
        .into_iter()
        .next()
    {
        if s.offset == 0 {
            return vec![(addr(insn), Feature::String(StringFeature::Plain(s.s)))];
        }
    }
    if let Some(s) = strings::extract_unicode_strings(buf, MIN_STRING_LEN)
        .into_iter()
        .next()
    {
        if s.offset == 0 {
            return vec![(addr(insn), Feature::String(StringFeature::Plain(s.s)))];
        }
    }
    vec![(addr(insn), Feature::Bytes(buf.to_vec()))]
}

/// port of `insn.py:extract_function_calls_from`.
fn extract_function_calls_from(
    insn: &DecodedInstruction,
    function_addr: u64,
) -> Vec<(Address, Feature)> {
    if insn.flow != Flow::Call {
        return Vec::new();
    }
    let Some(target) = insn.direct_target else {
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

/// port of `arch/arm/insn.py:extract_function_indirect_call_characteristic_features`
/// / `INDIRECT_CALL_PATTERNS` (`blx|bx|blr reg` -- `bx`/`blx` are ARM32-only
/// and never decoded here). `decoder.rs`'s `Flow::IndirectCall` already
/// covers `blr` and its pointer-authenticated forms (`blraa`/`blrab`/
/// `blraaz`/`blrabz`), so this needs no mnemonic pattern of its own.
fn extract_function_indirect_call_characteristic_features(
    insn: &DecodedInstruction,
) -> Vec<(Address, Feature)> {
    if insn.flow == Flow::IndirectCall {
        vec![(
            addr(insn),
            Feature::Characteristic("indirect call".to_string()),
        )]
    } else {
        Vec::new()
    }
}

/// The per-block entry point [`super::flirt`] calls: computes this block's
/// materialization table once, then extracts every instruction's features
/// against it.
pub fn extract_block_insn_features(
    analysis: &Analysis,
    function: &Function,
    block: &BasicBlock,
) -> BTreeMap<Address, Vec<(Address, Feature)>> {
    let materialized = materialize_addresses(block);
    let ctx = InsnContext {
        analysis,
        function,
        materialized: &materialized,
    };
    block
        .insns
        .iter()
        .map(|insn| {
            (
                Address::Absolute(insn.address),
                extract_features(&ctx, insn),
            )
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::extract::recovery::Edge;

    fn insn(address: u64, word: u32) -> DecodedInstruction {
        decoder::from_aarch64(address, word.to_le_bytes().to_vec(), word)
    }

    // `adrp x0, #0`; `add x0, x0, #0x10`; `ldr x0, [x0, #8]`; `bl .` (imm26=0);
    // encodings hand-derived from the ARM Architecture Reference Manual and
    // cross-checked against `decoder.rs`'s own verified
    // `ldr x17, [x16, #0xd80]` test vector (same LDST_POS formula).
    const ADRP_X0_PAGE0: u32 = 0x9000_0000;
    const ADD_X0_X0_0X10: u32 = 0x9100_4000;
    const LDR_X0_X0_8: u32 = 0xF940_0400;
    const BL_SELF: u32 = 0x9400_0000;
    const NOP: u32 = 0xD503_201F;

    fn block(insns: Vec<DecodedInstruction>) -> BasicBlock {
        BasicBlock {
            addr: insns.first().map_or(0, |i| i.address),
            insns,
            succs: Vec::<Edge>::new(),
        }
    }

    #[test]
    fn adrp_add_materializes_the_final_address() {
        // `adrp x0, #0` at 0x1000 resolves to page 0x1000 (already
        // page-aligned, zero page-relative offset), so the `add` completes
        // at 0x1000 + 0x10.
        let b = block(vec![
            insn(0x1000, ADRP_X0_PAGE0),
            insn(0x1004, ADD_X0_X0_0X10),
        ]);
        let out = materialize_addresses(&b);
        assert_eq!(out.get(&0x1004), Some(&0x1010));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn adrp_ldr_materializes_the_effective_address() {
        let b = block(vec![insn(0x1000, ADRP_X0_PAGE0), insn(0x1004, LDR_X0_X0_8)]);
        let out = materialize_addresses(&b);
        assert_eq!(out.get(&0x1004), Some(&0x1008));
    }

    /// A call between materialization steps must clear the chain:
    /// `adrp x0 ... bl foo ... add x0, x0, #lo12:sym` produces nothing.
    #[test]
    fn a_call_between_adrp_and_add_clobbers_the_chain() {
        let b = block(vec![
            insn(0x1000, ADRP_X0_PAGE0),
            insn(0x1004, BL_SELF),
            insn(0x1008, ADD_X0_X0_0X10),
        ]);
        assert!(materialize_addresses(&b).is_empty());
    }

    #[test]
    fn an_unrelated_instruction_between_adrp_and_add_clobbers_the_chain() {
        let b = block(vec![
            insn(0x1000, ADRP_X0_PAGE0),
            insn(0x1004, NOP),
            insn(0x1008, ADD_X0_X0_0X10),
        ]);
        assert!(materialize_addresses(&b).is_empty());
    }

    #[test]
    fn add_without_a_tracked_base_materializes_nothing() {
        let b = block(vec![insn(0x1000, ADD_X0_X0_0X10)]);
        assert!(materialize_addresses(&b).is_empty());
    }

    // ---- split_operands / parse_* ----

    #[test]
    fn split_operands_is_bracket_aware() {
        assert_eq!(split_operands(""), Vec::<String>::new());
        assert_eq!(split_operands("x0, [x1, #8]"), vec!["x0", "[x1, #8]"]);
        assert_eq!(split_operands("x0, [x1, #8]!"), vec!["x0", "[x1, #8]!"]);
        assert_eq!(split_operands("x0, [x1], #8"), vec!["x0", "[x1], #8"]);
        assert_eq!(
            split_operands("x0, x1, [x2, #16]"),
            vec!["x0", "x1", "[x2, #16]"]
        );
    }

    #[test]
    fn split_operands_merges_shift_suffixes() {
        assert_eq!(
            split_operands("x0, x1, x2, lsl #3"),
            vec!["x0", "x1", "x2, lsl #3"]
        );
        assert_eq!(
            split_operands("x0, x1, #0x1, lsl #12"),
            vec!["x0", "x1", "#0x1, lsl #12"]
        );
    }

    #[test]
    fn parse_bracket_with_imm_requires_an_explicit_immediate() {
        assert_eq!(parse_bracket_with_imm("[x1]"), None);
        assert_eq!(
            parse_bracket_with_imm("[x1, #8]"),
            Some(("x1".to_string(), 8))
        );
        assert_eq!(
            parse_bracket_with_imm("[x1, #-72]"),
            Some(("x1".to_string(), -72))
        );
        assert_eq!(
            parse_bracket_with_imm("[x1, #8]!"),
            Some(("x1".to_string(), 8))
        );
        assert_eq!(
            parse_bracket_with_imm("[x1], #8"),
            Some(("x1".to_string(), 8))
        );
    }

    #[test]
    fn parse_bracket_any_defaults_a_bare_register_to_zero_offset() {
        assert_eq!(parse_bracket_any("[x1]"), Some(("x1".to_string(), 0)));
    }

    #[test]
    fn parse_plain_imm_rejects_shifted_immediates() {
        assert_eq!(parse_plain_imm("#0x10"), Some(0x10));
        assert_eq!(parse_plain_imm("#-5"), Some(-5));
        assert_eq!(parse_plain_imm("#0x1, lsl #12"), None);
    }
}
