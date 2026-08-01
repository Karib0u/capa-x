//! No-return analysis: which call targets terminate control flow.
//!
//! Vivisect's code flow stops at a call whose target never returns -- there is
//! no fallthrough edge, so the caller's function ends there instead of
//! absorbing whatever bytes follow. The machinery is spread across four
//! pinned upstream sites, all of which this module ports:
//!
//! | Upstream | What it does |
//! |---|---|
//! | `vivisect/parsers/pe.py:416-436` | seeds the PE no-return API names |
//! | `vivisect/parsers/elf.py:295-305` | seeds the ELF no-return API names |
//! | `vivisect/__init__.py:479-546` | resolves those names to import VAs (`addNoReturnApi`, `addNoReturnApiRegex`, `checkNoRetApi`) |
//! | `envi/codeflow.py:230-261` | suppresses the fallthrough of a `BR_PROC` branch to a no-return target (`addNoFlow`) |
//! | `vivisect/analysis/generic/noret.py` | propagates: a function with no returning leaf block is itself no-return |
//!
//! The set is keyed by *address* exactly as `CodeFlowContext._cf_noret` is: it
//! holds import locations (IAT/GOT slot VAs) and function entry VAs in the
//! same map. Only the latter ever suppress a fallthrough -- see the note in
//! `recovery.rs`'s `IndirectCall` arm for why `call [ExitProcess]` does not.
//! An import reaches the set's effective half by way of a *thunk*
//! (`checkNoRetApi`), which callers reach with a direct call.

use std::collections::BTreeSet;

use super::decoder;
use super::decoder::Flow;
use super::engine::{memory_target, Analysis, Function};
use super::image::{ImageFormat, LoadedImage};

/// Literal no-return import names registered by the pinned PE loader
/// (`vivisect/parsers/pe.py:416-436`, via `addNoReturnApi`). Lowercased here
/// because `addNoReturnApi` lowercases before comparing.
const PE_NORETURN_APIS: &[&str] = &[
    "ntdll.rtlexituserthread",
    "kernel32.exitprocess",
    "kernel32.exitthread",
    "kernel32.fatalexit",
    "ntoskrnl.kebugcheckex",
];

/// The `addNoReturnApiRegex` patterns from the same block. Every one of them
/// has the shape `^<prefix>.*\.<suffix>$` under `re.IGNORECASE`, so they are
/// stored as (prefix, suffix) pairs and matched literally rather than pulling
/// in a regex engine for eight fixed patterns.
const PE_NORETURN_API_PATTERNS: &[(&str, &str)] = &[
    ("msvcr", "._cxxthrowexception"),
    ("msvcr", ".abort"),
    ("msvcr", ".exit"),
    ("msvcr", "._exit"),
    ("msvcr", ".quick_exit"),
    (
        "api_ms_win_crt_runtime_",
        "._invalid_parameter_noinfo_noreturn",
    ),
    ("api_ms_win_crt_runtime_", ".exit"),
    ("api_ms_win_crt_runtime_", "._exit"),
];

/// `vivisect/parsers/elf.py:295-305`. The ELF loader registers imports under
/// the literal library name `*`, so these match the import location name
/// directly.
const ELF_NORETURN_APIS: &[&str] = &[
    "*.abort",
    "*.exit",
    "*._exit",
    "*.longjmp",
    "*._setjmp",
    "*.j__zst9terminatev",
    "*.std::terminate(void)",
    "*.__assert_fail",
    "*.__stack_chk_fail",
    "*.pthread_exit",
];

/// Maximum number of discovery passes run to reach the no-return fixpoint.
/// Each pass can only *add* addresses to a set bounded by the function count,
/// so this is a guard against pathological input, not a correctness knob: on
/// the 200-sample corpus no sample needs more than three.
pub(crate) const MAX_PASSES: usize = 6;

fn matches_noreturn_api(format: ImageFormat, name: &str) -> bool {
    let name = name.to_lowercase();
    match format {
        ImageFormat::Pe => {
            PE_NORETURN_APIS.contains(&name.as_str())
                || PE_NORETURN_API_PATTERNS.iter().any(|(prefix, suffix)| {
                    // `^prefix.*\.suffix$`: `.*` matches any run of characters
                    // (including dots), so the pattern is exactly a prefix and
                    // a suffix that must not overlap.
                    name.len() >= prefix.len().saturating_add(suffix.len())
                        && name.starts_with(prefix)
                        && name.ends_with(suffix)
                })
        }
        ImageFormat::Elf => ELF_NORETURN_APIS.contains(&name.as_str()),
        // A raw blob has no import table, so no name can be resolved.
        ImageFormat::Sc => false,
        // No pinned Vivisect behavior exists for Mach-O to port a no-return
        // API list from (Vivisect never loaded this format at all).
        ImageFormat::Macho => false,
    }
}

/// The import locations whose name matches a pinned no-return API -- the state
/// `addNoReturnApi` installs by walking `getImports()` and calling
/// `cfctx.addNoReturnAddr(lva)` for each match. This is known before any code
/// flow runs, so it is the seed the first discovery pass starts from.
pub(crate) fn seed_addresses(image: &LoadedImage) -> BTreeSet<u64> {
    image
        .import_locations
        .iter()
        .filter(|(_, name)| matches_noreturn_api(image.format, name))
        .map(|(&address, _)| address)
        .collect()
}

/// The import location a function is a thunk to, if its *entry* instruction
/// branches or calls through a known import slot. Port of
/// `vivisect/analysis/generic/thunks.py::analyzeFunction`, which walks the
/// `REF_CODE` xrefs *from the function VA* and calls
/// `makeFunctionThunk(funcva, linfo)` when one lands on a `LOC_IMPORT`;
/// `makeFunctionThunk` then routes the import's name through
/// `checkNoRetApi` (`vivisect/__init__.py:1762`).
///
/// Reads the generic `Flow`/`memory_target` boundary for x86, so that half
/// is architecture-independent without a gate on its own: for AArch64
/// `memory_target` is always `None` (see `decoder.rs`), since AArch64 has no
/// single instruction whose *own* operand computes a GOT slot address the
/// way x86 `jmp [rip+X]` does. Its PLT stub is `adrp`+`ldr`+`br` instead, so
/// this also tries `decoder::aarch64_plt_got_target` on the function's first
/// two instructions, resolving straight to the GOT slot address -- the same
/// thing `memory_target` gives the x86 branch, and deliberately *not* the
/// stub's own address, since `propagate`'s `seed.contains(&slot)` check
/// needs to compare against `import_locations`' original, relocation-derived
/// keys. This must not depend on `run_aarch64_plt_wave` having already run
/// (it recomputes the pattern itself) since `noreturn::seed_addresses` is
/// captured once, before the first recovery pass -- an AArch64-thunk-to-a-
/// no-return-API needs to resolve on that very first pass, not one pass
/// behind.
fn import_thunk_location(analysis: &Analysis, function: &Function) -> Option<u64> {
    let insn = analysis.instructions.get(&function.addr)?;
    let target = if matches!(insn.flow, Flow::IndirectCall | Flow::IndirectBranch) {
        memory_target(insn)?
    } else {
        let second = analysis.instructions.get(&insn.next_address)?;
        decoder::aarch64_plt_got_target(insn, second)?
    };
    analysis
        .image
        .import_locations
        .contains_key(&target)
        .then_some(target)
}

/// Port of `vivisect/analysis/generic/noret.py::analyzeFunction`: walk the
/// function's leaf blocks (nodes with no outgoing edge) and decide whether any
/// of them can return.
///
/// Upstream sets `hasret` for exactly two kinds of leaf -- one ending in
/// `IF_RET`, and one ending in an unresolved `IF_BRANCH` -- and leaves it
/// false for every other terminator, including a block that simply stops
/// because the next bytes would not decode. capa-x used to treat that last
/// case as returning, on the theory that inferring "no-return" from its own
/// recovery gap would turn a missing-code bug into a truncated-caller bug.
/// Measured, the theory had it backwards: the gap is usually the *same* gap
/// upstream has, and not propagating from it is what lets capa-x fall
/// through a call upstream treats as terminal and absorb unrelated code.
fn function_never_returns(analysis: &Analysis, function: &Function) -> bool {
    // noret.py bails on import thunks before looking at the graph at all;
    // their no-return status comes from `checkNoRetApi` instead.
    if import_thunk_location(analysis, function).is_some() {
        return false;
    }
    for block in function
        .blocks
        .iter()
        .filter(|block| block.succs.is_empty())
    {
        let Some(last) = block.insns.last() else {
            continue;
        };
        // `if vw.isNoReturnVa(lva): continue` -- a leaf ending in a call whose
        // fallthrough was suppressed is exactly the non-returning case.
        if analysis.noreturn_calls.contains(&last.address) {
            continue;
        }
        match last.flow {
            // `linfo & envi.IF_RET`
            Flow::Return => return false,
            // `linfo & envi.IF_BRANCH` -- "be wary of dynamic branches we
            // couldn't resolve".
            Flow::UnconditionalBranch | Flow::ConditionalBranch | Flow::IndirectBranch => {
                return false
            }
            // Everything else -- `int3`/`ud2`/`eret`/`drps`, a call whose
            // fallthrough is gone, or a block cut short because the next
            // bytes do not decode -- is neither `IF_RET` nor `IF_BRANCH`, so
            // upstream lets `hasret` stay false and the function is marked
            // no-return.
            Flow::Terminal | Flow::Next | Flow::Call | Flow::IndirectCall => {}
        }
    }
    true
}

/// Recompute the full no-return address set from a completed recovery pass.
/// Returns the union of `seed` (the import locations, which never change) and
/// every function entry the two propagation rules mark.
pub(crate) fn propagate(analysis: &Analysis, seed: &BTreeSet<u64>) -> BTreeSet<u64> {
    let mut result = seed.clone();
    for function in analysis.functions.values() {
        // `checkNoRetApi`: a thunk inherits the no-return status of the
        // import it forwards to.
        if import_thunk_location(analysis, function).is_some_and(|slot| seed.contains(&slot)) {
            result.insert(function.addr);
            continue;
        }
        if function_never_returns(analysis, function) {
            result.insert(function.addr);
        }
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pe_literal_and_regex_api_names_match_case_insensitively() {
        assert!(matches_noreturn_api(
            ImageFormat::Pe,
            "kernel32.ExitProcess"
        ));
        assert!(matches_noreturn_api(ImageFormat::Pe, "KERNEL32.EXITTHREAD"));
        assert!(matches_noreturn_api(ImageFormat::Pe, "msvcr100.exit"));
        assert!(matches_noreturn_api(
            ImageFormat::Pe,
            "msvcrt._CxxThrowException"
        ));
        assert!(matches_noreturn_api(
            ImageFormat::Pe,
            "api_ms_win_crt_runtime_l1_1_0._invalid_parameter_noinfo_noreturn"
        ));
        // `^msvcr.*\.exit$` must not match a longer symbol that merely ends
        // in "exit", nor a different library.
        assert!(!matches_noreturn_api(ImageFormat::Pe, "msvcr100.quickexit"));
        assert!(!matches_noreturn_api(ImageFormat::Pe, "kernel32.ExitCode"));
        assert!(!matches_noreturn_api(ImageFormat::Pe, "ucrtbase.exit"));
        // The ELF list is not in scope for a PE.
        assert!(!matches_noreturn_api(ImageFormat::Pe, "*.abort"));
    }

    #[test]
    fn elf_api_names_match_the_star_library_form() {
        assert!(matches_noreturn_api(ImageFormat::Elf, "*.__stack_chk_fail"));
        assert!(matches_noreturn_api(ImageFormat::Elf, "*.pthread_exit"));
        assert!(!matches_noreturn_api(ImageFormat::Elf, "*.printf"));
        assert!(!matches_noreturn_api(
            ImageFormat::Elf,
            "kernel32.ExitProcess"
        ));
    }

    #[test]
    fn shellcode_has_no_noreturn_apis() {
        assert!(!matches_noreturn_api(
            ImageFormat::Sc,
            "kernel32.exitprocess"
        ));
    }
}
