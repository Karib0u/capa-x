//! Known effect models for runtime helpers that ordinary calling-convention
//! rules misdescribe.
//!
//! Ghidra replaces calls to these helpers with the p-code snippets declared as
//! `<callfixup>` entries in the compiler specification. The table maps a
//! recognized function name to the fixup it uses. The names are the `<target>`
//! entries of `x86-64-win.cspec` and `x86win.cspec`, compared without leading
//! underscores because FLIRT and Function ID spell the same helper with different
//! prefixes. A test checks both tables against the vendored specifications.

/// Ordered by fixup. Keep in step with the vendored `x86-64-win.cspec`.
const FIXUPS_X64: &[(&str, &str)] = &[
    ("security_check_cookie", "security_check_cookie"),
    ("alloca_probe", "alloca_probe"),
    ("alloca_probe2", "alloca_probe"),
    ("chkstk", "alloca_probe"),
    ("chkstk2", "alloca_probe"),
    ("chkstk_ms", "alloca_probe"),
    ("guard_dispatch_icall", "guard_dispatch_icall"),
];

/// Keep in step with the vendored `x86win.cspec` (27 target names, 10 fixups).
const FIXUPS_X86: &[(&str, &str)] = &[
    ("EH_prolog", "EH_prolog"),
    ("EH_prolog3", "EH_prolog3"),
    ("EH_prolog3_GS", "EH_prolog3"),
    ("EH_prolog3_catch", "EH_prolog3"),
    ("EH_prolog3_catch_GS", "EH_prolog3"),
    ("EH_epilog3", "EH_epilog3"),
    ("EH_epilog3_GS", "EH_epilog3"),
    ("EH_epilog3_catch", "EH_epilog3"),
    ("EH_epilog3_catch_GS", "EH_epilog3"),
    ("SEH_epilog", "EH_epilog3"),
    ("SEH_epilog4", "EH_epilog3"),
    ("SEH_epilog4_GS", "EH_epilog3"),
    ("EH_prolog3_align", "EH_prolog3_align"),
    ("EH_prolog3_GS_align", "EH_prolog3_align"),
    ("EH_prolog3_catch_align", "EH_prolog3_align"),
    ("EH_prolog3_catch_GS_align", "EH_prolog3_align"),
    ("EH_epilog3_align", "EH_epilog3_align"),
    ("EH_epilog3_GS_align", "EH_epilog3_align"),
    ("alloca_probe", "alloca_probe"),
    ("alloca_probe_8", "alloca_probe"),
    ("alloca_probe_16", "alloca_probe"),
    ("chkstk", "alloca_probe"),
    ("SEH_prolog", "SEH_prolog"),
    ("SEH_prolog4", "SEH_prolog4"),
    ("SEH_prolog4_GS", "SEH_prolog4"),
    ("RTC_CheckEsp", "__RTC_CheckEsp"),
    ("security_check_cookie", "security_check_cookie"),
];

/// The compiler-spec call fixup for a recognized helper, if there is one.
/// `wide` selects the x86-64 table, otherwise the x86-32 one.
pub fn call_fixup(name: &str, wide: bool) -> Option<&'static str> {
    let name = name.trim_start_matches('_');
    (if wide { FIXUPS_X64 } else { FIXUPS_X86 })
        .iter()
        .find(|(helper, _)| *helper == name)
        .map(|(_, fixup)| *fixup)
}

#[cfg(test)]
mod tests {
    use super::{call_fixup, FIXUPS_X64, FIXUPS_X86};
    use std::collections::BTreeSet;

    #[test]
    fn prefixes_do_not_matter() {
        assert_eq!(
            call_fixup("__security_check_cookie", true),
            Some("security_check_cookie")
        );
        assert_eq!(
            call_fixup("security_check_cookie", true),
            Some("security_check_cookie")
        );
        assert_eq!(call_fixup("___chkstk_ms", true), Some("alloca_probe"));
        assert_eq!(call_fixup("_alloca_probe_16", true), None);
        assert_eq!(call_fixup("_alloca_probe_16", false), Some("alloca_probe"));
        assert_eq!(call_fixup("__EH_prolog3_catch_GS", false), Some("EH_prolog3"));
        assert_eq!(call_fixup("memcpy", true), None);
        assert_eq!(call_fixup("memcpy", false), None);
    }

    /// The (target, fixup) pairs of a compiler spec, leading underscores removed.
    fn spec_pairs(path: &str) -> BTreeSet<(String, String)> {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../third_party/ghidra/specs/").to_owned() + path)
            .expect("vendored compiler spec");
        let mut pairs = BTreeSet::new();
        for block in text.split("<callfixup name=\"").skip(1) {
            let (fixup, rest) = block.split_once('"').expect("fixup name");
            let body = rest.split("</callfixup>").next().expect("fixup body");
            for target in body.split("<target name=\"").skip(1) {
                let name = target.split('"').next().expect("target name").trim_start_matches('_');
                if !name.starts_with("thunk_") && !name.starts_with("FID_conflict") {
                    pairs.insert((name.to_owned(), fixup.to_owned()));
                }
            }
        }
        pairs
    }

    fn table(entries: &[(&str, &str)]) -> BTreeSet<(String, String)> {
        entries.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    #[test]
    fn tables_match_the_vendored_compiler_specs() {
        assert_eq!(table(FIXUPS_X64), spec_pairs("x86-64-win.cspec"));
        assert_eq!(table(FIXUPS_X86), spec_pairs("x86win.cspec"));
    }
}
