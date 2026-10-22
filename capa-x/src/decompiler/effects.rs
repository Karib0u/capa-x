//! Known effect models for runtime helpers that ordinary calling-convention
//! rules misdescribe.
//!
//! Ghidra replaces calls to these helpers with the p-code snippets declared as
//! `<callfixup>` entries in the compiler specification. The table maps a
//! recognized function name to the fixup it uses. The names are the `<target>`
//! entries of `x86-64-win.cspec`, compared without leading underscores because
//! FLIRT and Function ID spell the same helper with different prefixes.

/// Ordered by fixup. Keep in step with the vendored `x86-64-win.cspec`.
const FIXUPS: &[(&str, &str)] = &[
    ("security_check_cookie", "security_check_cookie"),
    ("alloca_probe", "alloca_probe"),
    ("alloca_probe2", "alloca_probe"),
    ("chkstk", "alloca_probe"),
    ("chkstk2", "alloca_probe"),
    ("chkstk_ms", "alloca_probe"),
    ("guard_dispatch_icall", "guard_dispatch_icall"),
];

/// The compiler-spec call fixup for a recognized helper, if there is one.
pub fn call_fixup(name: &str) -> Option<&'static str> {
    let name = name.trim_start_matches('_');
    FIXUPS
        .iter()
        .find(|(helper, _)| *helper == name)
        .map(|(_, fixup)| *fixup)
}

#[cfg(test)]
mod tests {
    use super::call_fixup;

    #[test]
    fn prefixes_do_not_matter() {
        assert_eq!(
            call_fixup("__security_check_cookie"),
            Some("security_check_cookie")
        );
        assert_eq!(
            call_fixup("security_check_cookie"),
            Some("security_check_cookie")
        );
        assert_eq!(call_fixup("___chkstk_ms"), Some("alloca_probe"));
        assert_eq!(call_fixup("_alloca_probe_16"), None);
        assert_eq!(call_fixup("memcpy"), None);
    }
}
