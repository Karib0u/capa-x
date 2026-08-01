#![forbid(unsafe_code)]

pub mod address;
pub mod api;
pub mod capabilities;
pub mod com;
pub mod engine;
pub mod extract;
pub mod features;
pub mod freeze;
pub mod parallel;
pub mod result_document;
pub use result_document as rd;
pub mod render;
pub mod rules;

/// The crate version, as reported by `capa --version`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The capa-rules release this build is written against, from `PINNED.md`.
///
/// Two builds of the same capa-x version can produce different results if
/// they are pointed at different rule corpora, so a version string without a
/// rules pin does not identify a run. `rules_pin_matches_pinned_md` below
/// keeps this equal to `PINNED.md`, which is the single source of truth.
pub const RULES_PIN: &str = rules_pin!();

/// The literal lives in a macro so [`VERSION_STRING`] can `concat!` it: clap
/// wants a `&'static str` for `--version`, and building one at runtime would
/// mean leaking a `String` for a value known at compile time.
macro_rules! rules_pin {
    () => {
        "v9.4.0"
    };
}
use rules_pin;

/// `capa --version`: the port's version and the rules release it targets.
pub const VERSION_STRING: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (capa-rules ",
    rules_pin!(),
    ")"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!version().is_empty());
    }

    #[test]
    fn rules_pin_matches_pinned_md() {
        // PINNED.md is the single source of truth for every upstream version;
        // a constant that can drift away from it silently is worse than no
        // constant, because it appears in `--version` output users quote.
        let pinned = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("PINNED.md");
        let Ok(text) = std::fs::read_to_string(&pinned) else {
            // Released crate, no repo checkout beside it: nothing to check.
            return;
        };
        let row = text
            .lines()
            .find(|line| line.contains("capa-rules"))
            .unwrap_or_else(|| panic!("PINNED.md has no capa-rules row"));
        assert!(
            row.contains(&format!("`{RULES_PIN}`")),
            "RULES_PIN is {RULES_PIN}, but PINNED.md says: {row}"
        );
    }
}
