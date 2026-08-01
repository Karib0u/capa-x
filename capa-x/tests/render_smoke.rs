//! Text output must render for default/-v/-vv without panicking on the full
//! corpus. Runs all three renderers over every committed result
//! document fixture (see `schema_roundtrip.rs`).

use std::path::Path;

use capa_x::rd::ResultDocument;
use capa_x::render::{default, verbose, vverbose};

fn fixtures_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/resultdoc")
}

#[test]
#[allow(clippy::expect_used)]
fn all_renderers_run_without_panicking_on_every_fixture() {
    let dir = fixtures_dir();
    let mut checked = 0;
    for entry in
        std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
    {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let doc: ResultDocument = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{}: failed to parse fixture: {e}", path.display()));

        let default_out = default::render(&doc);
        let verbose_out = verbose::render(&doc);
        let vverbose_out = vverbose::render(&doc);

        assert!(
            !default_out.is_empty(),
            "{}: empty default output",
            path.display()
        );
        assert!(
            !verbose_out.is_empty(),
            "{}: empty verbose output",
            path.display()
        );
        assert!(
            !vverbose_out.is_empty(),
            "{}: empty vverbose output",
            path.display()
        );
        checked += 1;
    }
    assert!(
        checked >= 10,
        "expected at least 10 fixtures, found {checked}"
    );
}
