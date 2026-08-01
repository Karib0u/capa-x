//! Shared helpers for the integration tests. Not a test target itself --
//! `tests/` subdirectories are modules, not test binaries.
#![allow(dead_code)] // each test binary uses only the helpers it needs

use std::path::Path;

/// Sample names from a corpus list in `scripts/`, one per line.
///
/// Same convention as `scripts/difftest.py::read_sample_list`: `#` starts a
/// comment anywhere on the line, not only in column 0. The lists annotate
/// entries with the reason each sample earns its slot (see
/// `scripts/corpus-smoke.txt`), and a reader that only skipped whole-line
/// comments would fold the annotation into the filename.
pub fn read_corpus_list(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    text.lines()
        .filter_map(|line| {
            let name = line.split('#').next().unwrap_or("").trim();
            (!name.is_empty()).then(|| name.to_string())
        })
        .collect()
}
