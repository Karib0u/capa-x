//! Cross-product acceptance: all input shapes coexist. Run each of x86/x64
//! PE, x86/x64 ELF, x86_64 Mach-O, AArch64
//! ELF/Mach-O/PE, .NET, sc32/sc64, and freeze (static + dynamic) through:
//! `--jobs 1` vs default, malformed input, result-doc round-trip, repeated
//! output. Publish the table in the PR; every cell green."
//!
//! Goes through `capa_x::api::analyze` -- the same seam `capa-x-cli` calls
//! (J13) -- rather than a subprocess, so this is the fastest and most direct
//! way to exercise every format/arch combination through the *entire*
//! pipeline (format detection, extraction, recovery, FLIRT, matching, result
//! document) at once, with the full 1,042-rule pinned corpus loaded exactly
//! once and reused across every sample (the same "load once, scan many"
//! shape the Python binding exposes).
//!
//! "Result-doc round-trip" here means `rd::ResultDocument`'s own
//! `Serialize`/`Deserialize` round-trips losslessly for a document built
//! from each of these formats -- the same method `schema_roundtrip.rs` uses
//! against pre-captured *Python* output, applied here to freshly-generated
//! capa-x output for formats Python capa has no oracle for at all
//! (Mach-O, AArch64 PE) or that `schema_roundtrip.rs`'s fixed fixture list
//! doesn't happen to cover (AArch64 ELF, sc32/sc64, dynamic freeze).
//! Validating against pinned Python capa's own pydantic model (J14) is a
//! separate gate -- this only proves the Rust-side shape is
//! self-consistent, matching `capa-x/tests/schema_roundtrip.rs`'s own
//! stated scope.
//!
//! Every test here is `#[ignore]`d: the four of them together are ~197 s, the
//! single largest cost in `cargo test --workspace`, because each reloads the
//! 1,042-rule corpus and runs all 11 shapes (cell 1 also at four job counts).
//! This is a pre-merge acceptance matrix, not a test an ordinary edit moves.
//! CI runs it via `cargo test --workspace -- --include-ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::panic;
use std::path::{Path, PathBuf};

use capa_x::api::{self, AnalysisError, Format, Input};
use capa_x::capabilities::MatchingRuleSet;
use capa_x::parallel::{AnalysisOptions, Jobs};
use capa_x::rd::ResultDocument;
use capa_x::rules::load_rule_directory;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capa-x has a parent directory")
        .to_path_buf()
}

fn ruleset() -> MatchingRuleSet {
    let rules_dir = workspace_root().join("rules");
    let rules = load_rule_directory(&rules_dir, &AnalysisOptions::SERIAL)
        .expect("the pinned rules/ corpus loads");
    MatchingRuleSet::new(rules).expect("the pinned rules/ corpus builds a valid ruleset")
}

/// One cell of the matrix: a label for the table, a fixture path, and the
/// `AnalysisOptions` fields needed to select it (mirroring what `-f
/// <format>`/`--arch <arch>` would pass on the CLI).
struct Shape {
    label: &'static str,
    path: &'static str,
    format: Format,
    arch: Option<&'static str>,
}

/// One representative sample per input shape the brief lists. Bitness
/// parity within a format (x86 vs x64 PE/ELF) is already the 200-sample
/// corpus's job; this
/// table is about *shapes coexisting*, not re-proving bitness coverage.
fn shapes() -> Vec<Shape> {
    vec![
        Shape {
            label: "x86/x64 PE",
            path: "tests/testfiles/kernel32-64.dll_",
            format: Format::Pe,
            arch: None,
        },
        Shape {
            label: "x86/x64 ELF",
            path: "tests/testfiles/7351f8a40c5450557b24622417fc478d.elf_",
            format: Format::Elf,
            arch: None,
        },
        Shape {
            label: "x86_64 Mach-O",
            path: "capa-x/tests/fixtures/macho/thin-x86_64-exe",
            format: Format::Macho,
            arch: None,
        },
        Shape {
            label: "AArch64 ELF",
            path: "tests/testfiles/aarch64/687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf_",
            format: Format::Elf,
            arch: None,
        },
        Shape {
            label: "AArch64 Mach-O",
            path: "capa-x/tests/fixtures/macho/thin-arm64-exe",
            format: Format::Macho,
            arch: None,
        },
        Shape {
            label: "AArch64 PE",
            path: "capa-x/tests/fixtures/aarch64-pe/exe-with-import.exe",
            format: Format::Pe,
            arch: None,
        },
        Shape {
            label: ".NET",
            path: "tests/testfiles/dotnet/1c444ebeba24dcba8628b7dfe5fec7c6.exe_",
            format: Format::Dotnet,
            arch: None,
        },
        Shape {
            label: "sc32",
            path: "tests/testfiles/499c2a85f6e8142c3f48d4251c9c7cd6.raw32",
            format: Format::Sc32,
            arch: None,
        },
        Shape {
            label: "sc64",
            path: "tests/testfiles/4b9efd882c49ef7525370ffb5197ad86.raw64",
            format: Format::Sc64,
            arch: None,
        },
        Shape {
            label: "freeze (static)",
            path: "capa-x/tests/fixtures/freeze/pma01-01-dll.frz.json",
            format: Format::Freeze,
            arch: None,
        },
        Shape {
            label: "freeze (dynamic)",
            path: "capa-x/tests/fixtures/freeze/dynamic-sample.frz.json",
            format: Format::Freeze,
            arch: None,
        },
    ]
}

fn fixture_bytes(relative: &str) -> Vec<u8> {
    let path = workspace_root().join(relative);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn options(shape: &Shape, jobs: Jobs) -> AnalysisOptions {
    AnalysisOptions {
        jobs,
        format: shape.format,
        os: None,
        arch: shape.arch.map(str::to_string),
        file_only: false,
        signatures_path: None,
    }
}

fn analyze(
    bytes: &[u8],
    shape: &Shape,
    jobs: Jobs,
    rules: &MatchingRuleSet,
) -> Result<ResultDocument, AnalysisError> {
    let input = Input {
        bytes,
        sample_path: shape.label.to_string(),
        rules_paths: vec!["rules".to_string()],
        argv: None,
    };
    api::analyze(&input, rules, &options(shape, jobs))
}

/// `meta.timestamp` is wall-clock and therefore never equal across two
/// separate `analyze` calls -- normalized away before any structural
/// comparison, the same field `scripts/difftest.py::normalize_result_doc`
/// drops for the same reason.
fn normalized_json(doc: &ResultDocument) -> serde_json::Value {
    let mut value = serde_json::to_value(doc).expect("ResultDocument serializes");
    if let Some(timestamp) = value.pointer_mut("/meta/timestamp") {
        *timestamp = serde_json::Value::Null;
    }
    value
}

/// Cell 1: `--jobs 1` vs default (and a couple of points in between) --
/// byte-identical after timestamp normalization, matching AGENTS.md's
/// blanket rule for every backend.
#[test]
#[ignore = "slow acceptance gate; run with --include-ignored"]
fn jobs_1_matches_default_for_every_shape() {
    let rules = ruleset();
    let mut failures = Vec::new();
    for shape in shapes() {
        let bytes = fixture_bytes(shape.path);
        let serial = match analyze(&bytes, &shape, Jobs::SERIAL, &rules) {
            Ok(doc) => normalized_json(&doc),
            Err(e) => {
                failures.push(format!("{}: --jobs 1 failed: {e}", shape.label));
                continue;
            }
        };
        for jobs in [
            Jobs::new(2).unwrap(),
            Jobs::new(4).unwrap(),
            Jobs::default(),
        ] {
            match analyze(&bytes, &shape, jobs, &rules) {
                Ok(doc) => {
                    let parallel = normalized_json(&doc);
                    if parallel != serial {
                        failures.push(format!(
                            "{}: --jobs {} differs from --jobs 1",
                            shape.label,
                            jobs.get()
                        ));
                    }
                }
                Err(e) => failures.push(format!(
                    "{}: --jobs {} failed: {e}",
                    shape.label,
                    jobs.get()
                )),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Cell 2: repeated output -- two `--jobs 1` runs of the same input are
/// byte-identical (after timestamp normalization). Distinct from the jobs
/// check above: this catches nondeterminism that has nothing to do with
/// thread count (e.g. an unstable sort, an uninitialized-memory read, a
/// HashMap iteration order leaking into output).
#[test]
#[ignore = "slow acceptance gate; run with --include-ignored"]
fn repeated_output_is_identical_for_every_shape() {
    let rules = ruleset();
    let mut failures = Vec::new();
    for shape in shapes() {
        let bytes = fixture_bytes(shape.path);
        let first = match analyze(&bytes, &shape, Jobs::SERIAL, &rules) {
            Ok(doc) => normalized_json(&doc),
            Err(e) => {
                failures.push(format!("{}: first run failed: {e}", shape.label));
                continue;
            }
        };
        for attempt in 0..3 {
            match analyze(&bytes, &shape, Jobs::SERIAL, &rules) {
                Ok(doc) => {
                    let again = normalized_json(&doc);
                    if again != first {
                        failures.push(format!(
                            "{}: repeat #{attempt} differs from the first run",
                            shape.label
                        ));
                    }
                }
                Err(e) => failures.push(format!("{}: repeat #{attempt} failed: {e}", shape.label)),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Cell 3: result-doc round-trip -- `serde_json` deserializes the freshly
/// produced document back into `ResultDocument` and re-serializes to the
/// same structure. See the module doc for how this differs from J14.
#[test]
#[ignore = "slow acceptance gate; run with --include-ignored"]
fn result_document_round_trips_for_every_shape() {
    let rules = ruleset();
    let mut failures = Vec::new();
    for shape in shapes() {
        let bytes = fixture_bytes(shape.path);
        let doc = match analyze(&bytes, &shape, Jobs::SERIAL, &rules) {
            Ok(doc) => doc,
            Err(e) => {
                failures.push(format!("{}: analyze failed: {e}", shape.label));
                continue;
            }
        };
        let text = serde_json::to_string(&doc)
            .unwrap_or_else(|e| panic!("{}: failed to serialize ResultDocument: {e}", shape.label));
        let reparsed: ResultDocument = match serde_json::from_str(&text) {
            Ok(doc) => doc,
            Err(e) => {
                failures.push(format!(
                    "{}: round-tripped JSON failed to deserialize back into ResultDocument: {e}",
                    shape.label
                ));
                continue;
            }
        };
        let original_value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let round_tripped_value = serde_json::to_value(&reparsed).unwrap_or_else(|e| {
            panic!(
                "{}: failed to re-serialize ResultDocument: {e}",
                shape.label
            )
        });
        if round_tripped_value != original_value {
            failures.push(format!(
                "{}: round-tripped document differs structurally from the original",
                shape.label
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Cell 4: malformed input -- a byte-flipped copy of every clean fixture
/// must never panic through the full `analyze` pipeline, whether it ends up
/// `Ok` (tolerant parsing found something plausible) or `Err` (a contextual
/// failure). AGENTS.md's hard rule ("no panics on untrusted input") applies
/// to the whole pipeline, not just the per-format loaders that already have
/// their own dedicated fuzz tests (`macho_features.rs`,
/// `aarch64_pe_features.rs`, `aarch64_elf_fuzz.rs`, `dotnet_dnfile_fuzz.rs`)
/// -- this is the seam where they all funnel through matching and
/// result-document construction together for the first time.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() as usize) % n
    }
}

// The dedicated per-format fuzzers (`macho_features.rs`, `aarch64_pe_
// features.rs`, `aarch64_elf_fuzz.rs`, `dotnet_dnfile_fuzz.rs`) already run
// hundreds to thousands of mutants each through extraction/recovery alone,
// which is where a malformed-input panic would actually originate; nothing
// downstream of a validated `StaticFeatures`/`Analysis` reads raw sample
// bytes again, so matching against 1,042 real rules cannot itself panic
// differently per mutant. This cell's unique value is proving the *whole*
// `api::analyze` seam survives end to end, not re-finding format-level bugs
// the dedicated fuzzers already cover deeper -- so it stays intentionally
// small (dominated by two real-world samples, `kernel32-64.dll_`'s 721 KB
// and hundreds of recovered functions matched against the full corpus per
// mutant, unlike the tiny synthetic fixtures the dedicated fuzzers target).
const MUTANTS_PER_SHAPE: usize = 15;

#[test]
#[ignore = "slow acceptance gate; run with --include-ignored"]
fn malformed_input_never_panics_through_the_full_pipeline() {
    let rules = ruleset();
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    let mut failures: Vec<String> = Vec::new();
    for shape in shapes() {
        let original = fixture_bytes(shape.path);
        let mut rng = Rng(0xA5A5_5A5A_1234_5678 ^ (shape.label.len() as u64 + 1));
        for _ in 0..MUTANTS_PER_SHAPE {
            let mut data = original.clone();
            if data.is_empty() {
                continue;
            }
            let n_flips = 1 + rng.below(3);
            for _ in 0..n_flips {
                let idx = rng.below(data.len());
                data[idx] = (rng.next() & 0xFF) as u8;
            }
            let result = panic::catch_unwind(|| {
                let _: Result<ResultDocument, AnalysisError> =
                    analyze(&data, &shape, Jobs::SERIAL, &rules);
            });
            if result.is_err() {
                failures.push(format!("{}: mutant input panicked", shape.label));
            }
        }
    }

    panic::set_hook(default_hook);
    assert!(
        failures.is_empty(),
        "{} mutant(s) panicked instead of returning Err:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
