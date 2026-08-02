//! Regression guard for the ADR 0003 audit: every mutant returns `Err`.
//! This covers
//! the vendored `dnfile` fork's capa-x patches (`third_party/dnfile/PATCH.md`):
//! the coded-index panic, the `TypeDef::parse2`
//! empty-`Field`/`MethodDef`-table error found by this phase's row-count
//! validation, and (task 3) the CIL method-body reader's tiny/fat header,
//! exception-region, and operand-decoding bugs. Byte-flip mutants over all 8
//! pinned .NET samples through `capa_x::extract::dotnet::load`, wrapped
//! in `catch_unwind` -- a panic here is a regression in the vendored fork,
//! not a bug in the mutated bytes, which should only ever produce an `Err`.
//!
//! `dotnet::load` runs `DnPe::parse`, which decodes every `MethodDef`'s CIL
//! body eagerly (`ClrData::functions`) as part of loading -- so this is also
//! task 3's "fuzz target for method bodies": a mutation landing inside one
//! method's header/instructions/exception-region bytes now degrades to
//! skipping just that method (`parse_functions` catches
//! `MethodBodyFormatError`/`IoError` per method, task 3's own fix -- see
//! `PATCH.md`) rather than aborting the whole file, so later mutants keep
//! exercising the CIL decoder deeper into the file than before that fix.
//!
//! The full-pipeline test widens the call under test from `dotnet::load` (metadata parse
//! only) to [`extract_dotnet`], its caller: name-model resolution
//! (`TokenCache::build`), the call graph, and per-method feature synthesis
//! all run on every mutant now too, closing the "malformed corpus run
//! against the full CLI pipeline" item left open by earlier work (matching --
//! the one CLI stage left
//! unexercised here -- is generic engine code shared by every backend, not
//! new to this phase).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::panic;
use std::path::{Path, PathBuf};

use capa_x::extract::dotnet::features::extract_dotnet;
use capa_x::parallel::AnalysisOptions;

// Small deterministic xorshift64* PRNG so a failure is reproducible without
// committing a corpus of mutated files.
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

const MUTANTS_PER_SAMPLE: usize = 300;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests/testfiles/dotnet")
}

// 2,400 mutants through `dotnet::load`, single-threaded: ~20 s. Same shape as
// `aarch64_elf_fuzz.rs` -- a malformed-input panic guard, not a test an
// ordinary edit moves. CI runs it via
// `cargo test --workspace -- --include-ignored`.
#[test]
#[ignore = "slow robustness gate; run with --include-ignored"]
fn mutated_dotnet_samples_never_panic() {
    // The vendored fork's own panic hook still prints backtraces on our
    // caught panics; keep test output readable and restore it afterward.
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    let mut samples: Vec<PathBuf> = std::fs::read_dir(corpus_dir())
        .expect("tests/testfiles/dotnet present (capa-testfiles submodule checked out?)")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .map(|e| e == "exe_" || e == "dll_")
                .unwrap_or(false)
        })
        .collect();
    samples.sort();
    assert_eq!(samples.len(), 8, "expected 8 pinned .NET samples");

    let mut failures: Vec<String> = Vec::new();

    for path in &samples {
        let original =
            std::fs::read(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let mut rng = Rng(0x9E3779B97F4A7C15 ^ (name.len() as u64 + 1));

        for _ in 0..MUTANTS_PER_SAMPLE {
            let mut data = original.clone();
            let n_flips = 1 + rng.below(3);
            for _ in 0..n_flips {
                let idx = rng.below(data.len());
                data[idx] = (rng.next() & 0xFF) as u8;
            }

            let result = panic::catch_unwind(|| extract_dotnet(&data, &AnalysisOptions::SERIAL));
            if let Err(payload) = result {
                let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic payload>".to_string()
                };
                failures.push(format!("{name}: {msg}"));
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
