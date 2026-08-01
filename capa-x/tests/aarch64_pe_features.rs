//! AArch64 PE acceptance: structure, feature, `.pdata`-seeding,
//! synthetic-rule, and malformed-input coverage for `IMAGE_FILE_MACHINE_ARM64`
//! PE input through the existing, already-format-generic PE loader
//! (`capa-x/src/extract/loader/image.rs`'s `LoadedImage::from_pe`,
//! `extract/pe.rs`, and `recovery::analyze`/`collect_pe_seeds`'s ARM64
//! `IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY` branch).
//!
//! Pinned capa 9.4.0 has no ARM64 PE input at all (no Windows-on-ARM sample
//! in its own corpus), so -- exactly like `macho_features.rs` -- there is no
//! Python oracle to diff against. The oracle is
//! `capa-x/tests/fixtures/aarch64-pe/`: hand-transcribed
//! from the fixture *source* (`src/fixture_exe.c`/`fixture_dll.c`) and
//! cross-checked against this fixture directory's own captured
//! `llvm-readobj`/`llvm-objdump` output and this machine's `objdump`
//! (`coff-arm64` support), recorded in this file's own comments per
//! AGENTS.md's "never carry a measurement forward" rule.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::panic;
use std::path::{Path, PathBuf};

use capa_x::address::Address;
use capa_x::capabilities::{find_static_capabilities, MatchingRuleSet};
use capa_x::extract::flirt::enrich_static_features;
use capa_x::extract::image::LoadedImage;
use capa_x::extract::pe::extract_pe;
use capa_x::extract::recovery::{self, RecoveryError, SeedKind};
use capa_x::features::Feature;
use capa_x::freeze::StaticFeatures;
use capa_x::parallel::AnalysisOptions;
use capa_x::rules::Rule;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("aarch64-pe")
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = fixtures_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn full_features(bytes: &[u8]) -> (StaticFeatures, recovery::Analysis) {
    let mut features = extract_pe(bytes).expect("PE file/global features extract");
    let analysis = recovery::analyze(bytes).expect("PE code recovery");
    enrich_static_features(
        &mut features,
        &analysis,
        &BTreeMap::new(),
        &AnalysisOptions::SERIAL,
    );
    (features, analysis)
}

fn has_file_feature(features: &StaticFeatures, feature: &Feature, address: u64) -> bool {
    features
        .file_features
        .iter()
        .any(|(addr, f)| f == feature && *addr == Address::Absolute(address))
}

// ---------------------------------------------------------------------
// Structure: cross-checked against `objdump -d` (`coff-arm64` format) and
// this fixture directory's own `*.oracle.json` on this machine.
// ---------------------------------------------------------------------

#[test]
fn exe_sample_hash_matches_the_manifest() {
    let bytes = fixture_bytes("exe-with-import.exe");
    let (features, _) = full_features(&bytes);
    assert_eq!(
        features.sample_hashes.sha256,
        "9319db22682d4eb6564080dd197e0736e3152949dbed03e124a2539465c83dc1"
    );
}

#[test]
fn dll_sample_hash_matches_the_manifest() {
    let bytes = fixture_bytes("dll-with-export.dll");
    let (features, _) = full_features(&bytes);
    assert_eq!(
        features.sample_hashes.sha256,
        "c64bf560bb3f0bda39937d4caed088105871aed65eacf56e962ab0f989eb4ec8"
    );
}

#[test]
fn exe_global_features_are_pe_windows_aarch64() {
    let bytes = fixture_bytes("exe-with-import.exe");
    let (features, _) = full_features(&bytes);
    assert!(features
        .global_features
        .contains(&Feature::Format("pe".to_string())));
    // "aarch64", not "arm64" -- matches ELF/Mach-O's own arch-feature
    // string, since capa-rules rules keyed on `arch:` are written against
    // that upstream convention (`extract/elf.rs`, `extract/macho.rs`).
    assert!(features
        .global_features
        .contains(&Feature::Arch("aarch64".to_string())));
    assert!(features
        .global_features
        .contains(&Feature::Os("windows".to_string())));
}

#[test]
fn exe_sections_are_present_at_their_rva_mapped_addresses() {
    let bytes = fixture_bytes("exe-with-import.exe");
    let (features, _) = full_features(&bytes);
    assert!(has_file_feature(
        &features,
        &Feature::Section(".text".to_string()),
        0x1_4000_1000
    ));
    assert!(has_file_feature(
        &features,
        &Feature::Section(".rdata".to_string()),
        0x1_4000_2000
    ));
    assert!(has_file_feature(
        &features,
        &Feature::Section(".pdata".to_string()),
        0x1_4000_3000
    ));
}

/// `lld-link`'s resolved import: `FakeImportedFunc` (from the stub
/// `fake.lib` built from `fake.def`) at IAT slot `0x140002038` -- confirmed
/// against `objdump -d`'s `adrp x8, 0x140002000; ldr x8, [x8, #0x38]`
/// sequence at the call site (`0x140001034`, see the register-indirect-call
/// test below), `0x140002000 + 0x38 == 0x140002038`. Proves `from_pe`'s
/// already-format-generic import-table walk needs no ARM64-specific code
/// The test verifies the shared import path rather than reimplementing it.
#[test]
fn exe_import_resolves_at_its_iat_slot_address() {
    let bytes = fixture_bytes("exe-with-import.exe");
    let (features, _) = full_features(&bytes);
    assert!(has_file_feature(
        &features,
        &Feature::Import("FakeImportedFunc".to_string()),
        0x1_4000_2038
    ));
    assert!(has_file_feature(
        &features,
        &Feature::Import("fake.FakeImportedFunc".to_string()),
        0x1_4000_2038
    ));
}

#[test]
fn dll_exports_at_their_rva_mapped_addresses() {
    let bytes = fixture_bytes("dll-with-export.dll");
    let (features, _) = full_features(&bytes);
    assert!(has_file_feature(
        &features,
        &Feature::Export("ExportedAdd".to_string()),
        0x1_8000_1000
    ));
    assert!(has_file_feature(
        &features,
        &Feature::Export("ExportedMul".to_string()),
        0x1_8000_1020
    ));
}

// ---------------------------------------------------------------------
// `.pdata` / `IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY` seeding:
// `recovery.rs::collect_pe_seeds`'s ARM64 branch, gated on
// `image.architecture` rather than format (the AMD64 branch parses a
// different, 12-byte-entry layout and must never run against this data --
// before this branch existed, it flagged this exact `.pdata` as
// "malformed").
// ---------------------------------------------------------------------

#[test]
fn exe_pdata_seeds_every_runtime_function_begin_address() {
    let bytes = fixture_bytes("exe-with-import.exe");
    let analysis = recovery::analyze(&bytes).expect("PE code recovery");
    // `objdump -d`: `entry_point` at 0x140001000 (calls both), `add` at
    // 0x140001044, `mul` at 0x140001064 -- three ARM64 RUNTIME_FUNCTION
    // entries, 8 bytes each, in `.pdata`'s declared 24-byte directory.
    for address in [0x1_4000_1000u64, 0x1_4000_1044, 0x1_4000_1064] {
        assert!(
            analysis
                .seeds
                .get(&address)
                .is_some_and(|kinds| kinds.contains(&SeedKind::Unwind)),
            "expected SeedKind::Unwind at {address:#x}; seeds: {:?}",
            analysis.seeds.get(&address)
        );
        assert!(
            analysis.functions.contains_key(&address),
            "expected a recovered function at {address:#x}"
        );
    }
}

#[test]
fn dll_pdata_seeds_every_runtime_function_begin_address() {
    let bytes = fixture_bytes("dll-with-export.dll");
    let analysis = recovery::analyze(&bytes).expect("PE code recovery");
    // Only 2 RUNTIME_FUNCTION entries here (`.pdata`'s declared 16-byte
    // directory, confirmed against this fixture's own oracle -- 2 x 8
    // bytes), covering the two exports. `dll_entry` at 0x180001040 (`mov
    // w0, #1; ret`, `objdump -d`) is a trivial leaf function with no stack
    // frame and carries no unwind entry of its own -- it's still recovered
    // (via `SeedKind::EntryPoint`, checked separately below), just not
    // through `.pdata`.
    for address in [0x1_8000_1000u64, 0x1_8000_1020] {
        assert!(
            analysis
                .seeds
                .get(&address)
                .is_some_and(|kinds| kinds.contains(&SeedKind::Unwind)),
            "expected SeedKind::Unwind at {address:#x}; seeds: {:?}",
            analysis.seeds.get(&address)
        );
    }
    assert!(
        analysis.seeds.get(&0x1_8000_1040).is_some_and(|kinds| kinds
            .contains(&SeedKind::EntryPoint)
            && !kinds.contains(&SeedKind::Unwind)),
        "expected dll_entry (0x180001040) seeded by EntryPoint only, no .pdata entry; seeds: {:?}",
        analysis.seeds.get(&0x1_8000_1040)
    );
    assert!(analysis.functions.contains_key(&0x1_8000_1040));
}

/// Before the ARM64 `IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY` branch existed,
/// `collect_pe_seeds` tried to parse this same `.pdata` directory as AMD64's
/// 12-byte `RUNTIME_FUNCTION` triples and flagged it as malformed (16 bytes
/// is not a multiple of 12) even though the bytes are perfectly valid ARM64
/// unwind data (2 entries x 8 bytes). Regression guard for that specific
/// false diagnostic.
#[test]
fn no_diagnostic_calls_valid_arm64_pdata_malformed() {
    for name in ["exe-with-import.exe", "dll-with-export.dll"] {
        let bytes = fixture_bytes(name);
        let analysis = recovery::analyze(&bytes).expect("PE code recovery");
        for diagnostic in &analysis.diagnostics {
            assert!(
                !diagnostic.message.contains("malformed"),
                "{name}: unexpected diagnostic: {}",
                diagnostic.message
            );
        }
    }
}

// ---------------------------------------------------------------------
// Register-indirect import calls: matches upstream's own documented
// inability to resolve them (`aarch64_features.rs::extract_insn_api_
// features`'s doc comment) -- ARM64 has no memory-operand call form the way
// x64's `call [rip+disp32]` does, so a `blr` reg call can't reuse that
// path. `objdump -d exe-with-import.exe`: the call site inlines
// `adrp x8, page(IAT); ldr x8, [x8, #0x38]; blr x8` directly in the caller
// rather than through a separate `bl <stub>` thunk (contrast Mach-O's
// `__stubs`, `macho_features.rs`'s `a_function_scope_api_rule_matches_
// arm64_main_by_evidence_address`) -- so `run_aarch64_plt_wave` (which
// resolves *stub* aliases reached via `bl`) has nothing to alias here
// either. Recorded as an explicit test, not a silent gap, so a future
// change to `extract_insn_api_features` doesn't accidentally start
// guessing register values without a test noticing.
// ---------------------------------------------------------------------

#[test]
fn a_register_indirect_import_call_is_not_falsely_resolved_to_an_api() {
    let bytes = fixture_bytes("exe-with-import.exe");
    let (features, _) = full_features(&bytes);
    assert!(!features
        .file_features
        .iter()
        .any(|(_, f)| matches!(f, Feature::Api(_))));
}

// ---------------------------------------------------------------------
// Synthetic rules: matches *and* evidence addresses, since there is no
// Python-rendered result document to diff (same reasoning as
// `macho_features.rs`).
// ---------------------------------------------------------------------

fn ruleset_from(yaml: &str) -> MatchingRuleSet {
    let rule = Rule::from_yaml(yaml).expect("synthetic rule parses");
    MatchingRuleSet::new(vec![rule]).expect("synthetic ruleset builds")
}

#[test]
fn a_file_scope_import_rule_matches_the_iat_slot_address() {
    let bytes = fixture_bytes("exe-with-import.exe");
    let (features, _) = full_features(&bytes);
    let ruleset = ruleset_from(
        "rule:\n  meta:\n    name: imports FakeImportedFunc\n    authors: [t]\n    scopes:\n      \
         static: file\n      dynamic: unsupported\n  features:\n    - import: FakeImportedFunc\n",
    );
    let capabilities =
        find_static_capabilities(&ruleset, &features, &AnalysisOptions::SERIAL).unwrap();
    let matches = capabilities
        .matches
        .get("imports FakeImportedFunc")
        .expect("rule matched");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].0, Address::NoAddress);
}

#[test]
fn a_function_scope_rule_matches_add_by_evidence_address() {
    let bytes = fixture_bytes("exe-with-import.exe");
    let (features, _) = full_features(&bytes);
    // `add w0, w8, w9` at 0x140001058, inside the function at 0x140001044.
    let ruleset = ruleset_from(
        "rule:\n  meta:\n    name: has add arm64\n    authors: [t]\n    scopes:\n      static: \
         function\n      dynamic: unsupported\n  features:\n    - mnemonic: add\n",
    );
    let capabilities =
        find_static_capabilities(&ruleset, &features, &AnalysisOptions::SERIAL).unwrap();
    let matches = capabilities
        .matches
        .get("has add arm64")
        .expect("rule matched");
    assert!(matches
        .iter()
        .any(|(function, _)| *function == Address::Absolute(0x1_4000_1044)));
}

#[test]
fn a_pe_format_rule_matches_arch_aarch64() {
    let bytes = fixture_bytes("dll-with-export.dll");
    let (features, _) = full_features(&bytes);
    let ruleset = ruleset_from(
        "rule:\n  meta:\n    name: is arm64 pe\n    authors: [t]\n    scopes:\n      static: \
         file\n      dynamic: unsupported\n  features:\n    - and:\n      - format: pe\n      \
         - os: windows\n      - arch: aarch64\n",
    );
    let capabilities =
        find_static_capabilities(&ruleset, &features, &AnalysisOptions::SERIAL).unwrap();
    assert!(capabilities.matches.contains_key("is arm64 pe"));
}

// ---------------------------------------------------------------------
// `--jobs 1` vs `N`: byte-identical, same as every other backend (AGENTS.md).
// ---------------------------------------------------------------------

#[test]
fn extraction_is_independent_of_job_count() {
    use capa_x::parallel::Jobs;

    for name in ["exe-with-import.exe", "dll-with-export.dll"] {
        let bytes = fixture_bytes(name);
        let analysis = recovery::analyze(&bytes).expect("PE code recovery");

        let fingerprint = |options: &AnalysisOptions| -> String {
            let mut features = extract_pe(&bytes).expect("file/global features");
            enrich_static_features(&mut features, &analysis, &BTreeMap::new(), options);
            format!("{features:?}")
        };

        let serial = fingerprint(&AnalysisOptions::SERIAL);
        for jobs in [
            Jobs::new(2).unwrap(),
            Jobs::new(4).unwrap(),
            Jobs::default(),
        ] {
            let parallel = fingerprint(&AnalysisOptions::with_jobs(jobs));
            assert_eq!(parallel, serial, "{name} differs at --jobs {}", jobs.get());
        }
    }
}

// ---------------------------------------------------------------------
// Malformed-input hardening: no dedicated ARM64-malformed fixture corpus
// exists (`tests/fixtures/aarch64-pe/MANIFEST.md`'s own scoping decision --
// malformed-PE handling is general PE-loader hardening, not ARM64-specific,
// and belongs with whichever code extends the loader to accept the machine
// type; this file *is* that extension). So this fuzzes the two clean
// fixtures directly, mirroring `macho_features.rs`'s `mutated_macho_
// samples_never_panic` and `dotnet_dnfile_fuzz.rs`'s pattern.
// ---------------------------------------------------------------------

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
const CLEAN_FIXTURES: [&str; 2] = ["exe-with-import.exe", "dll-with-export.dll"];

#[test]
fn mutated_aarch64_pe_samples_never_panic() {
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    let mut failures: Vec<String> = Vec::new();

    for name in CLEAN_FIXTURES {
        let original = fixture_bytes(name);
        let mut rng = Rng(0xD1B5_4A32_D192_ED03 ^ (name.len() as u64 + 1));

        for _ in 0..MUTANTS_PER_SAMPLE {
            let mut data = original.clone();
            let n_flips = 1 + rng.below(3);
            for _ in 0..n_flips {
                let idx = rng.below(data.len());
                data[idx] = (rng.next() & 0xFF) as u8;
            }

            let load = panic::catch_unwind(|| {
                let _: Result<_, _> = LoadedImage::from_pe(&data);
            });
            if load.is_err() {
                failures.push(format!("{name}: LoadedImage::from_pe panicked"));
            }

            let extract = panic::catch_unwind(|| {
                let _: Result<_, _> = extract_pe(&data);
            });
            if extract.is_err() {
                failures.push(format!("{name}: extract_pe panicked"));
            }

            let recover = panic::catch_unwind(|| {
                let _: Result<_, RecoveryError> = recovery::analyze(&data);
            });
            if recover.is_err() {
                failures.push(format!("{name}: recovery::analyze panicked"));
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
