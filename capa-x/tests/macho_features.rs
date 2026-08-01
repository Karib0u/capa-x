//! Mach-O acceptance: structure, feature, synthetic-rule and malformed-fixture coverage for
//! the native x86_64 Mach-O loader (`capa-x/src/extract/loader/image.rs`'s
//! `LoadedImage::from_macho`, `extract/macho.rs`, and
//! `recovery::analyze_macho`/`collect_macho_seeds`) to cover x86_64 and AArch64
//! slices through the same loader and the shared decoder/recovery boundary.
//!
//! Pinned capa 9.4.0 has no raw Mach-O input at all (the "honesty
//! constraint" in the brief above), so there is no Python oracle to diff
//! against here the way `features_parity.rs` diffs PE/ELF against
//! `reference/capa/`. The oracle is instead
//! `capa-x/tests/fixtures/macho/`: hand-transcribed from
//! the fixture *source* (`src/fixture_exe.c`/`fixture_dylib.c`) and
//! cross-checked directly against `otool`/`nm`/`llvm-readobj` output on this
//! machine (recorded in this file's own comments, not carried forward from
//! a note -- see AGENTS.md's "never carry a measurement forward" rule).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::panic;
use std::path::{Path, PathBuf};

use capa_x::address::Address;
use capa_x::capabilities::{find_static_capabilities, MatchingRuleSet};
use capa_x::extract::flirt::enrich_static_features;
use capa_x::extract::image::{ImageError, LoadedImage};
use capa_x::extract::macho::extract_macho;
use capa_x::extract::recovery::{self, RecoveryError};
use capa_x::features::Feature;
use capa_x::freeze::StaticFeatures;
use capa_x::parallel::AnalysisOptions;
use capa_x::rules::Rule;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("macho")
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = fixtures_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn full_features(bytes: &[u8], arch: Option<&str>) -> StaticFeatures {
    let mut features = extract_macho(bytes, arch).expect("Mach-O file/global features extract");
    let analysis = recovery::analyze_macho(bytes, arch).expect("Mach-O code recovery");
    enrich_static_features(
        &mut features,
        &analysis,
        &BTreeMap::new(),
        &AnalysisOptions::SERIAL,
    );
    features
}

fn has_file_feature(features: &StaticFeatures, feature: &Feature, address: u64) -> bool {
    features
        .file_features
        .iter()
        .any(|(addr, f)| f == feature && *addr == Address::Absolute(address))
}

// ---------------------------------------------------------------------
// Structure: `thin-x86_64-exe` cross-checked against `otool -l`/`nm -m`/
// `otool -fixup_chains` on this machine (Apple clang 21, MacOSX.sdk).
// ---------------------------------------------------------------------

#[test]
fn thin_exe_sample_hash_matches_the_manifest() {
    let bytes = fixture_bytes("thin-x86_64-exe");
    let features = full_features(&bytes, None);
    assert_eq!(
        features.sample_hashes.sha256,
        "eb63def821a06ec238dccb1d509a80f67c93125694f288f7596ea633c12756f4"
    );
}

#[test]
fn thin_exe_global_features_are_macho_amd64_macos() {
    let bytes = fixture_bytes("thin-x86_64-exe");
    let features = full_features(&bytes, None);
    assert!(features
        .global_features
        .contains(&Feature::Format("macho".to_string())));
    assert!(features
        .global_features
        .contains(&Feature::Arch("amd64".to_string())));
    assert!(features
        .global_features
        .contains(&Feature::Os("macos".to_string())));
}

/// `otool -fixup_chains thin-x86_64-exe`: `dyld chained import[0..2]` bind to
/// `_malloc`/`_puts`/`_free` at `__got` slots `0x100001000`/`+8`/`+0x10`
/// (`__got`'s own `Address: 0x100001000` in the captured oracle). This
/// exercises the from-scratch `LC_DYLD_CHAINED_FIXUPS` reader
/// (`image.rs::parse_macho_chained_fixups`) end to end: `goblin` 0.10.7's
/// own `MachO::imports()` returns empty for this binary (no `LC_DYLD_INFO`).
#[test]
fn thin_exe_imports_resolve_through_chained_fixups() {
    let bytes = fixture_bytes("thin-x86_64-exe");
    let features = full_features(&bytes, None);
    for (name, address) in [
        ("malloc", 0x0001_0000_1000u64),
        ("puts", 0x0001_0000_1008u64),
        ("free", 0x0001_0000_1010u64),
    ] {
        assert!(
            has_file_feature(&features, &Feature::Import(name.to_string()), address),
            "missing import({name}) at {address:#x}"
        );
    }
}

/// `llvm-readobj --all` oracle: `_main` at `0x100000510`,
/// `__mh_execute_header` at `0x100000000`, both `Extern`/`Type: Section`.
#[test]
fn thin_exe_exports_the_symtab_extern_symbols() {
    let bytes = fixture_bytes("thin-x86_64-exe");
    let features = full_features(&bytes, None);
    assert!(has_file_feature(
        &features,
        &Feature::Export("main".to_string()),
        0x0001_0000_0510
    ));
    // The symbol itself is `__mh_execute_header` (two leading underscores);
    // stripping the Mach-O C-symbol convention's one leaves `_mh_execute_header`.
    assert!(has_file_feature(
        &features,
        &Feature::Export("_mh_execute_header".to_string()),
        0x0001_0000_0000
    ));
}

/// `otool -l`: `__TEXT,__text` at `0x100000510`; `__DATA,__bss` (the
/// `S_ZEROFILL` static array, no file backing) at `0x100002000`.
#[test]
fn thin_exe_sections_are_segment_qualified() {
    let bytes = fixture_bytes("thin-x86_64-exe");
    let features = full_features(&bytes, None);
    assert!(has_file_feature(
        &features,
        &Feature::Section("__TEXT,__text".to_string()),
        0x0001_0000_0510
    ));
    assert!(has_file_feature(
        &features,
        &Feature::Section("__DATA,__bss".to_string()),
        0x0001_0000_2000
    ));
}

/// `_main`'s only internal call target: `nm`/`llvm-readobj` name it `_add`
/// at `0x1000005C0`, a `STAB`-free `N_SECT` symbol in `__text` -- seeded and
/// named via `collect_macho_seeds`'s `LC_SYMTAB` walk, the same role
/// `capa.features.extractors.elf.SymTab` plays for ELF (there is no
/// upstream Mach-O counterpart to port from).
#[test]
fn thin_exe_recovers_the_internal_add_function_by_symbol() {
    let bytes = fixture_bytes("thin-x86_64-exe");
    let analysis = recovery::analyze_macho(&bytes, None).expect("Mach-O code recovery");
    let add = 0x1_0000_05c0u64;
    assert!(
        analysis.functions.contains_key(&add),
        "expected a recovered function at 0x1000005c0 (_add); got {:?}",
        analysis.functions.keys().collect::<Vec<_>>()
    );
    let names = analysis
        .elf_function_symbols
        .get(&0x1_0000_05c0u64)
        .expect("_add has a symbol name");
    assert!(names.iter().any(|n| n == "add"));
}

// ---------------------------------------------------------------------
// `thin-x86_64.dylib`: exports two internal functions, imports one libSystem
// symbol -- cross-checked against `nm -m`/`otool -fixup_chains` on this
// machine.
// ---------------------------------------------------------------------

#[test]
fn dylib_exports_and_imports_at_their_nm_addresses() {
    let bytes = fixture_bytes("thin-x86_64.dylib");
    let features = full_features(&bytes, None);
    assert!(has_file_feature(
        &features,
        &Feature::Export("capa_fixture_add".to_string()),
        0x3d0
    ));
    assert!(has_file_feature(
        &features,
        &Feature::Export("capa_fixture_zero_and_sum".to_string()),
        0x3f0
    ));
    // `___memset_chk` (`_FORTIFY_SOURCE`'s substitution for `memset`):
    // one leading `_` is the Mach-O C-symbol convention this extractor
    // strips, same as every other import; the other two are part of the
    // real linked symbol name.
    assert!(has_file_feature(
        &features,
        &Feature::Import("__memset_chk".to_string()),
        0x1000
    ));
}

// ---------------------------------------------------------------------
// Slice selection: host-independent, fat-header-order selection among
// `SUPPORTED_MACHO_ARCHES`.
// ---------------------------------------------------------------------

#[test]
fn fat_binary_auto_selects_x86_64_in_fat_header_order() {
    let bytes = fixture_bytes("fat-x86_64-arm64-exe");
    let features = extract_macho(&bytes, None).expect("auto-selects the x86_64 slice");
    assert!(features
        .global_features
        .contains(&Feature::Arch("amd64".to_string())));
}

#[test]
fn fat_binary_explicit_x86_64_matches_auto() {
    let bytes = fixture_bytes("fat-x86_64-arm64-exe");
    let auto = extract_macho(&bytes, None).expect("auto");
    let explicit = extract_macho(&bytes, Some("x86_64")).expect("explicit x86_64");
    assert_eq!(auto.sample_hashes.sha256, explicit.sample_hashes.sha256);
    assert_eq!(auto.file_features.len(), explicit.file_features.len());
}

#[test]
fn requesting_an_unsupported_slice_lists_whats_actually_there() {
    let bytes = fixture_bytes("fat-x86_64-arm64-exe");
    // Neither slice this fat binary actually has ("x86_64", "arm64") -- an
    // architecture with no compiled slice at all.
    let error = extract_macho(&bytes, Some("i386")).expect_err("no i386 slice exists");
    let message = error.to_string();
    assert!(message.contains("i386"), "{message}");
    assert!(message.contains("arm64"), "{message}");
    assert!(message.contains("x86_64"), "{message}");
}

// ---------------------------------------------------------------------
// AArch64 Mach-O: same fixtures, source, and loader as the
// x86_64 section above -- `thin-arm64-exe`/`thin-arm64.dylib` are the same
// C source cross-compiled, so addresses differ (different codegen) but the
// shape (imports/exports/sections/internal-call) is identical. Cross-checked
// against `nm`/`llvm-readobj --all` on this machine the same way as the
// x86_64 fixtures.
// ---------------------------------------------------------------------

#[test]
fn thin_arm64_exe_sample_hash_matches_the_manifest() {
    let bytes = fixture_bytes("thin-arm64-exe");
    let features = full_features(&bytes, None);
    assert_eq!(
        features.sample_hashes.sha256,
        "6dfcdfc42ed14eee59019ad8ae08d9a5b6581e9c3d4c62ea070b93cde80aba3f"
    );
}

#[test]
fn thin_arm64_exe_global_features_are_macho_aarch64_macos() {
    let bytes = fixture_bytes("thin-arm64-exe");
    let features = full_features(&bytes, None);
    assert!(features
        .global_features
        .contains(&Feature::Format("macho".to_string())));
    // "aarch64", not "arm64" -- matches ELF's own `EM_AARCH64` arch-feature
    // string (`extract/elf.rs`), which is what capa-rules rules keyed on
    // `arch:` are written against.
    assert!(features
        .global_features
        .contains(&Feature::Arch("aarch64".to_string())));
    assert!(features
        .global_features
        .contains(&Feature::Os("macos".to_string())));
}

/// `otool -fixup_chains thin-arm64-exe`: chained imports bind to
/// `_malloc`/`_puts`/`_free` at `__got` slots `0x100004000`/`+8`/`+0x10`.
/// Plain `arm64` (not `arm64e`) turns out to use the *same*
/// `DYLD_CHAINED_PTR_64_OFFSET` format the x86_64 fixture does -- verified
/// empirically, not assumed; see `image.rs::parse_macho_chained_fixups`'s
/// doc comment. So this exercises the identical reader as
/// `thin_exe_imports_resolve_through_chained_fixups` above, on an arm64
/// slice, with zero arm64-specific parsing code.
#[test]
fn thin_arm64_exe_imports_resolve_through_chained_fixups() {
    let bytes = fixture_bytes("thin-arm64-exe");
    let features = full_features(&bytes, None);
    for (name, address) in [
        ("malloc", 0x0001_0000_4000u64),
        ("puts", 0x0001_0000_4008u64),
        ("free", 0x0001_0000_4010u64),
    ] {
        assert!(
            has_file_feature(&features, &Feature::Import(name.to_string()), address),
            "missing import({name}) at {address:#x}"
        );
    }
}

#[test]
fn thin_arm64_exe_exports_the_symtab_extern_symbols() {
    let bytes = fixture_bytes("thin-arm64-exe");
    let features = full_features(&bytes, None);
    assert!(has_file_feature(
        &features,
        &Feature::Export("main".to_string()),
        0x0001_0000_04f8
    ));
    assert!(has_file_feature(
        &features,
        &Feature::Export("_mh_execute_header".to_string()),
        0x0001_0000_0000
    ));
}

#[test]
fn thin_arm64_exe_sections_are_segment_qualified() {
    let bytes = fixture_bytes("thin-arm64-exe");
    let features = full_features(&bytes, None);
    assert!(has_file_feature(
        &features,
        &Feature::Section("__TEXT,__text".to_string()),
        0x0001_0000_04f8
    ));
    assert!(has_file_feature(
        &features,
        &Feature::Section("__DATA,__bss".to_string()),
        0x0001_0000_8000
    ));
}

/// `_main`'s only internal call target: `_add` at `0x1000005C0`, an
/// `N_SECT` symbol in `__text` -- same `collect_macho_seeds` `LC_SYMTAB`
/// walk as the x86_64 fixture, proving it isn't x86_64-specific.
#[test]
fn thin_arm64_exe_recovers_the_internal_add_function_by_symbol() {
    let bytes = fixture_bytes("thin-arm64-exe");
    let analysis = recovery::analyze_macho(&bytes, None).expect("Mach-O code recovery");
    let add = 0x1_0000_05c0u64;
    assert!(
        analysis.functions.contains_key(&add),
        "expected a recovered function at 0x1000005c0 (_add); got {:?}",
        analysis.functions.keys().collect::<Vec<_>>()
    );
    let names = analysis
        .elf_function_symbols
        .get(&0x1_0000_05c0u64)
        .expect("_add has a symbol name");
    assert!(names.iter().any(|n| n == "add"));
}

/// `_main` at the image base itself is a red herring worth guarding against
/// directly: `__mh_execute_header` is an `Extern`/`N_SECT` symbol *and* an
/// export whose value is the image's load address, not real code -- see
/// `recovery.rs::collect_macho_seeds`'s `in_a_macho_section` guard. Without
/// it, AArch64's dense fixed-width opcode space decodes the Mach header and
/// load commands as if they were a real (9-block, in this fixture)
/// function that falls through into `_main`'s own code, manufacturing a
/// second, spurious match for every function-scope rule `_main` matches.
#[test]
fn no_spurious_function_is_recovered_at_the_arm64_image_base() {
    let bytes = fixture_bytes("thin-arm64-exe");
    let analysis = recovery::analyze_macho(&bytes, None).expect("Mach-O code recovery");
    assert!(
        !analysis.functions.contains_key(&analysis.image.image_base),
        "the Mach-O header/load-commands region must never be recovered as a function"
    );
}

#[test]
fn thin_arm64_dylib_exports_and_imports_at_their_nm_addresses() {
    let bytes = fixture_bytes("thin-arm64.dylib");
    let features = full_features(&bytes, None);
    assert!(has_file_feature(
        &features,
        &Feature::Export("capa_fixture_add".to_string()),
        0x3c0
    ));
    assert!(has_file_feature(
        &features,
        &Feature::Export("capa_fixture_zero_and_sum".to_string()),
        0x3e0
    ));
    assert!(has_file_feature(
        &features,
        &Feature::Import("__memset_chk".to_string()),
        0x4000
    ));
}

#[test]
fn a_thin_arm64_exe_loads_with_a_supported_slice() {
    let bytes = fixture_bytes("thin-arm64-exe");
    let features = extract_macho(&bytes, None).expect("arm64 is a supported slice");
    assert!(features
        .global_features
        .contains(&Feature::Arch("aarch64".to_string())));
}

#[test]
fn fat_binary_explicit_arm64_selects_the_arm64_slice() {
    let bytes = fixture_bytes("fat-x86_64-arm64-exe");
    let features = extract_macho(&bytes, Some("arm64")).expect("explicit arm64");
    assert!(features
        .global_features
        .contains(&Feature::Arch("aarch64".to_string())));
}

#[test]
fn a_function_scope_api_rule_matches_arm64_main_by_evidence_address() {
    let bytes = fixture_bytes("thin-arm64-exe");
    let features = full_features(&bytes, None);
    let ruleset = ruleset_from(
        "rule:\n  meta:\n    name: calls malloc arm64\n    authors: [t]\n    scopes:\n      \
         static: function\n      dynamic: unsupported\n  features:\n    - api: malloc\n",
    );
    let capabilities =
        find_static_capabilities(&ruleset, &features, &AnalysisOptions::SERIAL).unwrap();
    let matches = capabilities
        .matches
        .get("calls malloc arm64")
        .expect("rule matched");
    // Exactly one match: `_main`, reached through the `__stubs`/`__got`
    // `adrp`/`ldr`/`br` thunk (`recovery.rs::run_aarch64_plt_wave`), the
    // AArch64 analogue of `a_function_scope_api_rule_matches_main_by_
    // evidence_address`'s x86_64 `jmp [rip+disp32]` stub -- and this test's
    // own reason for existing: without `in_a_macho_section` (see the
    // `no_spurious_function...` test above) this would be 2.
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].0, Address::Absolute(0x1_0000_04f8));
}

#[test]
fn a_macho_extension_format_rule_matches_arch_aarch64() {
    let bytes = fixture_bytes("thin-arm64.dylib");
    let features = full_features(&bytes, None);
    let ruleset = ruleset_from(
        "rule:\n  meta:\n    name: is macho arm64\n    authors: [t]\n    scopes:\n      static: \
         file\n      dynamic: unsupported\n  features:\n    - and:\n      - format: macho\n      \
         - os: macos\n      - arch: aarch64\n",
    );
    let capabilities =
        find_static_capabilities(&ruleset, &features, &AnalysisOptions::SERIAL).unwrap();
    assert!(capabilities.matches.contains_key("is macho arm64"));
}

/// Host-independence is structural here (fat-header order, never
/// `std::env::consts::ARCH`), so this is a determinism check rather than a
/// cross-host one: the same process picks the same slice every time.
#[test]
fn slice_selection_is_deterministic_across_repeated_calls() {
    let bytes = fixture_bytes("fat-x86_64-arm64-exe");
    let first = extract_macho(&bytes, None).expect("first parse");
    for _ in 0..8 {
        let again = extract_macho(&bytes, None).expect("repeat parse");
        assert_eq!(first.sample_hashes.sha256, again.sample_hashes.sha256);
        assert_eq!(first.file_features.len(), again.file_features.len());
    }
}

// ---------------------------------------------------------------------
// Synthetic rules: matches *and* evidence addresses (J7's own acceptance
// wording), since there is no Python-rendered result document to diff.
// ---------------------------------------------------------------------

fn ruleset_from(yaml: &str) -> MatchingRuleSet {
    let rule = Rule::from_yaml(yaml).expect("synthetic rule parses");
    MatchingRuleSet::new(vec![rule]).expect("synthetic ruleset builds")
}

#[test]
fn a_file_scope_import_rule_matches_at_the_got_slot_address() {
    let bytes = fixture_bytes("thin-x86_64-exe");
    let features = full_features(&bytes, None);
    let ruleset = ruleset_from(
        "rule:\n  meta:\n    name: imports malloc\n    authors: [t]\n    scopes:\n      \
         static: file\n      dynamic: unsupported\n  features:\n    - import: malloc\n",
    );
    let capabilities =
        find_static_capabilities(&ruleset, &features, &AnalysisOptions::SERIAL).unwrap();
    let matches = capabilities
        .matches
        .get("imports malloc")
        .expect("rule matched");
    // File-scope matches are always recorded at `Address::NoAddress`
    // (`capabilities::find_file_capabilities` matches the whole scope at
    // that sentinel, same as PE/ELF -- file scope has no per-address
    // match). The evidence address lives on the underlying feature itself,
    // which `thin_exe_imports_resolve_through_chained_fixups` already
    // checks directly; this test's own job is proving the *rule* matches at
    // all against Mach-O file-scope features.
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].0, Address::NoAddress);
    assert!(has_file_feature(
        &features,
        &Feature::Import("malloc".to_string()),
        0x0001_0000_1000
    ));
}

/// `_main` calls `_malloc` through the `__stubs`/`__got` thunk pair -- this
/// proves the same format-neutral thunk-following recovery logic PE/ELF
/// already rely on (`image.rs`'s `import_locations`, walked generically by
/// `recovery.rs`/`insn_features.rs`) also resolves a Mach-O `jmp
/// qword ptr [rip+disp32]` stub with no Mach-O-specific code at all.
#[test]
fn a_function_scope_api_rule_matches_main_by_evidence_address() {
    let bytes = fixture_bytes("thin-x86_64-exe");
    let features = full_features(&bytes, None);
    let ruleset = ruleset_from(
        "rule:\n  meta:\n    name: calls malloc\n    authors: [t]\n    scopes:\n      static: \
         function\n      dynamic: unsupported\n  features:\n    - api: malloc\n",
    );
    let capabilities =
        find_static_capabilities(&ruleset, &features, &AnalysisOptions::SERIAL).unwrap();
    let matches = capabilities
        .matches
        .get("calls malloc")
        .expect("rule matched");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].0, Address::Absolute(0x1_0000_0510));
}

#[test]
fn a_macho_extension_format_rule_matches_globally() {
    let bytes = fixture_bytes("thin-x86_64.dylib");
    let features = full_features(&bytes, None);
    let ruleset = ruleset_from(
        "rule:\n  meta:\n    name: is macho\n    authors: [t]\n    scopes:\n      static: \
         file\n      dynamic: unsupported\n  features:\n    - and:\n      - format: macho\n      \
         - os: macos\n      - arch: amd64\n",
    );
    let capabilities =
        find_static_capabilities(&ruleset, &features, &AnalysisOptions::SERIAL).unwrap();
    assert!(capabilities.matches.contains_key("is macho"));
}

// ---------------------------------------------------------------------
// Malformed fixtures (ADR 0005): a contextual `Err`, never a
// panic, from every entry point a caller can reach directly.
// ---------------------------------------------------------------------

const MALFORMED_FIXTURES: [&str; 5] = [
    "truncated-load-commands",
    "bad-ncmds",
    "overlapping-segments",
    "filesize-gt-vmsize",
    "slice-offset-past-eof",
];

#[test]
fn every_malformed_fixture_is_a_contextual_error_not_a_panic() {
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    let mut failures = Vec::new();
    for name in MALFORMED_FIXTURES {
        let path = fixtures_dir().join("malformed").join(name);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {name}: {e}"));

        let load_result = panic::catch_unwind(|| LoadedImage::from_macho(&bytes, None));
        match load_result {
            Ok(Ok(_)) => failures.push(format!(
                "{name}: LoadedImage::from_macho unexpectedly succeeded"
            )),
            Ok(Err(_)) => {}
            Err(_) => failures.push(format!("{name}: LoadedImage::from_macho panicked")),
        }

        let extract_result = panic::catch_unwind(|| extract_macho(&bytes, None));
        match extract_result {
            Ok(Ok(_)) => failures.push(format!("{name}: extract_macho unexpectedly succeeded")),
            Ok(Err(_)) => {}
            Err(_) => failures.push(format!("{name}: extract_macho panicked")),
        }

        let recover_result = panic::catch_unwind(|| recovery::analyze_macho(&bytes, None));
        match recover_result {
            Ok(Ok(_)) => failures.push(format!("{name}: analyze_macho unexpectedly succeeded")),
            Ok(Err(_)) => {}
            Err(_) => failures.push(format!("{name}: analyze_macho panicked")),
        }
    }

    panic::set_hook(default_hook);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn error_messages_name_the_structural_problem() {
    let read = |name: &str| fixture_bytes(&format!("malformed/{name}"));

    let bad_ncmds = LoadedImage::from_macho(&read("bad-ncmds"), None).unwrap_err();
    assert!(matches!(bad_ncmds, ImageError::Macho(_)));

    let overlap = LoadedImage::from_macho(&read("overlapping-segments"), None).unwrap_err();
    let ImageError::Macho(message) = &overlap else {
        panic!("expected ImageError::Macho, got {overlap:?}");
    };
    assert!(message.contains("overlap"), "{message}");

    let slice_eof = LoadedImage::from_macho(&read("slice-offset-past-eof"), None).unwrap_err();
    assert!(matches!(slice_eof, ImageError::Macho(_)));
}

// ---------------------------------------------------------------------
// `--jobs 1` vs `N`: byte-identical, same as every other backend (AGENTS.md).
// ---------------------------------------------------------------------

#[test]
fn extraction_is_independent_of_job_count() {
    use capa_x::parallel::Jobs;

    for name in ["thin-x86_64-exe", "thin-arm64-exe"] {
        let bytes = fixture_bytes(name);
        let analysis = recovery::analyze_macho(&bytes, None).expect("Mach-O code recovery");

        let fingerprint = |options: &AnalysisOptions| -> String {
            let mut features = extract_macho(&bytes, None).expect("file/global features");
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
// Fuzz target: malformed-fixture coverage generalized to byte flips:
// byte-flip mutants of every clean fixture must never panic, mirroring
// `dotnet_dnfile_fuzz.rs`'s pattern (no `cargo-fuzz`/`libfuzzer-sys`, which
// would need `unsafe_code` this workspace forbids).
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
const CLEAN_FIXTURES: [&str; 8] = [
    "thin-x86_64-exe",
    "thin-arm64-exe",
    "thin-x86_64.dylib",
    "thin-arm64.dylib",
    "fat-x86_64-arm64-exe",
    "fat-x86_64-arm64.dylib",
    "symbols-x86_64-exe",
    "stripped-x86_64-exe",
];

#[test]
fn mutated_macho_samples_never_panic() {
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    let mut failures: Vec<String> = Vec::new();

    for name in CLEAN_FIXTURES {
        let original = fixture_bytes(name);
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ (name.len() as u64 + 1));

        for _ in 0..MUTANTS_PER_SAMPLE {
            let mut data = original.clone();
            let n_flips = 1 + rng.below(3);
            for _ in 0..n_flips {
                let idx = rng.below(data.len());
                data[idx] = (rng.next() & 0xFF) as u8;
            }

            let extract = panic::catch_unwind(|| {
                let _: Result<_, _> = extract_macho(&data, None);
            });
            if extract.is_err() {
                failures.push(format!("{name}: extract_macho panicked"));
            }

            let recover = panic::catch_unwind(|| {
                let _: Result<_, RecoveryError> = recovery::analyze_macho(&data, None);
            });
            if recover.is_err() {
                failures.push(format!("{name}: analyze_macho panicked"));
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
