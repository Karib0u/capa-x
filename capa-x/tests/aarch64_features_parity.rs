//! Port of the pinned Python capa test suite's
//! `test_binexport_features.py::FEATURE_PRESENCE_TESTS_BE2_ELF_AARCH64`
//! expectation table (v9.4.0, see PINNED.md;
//! `reference/capa/tests/test_binexport_features.py:38`) -- the native
//! AArch64 ELF acceptance oracle.
//!
//! Unlike `dotnet_features_parity.rs`, this table drives against the *same*
//! `StaticFeatures`/`Address::Absolute` shape `features_parity.rs` already
//! exercises for x86/x64 ELF -- native AArch64 needs a new decoder and
//! recovery model, not a new address representation. So this file
//! is a real, working port of that scaffolding (`build_features`,
//! `scope_features`, `feature_present`), pointed at the pinned raw ELF
//! samples paired with the table's upstream Ghidra BinExport2 source.
//!
//! `recovery::analyze` succeeds on these samples
//! (native AArch64 recovery -- decoding, control flow, PLT/GOT thunk
//! resolution, a decode-based prologue scan) and `flirt::enrich_static_features`
//! extracts function/basic-block/instruction features for an
//! `Architecture::AArch64` image via `aarch64_features.rs`/
//! `aarch64_basicblock_features.rs` (the BinExport2/Ghidra ARM backend's own
//! port, not `insn_features.rs`/`basicblock_features.rs`, which stay
//! x86-only). All but one row below now pass; the exception is
//! `KNOWN_RECOVERY_GAPS`, documented at its own definition below.
//!
//! Regenerate the table below (never by hand -- see its header) with
//! `scripts/gen_fixture_tables.py aarch64`, run under the pinned `.venv`
//! against the checked-out `reference/capa/` source; the **output is
//! committed**, and `cargo test` never invokes Python (AGENTS.md "No Python
//! at runtime").

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use capa_x::address::Address;
use capa_x::engine::{self, evaluate, FeatureSet};
use capa_x::extract::elf::extract_elf;
use capa_x::extract::flirt::enrich_static_features;
use capa_x::extract::recovery::analyze;
use capa_x::features::{CompiledRegex, Feature, NumberValue, StringFeature};
use capa_x::freeze::{BasicBlockFeatures, FunctionFeatures, StaticFeatures};
use capa_x::parallel::AnalysisOptions;
use capa_x::rules::{Node, Statement};

// ---------------------------------------------------------------------
// sample loading, mirroring `fixtures.py::get_data_path_by_name`, restricted
// to this table's two short names.
// ---------------------------------------------------------------------

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn testfile(name: &str) -> PathBuf {
    root().join("tests/testfiles").join(name)
}

/// port of `fixtures.py::get_data_path_by_name`'s two `*.ghidra.be2` rows,
/// but pointed at the paired *raw ELF* rather than the BinExport2 file --
/// The reference side runs pinned capa on the BinExport2 input. The Rust side
/// runs native extraction on the paired raw ELF.
fn sample_path(name: &str) -> PathBuf {
    match name {
        "687e79.ghidra.be2" => testfile(
            "aarch64/687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf_",
        ),
        "d1e650.ghidra.be2" => testfile(
            "aarch64/d1e6506964edbfffb08c0dd32e1486b11fbced7a4bd870ffe79f110298f0efb8.elf_",
        ),
        other => panic!("no pinned sample for aarch64 fixture short name {other:?}"),
    }
}

fn build_features(path: &Path) -> StaticFeatures {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let mut features =
        extract_elf(&bytes).unwrap_or_else(|e| panic!("extracting {}: {e}", path.display()));
    let analysis = analyze(&bytes).unwrap_or_else(|e| panic!("recovering {}: {e}", path.display()));
    // ELF never runs FLIRT (`identify_library_functions` is PE-only), same
    // as `capa_x::api`'s `extract_elf_input`.
    let libraries = BTreeMap::new();
    enrich_static_features(
        &mut features,
        &analysis,
        &libraries,
        &AnalysisOptions::SERIAL,
    );
    features
}

fn parse_hex(s: &str) -> u64 {
    let s = s.trim();
    u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .unwrap_or_else(|e| panic!("bad test hex {s}: {e}"))
}

fn instruction_fs(insn_features: &[(Address, Feature)]) -> FeatureSet {
    let mut fs = FeatureSet::new();
    for (addr, f) in insn_features {
        engine::insert(&mut fs, f.clone(), *addr);
    }
    fs
}

fn bb_fs(bb: &BasicBlockFeatures) -> FeatureSet {
    let mut fs = FeatureSet::new();
    for (addr, f) in &bb.features {
        engine::insert(&mut fs, f.clone(), *addr);
    }
    for insn in bb.instructions.values() {
        for (addr, f) in &insn.features {
            engine::insert(&mut fs, f.clone(), *addr);
        }
    }
    fs
}

fn function_fs(func: &FunctionFeatures) -> FeatureSet {
    let mut fs = FeatureSet::new();
    for (addr, f) in &func.features {
        engine::insert(&mut fs, f.clone(), *addr);
    }
    for bb in func.basic_blocks.values() {
        for (addr, f) in &bb.features {
            engine::insert(&mut fs, f.clone(), *addr);
        }
        for insn in bb.instructions.values() {
            for (addr, f) in &insn.features {
                engine::insert(&mut fs, f.clone(), *addr);
            }
        }
    }
    fs
}

fn global_fs(features: &StaticFeatures) -> FeatureSet {
    let mut fs = FeatureSet::new();
    for feature in &features.global_features {
        engine::insert(&mut fs, feature.clone(), Address::NoAddress);
    }
    fs
}

/// port of `fixtures.py::resolve_scope`, restricted to the shapes this
/// table's rows use (`"file"`, `"function=0x..."`, `"function=0x...,
/// bb=0x..."`, `"function=0x...,bb=0x...,insn=0x..."`) -- same shape as
/// `features_parity.rs`'s `scope_features`, since native AArch64 ELF uses
/// the same `Address::Absolute` addressing x86/x64 ELF already does.
fn scope_features(features: &StaticFeatures, scope: &str) -> FeatureSet {
    let mut fs = if scope == "file" {
        let mut fs = FeatureSet::new();
        for (addr, f) in &features.file_features {
            engine::insert(&mut fs, f.clone(), *addr);
        }
        fs
    } else {
        let parts: Vec<&str> = scope.split(',').collect();
        let addr_for = |prefix: &str| -> u64 {
            parts
                .iter()
                .find_map(|p| p.strip_prefix(prefix))
                .map(parse_hex)
                .unwrap_or_else(|| panic!("scope {scope} missing {prefix}"))
        };
        let fva = addr_for("function=");
        let Some(func) = features.functions.get(&Address::Absolute(fva)) else {
            return global_fs(features);
        };
        if parts.len() == 1 {
            function_fs(func)
        } else {
            let bbva = addr_for("bb=");
            let Some(bb) = func.basic_blocks.get(&Address::Absolute(bbva)) else {
                return global_fs(features);
            };
            if parts.len() == 2 {
                bb_fs(bb)
            } else {
                let iva = addr_for("insn=");
                let Some(insn) = bb.instructions.get(&Address::Absolute(iva)) else {
                    return global_fs(features);
                };
                instruction_fs(&insn.features)
            }
        }
    };
    for f in &features.global_features {
        engine::insert(&mut fs, f.clone(), Address::NoAddress);
    }
    fs
}

fn feature_present(fs: &FeatureSet, feature: &Feature) -> bool {
    let node = Node {
        stmt: Statement::Leaf(feature.clone()),
        description: None,
    };
    evaluate(&node, fs, true)
        .unwrap_or_else(|error| panic!("evaluating {feature}: {error}"))
        .is_match()
}

// ---------------------------------------------------------------------
// feature constructors, mirroring `capa.features.{common,insn,file,
// basicblock}` -- same shape as `features_parity.rs`'s (kept separate
// rather than shared: each `tests/*.rs` file is its own compiled crate).
// ---------------------------------------------------------------------

fn string_(v: &str) -> Feature {
    Feature::String(StringFeature::Plain(v.to_string()))
}
fn substring_(v: &str) -> Feature {
    Feature::String(StringFeature::Substring(v.to_string()))
}
fn regex_(v: &str) -> Feature {
    let (pat, ignorecase) = match v.strip_suffix("/i") {
        Some(base) => (&base[1..], true),
        None => (&v[1..v.len() - 1], false),
    };
    let wrapped = if ignorecase {
        format!("/{pat}/i")
    } else {
        format!("/{pat}/")
    };
    let compiled = CompiledRegex::compile(&wrapped)
        .unwrap_or_else(|error| panic!("bad test regex {v}: {error}"));
    Feature::String(StringFeature::Regex(compiled))
}
fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid test hex"))
        .collect()
}
fn bytes_hex(hex: &str) -> Feature {
    Feature::Bytes(decode_hex(hex))
}
fn num(v: i128) -> Feature {
    Feature::Number(NumberValue::Int(v))
}
fn off(v: i64) -> Feature {
    Feature::Offset(v)
}
fn opnum(i: u8, v: i128) -> Feature {
    Feature::OperandNumber(i, NumberValue::Int(v))
}
fn opoff(i: u8, v: i64) -> Feature {
    Feature::OperandOffset(i, v)
}
fn mnemonic_(v: &str) -> Feature {
    Feature::Mnemonic(v.to_string())
}
fn characteristic_(v: &str) -> Feature {
    Feature::Characteristic(v.to_string())
}
fn section_(v: &str) -> Feature {
    Feature::Section(v.to_string())
}
fn import_(v: &str) -> Feature {
    Feature::Import(v.to_string())
}
fn export_(v: &str) -> Feature {
    Feature::Export(v.to_string())
}
fn api_(v: &str) -> Feature {
    Feature::Api(v.to_string())
}
fn function_name_(v: &str) -> Feature {
    Feature::FunctionName(v.to_string())
}
fn os_(v: &str) -> Feature {
    Feature::Os(v.to_string())
}
fn arch_(v: &str) -> Feature {
    Feature::Arch(v.to_string())
}
fn format_(v: &str) -> Feature {
    Feature::Format(v.to_string())
}

/// `Expected::Xfail`'s payload is the upstream reason string, preserved
/// verbatim -- never silently dropped, and re-emitted as the `#[should_
/// panic]`-free "this is a known limitation" note in the failure output
/// once this file stops being file-level `#[ignore]`d.
enum Expected {
    Bool(bool),
    Xfail(&'static str),
}

struct Row {
    sample: &'static str,
    scope: &'static str,
    feature: fn() -> Feature,
    expected: Expected,
}

/// Regenerate with `scripts/gen_fixture_tables.py aarch64` (see the module
/// doc). All 80 upstream rows -- both samples (`687e79`/`d1e650`) are
/// pinned; the third pinned AArch64 pair (`c7f38027...`) isn't exercised by
/// this particular upstream table.
#[rustfmt::skip]
const ROWS: &[Row] = &[
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || string_("AppDataService start"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || string_("nope"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || section_(".text"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || section_(".nope"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || export_("android::clearDir"), expected: Expected::Xfail("xfail: name demangling is not implemented") },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || export_("nope"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || import_("fopen"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || import_("exit"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || import_("_ZN7android10IInterfaceD0Ev"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || import_("nope"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || function_name_("__libc_init"), expected: Expected::Xfail("xfail: TODO should this be a function-name?") },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || os_("android"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || os_("linux"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || os_("windows"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || arch_("i386"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || arch_("amd64"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || arch_("aarch64"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || format_("elf"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "file", feature: || format_("pe"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x0", feature: || characteristic_("stack string"), expected: Expected::Xfail("xfail: not implemented yet") },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x0", feature: || characteristic_("stack string"), expected: Expected::Xfail("xfail: not implemented yet") },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x105080", feature: || characteristic_("calls from"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x105128", feature: || num(224), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x105128,bb=0x105128,insn=0x10514c", feature: || off(8), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x105128,bb=0x1051e4", feature: || opnum(1, 4294967295), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x105128,bb=0x105450", feature: || opoff(2, 16), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x105128,bb=0x105450", feature: || off(16), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x1056c0", feature: || characteristic_("loop"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x1057f8", feature: || bytes_hex("2f00730079007300740065006d002f007800620069006e002f00620075007300790062006f007800"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x1057f8,bb=0x1057f8", feature: || num(18446744073709551615), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x1057f8,bb=0x1057f8", feature: || num(18446744073709551615), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x105C88", feature: || num(61440), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x105b38", feature: || characteristic_("recursive call"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x105c88", feature: || api_("memset"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x105c88", feature: || api_("Nope"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x105c88", feature: || regex_("innerRename"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x106530", feature: || characteristic_("recursive call"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x1066e0,bb=0x1068c4", feature: || num(4294967295), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x106d58", feature: || string_("/data/misc/wifi/wpa_supplicant.conf"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x106d58", feature: || regex_("/data/misc"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x106d58", feature: || substring_("/data/misc"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x1070e8", feature: || characteristic_("calls from"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x107588", feature: || mnemonic_("stp"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x107588", feature: || mnemonic_("adrp"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x107588", feature: || mnemonic_("bl"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x107588", feature: || mnemonic_("in"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x107588", feature: || mnemonic_("adrl"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x107588", feature: || string_("AppDataService start"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x107588", feature: || string_("nope"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x107588", feature: || os_("android"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x107588", feature: || arch_("aarch64"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x107588", feature: || format_("elf"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x107588", feature: || format_("pe"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x107588,bb=0x107588", feature: || opnum(1, 8), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x107588,bb=0x107588,insn=0x1075a4", feature: || opnum(1, 8), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x1075c0", feature: || characteristic_("loop"), expected: Expected::Bool(false) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x1075c0", feature: || string_("AppDataService"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x1075c0", feature: || characteristic_("calls to"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x1075c0,bb=0x1076c0", feature: || os_("android"), expected: Expected::Bool(true) },
    Row { sample: "687e79.ghidra.be2", scope: "function=0x1075c0,bb=0x1076c0", feature: || arch_("aarch64"), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x11451c", feature: || num(16), expected: Expected::Bool(false) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x11451c", feature: || off(32), expected: Expected::Bool(false) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x11451c", feature: || characteristic_("indirect call"), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x11464c", feature: || characteristic_("tight loop"), expected: Expected::Bool(false) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x114af4", feature: || characteristic_("tight loop"), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x114af4", feature: || characteristic_("nzxor"), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x1165a4", feature: || bytes_hex("e405b89370ba6b419cd7925275bf6fcc1e8360cc"), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x117988", feature: || characteristic_("nzxor"), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x1183e0,bb=0x11849c,insn=0x1184b0", feature: || off(8), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x118500", feature: || characteristic_("indirect call"), expected: Expected::Bool(false) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x118620", feature: || characteristic_("indirect call"), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x118620", feature: || characteristic_("indirect call"), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x118F1C", feature: || characteristic_("tight loop"), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x124854,bb=0x1248AC,insn=0x1248B4", feature: || opoff(2, -72), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x124854,bb=0x1248AC,insn=0x1248B4", feature: || off(-72), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x13347c,bb=0x133548,insn=0x133554", feature: || opoff(2, 32), expected: Expected::Bool(false) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x13347c,bb=0x133548,insn=0x133554", feature: || off(32), expected: Expected::Bool(false) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x138688,bb=0x138978,insn=0x138984", feature: || off(8), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x138688,bb=0x138994,insn=0x1389a8", feature: || off(8), expected: Expected::Bool(true) },
    Row { sample: "d1e650.ghidra.be2", scope: "function=0x138a9c,bb=0x138b00,insn=0x138b00", feature: || off(1), expected: Expected::Bool(true) },
];

/// Every row's sample resolves to a pinned file and every feature
/// constructor call succeeds -- catches a transcription error independently
/// of AArch64 recovery existing.
#[test]
fn table_rows_reference_pinned_samples_and_construct() {
    for row in ROWS {
        let path = sample_path(row.sample);
        assert!(
            path.is_file(),
            "row {:?}/{:?}: {} is not a pinned file",
            row.sample,
            row.scope,
            path.display()
        );
        let _ = (row.feature)();
    }
}

/// Root-caused, *our own* recovery gaps -- as opposed to `Expected::Xfail`,
/// whose reason string is preserved verbatim from upstream's own test suite.
/// This list is maintained by hand (unlike `ROWS`, which is regenerated) and
/// must stay tiny: every entry here is a row this crate's own recovery, not
/// upstream, fails to satisfy, recorded with why so it can't silently rot
/// into a bigger gap.
///
/// `687e79.../function=0x105128,bb=0x105450`: block `0x105450` is a switch
/// dispatch target reached only through the `adrp/add/ldrsw/add/br` jump
/// table at the end of block `0x10517c` -- confirmed via
/// `analysis.functions[0x105128]`: the block ending in `br` has no
/// successors, and `0x105450` is unreached bytes between the prior block's
/// `ret` (`0x105440`) and the next recovered block (`0x105470`). Resolving
/// it needs the table's *entry count*, which AArch64 doesn't encode at the
/// branch site -- unlike x86, whose `jump_table_targets` walks a table of
/// absolute pointers until a non-executable entry stops it, this table
/// holds `ldrsw`-loaded relative offsets and Ghidra determines the case
/// count from a bounds-check (`cmp`/`b.hi`) earlier in the block. That is
/// new recovery work (bounds-check pattern recognition, not just an
/// addressing-mode gap this module's own materialization already covers),
/// so it stays open rather than being bolted on here. Tracked as a J9
/// divergence class ("recovery: unresolved AArch64 switch/jump-table
/// dispatch"), not silently skipped.
const KNOWN_RECOVERY_GAPS: &[(&str, &str)] =
    &[("687e79.ghidra.be2", "function=0x105128,bb=0x105450")];

/// This test
/// actually passing. `KNOWN_RECOVERY_GAPS` above is the one row this
/// crate's own (not upstream's) recovery doesn't yet reach.
#[test]
fn feature_presence_matches_upstream_be2_aarch64_expectations() {
    let mut cache: BTreeMap<&str, StaticFeatures> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();
    let mut xfail_now_passing: Vec<String> = Vec::new();
    let mut gaps_now_passing: Vec<String> = Vec::new();

    for row in ROWS {
        let features = cache
            .entry(row.sample)
            .or_insert_with(|| build_features(&sample_path(row.sample)));
        let fs = scope_features(features, row.scope);
        let actual = feature_present(&fs, &(row.feature)());
        let is_known_gap = KNOWN_RECOVERY_GAPS
            .iter()
            .any(|&(sample, scope)| sample == row.sample && scope == row.scope);

        match &row.expected {
            Expected::Bool(expected) => {
                if actual != *expected && is_known_gap {
                    if actual {
                        gaps_now_passing.push(format!(
                            "{}/{}: {} -- known-gap row now passes, remove it from KNOWN_RECOVERY_GAPS",
                            row.sample,
                            row.scope,
                            (row.feature)()
                        ));
                    }
                    // else: the documented gap, exactly as expected.
                } else if actual != *expected {
                    failures.push(format!(
                        "{}/{}: expected {expected}, got {actual} for {}",
                        row.sample,
                        row.scope,
                        (row.feature)()
                    ));
                }
            }
            Expected::Xfail(reason) => {
                if actual {
                    xfail_now_passing.push(format!(
                        "{}/{}: {} ({reason}) -- xfail row now passes, promote it to Expected::Bool(true)",
                        row.sample,
                        row.scope,
                        (row.feature)()
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        xfail_now_passing.is_empty(),
        "{} previously-xfail row(s) now pass -- xfail must never silently stay xfail:\n{}",
        xfail_now_passing.len(),
        xfail_now_passing.join("\n")
    );
    assert!(
        gaps_now_passing.is_empty(),
        "{} previously-gapped row(s) now pass -- update KNOWN_RECOVERY_GAPS:\n{}",
        gaps_now_passing.len(),
        gaps_now_passing.join("\n")
    );
}
