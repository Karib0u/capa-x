//! Port of the pinned Python capa test suite's
//! `fixtures.py::FEATURE_PRESENCE_TESTS_DOTNET` /
//! `FEATURE_COUNT_TESTS_DOTNET` expectation tables (v9.4.0, see PINNED.md;
//! `reference/capa/tests/fixtures.py:1147,1534`) -- the native .NET
//! acceptance oracle.
//!
//! Regenerate the two tables below (never by hand -- see each table's
//! header) with `scripts/gen_fixture_tables.py dotnet`, run under the
//! pinned `.venv` against the checked-out `reference/capa/` source; the
//! **output is committed**, and `cargo test` never invokes Python (AGENTS.md
//! "No Python at runtime").
//!
//! ## Scope resolution
//!
//! Unlike `features_parity.rs`'s x86/x64 tables, a .NET row's `scope`
//! resolves to *two different address kinds* depending on its prefix --
//! `reference/capa/tests/fixtures.py::resolve_scope` dispatches
//! `"function=0x..."` through `get_function` and `"token=0x..."` through
//! `get_function_by_token`. For a `DnfileFeatureExtractor`, `get_function`/
//! `get_basic_block`/`get_instruction` match on `fh.inner.offset` -- a
//! `CilMethodBody`'s raw *file offset*, not a token -- while
//! `get_function_by_token` matches `fh.address` (`DNTokenAddress`)
//! directly. The managed feature extractor is
//! (`capa_x::extract::dotnet::features::extract_dotnet`), so this file
//! resolves both: `token=0x...` looks up `Address::DnToken` directly (the
//! same way `StaticFeatures.functions` is keyed), and `function=0x...`
//! (optionally with `bb=`/`insn=`) bridges the raw file offset to the
//! corresponding `DnToken`/`DnTokenOffset` address via a second, raw
//! `dnfile::DnPe` parse of the same sample -- see
//! `resolve_raw_function`/`resolve_raw_instruction` below.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use capa_x::address::Address;
use capa_x::engine::{self, evaluate, FeatureSet};
use capa_x::extract::dotnet::features::extract_dotnet;
use capa_x::extract::dotnet::{function::managed_method_bodies, load as load_dotnet};
use capa_x::features::{Access, Feature, NumberValue, StringFeature};
use capa_x::freeze::{BasicBlockFeatures, FunctionFeatures, StaticFeatures};
use capa_x::rules::{Node, Statement};

// ---------------------------------------------------------------------
// sample loading, mirroring `fixtures.py::get_data_path_by_name`, restricted
// to this table's *backed* short names -- see "excluded" below.
// ---------------------------------------------------------------------

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn testfile(name: &str) -> PathBuf {
    root().join("tests/testfiles").join(name)
}

/// port of `fixtures.py::get_data_path_by_name`, restricted to the dotnet
/// presence/count tables' short names that resolve to a file this repo
/// actually pins (see the module doc's "excluded" note for the two that
/// don't).
fn sample_path(name: &str) -> std::path::PathBuf {
    match name {
        "_039a6" => {
            testfile("039a6336d0802a2255669e6867a5679c7eb83313dbc61fb1c7232147379bd304.exe_")
        }
        "_0953c" => {
            testfile("0953cc3b77ed2974b09e3a00708f88de931d681e2d0cb64afbaf714610beabe6.exe_")
        }
        "_1c444" => testfile("dotnet/1c444ebeba24dcba8628b7dfe5fec7c6.exe_"),
        "_387f15" => {
            testfile("dotnet/387f15043f0198fd3a637b0758c2b6dde9ead795c3ed70803426fc355731b173.dll_")
        }
        "_692f" => testfile("dotnet/692f7fd6d198e804d6af98eb9e390d61.exe_"),
        "b9f5b" => testfile("b9f5bd514485fb06da39beff051b9fdc.exe_"),
        "nested_typedef" => testfile("dotnet/dd9098ff91717f4906afe9dafdfa2f52.exe_"),
        "nested_typeref" => testfile("dotnet/2c7d60f77812607dec5085973ff76cea.dll_"),
        other => panic!("no pinned sample for dotnet fixture short name {other:?}"),
    }
}

// ---------------------------------------------------------------------
// feature constructors, mirroring `capa.features.{common,insn,file}` --
// same shape as `features_parity.rs`'s, kept separate rather than shared
// (each `tests/*.rs` file is its own compiled crate) plus the three .NET
// -only constructors (`class_`/`namespace_`/`property_`) that file has no
// use for.
// ---------------------------------------------------------------------

fn string_(v: &str) -> Feature {
    Feature::String(StringFeature::Plain(v.to_string()))
}
fn num(v: i128) -> Feature {
    Feature::Number(NumberValue::Int(v))
}
fn characteristic_(v: &str) -> Feature {
    Feature::Characteristic(v.to_string())
}
fn import_(v: &str) -> Feature {
    Feature::Import(v.to_string())
}
fn api_(v: &str) -> Feature {
    Feature::Api(v.to_string())
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
fn class_(v: &str) -> Feature {
    Feature::Class(v.to_string())
}
fn namespace_(v: &str) -> Feature {
    Feature::Namespace(v.to_string())
}
/// port of `capa.features.common.Property.__init__`'s `access` argument
/// (`"read"`/`"write"`/`None`).
fn property_(name: &str, access: Option<&str>) -> Feature {
    Feature::Property {
        name: name.to_string(),
        access: access.map(|a| match a {
            "read" => Access::Read,
            "write" => Access::Write,
            other => panic!("unknown property access {other:?}"),
        }),
    }
}

struct Row {
    sample: &'static str,
    /// exactly as `fixtures.py::resolve_scope` parses it: `"file"`,
    /// `"function=0x..."` (code-address lookup), `"function=0x...,bb=0x...
    /// [,insn=0x...]"`, or `"token=0x..."` (metadata-token lookup) -- see
    /// the module doc for why this stays a string rather than a resolved
    /// `Address` here.
    scope: &'static str,
    feature: fn() -> Feature,
    expected: bool,
}

struct CountRow {
    sample: &'static str,
    scope: &'static str,
    feature: fn() -> Feature,
    expected: usize,
}

/// Regenerate with `scripts/gen_fixture_tables.py dotnet` (see the module
/// doc). 70 of the upstream table's 87 rows: the other 17 reference
/// `hello-world`/`mixed-mode-64`, which live in `dnfile`'s own bundled test
/// fixtures (`reference/capa/tests/data/dotnet/dnfile-testfiles/`) --  a
/// *nested* submodule inside `reference/capa` (`tests/data`, pinned to its
/// own separate `mandiant/capa-testfiles` commit) that this repo does not
/// check out: PINNED.md pins exactly one `capa-testfiles` commit
/// (`tests/testfiles`), and pulling in a second, differently-pinned copy
/// for 17 rows would contradict that. Excluded, not silently dropped: this
/// note is the record.
#[rustfmt::skip]
const ROWS: &[Row] = &[
    Row { sample: "_039a6", scope: "token=0x6000007", feature: || api_("System.Reflection.Assembly::Load"), expected: true },
    Row { sample: "_039a6", scope: "token=0x600001C", feature: || property_("StagelessHollow.Arac::Marka", Some("read")), expected: false },
    Row { sample: "_039a6", scope: "token=0x600001D", feature: || property_("StagelessHollow.Arac::Marka", Some("read")), expected: true },
    Row { sample: "_039a6", scope: "token=0x6000023", feature: || property_("System.Runtime.CompilerServices.AsyncTaskMethodBuilder::Task", Some("read")), expected: false },
    Row { sample: "_0953c", scope: "token=0x6000004", feature: || property_("System.Diagnostics.Debugger::IsAttached", Some("read")), expected: true },
    Row { sample: "_0953c", scope: "token=0x6000004", feature: || class_("System.Diagnostics.Debugger"), expected: true },
    Row { sample: "_0953c", scope: "token=0x6000004", feature: || namespace_("System.Diagnostics"), expected: true },
    Row { sample: "_1c444", scope: "file", feature: || string_("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"), expected: true },
    Row { sample: "_1c444", scope: "file", feature: || string_("get_IsAlive"), expected: true },
    Row { sample: "_1c444", scope: "file", feature: || import_("gdi32.CreateCompatibleBitmap"), expected: true },
    Row { sample: "_1c444", scope: "file", feature: || import_("CreateCompatibleBitmap"), expected: true },
    Row { sample: "_1c444", scope: "file", feature: || import_("gdi32::CreateCompatibleBitmap"), expected: false },
    Row { sample: "_1c444", scope: "function=0x1F59, bb=0x1F59, insn=0x1F5B", feature: || characteristic_("unmanaged call"), expected: true },
    Row { sample: "_1c444", scope: "function=0x1F68", feature: || api_("GetWindowDC"), expected: true },
    Row { sample: "_1c444", scope: "function=0x1F68", feature: || api_("user32.GetWindowDC"), expected: false },
    Row { sample: "_1c444", scope: "function=0x1F68", feature: || num(13369376), expected: true },
    Row { sample: "_1c444", scope: "function=0x1F68", feature: || num(0), expected: true },
    Row { sample: "_1c444", scope: "function=0x1F68", feature: || num(1), expected: false },
    Row { sample: "_1c444", scope: "function=0x1F68, bb=0x1F68, insn=0x1FF9", feature: || api_("System.Drawing.Image::FromHbitmap"), expected: true },
    Row { sample: "_1c444", scope: "function=0x1F68, bb=0x1F68, insn=0x1FF9", feature: || api_("FromHbitmap"), expected: false },
    Row { sample: "_1c444", scope: "function=0x2544", feature: || characteristic_("unmanaged call"), expected: false },
    Row { sample: "_1c444", scope: "token=0x600000F", feature: || characteristic_("calls from"), expected: false },
    Row { sample: "_1c444", scope: "token=0x6000018", feature: || characteristic_("calls to"), expected: false },
    Row { sample: "_1c444", scope: "token=0x600001D", feature: || characteristic_("calls to"), expected: true },
    Row { sample: "_1c444", scope: "token=0x600001D", feature: || characteristic_("calls from"), expected: true },
    Row { sample: "_1c444", scope: "token=0x6000020", feature: || namespace_("Reqss"), expected: true },
    Row { sample: "_1c444", scope: "token=0x6000020", feature: || class_("Reqss.Reqss"), expected: true },
    Row { sample: "_1c444", scope: "token=0x600002B", feature: || property_("System.IO.FileInfo::Length", Some("read")), expected: true },
    Row { sample: "_1c444", scope: "token=0x600002B", feature: || property_("System.IO.FileInfo::Length", None), expected: true },
    Row { sample: "_1c444", scope: "token=0x6000081", feature: || api_("System.Diagnostics.Process::Start"), expected: true },
    Row { sample: "_1c444", scope: "token=0x6000081", feature: || property_("System.Diagnostics.ProcessStartInfo::UseShellExecute", Some("write")), expected: true },
    Row { sample: "_1c444", scope: "token=0x6000081", feature: || property_("System.Diagnostics.ProcessStartInfo::WorkingDirectory", Some("write")), expected: true },
    Row { sample: "_1c444", scope: "token=0x6000081", feature: || property_("System.Diagnostics.ProcessStartInfo::FileName", Some("write")), expected: true },
    Row { sample: "_1c444", scope: "token=0x6000087", feature: || property_("Sockets.MySocket::reConnectionDelay", Some("write")), expected: true },
    Row { sample: "_1c444", scope: "token=0x6000088", feature: || characteristic_("unmanaged call"), expected: false },
    Row { sample: "_1c444", scope: "token=0x600008A", feature: || property_("Sockets.MySocket::isConnected", Some("write")), expected: true },
    Row { sample: "_1c444", scope: "token=0x600008A", feature: || class_("Sockets.MySocket"), expected: true },
    Row { sample: "_1c444", scope: "token=0x600008A", feature: || namespace_("Sockets"), expected: true },
    Row { sample: "_1c444", scope: "token=0x600008A", feature: || property_("Sockets.MySocket::onConnected", Some("read")), expected: true },
    Row { sample: "_387f15", scope: "token=0x600009E", feature: || property_("Modulo.IqQzcRDvSTulAhyLtZHqyeYGgaXGbuLwhxUKXYmhtnOmgpnPJDTSIPhYPpnE::geoplugin_countryCode", Some("read")), expected: true },
    Row { sample: "_387f15", scope: "token=0x600009E", feature: || class_("Modulo.IqQzcRDvSTulAhyLtZHqyeYGgaXGbuLwhxUKXYmhtnOmgpnPJDTSIPhYPpnE"), expected: true },
    Row { sample: "_387f15", scope: "token=0x600009E", feature: || namespace_("Modulo"), expected: true },
    Row { sample: "_692f", scope: "token=0x6000004", feature: || api_("System.Linq.Enumerable::First"), expected: true },
    Row { sample: "_692f", scope: "token=0x6000004", feature: || property_("System.Linq.Enumerable::First", None), expected: false },
    Row { sample: "_692f", scope: "token=0x6000004", feature: || namespace_("System.Linq"), expected: true },
    Row { sample: "_692f", scope: "token=0x6000004", feature: || class_("System.Linq.Enumerable"), expected: true },
    Row { sample: "_692f", scope: "token=0x6000006", feature: || property_("System.Management.Automation.PowerShell::Streams", Some("read")), expected: false },
    Row { sample: "b9f5b", scope: "file", feature: || arch_("i386"), expected: true },
    Row { sample: "b9f5b", scope: "file", feature: || arch_("amd64"), expected: false },
    Row { sample: "b9f5b", scope: "file", feature: || os_("any"), expected: true },
    Row { sample: "b9f5b", scope: "file", feature: || format_("pe"), expected: true },
    Row { sample: "b9f5b", scope: "file", feature: || format_("dotnet"), expected: true },
    Row { sample: "nested_typedef", scope: "file", feature: || class_("mynamespace.myclass_outer0"), expected: true },
    Row { sample: "nested_typedef", scope: "file", feature: || class_("mynamespace.myclass_outer1"), expected: true },
    Row { sample: "nested_typedef", scope: "file", feature: || class_("mynamespace.myclass_outer0/myclass_inner0_0"), expected: true },
    Row { sample: "nested_typedef", scope: "file", feature: || class_("mynamespace.myclass_outer0/myclass_inner0_1"), expected: true },
    Row { sample: "nested_typedef", scope: "file", feature: || class_("mynamespace.myclass_outer1/myclass_inner1_0"), expected: true },
    Row { sample: "nested_typedef", scope: "file", feature: || class_("mynamespace.myclass_outer1/myclass_inner1_1"), expected: true },
    Row { sample: "nested_typedef", scope: "file", feature: || class_("mynamespace.myclass_outer1/myclass_inner1_0/myclass_inner_inner"), expected: true },
    Row { sample: "nested_typedef", scope: "file", feature: || class_("myclass_inner_inner"), expected: false },
    Row { sample: "nested_typedef", scope: "file", feature: || class_("myclass_inner1_0"), expected: false },
    Row { sample: "nested_typedef", scope: "file", feature: || class_("myclass_inner1_1"), expected: false },
    Row { sample: "nested_typedef", scope: "file", feature: || class_("myclass_inner0_0"), expected: false },
    Row { sample: "nested_typedef", scope: "file", feature: || class_("myclass_inner0_1"), expected: false },
    Row { sample: "nested_typeref", scope: "file", feature: || import_("Android.OS.Build/VERSION::SdkInt"), expected: true },
    Row { sample: "nested_typeref", scope: "file", feature: || import_("Android.Media.Image/Plane::Buffer"), expected: true },
    Row { sample: "nested_typeref", scope: "file", feature: || import_("Android.Provider.Telephony/Sent/Sent::ContentUri"), expected: true },
    Row { sample: "nested_typeref", scope: "file", feature: || import_("Android.OS.Build::SdkInt"), expected: false },
    Row { sample: "nested_typeref", scope: "file", feature: || import_("Plane::Buffer"), expected: false },
    Row { sample: "nested_typeref", scope: "file", feature: || import_("Sent::ContentUri"), expected: false },
];

/// Regenerate with `scripts/gen_fixture_tables.py dotnet` (see the module
/// doc).
#[rustfmt::skip]
const COUNT_ROWS: &[CountRow] = &[
    CountRow { sample: "_1c444", scope: "token=0x600001D", feature: || characteristic_("calls to"), expected: 1 },
    CountRow { sample: "_1c444", scope: "token=0x600001D", feature: || characteristic_("calls from"), expected: 9 },
];

/// Every row's sample resolves to a pinned file and every feature
/// constructor call succeeds -- catches a transcription error (a typo'd
/// short name, a malformed feature) independently of the backend that will
/// eventually consume this table.
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
    for row in COUNT_ROWS {
        let path = sample_path(row.sample);
        assert!(
            path.is_file(),
            "count row {:?}: {} is not a pinned file",
            row.sample,
            path.display()
        );
        let _ = (row.feature)();
    }
}

// ---------------------------------------------------------------------
// extraction, cached per sample (mirrors `features_parity.rs::extractor`)
// ---------------------------------------------------------------------

fn build_features(path: &Path) -> StaticFeatures {
    let bytes =
        std::fs::read(path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    extract_dotnet(&bytes, &capa_x::parallel::AnalysisOptions::SERIAL)
        .unwrap_or_else(|error| panic!("extracting .NET features from {}: {error}", path.display()))
}

fn extractor(name: &str) -> Arc<StaticFeatures> {
    type Cell = Arc<OnceLock<Arc<StaticFeatures>>>;
    static CACHE: OnceLock<Mutex<HashMap<String, Cell>>> = OnceLock::new();

    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let cell = {
        let mut guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());
        guard.entry(name.to_string()).or_default().clone()
    };
    cell.get_or_init(|| Arc::new(build_features(&sample_path(name))))
        .clone()
}

// ---------------------------------------------------------------------
// scope resolution, mirroring `fixtures.py::resolve_scope`'s
// `DnfileFeatureExtractor` branch (`get_function`/`get_basic_block`/
// `get_instruction` match on `.inner.offset`/token, not `fh.address`).
// ---------------------------------------------------------------------

fn parse_hex(s: &str) -> u64 {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).unwrap_or_else(|error| panic!("bad hex address {s}: {error}"))
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
    for insn in bb.instructions.values() {
        for (addr, f) in &insn.features {
            engine::insert(&mut fs, f.clone(), *addr);
        }
    }
    for (addr, f) in &bb.features {
        engine::insert(&mut fs, f.clone(), *addr);
    }
    fs
}

fn function_fs(func: &FunctionFeatures) -> FeatureSet {
    let mut fs = FeatureSet::new();
    for bb in func.basic_blocks.values() {
        engine::merge(&mut fs, &bb_fs(bb));
    }
    for (addr, f) in &func.features {
        engine::insert(&mut fs, f.clone(), *addr);
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

/// `fixtures.py::get_function`'s `DnfileFeatureExtractor` branch: find the
/// `MethodDef` token whose `CilMethodBody` starts at raw file offset
/// `offset` -- a second, raw parse of the sample, since `StaticFeatures`
/// only carries the token-addressed view.
fn resolve_raw_function(path: &Path, offset: u64) -> Option<u32> {
    let bytes = std::fs::read(path).ok()?;
    let pe = load_dotnet(&bytes).ok()?;
    let bodies = managed_method_bodies(&pe).ok()?;
    bodies
        .iter()
        .find(|f| f.body.offset as u64 == offset)
        .map(|f| f.token)
}

/// `fixtures.py::get_instruction`'s `DnfileFeatureExtractor` branch: find
/// the instruction at raw file offset `insn_offset` inside the method whose
/// body starts at `fn_offset`, then translate it to the same
/// `Address::DnTokenOffset` `StaticFeatures` addresses instructions by
/// (`DnFunction::instruction_address`, task 3).
fn resolve_raw_instruction(path: &Path, fn_offset: u64, insn_offset: u64) -> Option<Address> {
    let bytes = std::fs::read(path).ok()?;
    let pe = load_dotnet(&bytes).ok()?;
    let bodies = managed_method_bodies(&pe).ok()?;
    let f = bodies.iter().find(|f| f.body.offset as u64 == fn_offset)?;
    let insn = f
        .body
        .instructions
        .iter()
        .find(|i| i.offset as u64 == insn_offset)?;
    Some(f.instruction_address(insn))
}

fn scope_features(features: &StaticFeatures, sample_path: &Path, scope: &str) -> FeatureSet {
    let mut fs = if scope == "file" {
        let mut fs = FeatureSet::new();
        for (addr, f) in &features.file_features {
            engine::insert(&mut fs, f.clone(), *addr);
        }
        fs
    } else if let Some(rest) = scope.strip_prefix("token=") {
        let token = parse_hex(rest) as u32;
        let Some(func) = features.functions.get(&Address::DnToken(token)) else {
            return global_fs(features);
        };
        function_fs(func)
    } else {
        // `function=0x...` (optionally `,bb=0x...[,insn=0x...]`): raw CIL
        // body/instruction file offsets, bridged to a token via a fresh raw
        // parse -- see `resolve_raw_function`/`resolve_raw_instruction`.
        // Some rows format multi-part scopes with a space after the comma
        // (`"function=0x1F59, bb=0x1F59, insn=0x1F5B"`) -- trim each part.
        let parts: Vec<&str> = scope.split(',').map(str::trim).collect();
        let addr_for = |prefix: &str| -> u64 {
            parts
                .iter()
                .find_map(|p| p.strip_prefix(prefix))
                .map(parse_hex)
                .unwrap_or_else(|| panic!("scope {scope} missing {prefix}"))
        };
        let fspec = addr_for("function=");
        let Some(token) = resolve_raw_function(sample_path, fspec) else {
            return global_fs(features);
        };
        let Some(func) = features.functions.get(&Address::DnToken(token)) else {
            return global_fs(features);
        };
        if parts.len() == 1 {
            function_fs(func)
        } else {
            // one basic block per method (task 3): `bb=` always names the
            // same offset as `function=`, so the block is already resolved.
            let Some(bb) = func.basic_blocks.get(&Address::DnToken(token)) else {
                return global_fs(features);
            };
            if parts.len() == 2 {
                bb_fs(bb)
            } else {
                let iva = addr_for("insn=");
                let Some(insn_addr) = resolve_raw_instruction(sample_path, fspec, iva) else {
                    return global_fs(features);
                };
                let Some(insn) = bb.instructions.get(&insn_addr) else {
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

// ---------------------------------------------------------------------
// leaf evaluation, mirroring `fixtures.py::do_test_feature_{presence,count}`
// ---------------------------------------------------------------------

fn feature_present(fs: &FeatureSet, feature: &Feature) -> bool {
    let node = Node {
        stmt: Statement::Leaf(feature.clone()),
        description: None,
    };
    evaluate(&node, fs, true)
        .unwrap_or_else(|error| panic!("evaluating {feature}: {error}"))
        .is_match()
}

fn feature_count(fs: &FeatureSet, feature: &Feature) -> usize {
    fs.get(feature).map(BTreeSet::len).unwrap_or(0)
}

#[test]
fn feature_presence_matches_upstream_dotnet_expectations() {
    for row in ROWS {
        let path = sample_path(row.sample);
        let features = extractor(row.sample);
        let fs = scope_features(&features, &path, row.scope);
        let feature = (row.feature)();
        let present = feature_present(&fs, &feature);
        assert_eq!(
            present, row.expected,
            "sample {:?} scope {:?}: expected {feature} present={}, got {present}",
            row.sample, row.scope, row.expected
        );
    }
}

#[test]
fn feature_count_matches_upstream_dotnet_expectations() {
    for row in COUNT_ROWS {
        let path = sample_path(row.sample);
        let features = extractor(row.sample);
        let fs = scope_features(&features, &path, row.scope);
        let feature = (row.feature)();
        let count = feature_count(&fs, &feature);
        assert_eq!(
            count, row.expected,
            "sample {:?} scope {:?}: expected {feature} count={}, got {count}",
            row.sample, row.scope, row.expected
        );
    }
}
