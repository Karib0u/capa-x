//! The library entrypoint: bytes plus a built [`MatchingRuleSet`] plus
//! [`AnalysisOptions`] in, a [`rd::ResultDocument`] out.
//!
//! Hoisted out of `capa-x-cli/src/main.rs` so a binding or a test can reach
//! the whole PE/ELF/shellcode/freeze pipeline -- format
//! detection, extraction, recovery, FLIRT, matching, and result-document
//! construction -- under `cargo test`, instead of only through the compiled
//! `capa` binary. Nothing here changes behavior versus the code it replaced;
//! the byte-identical-output check covers that claim.
//!
//! What deliberately stays outside this module, in `capa-x-cli`:
//!
//! - reading the input file and the rules directory from disk (a library
//!   caller supplies bytes and an already-built [`MatchingRuleSet`]; a
//!   binding's caller may not have either on a filesystem at all);
//! - rule loading and [`filter_rules_by_tag`]'s tag filter runs *before*
//!   [`MatchingRuleSet::new`], so it is a step the caller takes when building
//!   the ruleset, not something [`analyze`] does;
//! - presentation: `--json`/verbosity rendering, `--timing`'s stderr format,
//!   and the `--dump-*` debug surfaces call the primitives here directly
//!   (see [`load_input`], which is `pub` for exactly that reason) rather than
//!   going through [`analyze`], which always produces a complete document.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::address::Address;
use crate::capabilities::{find_dynamic_capabilities, find_static_capabilities, MatchingRuleSet};
use crate::extract::{
    self,
    dotnet::{features::extract_dotnet_from_pe, looks_like_dotnet_pe},
    elf::extract_elf,
    flirt::{enrich_static_features, identify_library_functions, FlirtError, Signatures},
    image::Architecture,
    macho::extract_macho,
    pe::extract_pe,
    recovery::{self, RecoveryError},
    sc::extract_sc,
    ExtractError,
};
use crate::freeze::{self, Freeze, FreezeError};
use crate::parallel::AnalysisOptions;
use crate::rd::{self, MetaInputs, ARCH_AUTO, OS_AUTO};
use crate::rules::Rule;

// Mirrors capa/main.py's E_* constants for the subset of failures that can
// occur inside `analyze`; `E_MISSING_FILE`/`E_INVALID_RULE` never appear here
// because reading the input file and loading rules both stay in the caller.
const E_CORRUPT_FILE: u8 = 13;
const E_INVALID_SIG: u8 = 15;
const E_INVALID_FILE_TYPE: u8 = 16;

/// `-f`/`--format`'s values. `Auto` mirrors
/// `capa.features.extractors.common.extract_format`'s magic-byte dispatch
/// order (PE, then ELF, then freeze); the rest select a format explicitly,
/// skipping auto-detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    #[default]
    Auto,
    Pe,
    Elf,
    Sc32,
    Sc64,
    Freeze,
    Dotnet,
    /// A capa-x extension -- pinned capa 9.4.0 has no raw
    /// Mach-O input, so this is never part of `Auto`'s cascade (which
    /// mirrors upstream's own detection order exactly); it is only ever
    /// selected explicitly. See `extract::image::ImageFormat::Macho`.
    Macho,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Auto => "auto",
            Format::Pe => "pe",
            Format::Elf => "elf",
            Format::Sc32 => "sc32",
            Format::Sc64 => "sc64",
            Format::Freeze => "freeze",
            Format::Dotnet => "dotnet",
            Format::Macho => "macho",
        }
    }
}

/// One analysis run's identity: the bytes to analyze, plus the invocation
/// metadata that ends up in `meta` but cannot be derived from `bytes` or an
/// already-built [`MatchingRuleSet`] alone (the ruleset retains no memory of
/// which directory it was loaded from, and argv is meaningless to compute
/// inside a library).
///
/// `sample_path`/`rules_paths` should be whatever string the caller wants
/// `meta.sample.path`/`meta.analysis.rules` to read verbatim -- the CLI
/// passes the canonicalized filesystem path it read `bytes` from and the
/// canonicalized rules directory; a binding fed bytes directly may pass
/// anything descriptive, or an empty string.
pub struct Input<'a> {
    pub bytes: &'a [u8],
    pub sample_path: String,
    pub rules_paths: Vec<String>,
    /// `Some(vec![])` for a caller with no meaningful argv (a binding); the
    /// CLI passes `std::env::args().skip(1).collect()`. Not `None`: the
    /// binding parity check found that upstream's `ResultDocument.meta.argv`
    /// pydantic field is a required `list[str]`, not `Optional` -- `None`
    /// here serializes to JSON `null`, which fails
    /// `ResultDocument.model_validate_json` with "Field required" rather
    /// than validating with an empty list. `Option` stays the field's type
    /// (rather than requiring every internal caller, including test
    /// fixtures with no schema-validation stake, to pass an empty `Vec`
    /// explicitly) -- `None` is still meaningful for callers that only need
    /// this crate's own round-trip, just not for one that hands the
    /// document to upstream's model.
    pub argv: Option<Vec<String>>,
}

/// The parsed/recovered result of [`load_input`]: static or dynamic features
/// plus any FLIRT-recognized library functions (PE only; empty otherwise).
pub struct LoadedInput {
    pub freeze: Freeze,
    pub library_functions: Vec<rd::LibraryFunction>,
}

/// Every way [`analyze`]/[`load_input`] can fail. Each variant's message
/// text and [`AnalysisError::exit_code`] reproduce what `capa-x-cli/src/
/// main.rs`'s `CliError` produced for the same failure before the hoist --
/// see that binary's `From<AnalysisError> for CliError`.
#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    #[error("extracting PE features: {0}")]
    PeExtract(ExtractError),
    #[error("recovering PE code: {0}")]
    PeRecover(RecoveryError),
    #[error("extracting ELF features: {0}")]
    ElfExtract(ExtractError),
    #[error("recovering ELF code: {0}")]
    ElfRecover(RecoveryError),
    #[error("extracting .NET features: {0}")]
    DotnetExtract(ExtractError),
    #[error("recovering shellcode: {0}")]
    ScRecover(RecoveryError),
    #[error("extracting Mach-O features: {0}")]
    MachoExtract(ExtractError),
    #[error("recovering Mach-O code: {0}")]
    MachoRecover(RecoveryError),
    #[error("parsing freeze file: {0}")]
    Freeze(FreezeError),
    #[error(
        "could not auto-detect input format: capa-x supports PE, ELF, and freeze-file input \
         (shellcode has no magic bytes to detect; pass --format sc32/sc64 explicitly)"
    )]
    UnknownFormat,
    #[error("{0}")]
    Signature(#[from] FlirtError),
    /// `source` is pre-formatted rather than the matcher's own error type:
    /// `find_static_capabilities` returns `CapabilityError` and
    /// `find_dynamic_capabilities` returns `engine::EngineError` -- two
    /// unrelated types this crate has never needed a common supertype for,
    /// same as the CLI's original `matching_failed(cli, error: impl
    /// Display)` this ports.
    #[error("matching {sample}: {reason}")]
    Matching { sample: String, reason: String },
    #[error("building result document: {0}")]
    ResultDocument(#[from] rd::FromCapaError),
}

impl AnalysisError {
    /// Mirrors `capa/main.py`'s `E_*` exit codes, for a caller (the CLI) that
    /// wants the same process exit status this crate produced before the
    /// hoist.
    pub fn exit_code(&self) -> u8 {
        match self {
            AnalysisError::Signature(_) => E_INVALID_SIG,
            AnalysisError::UnknownFormat => E_INVALID_FILE_TYPE,
            _ => E_CORRUPT_FILE,
        }
    }
}

/// Wall-clock time for each phase inside [`analyze`]/[`analyze_with_timings`].
/// Rule loading and the caller's own bookkeeping (argument parsing,
/// rendering) happen outside this crate's scope and are not included here --
/// see `capa-x-cli/src/main.rs`'s `Timings`, which adds those two phases around
/// this struct's four to reproduce `--timing`'s exact five-phase-plus-total
/// report.
#[derive(Debug, Clone, Copy, Default)]
pub struct PhaseTimings {
    pub load_and_recover: std::time::Duration,
    pub extraction: std::time::Duration,
    pub matching: std::time::Duration,
    pub result: std::time::Duration,
}

fn timed<T>(slot: &mut std::time::Duration, f: impl FnOnce() -> T) -> T {
    let start = std::time::Instant::now();
    let value = f();
    *slot += start.elapsed();
    value
}

/// port of `get_input_format_from_cli` + `get_extractor_from_cli`: PE/ELF go
/// through the file-scope extractors (`crate::extract`) plus, unless
/// `options.file_only` asked to stop there, the code-analysis pipeline
/// (`recovery::analyze` + FLIRT + `enrich_static_features`); `sc32`/`sc64` go
/// through the shellcode counterpart (`recovery::analyze_shellcode`, no
/// FLIRT step -- PE-only); freeze input is parsed directly.
///
/// `pub` (unlike the rest of this module's helpers) because `--file-only`
/// and the CLI's `--dump-features`/`--dump-matches` debug surfaces need this
/// exact dispatch without going through [`analyze`], which always continues
/// on to build a full result document.
///
/// Returns the *resolved* format name alongside the parsed features --
/// mirroring `get_input_format_from_cli`'s auto-resolution to a concrete
/// format string -- for [`analyze`] to use as `meta.analysis.format`'s
/// fallback (`collect_metadata`'s `input_format` parameter) when the
/// extractor's own global features carry no `Format` feature (true of the
/// file-only PE/ELF extractors: `extract_file_format` is one of their *file*
/// handlers, not a global one -- see `extract/{pe,elf}.rs`).
pub fn load_input(
    bytes: &[u8],
    options: &AnalysisOptions,
    timings: &mut PhaseTimings,
) -> Result<(LoadedInput, &'static str), AnalysisError> {
    match options.format {
        Format::Pe => {
            return if options.file_only {
                extract_pe_file_only(bytes)
            } else {
                extract_pe_input(bytes, options, timings)
            }
            .map(|f| (f, "pe"));
        }
        Format::Elf => {
            return if options.file_only {
                extract_elf_file_only(bytes)
            } else {
                extract_elf_input(bytes, options, timings)
            }
            .map(|f| (f, "elf"));
        }
        Format::Sc32 | Format::Sc64 => {
            let architecture = if options.format == Format::Sc32 {
                Architecture::X86
            } else {
                Architecture::X64
            };
            return if options.file_only {
                Ok(extract_sc_file_only(
                    bytes,
                    architecture,
                    options.os.as_deref(),
                ))
            } else {
                extract_sc_input(bytes, architecture, options.os.as_deref(), options, timings)
            }
            .map(|f| (f, options.format.as_str()));
        }
        Format::Freeze => {
            return parse_freeze_bytes(bytes)
                .map(|freeze| {
                    (
                        LoadedInput {
                            freeze,
                            library_functions: Vec::new(),
                        },
                        "freeze",
                    )
                })
                .map_err(AnalysisError::Freeze);
        }
        // `--file-only` has no .NET counterpart: unlike PE/ELF, there is no
        // separate disassembly-based recovery step to skip -- `extract_dotnet`
        // already does file *and* per-method extraction in one pass (CIL
        // decoding, not emulation), so it always runs in full.
        Format::Dotnet => {
            return extract_dotnet_input(bytes, options, timings).map(|f| (f, "dotnet"));
        }
        Format::Macho => {
            return if options.file_only {
                extract_macho_file_only(bytes, options)
            } else {
                extract_macho_input(bytes, options, timings)
            }
            .map(|f| (f, "macho"));
        }
        Format::Auto => {}
    }

    // auto: mirrors `capa.loader.py`'s managed-PE routing -- a CLR PE goes to
    // the native .NET path ahead of the x86 extractor, checked before
    // `looks_like_pe` (a managed PE is still a well-formed PE and would
    // otherwise match that check first). `-f pe` bypasses this entirely by
    // returning from the explicit-format match above.
    if looks_like_dotnet_pe(bytes) {
        return extract_dotnet_input(bytes, options, timings).map(|f| (f, "dotnet"));
    }
    if extract::looks_like_pe(bytes) {
        return if options.file_only {
            extract_pe_file_only(bytes)
        } else {
            extract_pe_input(bytes, options, timings)
        }
        .map(|f| (f, "pe"));
    }
    if extract::looks_like_elf(bytes) {
        return if options.file_only {
            extract_elf_file_only(bytes)
        } else {
            extract_elf_input(bytes, options, timings)
        }
        .map(|f| (f, "elf"));
    }
    if freeze::is_freeze(bytes) {
        return freeze::load(bytes)
            .map(|freeze| {
                (
                    LoadedInput {
                        freeze,
                        library_functions: Vec::new(),
                    },
                    "freeze",
                )
            })
            .map_err(AnalysisError::Freeze);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if freeze::loads(text).is_ok() {
            // re-parse via parse_freeze_bytes to reuse one code path.
            return parse_freeze_bytes(bytes)
                .map(|freeze| {
                    (
                        LoadedInput {
                            freeze,
                            library_functions: Vec::new(),
                        },
                        "freeze",
                    )
                })
                .map_err(AnalysisError::Freeze);
        }
    }

    Err(AnalysisError::UnknownFormat)
}

fn extract_pe_input(
    bytes: &[u8],
    options: &AnalysisOptions,
    timings: &mut PhaseTimings,
) -> Result<LoadedInput, AnalysisError> {
    let (mut features, analysis, libraries) = timed(&mut timings.load_and_recover, || {
        let features = extract_pe(bytes).map_err(AnalysisError::PeExtract)?;
        let analysis = recovery::analyze(bytes).map_err(AnalysisError::PeRecover)?;
        let signatures = if let Some(path) = &options.signatures_path {
            Signatures::from_path_with_options(path, options)
        } else {
            Signatures::embedded_with_options(options)
        }
        .map_err(AnalysisError::Signature)?;
        let libraries =
            identify_library_functions(&analysis, &signatures).map_err(AnalysisError::Signature)?;
        Ok::<_, AnalysisError>((features, analysis, libraries))
    })?;
    timed(&mut timings.extraction, || {
        enrich_static_features(&mut features, &analysis, &libraries, options)
    });
    let library_functions = libraries
        .into_iter()
        .map(|(address, name)| rd::LibraryFunction {
            address: Address::Absolute(address).into(),
            name,
        })
        .collect();
    Ok(LoadedInput {
        freeze: Freeze::Static(features),
        library_functions,
    })
}

fn extract_pe_file_only(bytes: &[u8]) -> Result<LoadedInput, AnalysisError> {
    extract_pe(bytes)
        .map(|features| LoadedInput {
            freeze: Freeze::Static(features),
            library_functions: Vec::new(),
        })
        .map_err(AnalysisError::PeExtract)
}

fn extract_elf_input(
    bytes: &[u8],
    options: &AnalysisOptions,
    timings: &mut PhaseTimings,
) -> Result<LoadedInput, AnalysisError> {
    let (mut features, analysis) = timed(&mut timings.load_and_recover, || {
        let features = extract_elf(bytes).map_err(AnalysisError::ElfExtract)?;
        let analysis = recovery::analyze(bytes).map_err(AnalysisError::ElfRecover)?;
        Ok::<_, AnalysisError>((features, analysis))
    })?;
    // `identify_library_functions` is PE-only (it returns an empty map for
    // any other image format), so there's no FLIRT step to run here.
    let libraries = BTreeMap::new();
    timed(&mut timings.extraction, || {
        enrich_static_features(&mut features, &analysis, &libraries, options)
    });
    Ok(LoadedInput {
        freeze: Freeze::Static(features),
        library_functions: Vec::new(),
    })
}

fn extract_elf_file_only(bytes: &[u8]) -> Result<LoadedInput, AnalysisError> {
    extract_elf(bytes)
        .map(|features| LoadedInput {
            freeze: Freeze::Static(features),
            library_functions: Vec::new(),
        })
        .map_err(AnalysisError::ElfExtract)
}

/// `-f macho`. `options.arch` doubles as Mach-O slice selection (`--arch
/// x86_64` explicit, `--arch auto`/`None` takes the first `x86_64` slice in
/// fat-header order) alongside its usual PE/ELF role of overriding
/// `meta.analysis.arch` -- both are "which architecture", and Mach-O is the
/// only format where the choice also changes *which bytes* get analysed.
/// No FLIRT step and no `library_functions` (PE-only, same as ELF/shellcode
/// -- `identify_library_functions` returns an empty map for any other
/// image format).
fn extract_macho_input(
    bytes: &[u8],
    options: &AnalysisOptions,
    timings: &mut PhaseTimings,
) -> Result<LoadedInput, AnalysisError> {
    let (mut features, analysis) = timed(&mut timings.load_and_recover, || {
        let features =
            extract_macho(bytes, options.arch.as_deref()).map_err(AnalysisError::MachoExtract)?;
        let analysis = recovery::analyze_macho(bytes, options.arch.as_deref())
            .map_err(AnalysisError::MachoRecover)?;
        Ok::<_, AnalysisError>((features, analysis))
    })?;
    let libraries = BTreeMap::new();
    timed(&mut timings.extraction, || {
        enrich_static_features(&mut features, &analysis, &libraries, options)
    });
    Ok(LoadedInput {
        freeze: Freeze::Static(features),
        library_functions: Vec::new(),
    })
}

fn extract_macho_file_only(
    bytes: &[u8],
    options: &AnalysisOptions,
) -> Result<LoadedInput, AnalysisError> {
    extract_macho(bytes, options.arch.as_deref())
        .map(|features| LoadedInput {
            freeze: Freeze::Static(features),
            library_functions: Vec::new(),
        })
        .map_err(AnalysisError::MachoExtract)
}

/// No FLIRT step (PE-only, and a managed method body is CIL, not native
/// code a signature could match) and no `library_functions` (nothing here
/// plays the role `identify_library_functions` does for PE). Parsing --
/// which includes the vendored fork's eager CIL decode, `dotnet/function.rs`'s
/// module doc -- is timed as `load_and_recover`, same bucket as PE/ELF's own
/// parse+recovery step; `extract_dotnet_from_pe`'s per-method loop, the
/// `--jobs` parallel seam, is timed as `extraction`.
fn extract_dotnet_input(
    bytes: &[u8],
    options: &AnalysisOptions,
    timings: &mut PhaseTimings,
) -> Result<LoadedInput, AnalysisError> {
    let pe = timed(&mut timings.load_and_recover, || {
        extract::dotnet::load(bytes)
    })
    .map_err(AnalysisError::DotnetExtract)?;
    let features = timed(&mut timings.extraction, || {
        extract_dotnet_from_pe(&pe, bytes, options)
    })
    .map_err(AnalysisError::DotnetExtract)?;
    Ok(LoadedInput {
        freeze: Freeze::Static(features),
        library_functions: Vec::new(),
    })
}

fn extract_sc_input(
    bytes: &[u8],
    architecture: Architecture,
    os: Option<&str>,
    options: &AnalysisOptions,
    timings: &mut PhaseTimings,
) -> Result<LoadedInput, AnalysisError> {
    let (mut features, analysis) = timed(&mut timings.load_and_recover, || {
        let features = extract_sc(bytes, architecture, os);
        let analysis =
            recovery::analyze_shellcode(bytes, architecture).map_err(AnalysisError::ScRecover)?;
        Ok::<_, AnalysisError>((features, analysis))
    })?;
    // FLIRT is PE-only (`identify_library_functions` returns an empty map
    // for any other image format), same as `extract_elf_input`.
    let libraries = BTreeMap::new();
    timed(&mut timings.extraction, || {
        enrich_static_features(&mut features, &analysis, &libraries, options)
    });
    Ok(LoadedInput {
        freeze: Freeze::Static(features),
        library_functions: Vec::new(),
    })
}

fn extract_sc_file_only(bytes: &[u8], architecture: Architecture, os: Option<&str>) -> LoadedInput {
    LoadedInput {
        freeze: Freeze::Static(extract_sc(bytes, architecture, os)),
        library_functions: Vec::new(),
    }
}

fn parse_freeze_bytes(bytes: &[u8]) -> Result<Freeze, FreezeError> {
    if freeze::is_freeze(bytes) {
        freeze::load(bytes)
    } else {
        let text =
            String::from_utf8(bytes.to_vec()).map_err(|e| FreezeError::Utf8(e.to_string()))?;
        freeze::loads(&text)
    }
}

/// port of `RuleSet.filter_rules_by_meta`: keep every rule whose *raw* meta
/// mapping has a string (or list-of-strings) field value containing `tag`
/// as a substring, plus each kept rule's full dependency closure
/// (`match:`/namespace references), computed pre subscope-extraction (the
/// synthetic subscope rules `MatchingRuleSet::new` derives have no
/// user-authored meta fields a tag could ever match, so filtering before
/// that expansion is equivalent for real corpora).
///
/// Runs *before* [`MatchingRuleSet::new`], so it is not part of [`analyze`]
/// (which only ever sees an already-built ruleset) -- a caller filters, then
/// builds the ruleset, then analyzes, exactly as `capa-x-cli` does.
pub fn filter_rules_by_tag(rules: Vec<Rule>, tag: &str) -> Vec<Rule> {
    let namespaces = crate::rules::index_rules_by_namespace(&rules);
    let by_name: HashMap<String, &Rule> = rules.iter().map(|r| (r.name.clone(), r)).collect();

    fn tag_in_value(value: &serde_yaml::Value, tag: &str) -> bool {
        match value {
            serde_yaml::Value::String(s) => s.contains(tag),
            serde_yaml::Value::Sequence(seq) => seq
                .iter()
                .any(|v| matches!(v, serde_yaml::Value::String(s) if s.contains(tag))),
            _ => false,
        }
    }

    fn collect_closure(
        by_name: &HashMap<String, &Rule>,
        namespaces: &HashMap<String, Vec<String>>,
        name: &str,
        out: &mut HashSet<String>,
    ) {
        if !out.insert(name.to_string()) {
            return;
        }
        let Some(rule) = by_name.get(name) else {
            return;
        };
        for dep in rule.dependencies(namespaces) {
            collect_closure(by_name, namespaces, &dep, out);
        }
    }

    let mut keep: HashSet<String> = HashSet::new();
    for rule in &rules {
        let matched = rule.meta.raw.values().any(|v| tag_in_value(v, tag));
        if matched {
            collect_closure(&by_name, &namespaces, &rule.name, &mut keep);
        }
    }

    rules
        .into_iter()
        .filter(|r| keep.contains(&r.name))
        .collect()
}

/// port of `collect_metadata` + `compute_layout`, dispatched over the
/// freeze-driven static/dynamic split.
fn build_result_document(
    input: &Input,
    ruleset: &MatchingRuleSet,
    parsed: &LoadedInput,
    resolved_format: &str,
    options: &AnalysisOptions,
    timings: &mut PhaseTimings,
) -> Result<rd::ResultDocument, AnalysisError> {
    let os_override = options.os.clone().unwrap_or_else(|| OS_AUTO.to_string());
    let arch_override = options
        .arch
        .clone()
        .unwrap_or_else(|| ARCH_AUTO.to_string());
    let timestamp = now_iso8601();

    match &parsed.freeze {
        Freeze::Static(sf) => {
            let capabilities = timed(&mut timings.matching, || {
                find_static_capabilities(ruleset, sf, options)
                    .map_err(|source| matching_failed(input, source))
            })?;
            let start = std::time::Instant::now();
            let layout = rd::compute_static_layout(ruleset, sf, &capabilities.matches);

            let inputs = MetaInputs {
                argv: input.argv.clone(),
                version: crate::version().to_string(),
                timestamp,
                sample: rd::Sample {
                    md5: sf.sample_hashes.md5.clone(),
                    sha1: sf.sample_hashes.sha1.clone(),
                    sha256: sf.sample_hashes.sha256.clone(),
                    path: input.sample_path.clone(),
                },
                input_format_fallback: resolved_format.to_string(),
                os_override,
                arch_override,
                rules_paths: input.rules_paths.clone(),
            };
            let counts = rd::StaticCounts {
                file_feature_count: capabilities.file_feature_count as u64,
                function_feature_counts: capabilities
                    .function_feature_counts
                    .iter()
                    .map(|(addr, count)| (*addr, *count as u64))
                    .collect(),
            };
            let meta = rd::build_static_metadata(
                inputs,
                sf,
                counts,
                parsed.library_functions.clone(),
                layout,
            );

            let doc = rd::build_result_document(ruleset, &capabilities.matches, meta)
                .map_err(AnalysisError::ResultDocument);
            timings.result += start.elapsed();
            doc
        }
        Freeze::Dynamic(df) => {
            let capabilities = timed(&mut timings.matching, || {
                find_dynamic_capabilities(ruleset, df)
                    .map_err(|source| matching_failed(input, source))
            })?;
            let start = std::time::Instant::now();
            let layout = rd::compute_dynamic_layout(df, &capabilities.matches);

            let inputs = MetaInputs {
                argv: input.argv.clone(),
                version: crate::version().to_string(),
                timestamp,
                sample: rd::Sample {
                    md5: df.sample_hashes.md5.clone(),
                    sha1: df.sample_hashes.sha1.clone(),
                    sha256: df.sample_hashes.sha256.clone(),
                    path: input.sample_path.clone(),
                },
                input_format_fallback: resolved_format.to_string(),
                os_override,
                arch_override,
                rules_paths: input.rules_paths.clone(),
            };
            let counts = rd::DynamicCounts {
                file_feature_count: capabilities.file_feature_count as u64,
                process_feature_counts: capabilities
                    .process_feature_counts
                    .iter()
                    .map(|(addr, count)| (*addr, *count as u64))
                    .collect(),
            };
            let meta = rd::build_dynamic_metadata(inputs, df, counts, layout);

            let doc = rd::build_result_document(ruleset, &capabilities.matches, meta)
                .map_err(AnalysisError::ResultDocument);
            timings.result += start.elapsed();
            doc
        }
    }
}

/// Names the sample alongside whatever the matcher said. The matcher's own
/// message already carries the failing function and the scope; the sample
/// path is the one piece only the caller knows, and without it a corpus run
/// reports a failure with no way to tell which of 200 files produced it.
fn matching_failed(input: &Input, reason: impl std::fmt::Display) -> AnalysisError {
    AnalysisError::Matching {
        sample: input.sample_path.clone(),
        reason: reason.to_string(),
    }
}

/// The full pipeline, with per-phase timings -- what `--timing` reports.
/// [`analyze`] is the simpler wrapper most callers want.
pub fn analyze_with_timings(
    input: &Input,
    rules: &MatchingRuleSet,
    options: &AnalysisOptions,
) -> Result<(rd::ResultDocument, PhaseTimings), AnalysisError> {
    let mut timings = PhaseTimings::default();
    let (parsed, resolved_format) = load_input(input.bytes, options, &mut timings)?;
    let doc = build_result_document(
        input,
        rules,
        &parsed,
        resolved_format,
        options,
        &mut timings,
    )?;
    Ok((doc, timings))
}

/// bytes plus a built [`MatchingRuleSet`] plus [`AnalysisOptions`] in, a
/// [`rd::ResultDocument`] out -- the whole PE/ELF/shellcode/freeze pipeline
/// in one call. See the module docs for what deliberately stays outside it.
pub fn analyze(
    input: &Input,
    rules: &MatchingRuleSet,
    options: &AnalysisOptions,
) -> Result<rd::ResultDocument, AnalysisError> {
    analyze_with_timings(input, rules, options).map(|(doc, _timings)| doc)
}

/// a dependency-free UTC ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SS.ffffff`),
/// matching `datetime.datetime`'s pydantic JSON encoding shape. Exact clock
/// value is immaterial: `scripts/difftest.py --mode json` normalizes
/// `meta.timestamp` away entirely, so this deliberately doesn't pull in a
/// calendar crate just to compute a value nothing ever compares.
fn now_iso8601() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let micros = now.subsec_micros();
    let days = secs.div_euclid(86400);
    let secs_of_day = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{micros:06}")
}

/// Howard Hinnant's `civil_from_days`: days-since-epoch -> (year, month, day).
/// http://howardhinnant.github.io/date_algorithms.html
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
