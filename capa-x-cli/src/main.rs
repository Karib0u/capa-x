#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;

use capa_x::api::{self, AnalysisError, PhaseTimings};
use capa_x::capabilities::{find_dynamic_capabilities, find_static_capabilities, MatchingRuleSet};
use capa_x::engine::MatchResults;
use capa_x::freeze::Freeze;
use capa_x::parallel::{AnalysisOptions, Jobs};
use capa_x::rd::{ARCH_AUTO, OS_AUTO};
use capa_x::render::{default, verbose, vverbose};
use capa_x::rules::{load_rule_directory, Rule};

/// capa: detect capabilities in executable files.
///
/// PE/ELF file and recovered code scopes with FLIRT library-function
/// exclusion, `-f sc32`/`sc64` shellcode (base address
/// [`capa_x::extract::image::SHELLCODE_BASE`], no FLIRT), `-f dotnet`
/// managed PE (CIL decode instead of code recovery, no FLIRT; mixed-mode
/// assemblies are analyzed for their managed methods only -- there is no
/// cross-runtime call graph into the native portion, matching upstream),
/// plus freeze-file input. Auto-detection routes a CLR PE to `dotnet` ahead
/// of `pe`; `-f pe` overrides that and forces the native x86 extractor.
/// `-f macho` (x86_64/arm64/arm64e thin or fat Mach-O, `--arch` selects a
/// fat slice) is a capa-x extension -- pinned capa has no raw Mach-O
/// input, so it is never part of `-f auto`'s detection cascade and must be
/// requested explicitly. `-f pe` accepts `IMAGE_FILE_MACHINE_ARM64`
/// alongside x86/x64.
#[derive(Parser)]
#[command(name = "capa-x", version = capa_x::VERSION_STRING)]
struct Cli {
    /// path to file to analyze (PE, ELF, or a capa freeze file)
    ///
    /// Optional only so `capa fetch-rules` can run without one; every
    /// analysis still requires it.
    input_file: Option<PathBuf>,

    /// download the pinned capa rules (an explicit action -- capa-x never
    /// fetches anything while analysing a sample)
    #[command(subcommand)]
    command: Option<Command>,

    /// path to rule file or directory [default: ./rules, else rules/ beside
    /// the executable]
    #[arg(short = 'r', long = "rules", env = "CAPA_RULES_DIR")]
    rules: Option<PathBuf>,

    /// path to a .sig/.pat file or directory used to identify library
    /// functions; embedded capa signatures are used by default
    #[arg(short = 's', long = "signatures")]
    signatures: Option<PathBuf>,

    /// select input format
    #[arg(short = 'f', long = "format", value_enum, default_value_t = Format::Auto)]
    format: Format,

    /// emit JSON instead of text
    #[arg(short = 'j', long = "json")]
    json: bool,

    /// enable verbose result document (no effect with --json). Repeating
    /// the short flag (`-vv`, via clap's short-flag clustering) selects
    /// vverbose, matching upstream's separate `-v`/`-vv` flags.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// enable very verbose result document (no effect with --json)
    #[arg(long = "vverbose")]
    vverbose: bool,

    /// filter on rule meta field values
    #[arg(short = 't', long = "tag")]
    tag: Option<String>,

    /// select sample OS: auto, linux, macos, windows
    #[arg(long = "os", default_value = OS_AUTO)]
    os: String,

    /// select sample architecture (capa-x addition; upstream has no
    /// `--arch` flag)
    #[arg(long = "arch", default_value = ARCH_AUTO)]
    arch: String,

    /// disable all output but errors
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// number of threads used for rule parsing and for per-function feature
    /// extraction and matching [default: logical cores, capped by the number
    /// of work items]. `1` is the single-threaded reference mode: every other
    /// value must produce byte-identical output (capa-x addition; upstream
    /// has no `--jobs`).
    #[arg(long = "jobs", value_name = "N", value_parser = parse_jobs)]
    jobs: Option<Jobs>,

    /// print per-phase timings (rule loading, extraction, matching, result
    /// construction, total) to stderr
    #[arg(long = "timing")]
    timing: bool,

    /// print "<rule name>@<address>" lines (one per matched location),
    /// sorted for deterministic diffing -- a difftest debug surface, kept
    /// alongside `-j`.
    #[arg(long = "dump-matches", hide = true)]
    dump_matches: bool,

    /// print "<scope>\t<feature>\t<address>" lines (one per extracted
    /// global/file feature), sorted for deterministic diffing -- a difftest
    /// debug surface, the raw-feature-set counterpart to `--dump-matches`.
    #[arg(long = "dump-features", hide = true)]
    dump_features: bool,

    /// Keep raw PE/ELF analysis on the file-scope extractors, skipping code
    /// recovery. Used only by the file-scope differential gate.
    #[arg(long = "file-only", hide = true)]
    file_only: bool,

    /// Emit recovered functions, basic blocks, seeds, and diagnostics as
    /// deterministic JSON for the code-layout differential gate.
    #[arg(long = "dump-code-layout", hide = true)]
    dump_code_layout: bool,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Clone the pinned capa-rules release into a directory (default:
    /// `./rules`), so `capa` can find it without `-r`.
    ///
    /// Release archives already ship the rules; this is for `cargo install`
    /// users and source checkouts without the submodule. It runs `git`, and
    /// only when you ask -- analysis never reaches the network.
    FetchRules {
        /// where to clone into
        #[arg(default_value = "rules")]
        directory: PathBuf,

        /// rules release to fetch [default: the pinned one this binary
        /// targets]
        #[arg(long = "ref")]
        reference: Option<String>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Format {
    Auto,
    Pe,
    Elf,
    Sc32,
    Sc64,
    Freeze,
    Dotnet,
    /// A capa-x extension -- never
    /// selected by `Auto`.
    Macho,
}

impl From<Format> for api::Format {
    fn from(f: Format) -> api::Format {
        match f {
            Format::Auto => api::Format::Auto,
            Format::Pe => api::Format::Pe,
            Format::Elf => api::Format::Elf,
            Format::Sc32 => api::Format::Sc32,
            Format::Sc64 => api::Format::Sc64,
            Format::Freeze => api::Format::Freeze,
            Format::Dotnet => api::Format::Dotnet,
            Format::Macho => api::Format::Macho,
        }
    }
}

// exit codes mirrored from capa/main.py's E_* constants. E_INVALID_SIG and
// E_INVALID_FILE_TYPE no longer appear here: both errors now originate
// inside `capa_x::api`, which carries its own copies
// (`AnalysisError::exit_code`) -- see `impl From<AnalysisError> for
// CliError` below.
const E_MISSING_FILE: u8 = 11;
const E_INVALID_RULE: u8 = 12;
const E_CORRUPT_FILE: u8 = 13;

struct CliError {
    code: u8,
    message: String,
}

impl CliError {
    fn new(code: u8, message: impl Into<String>) -> CliError {
        CliError {
            code,
            message: message.into(),
        }
    }
}

/// `capa_x::api::AnalysisError`'s message text and exit code already
/// reproduce what this binary produced for the same failure before the
/// analysis API was hoisted into the library -- see that type's doc comment.
impl From<AnalysisError> for CliError {
    fn from(e: AnalysisError) -> CliError {
        CliError::new(e.exit_code(), e.to_string())
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e.message);
            ExitCode::from(e.code)
        }
    }
}

impl Cli {
    /// The rule directory to load, resolving the default when neither
    /// `--rules` nor `CAPA_RULES_DIR` was given.
    ///
    /// `./rules` comes first: that is a source checkout with the capa-rules
    /// submodule initialised, and it is what every existing invocation means.
    /// The fallback is `rules/` beside the executable, which is how the release
    /// archive is laid out -- without it, an unpacked archive only works when
    /// the working directory happens to be the archive's own.
    fn rules_dir(&self) -> PathBuf {
        if let Some(explicit) = &self.rules {
            return explicit.clone();
        }
        let cwd_rules = PathBuf::from("rules");
        if cwd_rules.is_dir() {
            return cwd_rules;
        }
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("rules")))
            .filter(|beside_exe| beside_exe.is_dir())
            .unwrap_or(cwd_rules)
    }

    /// The analysis-shaped knobs `capa_x::api` reads. `os`/`arch` collapse
    /// their `"auto"` CLI sentinel to `None` here -- `api`'s `AnalysisOptions`
    /// uses `Option` so [`AnalysisOptions::SERIAL`] can stay a `const` (see
    /// its doc comment); presentation flags (`--json`, verbosity, `--timing`,
    /// the `--dump-*` debug flags) stay on `Cli` and never reach this struct.
    fn analysis_options(&self) -> AnalysisOptions {
        AnalysisOptions {
            jobs: self.jobs.unwrap_or_else(Jobs::available),
            format: self.format.into(),
            os: (self.os != OS_AUTO).then(|| self.os.clone()),
            arch: (self.arch != ARCH_AUTO).then(|| self.arch.clone()),
            file_only: self.file_only,
            signatures_path: self.signatures.clone(),
        }
    }
}

/// `--jobs`' value parser, so `--jobs 0` fails at argument-parsing time with
/// clap's own contextual message (flag name, offending value, and the reason)
/// rather than somewhere inside the analysis.
fn parse_jobs(raw: &str) -> Result<Jobs, String> {
    let count: usize = raw
        .parse()
        .map_err(|_| format!("`{raw}` is not a whole number of threads"))?;
    Jobs::new(count).map_err(|e| e.to_string())
}

/// Wall-clock time per analysis phase, printed by `--timing` and consumed by
/// `scripts/bench.py`. Separated because the phases scale differently:
/// rule loading is fixed per invocation, extraction and matching are the two
/// that `--jobs` can move, and only a split like this can show which one a
/// change actually affected.
///
/// `rules` and `total` are this binary's own bookkeeping (rule loading stays
/// a CLI-side step, ahead of `capa_x::api`, per that module's doc
/// comment); the other four fold in from an [`api::PhaseTimings`] returned by
/// [`api::load_input`]/[`api::analyze_with_timings`].
#[derive(Default)]
struct Timings {
    rules: Duration,
    load_and_recover: Duration,
    extraction: Duration,
    matching: Duration,
    result: Duration,
    total: Duration,
}

impl Timings {
    fn report(&self) {
        for (phase, elapsed) in [
            ("rules", self.rules),
            ("load+recovery", self.load_and_recover),
            ("extraction", self.extraction),
            ("matching", self.matching),
            ("result", self.result),
            ("total", self.total),
        ] {
            eprintln!("timing\t{phase}\t{:.6}", elapsed.as_secs_f64());
        }
    }

    fn fold_phases(&mut self, phases: &PhaseTimings) {
        self.load_and_recover += phases.load_and_recover;
        self.extraction += phases.extraction;
        self.matching += phases.matching;
        self.result += phases.result;
    }
}

fn timed<T>(slot: &mut Duration, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = f();
    *slot += start.elapsed();
    value
}

fn run(cli: &Cli) -> Result<(), CliError> {
    if let Some(Command::FetchRules {
        directory,
        reference,
    }) = &cli.command
    {
        return fetch_rules(directory, reference.as_deref());
    }

    let started = Instant::now();
    let mut timings = Timings::default();
    let result = run_analysis(cli, &mut timings);
    timings.total = started.elapsed();
    if cli.timing {
        timings.report();
    }
    result
}

/// `capa fetch-rules`: clone the pinned capa-rules release.
///
/// Shelling out to `git` rather than linking an HTTP or git client: this is a
/// one-shot convenience the user invoked by name, `git` is already installed
/// wherever a checkout came from, and a network stack inside the analysis
/// binary is exactly what "no auto-download at analysis time" is meant to
/// avoid having.
fn fetch_rules(directory: &std::path::Path, reference: Option<&str>) -> Result<(), CliError> {
    const RULES_REPO: &str = "https://github.com/mandiant/capa-rules.git";
    let reference = reference.unwrap_or(capa_x::RULES_PIN);

    if directory.exists() {
        return Err(CliError::new(
            E_MISSING_FILE,
            format!(
                "{} already exists; remove it or pass another directory",
                directory.display()
            ),
        ));
    }

    eprintln!(
        "cloning {RULES_REPO} at {reference} into {}",
        directory.display()
    );
    let status = std::process::Command::new("git")
        .args(["clone", "--depth", "1", "--branch", reference, RULES_REPO])
        .arg(directory)
        .status()
        .map_err(|e| {
            CliError::new(
                E_MISSING_FILE,
                format!(
                    "running git: {e}\ncapa fetch-rules needs git on PATH; alternatively \
                         download the rules from {RULES_REPO} yourself and point -r at them."
                ),
            )
        })?;
    if !status.success() {
        return Err(CliError::new(
            E_MISSING_FILE,
            format!("git clone failed ({status})"),
        ));
    }
    eprintln!(
        "rules ready: {} (capa {} targets capa-rules {})",
        directory.display(),
        capa_x::version(),
        capa_x::RULES_PIN
    );
    Ok(())
}

/// Canonicalizes a path for `meta.sample.path`/`meta.analysis.rules`,
/// falling back to the given path unchanged if canonicalization fails (a
/// relative path under a working directory that's since moved, say) --
/// matches the pre-hoist behavior exactly.
fn canonical_path_string(path: &std::path::Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn run_analysis(cli: &Cli, timings: &mut Timings) -> Result<(), CliError> {
    let options = cli.analysis_options();

    let Some(input_file) = cli.input_file.as_ref() else {
        return Err(CliError::new(
            E_MISSING_FILE,
            "no input file given\nUsage: capa [OPTIONS] <INPUT_FILE>, or `capa fetch-rules` to \
             download the pinned rules first.",
        ));
    };

    if !input_file.exists() {
        return Err(CliError::new(
            E_MISSING_FILE,
            format!("input file does not exist: {}", input_file.display()),
        ));
    }

    let bytes = std::fs::read(input_file).map_err(|e| {
        CliError::new(
            E_MISSING_FILE,
            format!("reading {}: {e}", input_file.display()),
        )
    })?;

    if cli.dump_code_layout {
        print_code_layout(&bytes)?;
        return Ok(());
    }

    let input = api::Input {
        bytes: &bytes,
        sample_path: canonical_path_string(input_file),
        rules_paths: vec![canonical_path_string(&cli.rules_dir())],
        argv: Some(std::env::args().skip(1).collect()),
    };

    if cli.dump_features {
        // `--dump-features` always wants the file-scope-only extraction,
        // regardless of `--file-only`'s own value -- mirrors the pre-hoist
        // `cli.file_only || cli.dump_features` dispatch in `load_input`.
        let dump_options = AnalysisOptions {
            file_only: true,
            ..options.clone()
        };
        let mut phases = PhaseTimings::default();
        let (parsed, _resolved_format) =
            api::load_input(input.bytes, &dump_options, &mut phases).map_err(CliError::from)?;
        timings.fold_phases(&phases);
        print_dump_features(&parsed.freeze);
        return Ok(());
    }

    let rules_dir = cli.rules_dir();
    let ruleset = timed(&mut timings.rules, || {
        let mut rules: Vec<Rule> = load_rule_directory(&rules_dir, &options).map_err(|e| {
            CliError::new(
                E_INVALID_RULE,
                format!(
                    "loading rules from {}: {e}\nPoint --rules (or CAPA_RULES_DIR) at a directory \
                     of capa rules; see https://github.com/mandiant/capa-rules.",
                    rules_dir.display()
                ),
            )
        })?;

        if let Some(tag) = &cli.tag {
            rules = api::filter_rules_by_tag(rules, tag);
        }

        MatchingRuleSet::new(rules).map_err(|e| {
            CliError::new(
                E_INVALID_RULE,
                format!("building the matching rule set: {e}"),
            )
        })
    })?;

    if cli.dump_matches {
        let mut phases = PhaseTimings::default();
        let (parsed, _resolved_format) =
            api::load_input(input.bytes, &options, &mut phases).map_err(CliError::from)?;
        timings.fold_phases(&phases);
        let matches = timed(&mut timings.matching, || match &parsed.freeze {
            Freeze::Static(sf) => find_static_capabilities(&ruleset, sf, &options)
                .map(|c| c.matches)
                .map_err(|e| matching_failed(cli, e)),
            Freeze::Dynamic(df) => find_dynamic_capabilities(&ruleset, df)
                .map(|c| c.matches)
                .map_err(|e| matching_failed(cli, e)),
        })?;
        print_dump_matches(&ruleset, &matches);
        return Ok(());
    }

    let (doc, phases) =
        api::analyze_with_timings(&input, &ruleset, &options).map_err(CliError::from)?;
    timings.fold_phases(&phases);

    let vverbose_level = cli.vverbose || cli.verbose >= 2;
    let verbose_level = cli.verbose >= 1;

    let output = if cli.json {
        serde_json::to_string(&doc).map_err(|e| {
            CliError::new(E_CORRUPT_FILE, format!("serializing result document: {e}"))
        })?
    } else if vverbose_level {
        vverbose::render(&doc)
    } else if verbose_level {
        verbose::render(&doc)
    } else {
        default::render(&doc)
    };

    println!("{output}");
    Ok(())
}

/// Names the sample alongside whatever the matcher said, for the
/// `--dump-matches` debug surface -- the one remaining direct
/// `find_static_capabilities`/`find_dynamic_capabilities` call site left in
/// this binary (the normal path's matching happens inside
/// `capa_x::api::analyze_with_timings`, which has its own copy of this
/// for the same reason: `find_dynamic_capabilities` and
/// `find_static_capabilities` return unrelated error types).
fn matching_failed(cli: &Cli, error: impl std::fmt::Display) -> CliError {
    let sample = cli
        .input_file
        .as_deref()
        .unwrap_or_else(|| std::path::Path::new("<no input file>"));
    CliError::new(
        E_CORRUPT_FILE,
        format!("matching {}: {error}", sample.display()),
    )
}

/// prints one deterministically sorted `"<rule name>@<address>"` line per
/// (rule, matched location) pair -- see `scripts/difftest.py` for the
/// counterpart that extracts the same shape from `capa -j`.
fn print_dump_matches(ruleset: &MatchingRuleSet, matches: &MatchResults) {
    let mut lines: Vec<(String, String)> = Vec::new();
    for (rule_name, results) in matches {
        if ruleset.get(rule_name).is_some_and(|r| r.is_subscope_rule()) {
            continue;
        }
        let mut addrs: Vec<capa_x::address::Address> =
            results.iter().map(|(addr, _)| *addr).collect();
        addrs.sort();
        addrs.dedup();
        for addr in addrs {
            lines.push((rule_name.clone(), addr.canonical_key()));
        }
    }
    lines.sort();
    for (rule_name, addr) in lines {
        println!("{rule_name}@{addr}");
    }
}

/// prints one deterministically sorted `"<scope>\t<feature>\t<address>"`
/// line per extracted global/file feature -- see `scripts/difftest.py`'s
/// `--mode file-features` for the counterpart that extracts the same shape
/// from a Python-side dump script. Global features have no address (mirrors
/// the freeze wire format's `GlobalFeature`, which carries no address
/// field), so their line omits the trailing column entirely.
fn print_dump_features(parsed: &Freeze) {
    let Freeze::Static(sf) = parsed else {
        // dynamic (CAPE/etc.) inputs have no file-only-extractor
        // counterpart to diff against; this surface only concerns itself
        // with static PE/ELF extraction.
        return;
    };

    let mut lines: Vec<String> = Vec::new();
    for f in &sf.global_features {
        lines.push(format!("global\t{f}"));
    }
    for (addr, f) in &sf.file_features {
        lines.push(format!("file\t{f}\t{}", addr.canonical_key()));
    }
    for (function_addr, function) in &sf.functions {
        for (addr, feature) in &function.features {
            lines.push(format!(
                "function\t{}\t{feature}\t{}",
                function_addr.canonical_key(),
                addr.canonical_key()
            ));
        }
        for (block_addr, block) in &function.basic_blocks {
            for (addr, feature) in &block.features {
                lines.push(format!(
                    "basic block\t{}\t{}\t{feature}\t{}",
                    function_addr.canonical_key(),
                    block_addr.canonical_key(),
                    addr.canonical_key()
                ));
            }
            for (instruction_addr, instruction) in &block.instructions {
                for (addr, feature) in &instruction.features {
                    lines.push(format!(
                        "instruction\t{}\t{}\t{}\t{feature}\t{}",
                        function_addr.canonical_key(),
                        block_addr.canonical_key(),
                        instruction_addr.canonical_key(),
                        addr.canonical_key()
                    ));
                }
            }
        }
    }
    lines.sort();
    for line in lines {
        println!("{line}");
    }
}

fn print_code_layout(bytes: &[u8]) -> Result<(), CliError> {
    let analysis = capa_x::extract::recovery::analyze(bytes).map_err(|error| {
        CliError::new(E_CORRUPT_FILE, format!("recovering code layout: {error}"))
    })?;
    let functions: Vec<_> = analysis
        .functions
        .values()
        .map(|function| {
            serde_json::json!({
                "address": function.addr,
                "instruction_count": function.blocks.iter().map(|block| block.insns.len()).sum::<usize>(),
                "basic_blocks": function.blocks.iter().map(|block| block.addr).collect::<Vec<_>>(),
                // Per-instruction addresses (not just the count) so the layout
                // oracle can compare instruction *ownership* per function, not a
                // global flattened set.
                "instructions": function.blocks.iter().flat_map(|block| block.insns.iter().map(|insn| insn.address)).collect::<Vec<_>>(),
                "calls": analysis.callees.get(&function.addr).map(|targets| targets.iter().copied().collect::<Vec<_>>()).unwrap_or_default(),
                "edges": function.blocks.iter().flat_map(|block| block.succs.iter().map(move |edge| serde_json::json!({
                    "source": block.addr,
                    "target": edge.target,
                    "kind": format!("{:?}", edge.kind),
                }))).collect::<Vec<_>>(),
                // Mirrors `scripts/triage/dump_code_layout.py`'s `workspace.isNoReturnVa(fva)`
                // so `compare_code_layout.py` can diff the no-return sets directly.
                "noreturn": analysis.is_noreturn_va(function.addr),
            })
        })
        .collect();
    let seeds: Vec<_> = analysis
        .seeds
        .iter()
        .map(|(address, kinds)| {
            serde_json::json!({
                "address": address,
                "kinds": kinds.iter().map(|kind| format!("{kind:?}")).collect::<Vec<_>>(),
            })
        })
        .collect();
    let diagnostics: Vec<_> = analysis
        .diagnostics
        .iter()
        .map(|diagnostic| {
            serde_json::json!({
                "address": diagnostic.address,
                "message": diagnostic.message,
            })
        })
        .collect();
    let output = serde_json::json!({
        "functions": functions,
        "seeds": seeds,
        "diagnostics": diagnostics,
    });
    println!(
        "{}",
        serde_json::to_string(&output).map_err(|error| {
            CliError::new(E_CORRUPT_FILE, format!("serializing code layout: {error}"))
        })?
    );
    Ok(())
}
