//! FLIRT signature loading and library-function recognition.
//!
//! The matching behavior follows the pinned `viv_utils/flirt.py`: signature
//! files are applied in deterministic order, recursive reference names are
//! validated, conflicting root names are rejected, and the first signature
//! database that recognizes a function wins.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use lancelot_flirt::{FlirtSignature, Name, SigElement, Symbol};

use crate::address::Address;
use crate::features::Feature;
use crate::freeze::{BasicBlockFeatures, FunctionFeatures, InstructionFeatures, StaticFeatures};
use crate::parallel::{self, AnalysisOptions};

use super::aarch64_basicblock_features;
use super::aarch64_features;
use super::basicblock_features;
use super::engine::{Analysis, EdgeKind, Function};
use super::function_features;
use super::image::{Architecture, ImageFormat};
use super::insn_features::{self, InsnContext};

const MATCH_WINDOW: usize = 0x1_0000;

const DEFAULT_SIGNATURES: [(&str, &[u8]); 3] = [
    (
        "1_flare_msvc_rtf_32_64.sig",
        include_bytes!("../../../sigs/1_flare_msvc_rtf_32_64.sig"),
    ),
    (
        "2_flare_msvc_atlmfc_32_64.sig",
        include_bytes!("../../../sigs/2_flare_msvc_atlmfc_32_64.sig"),
    ),
    (
        "3_flare_common_libs.sig",
        include_bytes!("../../../sigs/3_flare_common_libs.sig"),
    ),
];

#[derive(Debug, thiserror::Error)]
pub enum FlirtError {
    #[error("signature path {path} does not exist")]
    MissingPath { path: PathBuf },
    #[error("reading signature path {path}: {context}")]
    Io { path: PathBuf, context: String },
    #[error("unsupported signature file extension: {path}")]
    UnsupportedExtension { path: PathBuf },
    #[error("parsing signature file {path}: {context}")]
    Parse { path: PathBuf, context: String },
    #[error("compiling signature file {path}: matcher panicked")]
    CompilePanic { path: PathBuf },
    #[error("matching signature file {path} at {address:#x}: matcher panicked")]
    MatchPanic { path: PathBuf, address: u64 },
    #[error("matching signature file {path} at {address:#x}: matched signature has no root name")]
    MissingRootName { path: PathBuf, address: u64 },
}

struct SignatureDatabase {
    path: PathBuf,
    matcher: SignatureMatcher,
}

/// Compact lossless index over lancelot's parsed signatures.
///
/// `lancelot_flirt::FlirtSignatureSet` builds a one-pattern-per-leaf decision
/// tree. Wildcard patterns are copied into every applicable branch, which
/// makes the pinned 14 MiB signature corpus take hundreds of MiB and seconds
/// to initialize. The first eight head bytes are enough to form a selective
/// index without changing any matching rule: candidates still pass through
/// lancelot's head, CRC, tail-byte, and footer checks below.
struct SignatureMatcher {
    signatures: Vec<FlirtSignature>,
    prefix_shapes: Vec<(u8, u8)>,
    prefixes: HashMap<(u8, u8, u64), Vec<usize>>,
}

impl SignatureMatcher {
    const PREFIX_LEN: usize = 8;

    fn with_signatures(signatures: Vec<FlirtSignature>) -> Self {
        let mut shapes = BTreeSet::new();
        let mut prefixes: HashMap<(u8, u8, u64), Vec<usize>> = HashMap::new();
        for (index, signature) in signatures.iter().enumerate() {
            let (length, mask, value) = signature_prefix(signature);
            shapes.insert((length, mask));
            prefixes
                .entry((length, mask, value))
                .or_default()
                .push(index);
        }
        Self {
            signatures,
            prefix_shapes: shapes.into_iter().collect(),
            prefixes,
        }
    }

    fn r#match(&self, bytes: &[u8]) -> Vec<&FlirtSignature> {
        let mut candidates = Vec::new();
        for &(length, mask) in &self.prefix_shapes {
            let length = usize::from(length);
            if bytes.len() < length {
                continue;
            }
            let value = masked_prefix_value(&bytes[..length], mask);
            if let Some(indices) = self.prefixes.get(&(length as u8, mask, value)) {
                candidates.extend(indices.iter().copied());
            }
        }
        candidates.sort_unstable();
        candidates.dedup();
        candidates
            .into_iter()
            .filter_map(|index| self.signatures.get(index))
            .filter(|signature| signature_head_matches(signature, bytes))
            .filter(|signature| signature.match_crc16(bytes))
            .filter(|signature| signature.match_tail_bytes(bytes))
            .filter(|signature| signature.match_footer(bytes))
            .collect()
    }
}

fn signature_prefix(signature: &FlirtSignature) -> (u8, u8, u64) {
    let head_len = effective_head_len(signature).min(SignatureMatcher::PREFIX_LEN);
    let mut mask = 0u8;
    let mut value = 0u64;
    for (index, element) in signature.byte_sig.0.iter().take(head_len).enumerate() {
        if let SigElement::Byte(byte) = element {
            mask |= 1 << index;
            value |= u64::from(*byte) << (index * 8);
        }
    }
    (head_len as u8, mask, value)
}

fn masked_prefix_value(bytes: &[u8], mask: u8) -> u64 {
    bytes
        .iter()
        .enumerate()
        .filter(|(index, _)| mask & (1 << index) != 0)
        .fold(0u64, |value, (index, byte)| {
            value | (u64::from(*byte) << (index * 8))
        })
}

fn effective_head_len(signature: &FlirtSignature) -> usize {
    // `FlirtSignatureSet::with_signatures` indexes the complete byte pattern;
    // its separate single-signature regex helper truncates short functions,
    // but that helper is not used by capa-x's set-matching path.
    signature.byte_sig.0.len()
}

fn signature_head_matches(signature: &FlirtSignature, bytes: &[u8]) -> bool {
    let head_len = effective_head_len(signature);
    if bytes.len() < head_len {
        return false;
    }
    signature
        .byte_sig
        .0
        .iter()
        .take(head_len)
        .zip(bytes)
        .all(|(element, byte)| match element {
            SigElement::Byte(expected) => expected == byte,
            SigElement::Wildcard => true,
        })
}

/// Ordered FLIRT databases. Keeping databases separate preserves upstream's
/// first-file-wins behavior instead of creating false ambiguity across files.
pub struct Signatures {
    databases: Vec<SignatureDatabase>,
}

impl Signatures {
    pub fn embedded() -> Result<Self, FlirtError> {
        Self::embedded_with_options(&AnalysisOptions::SERIAL)
    }

    pub fn embedded_with_options(options: &AnalysisOptions) -> Result<Self, FlirtError> {
        let databases = parallel::try_map(options.jobs, &DEFAULT_SIGNATURES, |(name, bytes)| {
            let path = PathBuf::from(format!("(embedded signatures)/{name}"));
            parse_database(path, bytes)
        })?;
        Ok(Self { databases })
    }

    /// Loads one `.sig`, `.pat`, or `.pat.gz` file, or every such file under
    /// a directory. Directory entries are sorted by filename like
    /// `capa.loader.get_signatures`, with full path as a deterministic tie
    /// breaker for equally named files in separate subdirectories.
    pub fn from_path(path: &Path) -> Result<Self, FlirtError> {
        Self::from_path_with_options(path, &AnalysisOptions::SERIAL)
    }

    pub fn from_path_with_options(
        path: &Path,
        options: &AnalysisOptions,
    ) -> Result<Self, FlirtError> {
        if !path.exists() {
            return Err(FlirtError::MissingPath {
                path: path.to_path_buf(),
            });
        }
        let mut paths = Vec::new();
        if path.is_file() {
            if !is_supported_signature(path) {
                return Err(FlirtError::UnsupportedExtension {
                    path: path.to_path_buf(),
                });
            }
            paths.push(path.to_path_buf());
        } else {
            collect_signature_paths(path, &mut paths)?;
        }
        paths.sort_by(|left, right| {
            left.file_name()
                .cmp(&right.file_name())
                .then_with(|| left.cmp(right))
        });

        let databases = parallel::try_map(options.jobs, &paths, |path| {
            let bytes = read_signature_file(path)?;
            parse_database(path.clone(), &bytes)
        })?;
        Ok(Self { databases })
    }

    /// Loads an explicit, ordered list of `.sig`/`.pat`/`.pat.gz` files,
    /// preserving first-database-wins order across the list (unlike
    /// [`Signatures::from_path`] on a directory, which re-sorts by
    /// filename). Needed so difftest/parity harnesses can reproduce the
    /// pinned Python test suite's `sigpaths` lists exactly, where the
    /// test-only `.pat` signatures are listed before the default `.sig`
    /// files.
    pub fn from_paths(paths: &[PathBuf]) -> Result<Self, FlirtError> {
        let mut databases = Vec::with_capacity(paths.len());
        for path in paths {
            if !path.exists() {
                return Err(FlirtError::MissingPath { path: path.clone() });
            }
            if !is_supported_signature(path) {
                return Err(FlirtError::UnsupportedExtension { path: path.clone() });
            }
            let bytes = read_signature_file(path)?;
            databases.push(parse_database(path.clone(), &bytes)?);
        }
        Ok(Self { databases })
    }

    pub fn is_empty(&self) -> bool {
        self.databases.is_empty()
    }
}

fn collect_signature_paths(directory: &Path, out: &mut Vec<PathBuf>) -> Result<(), FlirtError> {
    let entries = fs::read_dir(directory).map_err(|error| FlirtError::Io {
        path: directory.to_path_buf(),
        context: error.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| FlirtError::Io {
            path: directory.to_path_buf(),
            context: error.to_string(),
        })?;
        let file_type = entry.file_type().map_err(|error| FlirtError::Io {
            path: entry.path(),
            context: error.to_string(),
        })?;
        if file_type.is_dir() {
            collect_signature_paths(&entry.path(), out)?;
        } else if file_type.is_file() && is_supported_signature(&entry.path()) {
            out.push(entry.path());
        }
    }
    Ok(())
}

fn is_supported_signature(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".sig") || name.ends_with(".pat") || name.ends_with(".pat.gz")
}

fn read_signature_file(path: &Path) -> Result<Vec<u8>, FlirtError> {
    let bytes = fs::read(path).map_err(|error| FlirtError::Io {
        path: path.to_path_buf(),
        context: error.to_string(),
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !name.ends_with(".pat.gz") {
        return Ok(bytes);
    }
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(bytes.as_slice())
        .read_to_end(&mut decoded)
        .map_err(|error| FlirtError::Parse {
            path: path.to_path_buf(),
            context: format!("decompressing gzip data: {error}"),
        })?;
    Ok(decoded)
}

fn parse_database(path: PathBuf, bytes: &[u8]) -> Result<SignatureDatabase, FlirtError> {
    let lower_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if lower_name.ends_with(".sig") {
            lancelot_flirt::sig::parse(bytes).map_err(|error| error.to_string())
        } else {
            let text =
                std::str::from_utf8(bytes).map_err(|error| format!("PAT is not UTF-8: {error}"))?;
            lancelot_flirt::pat::parse(&text.replace("\r\n", "\n"))
                .map_err(|error| error.to_string())
        }
    }))
    .map_err(|_| FlirtError::Parse {
        path: path.clone(),
        context: "parser panicked".to_string(),
    })?
    .map_err(|error| FlirtError::Parse {
        path: path.clone(),
        context: error.to_string(),
    })?;

    let matcher = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        SignatureMatcher::with_signatures(parsed)
    }))
    .map_err(|_| FlirtError::CompilePanic { path: path.clone() })?;
    Ok(SignatureDatabase { path, matcher })
}

/// port of `viv_utils/flirt.py:get_match_name`: the function's root name is
/// *any* name at offset 0, regardless of symbol kind (public/local/
/// reference) -- unlike `lancelot_flirt::FlirtSignature::get_name()`, which
/// only recognizes a `Public` name at offset 0 and so misses signatures
/// whose offset-0 entry happens to be `Local`, wrongly rejecting them as
/// rootless.
fn root_name(candidate: &FlirtSignature) -> Option<&str> {
    for symbol in &candidate.names {
        let name = match symbol {
            Symbol::Public(name) | Symbol::Local(name) | Symbol::Reference(name) => name,
        };
        if name.offset == 0 {
            return Some(&name.name);
        }
    }
    None
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CacheEntry {
    Visiting,
    Complete(Option<String>),
}

struct MatcherState<'a> {
    analysis: &'a Analysis,
    database: &'a SignatureDatabase,
    code_xrefs_from: &'a BTreeMap<u64, Vec<u64>>,
    data_xrefs_from: &'a BTreeMap<u64, Vec<u64>>,
    recognized: &'a mut BTreeMap<u64, String>,
    cache: BTreeMap<u64, CacheEntry>,
}

fn index_xrefs_by_source(index: &BTreeMap<u64, Vec<u64>>) -> BTreeMap<u64, Vec<u64>> {
    let mut by_source = BTreeMap::<u64, Vec<u64>>::new();
    for (target, sources) in index {
        for source in sources {
            by_source.entry(*source).or_default().push(*target);
        }
    }
    by_source
}

/// Identifies library functions in a recovered PE image. The pinned capa CLI
/// only enables FLIRT for PE input, so ELF analysis deliberately returns no
/// matches even when signatures were explicitly supplied.
pub fn identify_library_functions(
    analysis: &Analysis,
    signatures: &Signatures,
) -> Result<BTreeMap<u64, String>, FlirtError> {
    if analysis.image.format != ImageFormat::Pe || signatures.is_empty() {
        return Ok(BTreeMap::new());
    }

    let mut recognized = BTreeMap::new();
    let code_xrefs_from = index_xrefs_by_source(&analysis.code_xrefs);
    let data_xrefs_from = index_xrefs_by_source(&analysis.data_xrefs);
    for database in &signatures.databases {
        let mut state = MatcherState {
            analysis,
            database,
            code_xrefs_from: &code_xrefs_from,
            data_xrefs_from: &data_xrefs_from,
            recognized: &mut recognized,
            cache: BTreeMap::new(),
        };
        for address in analysis.functions.keys().copied() {
            if state.recognized.contains_key(&address) {
                continue;
            }
            let _ = state.match_function(address)?;
        }
    }
    Ok(recognized)
}

/// Adds the recovered code hierarchy while omitting recognized library
/// functions, and emits upstream-compatible file-scope function names for
/// every recognized address. The leading-underscore alias mirrors
/// `viv/file.py:extract_file_function_names`.
///
/// Each scope's `.features` is populated by the
/// corresponding ported extractor
/// ([`super::insn_features`]/[`super::basicblock_features`]/
/// [`super::function_features`]), not left empty.
///
/// The per-function body is the crate's first parallel seam
/// (`options.jobs`): every recovered function reads the same immutable
/// [`Analysis`] and writes only its own owned [`FunctionFeatures`], and the
/// results are collected in input -- that is, address -- order before being
/// inserted, so the produced [`StaticFeatures`] does not depend on how many
/// threads ran. See [`crate::parallel`].
pub fn enrich_static_features(
    features: &mut StaticFeatures,
    analysis: &Analysis,
    libraries: &BTreeMap<u64, String>,
    options: &AnalysisOptions,
) {
    for (address, name) in libraries {
        features.file_features.push((
            Address::Absolute(*address),
            Feature::FunctionName(name.clone()),
        ));
        if let Some(unmangled) = name.strip_prefix('_') {
            features.file_features.push((
                Address::Absolute(*address),
                Feature::FunctionName(unmangled.to_string()),
            ));
        }
    }

    // `insn_features`/`basicblock_features` are direct ports of x86-specific
    // upstream Python (see `decoder.rs`'s module doc) and reach
    // `DecodedInstruction::x86_instruction`, which panics by design for
    // AArch64; `aarch64_features`/`aarch64_basicblock_features`
    // task 4) are their AArch64 counterparts, ported from the
    // BinExport2/Ghidra ARM backend instead. `function_features` needs
    // neither -- it never reaches a `DecodedInstruction` at all (see its own
    // module doc) -- so it runs unchanged for both. Any other architecture
    // (there is none yet) would still contribute no function/basic-block/
    // instruction features.
    if !matches!(
        analysis.image.architecture,
        Architecture::X86 | Architecture::X64 | Architecture::AArch64
    ) {
        return;
    }

    let targets: Vec<(&u64, &Function)> = analysis
        .functions
        .iter()
        .filter(|(address, _)| !libraries.contains_key(address))
        .collect();
    let extracted = parallel::map(options.jobs, &targets, |(address, recovered_function)| {
        (
            Address::Absolute(**address),
            extract_function_features(analysis, libraries, recovered_function),
        )
    });
    features.functions.extend(extracted);
}

/// The body of [`enrich_static_features`]' per-function loop, lifted out so it
/// can run on a worker thread. Takes only shared references, returns an owned
/// result, touches no shared state.
fn extract_function_features(
    analysis: &Analysis,
    libraries: &BTreeMap<u64, String>,
    recovered_function: &Function,
) -> FunctionFeatures {
    let function = function_with_tail_blocks(analysis, recovered_function);
    let mut function_features = FunctionFeatures {
        features: function_features::extract_features(analysis, &function),
        basic_blocks: BTreeMap::new(),
    };
    let is_aarch64 = analysis.image.architecture == Architecture::AArch64;
    for block in &function.blocks {
        let mut basic_block = BasicBlockFeatures {
            features: if is_aarch64 {
                aarch64_basicblock_features::extract_features(block)
            } else {
                basicblock_features::extract_features(block)
            },
            instructions: BTreeMap::new(),
        };
        if is_aarch64 {
            for (address, features) in
                aarch64_features::extract_block_insn_features(analysis, &function, block)
            {
                basic_block
                    .instructions
                    .insert(address, InstructionFeatures { features });
            }
        } else {
            let ctx = InsnContext {
                analysis,
                libraries,
                function: &function,
                block,
            };
            for instruction in &block.insns {
                basic_block.instructions.insert(
                    Address::Absolute(instruction.address),
                    InstructionFeatures {
                        features: insn_features::extract_features(&ctx, instruction),
                    },
                );
            }
        }
        function_features
            .basic_blocks
            .insert(Address::Absolute(block.addr), basic_block);
    }
    function_features
}

/// Compose blocks behind recovery's shared tail-call boundaries. This keeps
/// large connected regions available to the root scope without decoding the
/// same bytes repeatedly.
fn function_with_tail_blocks(analysis: &Analysis, root: &Function) -> Function {
    let mut function = root.clone();
    let mut seen_blocks: BTreeSet<u64> = function.blocks.iter().map(|block| block.addr).collect();
    let mut seen_functions = BTreeSet::from([root.addr]);
    let mut pending = Vec::new();
    for block in &root.blocks {
        for edge in &block.succs {
            if edge.kind == EdgeKind::TailCall {
                pending.push(edge.target);
            }
        }
    }
    while let Some(address) = pending.pop() {
        if !seen_functions.insert(address) {
            continue;
        }
        let Some(target) = analysis.functions.get(&address) else {
            continue;
        };
        for block in &target.blocks {
            if seen_blocks.insert(block.addr) {
                for edge in &block.succs {
                    if edge.kind == EdgeKind::TailCall {
                        pending.push(edge.target);
                    }
                }
                function.blocks.push(block.clone());
            }
        }
    }
    function.blocks.sort_by_key(|block| block.addr);
    function
}

impl MatcherState<'_> {
    fn match_function(&mut self, address: u64) -> Result<Option<String>, FlirtError> {
        if let Some(name) = self.recognized.get(&address) {
            return Ok(Some(name.clone()));
        }
        if !self.analysis.functions.contains_key(&address) {
            return Ok(None);
        }
        if let Some(entry) = self.cache.get(&address) {
            return Ok(match entry {
                CacheEntry::Visiting => None,
                CacheEntry::Complete(name) => name.clone(),
            });
        }
        self.cache.insert(address, CacheEntry::Visiting);

        let function_size = self
            .analysis
            .functions
            .get(&address)
            .and_then(|function| {
                function
                    .blocks
                    .iter()
                    .flat_map(|block| block.insns.iter())
                    .filter_map(|instruction| instruction.next_address.checked_sub(address))
                    .max()
            })
            .and_then(|size| usize::try_from(size).ok())
            .unwrap_or(0);
        let Some(bytes) = self
            .analysis
            .image
            .bytes_at(address, MATCH_WINDOW.max(function_size))
        else {
            self.cache.insert(address, CacheEntry::Complete(None));
            return Ok(None);
        };
        let candidates: Vec<FlirtSignature> =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let candidates: Vec<FlirtSignature> = self
                    .database
                    .matcher
                    .r#match(bytes)
                    .into_iter()
                    .cloned()
                    .collect();
                if candidates.len() < 2 {
                    return candidates;
                }

                // Candidate order is observable when signatures share a root
                // name but carry different local/public names. Reconstruct
                // lancelot's original ordering over only the fully matched
                // candidates, avoiding its corpus-wide wildcard tree while
                // retaining that tie-break.
                let ordering = lancelot_flirt::FlirtSignatureSet::with_signatures(candidates);
                ordering.r#match(bytes).into_iter().cloned().collect()
            }))
            .map_err(|_| FlirtError::MatchPanic {
                path: self.database.path.clone(),
                address,
            })?;

        let mut valid = Vec::new();
        for candidate in candidates {
            if self.references_match(address, &candidate)? {
                valid.push(candidate);
            }
        }
        let mut names = BTreeSet::new();
        for candidate in &valid {
            let Some(name) = root_name(candidate) else {
                return Err(FlirtError::MissingRootName {
                    path: self.database.path.clone(),
                    address,
                });
            };
            names.insert(name.to_string());
        }
        let name = if names.len() == 1 {
            names.into_iter().next()
        } else {
            None
        };

        if let Some(name) = &name {
            if let Some(candidate) = valid
                .iter()
                .find(|candidate| root_name(candidate) == Some(name.as_str()))
            {
                self.apply_names(address, candidate);
            }
        }
        let result = self.recognized.get(&address).cloned().or(name);
        self.cache
            .insert(address, CacheEntry::Complete(result.clone()));
        Ok(result)
    }

    fn references_match(
        &mut self,
        function_address: u64,
        signature: &FlirtSignature,
    ) -> Result<bool, FlirtError> {
        for symbol in &signature.names {
            let Symbol::Reference(reference) = symbol else {
                continue;
            };
            let Ok(offset) = u64::try_from(reference.offset) else {
                return Ok(false);
            };
            let Some(reference_address) = function_address.checked_add(offset) else {
                return Ok(false);
            };
            let Some(instruction_address) = self.containing_instruction(reference_address) else {
                return Ok(false);
            };

            if reference.name == "." {
                if self.data_xrefs_from.contains_key(&instruction_address) {
                    continue;
                }
                return Ok(false);
            }

            let targets = self
                .code_xrefs_from
                .get(&instruction_address)
                .cloned()
                .unwrap_or_default();
            let mut matched = false;
            for target in targets {
                if self.match_function(target)?.as_deref() == Some(reference.name.as_str()) {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn containing_instruction(&self, address: u64) -> Option<u64> {
        let (&start, instruction) = self.analysis.instructions.range(..=address).next_back()?;
        let end = start.checked_add(u64::try_from(instruction.bytes.len()).ok()?)?;
        (address < end).then_some(start)
    }

    fn apply_names(&mut self, base: u64, signature: &FlirtSignature) {
        for public in [false, true] {
            for symbol in &signature.names {
                let name = match (public, symbol) {
                    (false, Symbol::Local(name)) | (true, Symbol::Public(name)) => name,
                    _ => continue,
                };
                self.apply_name(base, name);
            }
        }
    }

    fn apply_name(&mut self, base: u64, name: &Name) {
        let address = if name.offset >= 0 {
            u64::try_from(name.offset)
                .ok()
                .and_then(|offset| base.checked_add(offset))
        } else {
            name.offset
                .checked_neg()
                .and_then(|offset| u64::try_from(offset).ok())
                .and_then(|offset| base.checked_sub(offset))
        };
        if let Some(address) =
            address.filter(|address| self.analysis.functions.contains_key(address))
        {
            self.recognized.insert(address, name.name.clone());
            self.cache
                .insert(address, CacheEntry::Complete(Some(name.name.clone())));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::extract::pe::extract_pe;
    use crate::extract::recovery::analyze;

    #[test]
    fn parses_pat_and_matches_a_tiny_signature() {
        let path = PathBuf::from("tiny.pat");
        let pat = format!("558BEC{} 00 0000 0020 :0000 tiny\n---", ".".repeat(58));
        let database = parse_database(path, pat.as_bytes()).expect("tiny PAT parses");
        let mut bytes = vec![0u8; 32];
        bytes[..3].copy_from_slice(&[0x55, 0x8b, 0xec]);
        let matches = database.matcher.r#match(&bytes);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].get_name(), Some("tiny"));
    }

    #[test]
    fn unsupported_single_file_is_an_error() {
        let path = std::env::temp_dir().join(format!(
            "capa-x-flirt-{}-unsupported.txt",
            std::process::id()
        ));
        fs::write(&path, b"not a signature").expect("temporary file is writable");
        let result = Signatures::from_path(&path);
        let _ = fs::remove_file(&path);
        assert!(matches!(
            result,
            Err(FlirtError::UnsupportedExtension { .. })
        ));
    }

    #[test]
    fn recognized_function_is_named_and_removed_from_code_scopes() {
        use std::fmt::Write as _;

        let sample = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("tests/testfiles/Practical Malware Analysis Lab 01-01.exe_");
        let bytes = fs::read(sample).expect("pinned PE sample exists");
        let analysis = analyze(&bytes).expect("sample recovery succeeds");
        let (&address, _) = analysis
            .functions
            .iter()
            .find(|(address, _)| {
                analysis
                    .image
                    .bytes_at(**address, 32)
                    .is_some_and(|b| b.len() == 32)
            })
            .expect("sample has a 32-byte file-backed function");
        let function_bytes = analysis
            .image
            .bytes_at(address, 32)
            .expect("selected function bytes remain available");
        let mut pattern = String::new();
        for byte in function_bytes {
            write!(pattern, "{byte:02X}").expect("writing to String is infallible");
        }
        let pat = format!("{pattern} 00 0000 0020 :0000 __m5_test_library\n---");
        let signatures = Signatures {
            databases: vec![parse_database(PathBuf::from("test.pat"), pat.as_bytes())
                .expect("generated PAT parses")],
        };

        let libraries = identify_library_functions(&analysis, &signatures)
            .expect("generated signature matches without error");
        assert_eq!(
            libraries.get(&address).map(String::as_str),
            Some("__m5_test_library")
        );

        let mut features = extract_pe(&bytes).expect("file features extract");
        enrich_static_features(
            &mut features,
            &analysis,
            &libraries,
            &AnalysisOptions::SERIAL,
        );
        assert!(!features.functions.contains_key(&Address::Absolute(address)));
        assert!(features.file_features.contains(&(
            Address::Absolute(address),
            Feature::FunctionName("__m5_test_library".to_string())
        )));
        assert!(features.file_features.contains(&(
            Address::Absolute(address),
            Feature::FunctionName("_m5_test_library".to_string())
        )));
    }
}
