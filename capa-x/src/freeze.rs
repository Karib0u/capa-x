//! capa freeze file reader, ported from
//! `capa/features/freeze/{__init__,features}.py` (v9.4.0, see PINNED.md).
//!
//! Read-only: capa-x never *produces* freeze files (nothing here needs to
//! be a runtime write path), only consumes them -- as difftest fixtures and
//! as `capa-x-cli --format freeze` input.
//!
//! Field names on the wire are pydantic's Python *attribute* names, not
//! their `Field(alias=...)` values: `Freeze.model_dump_json()` is called
//! upstream without `by_alias=True`, so e.g. `StaticFeatures.functions[].
//! basic_blocks` (not `"basic blocks"`), `ImportFeature.import_` (not
//! `"import"`). Verified empirically against the fixtures in
//! `tests/testfiles/fixtures/snapshots/features/*.frz`. The `type`
//! discriminator values themselves are unaffected (they're literal defaults,
//! not aliases), and some of those *do* contain spaces, e.g. `"basic block"`,
//! `"operand number"`, `"dn token offset"`.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value as Json;

use crate::address::Address;
use crate::features::{hex_decode, Access, Feature, NumberValue, StringFeature};
use crate::features::{CompiledRegex, MAX_OPERAND_INDEX};

/// capa/features/freeze/__init__.py: MAGIC
pub const MAGIC: &[u8] = b"capa0000";
/// capa/features/freeze/__init__.py: CURRENT_VERSION
pub const CURRENT_VERSION: u32 = 3;

#[derive(Debug, thiserror::Error)]
pub enum FreezeError {
    #[error("missing magic header")]
    MissingMagic,
    #[error("zlib decompression failed: {0}")]
    Zlib(String),
    #[error("freeze file is not valid utf-8: {0}")]
    Utf8(String),
    #[error("invalid freeze json: {0}")]
    Json(String),
    #[error("unsupported freeze format version: {0}")]
    UnsupportedVersion(u32),
    #[error("unsupported freeze format flavor: {0}")]
    UnsupportedFlavor(String),
    #[error("invalid freeze data: {0}")]
    Invalid(String),
}

impl FreezeError {
    fn invalid(msg: impl Into<String>) -> Self {
        FreezeError::Invalid(msg.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Default)]
pub struct InstructionFeatures {
    pub features: Vec<(Address, Feature)>,
}

#[derive(Debug, Clone, Default)]
pub struct BasicBlockFeatures {
    pub features: Vec<(Address, Feature)>,
    /// keyed and iterated in address order, matching
    /// `NullStaticFeatureExtractor.get_instructions`'s `sorted(...keys())`.
    pub instructions: BTreeMap<Address, InstructionFeatures>,
}

#[derive(Debug, Clone, Default)]
pub struct FunctionFeatures {
    pub features: Vec<(Address, Feature)>,
    /// keyed and iterated in address order, matching `get_basic_blocks`.
    pub basic_blocks: BTreeMap<Address, BasicBlockFeatures>,
}

#[derive(Debug, Clone)]
pub struct StaticFeatures {
    pub base_address: Address,
    pub sample_hashes: SampleHashes,
    pub global_features: Vec<Feature>,
    pub file_features: Vec<(Address, Feature)>,
    /// keyed and iterated in address order, matching `get_functions`.
    pub functions: BTreeMap<Address, FunctionFeatures>,
}

#[derive(Debug, Clone, Default)]
pub struct CallFeatures {
    pub name: String,
    pub features: Vec<(Address, Feature)>,
}

#[derive(Debug, Clone, Default)]
pub struct ThreadFeatures {
    pub features: Vec<(Address, Feature)>,
    /// keyed and iterated in address order, matching `get_calls`.
    pub calls: BTreeMap<Address, CallFeatures>,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessFeatures {
    pub name: String,
    pub features: Vec<(Address, Feature)>,
    /// keyed and iterated in address order, matching `get_threads`.
    pub threads: BTreeMap<Address, ThreadFeatures>,
}

#[derive(Debug, Clone)]
pub struct DynamicFeatures {
    pub base_address: Address,
    pub sample_hashes: SampleHashes,
    pub global_features: Vec<Feature>,
    pub file_features: Vec<(Address, Feature)>,
    /// keyed and iterated in address order, matching `get_processes`.
    pub processes: BTreeMap<Address, ProcessFeatures>,
}

#[derive(Debug, Clone)]
pub enum Freeze {
    Static(StaticFeatures),
    Dynamic(DynamicFeatures),
}

/// port of `is_freeze`
pub fn is_freeze(buf: &[u8]) -> bool {
    buf.starts_with(MAGIC)
}

/// port of `load`: magic-prefixed, zlib-compressed freeze bytes.
pub fn load(buf: &[u8]) -> Result<Freeze, FreezeError> {
    if !is_freeze(buf) {
        return Err(FreezeError::MissingMagic);
    }
    let mut out = Vec::new();
    {
        use std::io::Read;
        let mut decoder = flate2::read::ZlibDecoder::new(&buf[MAGIC.len()..]);
        decoder
            .read_to_end(&mut out)
            .map_err(|e| FreezeError::Zlib(e.to_string()))?;
    }
    let s = String::from_utf8(out).map_err(|e| FreezeError::Utf8(e.to_string()))?;
    loads(&s)
}

/// port of `loads`: a plain (uncompressed) freeze JSON document.
pub fn loads(s: &str) -> Result<Freeze, FreezeError> {
    let envelope: RawFreeze =
        serde_json::from_str(s).map_err(|e| FreezeError::Json(e.to_string()))?;

    if envelope.version != CURRENT_VERSION {
        return Err(FreezeError::UnsupportedVersion(envelope.version));
    }

    let base_address = envelope.base_address.to_capa()?;
    let sample_hashes = SampleHashes {
        md5: envelope.sample_hashes.md5,
        sha1: envelope.sample_hashes.sha1,
        sha256: envelope.sample_hashes.sha256,
    };

    match envelope.flavor.as_str() {
        "static" => {
            let raw: RawStaticFeatures = serde_json::from_value(envelope.features)
                .map_err(|e| FreezeError::Json(e.to_string()))?;
            Ok(Freeze::Static(StaticFeatures {
                base_address,
                sample_hashes,
                global_features: raw
                    .global_
                    .into_iter()
                    .map(|g| g.feature.to_capa())
                    .collect::<Result<_, _>>()?,
                file_features: raw
                    .file
                    .into_iter()
                    .map(|f| Ok((f.address.to_capa()?, f.feature.to_capa()?)))
                    .collect::<Result<_, FreezeError>>()?,
                functions: raw
                    .functions
                    .into_iter()
                    .map(|f| Ok((f.address.to_capa()?, f.to_capa()?)))
                    .collect::<Result<_, FreezeError>>()?,
            }))
        }
        "dynamic" => {
            let raw: RawDynamicFeatures = serde_json::from_value(envelope.features)
                .map_err(|e| FreezeError::Json(e.to_string()))?;
            Ok(Freeze::Dynamic(DynamicFeatures {
                base_address,
                sample_hashes,
                global_features: raw
                    .global_
                    .into_iter()
                    .map(|g| g.feature.to_capa())
                    .collect::<Result<_, _>>()?,
                file_features: raw
                    .file
                    .into_iter()
                    .map(|f| Ok((f.address.to_capa()?, f.feature.to_capa()?)))
                    .collect::<Result<_, FreezeError>>()?,
                processes: raw
                    .processes
                    .into_iter()
                    .map(|p| Ok((p.address.to_capa()?, p.to_capa()?)))
                    .collect::<Result<_, FreezeError>>()?,
            }))
        }
        other => Err(FreezeError::UnsupportedFlavor(other.to_string())),
    }
}

// ---------------------------------------------------------------------
// wire DTOs
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawFreeze {
    version: u32,
    base_address: RawAddress,
    sample_hashes: RawSampleHashes,
    flavor: String,
    features: Json,
}

#[derive(Debug, Deserialize)]
struct RawSampleHashes {
    md5: String,
    sha1: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct RawAddress {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    value: Json,
}

fn as_u64(v: &Json, ctx: &str) -> Result<u64, FreezeError> {
    v.as_u64()
        .ok_or_else(|| FreezeError::invalid(format!("{ctx}: expected a non-negative integer")))
}

fn as_u32_tuple<const N: usize>(v: &Json, ctx: &str) -> Result<[u32; N], FreezeError> {
    let arr = v
        .as_array()
        .filter(|a| a.len() == N)
        .ok_or_else(|| FreezeError::invalid(format!("{ctx}: expected a {N}-tuple")))?;
    let mut out = [0u32; N];
    for (i, item) in arr.iter().enumerate() {
        out[i] = item
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| FreezeError::invalid(format!("{ctx}: tuple element out of range")))?;
    }
    Ok(out)
}

impl RawAddress {
    fn to_capa(&self) -> Result<Address, FreezeError> {
        match self.kind.as_str() {
            "absolute" => Ok(Address::Absolute(as_u64(&self.value, "absolute address")?)),
            "relative" => Ok(Address::Relative(as_u64(&self.value, "relative address")?)),
            "file" => Ok(Address::File(as_u64(&self.value, "file address")?)),
            "dn token" => Ok(Address::DnToken(
                as_u64(&self.value, "dn token address")?
                    .try_into()
                    .map_err(|_| FreezeError::invalid("dn token value out of range"))?,
            )),
            "dn token offset" => {
                let [token, offset] = as_u32_tuple(&self.value, "dn token offset address")?;
                Ok(Address::DnTokenOffset { token, offset })
            }
            "process" => {
                let [ppid, pid] = as_u32_tuple(&self.value, "process address")?;
                Ok(Address::Process { ppid, pid })
            }
            "thread" => {
                let [ppid, pid, tid] = as_u32_tuple(&self.value, "thread address")?;
                Ok(Address::Thread { ppid, pid, tid })
            }
            "call" => {
                // a 4-tuple (ppid, pid, tid, id); id can exceed u32, so this
                // can't reuse `as_u32_tuple::<4>` (which would force it into
                // u32 too) -- pull it out separately as u64.
                let arr = self
                    .value
                    .as_array()
                    .filter(|a| a.len() == 4)
                    .ok_or_else(|| FreezeError::invalid("call address: expected a 4-tuple"))?;
                let as_u32_field = |v: &Json| -> Result<u32, FreezeError> {
                    v.as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(|| {
                            FreezeError::invalid("call address: tuple element out of range")
                        })
                };
                let ppid = as_u32_field(&arr[0])?;
                let pid = as_u32_field(&arr[1])?;
                let tid = as_u32_field(&arr[2])?;
                let id = arr[3]
                    .as_u64()
                    .ok_or_else(|| FreezeError::invalid("call address: id out of range"))?;
                Ok(Address::Call { ppid, pid, tid, id })
            }
            "no address" => Ok(Address::NoAddress),
            other => Err(FreezeError::invalid(format!(
                "unknown address type: {other}"
            ))),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawFeature {
    #[serde(rename = "type")]
    kind: String,
    #[serde(flatten)]
    rest: serde_json::Map<String, Json>,
}

impl RawFeature {
    fn field(&self, key: &str) -> Result<&Json, FreezeError> {
        self.rest
            .get(key)
            .ok_or_else(|| FreezeError::invalid(format!("feature {}: missing {key}", self.kind)))
    }

    fn str_field(&self, key: &str) -> Result<String, FreezeError> {
        self.field(key)?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| {
                FreezeError::invalid(format!("feature {}: {key} must be a string", self.kind))
            })
    }

    fn int_field(&self, key: &str) -> Result<i128, FreezeError> {
        let v = self.field(key)?;
        if let Some(n) = v.as_i64() {
            Ok(n as i128)
        } else if let Some(n) = v.as_u64() {
            Ok(n as i128)
        } else {
            Err(FreezeError::invalid(format!(
                "feature {}: {key} must be an integer",
                self.kind
            )))
        }
    }

    fn number_field(&self, key: &str) -> Result<NumberValue, FreezeError> {
        let v = self.field(key)?;
        if let Some(n) = v.as_i64() {
            Ok(NumberValue::Int(n as i128))
        } else if let Some(n) = v.as_u64() {
            Ok(NumberValue::Int(n as i128))
        } else if let Some(f) = v.as_f64() {
            Ok(NumberValue::Float(f))
        } else {
            Err(FreezeError::invalid(format!(
                "feature {}: {key} must be a number",
                self.kind
            )))
        }
    }

    /// `description` is present on every freeze feature and always
    /// optional/nullable; absent from our `Feature` model (which doesn't carry
    /// per-leaf descriptions from extracted data, only from rule text), so
    /// we read and discard it -- this at least validates its shape.
    fn check_description(&self) -> Result<(), FreezeError> {
        match self.rest.get("description") {
            None | Some(Json::Null) => Ok(()),
            Some(Json::String(_)) => Ok(()),
            Some(other) => Err(FreezeError::invalid(format!(
                "feature {}: description must be a string or null, got {other:?}",
                self.kind
            ))),
        }
    }

    fn to_capa(&self) -> Result<Feature, FreezeError> {
        self.check_description()?;
        Ok(match self.kind.as_str() {
            "os" => Feature::Os(self.str_field("os")?),
            "arch" => Feature::Arch(self.str_field("arch")?),
            "format" => Feature::Format(self.str_field("format")?),
            "match" => Feature::MatchedRule(self.str_field("match")?),
            "characteristic" => Feature::Characteristic(self.str_field("characteristic")?),
            "export" => Feature::Export(self.str_field("export")?),
            "import" => Feature::Import(self.str_field("import_")?),
            "section" => Feature::Section(self.str_field("section")?),
            "function name" => Feature::FunctionName(self.str_field("function_name")?),
            "substring" => Feature::String(StringFeature::Substring(self.str_field("substring")?)),
            "regex" => {
                let raw = self.str_field("regex")?;
                let re = CompiledRegex::compile(&raw).map_err(FreezeError::invalid)?;
                Feature::String(StringFeature::Regex(re))
            }
            "string" => Feature::String(StringFeature::Plain(self.str_field("string")?)),
            "class" => Feature::Class(self.str_field("class_")?),
            "namespace" => Feature::Namespace(self.str_field("namespace")?),
            "basic block" => Feature::BasicBlock,
            "api" => Feature::Api(self.str_field("api")?),
            "property" => {
                let name = self.str_field("property")?;
                let access = match self.rest.get("access") {
                    None | Some(Json::Null) => None,
                    Some(Json::String(s)) => Some(Access::parse(s).ok_or_else(|| {
                        FreezeError::invalid(format!("property: unknown access {s}"))
                    })?),
                    Some(other) => {
                        return Err(FreezeError::invalid(format!(
                            "property: access must be a string or null, got {other:?}"
                        )))
                    }
                };
                Feature::Property { name, access }
            }
            "number" => Feature::Number(self.number_field("number")?),
            "bytes" => {
                let s = self.str_field("bytes")?;
                let bytes = hex_decode(&s).map_err(|_| {
                    FreezeError::invalid(format!("bytes: not a valid hex string: {s}"))
                })?;
                Feature::Bytes(bytes)
            }
            "offset" => Feature::Offset(self.int_offset("offset")?),
            "mnemonic" => Feature::Mnemonic(self.str_field("mnemonic")?),
            "operand number" => {
                let index = self.operand_index()?;
                Feature::OperandNumber(index, self.number_field("operand_number")?)
            }
            "operand offset" => {
                let index = self.operand_index()?;
                Feature::OperandOffset(index, self.int_offset("operand_offset")?)
            }
            other => {
                return Err(FreezeError::invalid(format!(
                    "unknown freeze feature type: {other}"
                )))
            }
        })
    }

    fn int_offset(&self, key: &str) -> Result<i64, FreezeError> {
        let n = self.int_field(key)?;
        i64::try_from(n).map_err(|_| FreezeError::invalid(format!("{key} out of range: {n}")))
    }

    fn operand_index(&self) -> Result<u8, FreezeError> {
        let n = self.int_field("index")?;
        if n < 0 || n > MAX_OPERAND_INDEX as i128 {
            return Err(FreezeError::invalid(format!(
                "operand index out of range: {n}"
            )));
        }
        Ok(n as u8)
    }
}

#[derive(Debug, Deserialize)]
struct RawGlobalFeature {
    feature: RawFeature,
}

#[derive(Debug, Deserialize)]
struct RawFileFeature {
    address: RawAddress,
    feature: RawFeature,
}

#[derive(Debug, Deserialize)]
struct RawInstructionFeature {
    address: RawAddress,
    feature: RawFeature,
}

#[derive(Debug, Deserialize)]
struct RawInstructionFeatures {
    address: RawAddress,
    features: Vec<RawInstructionFeature>,
}

impl RawInstructionFeatures {
    fn to_capa(&self) -> Result<InstructionFeatures, FreezeError> {
        Ok(InstructionFeatures {
            features: self
                .features
                .iter()
                .map(|f| Ok((f.address.to_capa()?, f.feature.to_capa()?)))
                .collect::<Result<_, FreezeError>>()?,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawBasicBlockFeature {
    address: RawAddress,
    feature: RawFeature,
}

#[derive(Debug, Deserialize)]
struct RawBasicBlockFeatures {
    address: RawAddress,
    features: Vec<RawBasicBlockFeature>,
    instructions: Vec<RawInstructionFeatures>,
}

impl RawBasicBlockFeatures {
    fn to_capa(&self) -> Result<BasicBlockFeatures, FreezeError> {
        Ok(BasicBlockFeatures {
            features: self
                .features
                .iter()
                .map(|f| Ok((f.address.to_capa()?, f.feature.to_capa()?)))
                .collect::<Result<_, FreezeError>>()?,
            instructions: self
                .instructions
                .iter()
                .map(|i| Ok((i.address.to_capa()?, i.to_capa()?)))
                .collect::<Result<_, FreezeError>>()?,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawFunctionFeature {
    address: RawAddress,
    feature: RawFeature,
}

#[derive(Debug, Deserialize)]
struct RawFunctionFeatures {
    address: RawAddress,
    features: Vec<RawFunctionFeature>,
    basic_blocks: Vec<RawBasicBlockFeatures>,
}

impl RawFunctionFeatures {
    fn to_capa(&self) -> Result<FunctionFeatures, FreezeError> {
        Ok(FunctionFeatures {
            features: self
                .features
                .iter()
                .map(|f| Ok((f.address.to_capa()?, f.feature.to_capa()?)))
                .collect::<Result<_, FreezeError>>()?,
            basic_blocks: self
                .basic_blocks
                .iter()
                .map(|bb| Ok((bb.address.to_capa()?, bb.to_capa()?)))
                .collect::<Result<_, FreezeError>>()?,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawStaticFeatures {
    global_: Vec<RawGlobalFeature>,
    file: Vec<RawFileFeature>,
    functions: Vec<RawFunctionFeatures>,
}

#[derive(Debug, Deserialize)]
struct RawCallFeature {
    address: RawAddress,
    feature: RawFeature,
}

#[derive(Debug, Deserialize)]
struct RawCallFeatures {
    address: RawAddress,
    name: String,
    features: Vec<RawCallFeature>,
}

impl RawCallFeatures {
    fn to_capa(&self) -> Result<CallFeatures, FreezeError> {
        Ok(CallFeatures {
            name: self.name.clone(),
            features: self
                .features
                .iter()
                .map(|f| Ok((f.address.to_capa()?, f.feature.to_capa()?)))
                .collect::<Result<_, FreezeError>>()?,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawThreadFeature {
    address: RawAddress,
    feature: RawFeature,
}

#[derive(Debug, Deserialize)]
struct RawThreadFeatures {
    address: RawAddress,
    features: Vec<RawThreadFeature>,
    calls: Vec<RawCallFeatures>,
}

impl RawThreadFeatures {
    fn to_capa(&self) -> Result<ThreadFeatures, FreezeError> {
        Ok(ThreadFeatures {
            features: self
                .features
                .iter()
                .map(|f| Ok((f.address.to_capa()?, f.feature.to_capa()?)))
                .collect::<Result<_, FreezeError>>()?,
            calls: self
                .calls
                .iter()
                .map(|c| Ok((c.address.to_capa()?, c.to_capa()?)))
                .collect::<Result<_, FreezeError>>()?,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawProcessFeature {
    address: RawAddress,
    feature: RawFeature,
}

#[derive(Debug, Deserialize)]
struct RawProcessFeatures {
    address: RawAddress,
    name: String,
    features: Vec<RawProcessFeature>,
    threads: Vec<RawThreadFeatures>,
}

impl RawProcessFeatures {
    fn to_capa(&self) -> Result<ProcessFeatures, FreezeError> {
        Ok(ProcessFeatures {
            name: self.name.clone(),
            features: self
                .features
                .iter()
                .map(|f| Ok((f.address.to_capa()?, f.feature.to_capa()?)))
                .collect::<Result<_, FreezeError>>()?,
            threads: self
                .threads
                .iter()
                .map(|t| Ok((t.address.to_capa()?, t.to_capa()?)))
                .collect::<Result<_, FreezeError>>()?,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawDynamicFeatures {
    global_: Vec<RawGlobalFeature>,
    file: Vec<RawFileFeature>,
    processes: Vec<RawProcessFeatures>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixtures_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/freeze")
    }

    #[test]
    fn loads_static_fixture() {
        let path = fixtures_dir().join("pma01-01-dll.frz.json");
        let s = std::fs::read_to_string(&path).expect("fixture present");
        let freeze = loads(&s).expect("valid static freeze json");
        match freeze {
            Freeze::Static(sf) => {
                assert!(!sf.global_features.is_empty());
                assert!(!sf.file_features.is_empty());
                assert!(!sf.functions.is_empty());
                assert_eq!(sf.sample_hashes.md5.len(), 32);
            }
            Freeze::Dynamic(_) => panic!("expected static flavor"),
        }
    }

    #[test]
    fn loads_dynamic_fixture() {
        let path = fixtures_dir().join("dynamic-sample.frz.json");
        let s = std::fs::read_to_string(&path).expect("fixture present");
        let freeze = loads(&s).expect("valid dynamic freeze json");
        match freeze {
            Freeze::Dynamic(df) => {
                assert!(!df.global_features.is_empty());
                assert!(!df.file_features.is_empty());
                assert!(!df.processes.is_empty());
                let (_, process) = df.processes.iter().next().expect("at least one process");
                assert!(!process.name.is_empty());
                assert!(!process.threads.is_empty());
                let (_, thread) = process.threads.iter().next().expect("at least one thread");
                assert!(!thread.calls.is_empty());
            }
            Freeze::Static(_) => panic!("expected dynamic flavor"),
        }
    }

    #[test]
    fn loads_dotnet_fixture_with_float_numbers() {
        let path = fixtures_dir().join("1c444-dotnet.frz.json");
        let s = std::fs::read_to_string(&path).expect("fixture present");
        let freeze = loads(&s).expect("valid static freeze json");
        let Freeze::Static(sf) = freeze else {
            panic!("expected static flavor")
        };
        let mut saw_float = false;
        for f in sf.functions.values() {
            for (_, feature) in &f.features {
                if let Feature::Number(NumberValue::Float(_)) = feature {
                    saw_float = true;
                }
            }
            for bb in f.basic_blocks.values() {
                for (_, feature) in &bb.features {
                    if let Feature::Number(NumberValue::Float(_)) = feature {
                        saw_float = true;
                    }
                }
                for insn in bb.instructions.values() {
                    for (_, feature) in &insn.features {
                        if let Feature::Number(NumberValue::Float(v)) = feature {
                            saw_float = true;
                            assert_eq!(*v, v.trunc());
                        }
                    }
                }
            }
        }
        assert!(saw_float, "expected at least one float Number feature");
    }

    #[test]
    fn magic_and_zlib_round_trip() {
        let json = std::fs::read_to_string(fixtures_dir().join("pma01-01-dll.frz.json"))
            .expect("fixture present");
        // re-derive the magic+zlib wrapped form so `load()` is exercised too,
        // without needing to commit another (redundant) binary fixture.
        use std::io::Write;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(json.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut buf = MAGIC.to_vec();
        buf.extend(compressed);

        assert!(is_freeze(&buf));
        let freeze = load(&buf).expect("valid compressed freeze");
        assert!(matches!(freeze, Freeze::Static(_)));

        assert!(matches!(
            load(b"not a freeze file"),
            Err(FreezeError::MissingMagic)
        ));
    }

    #[test]
    fn rejects_unsupported_version() {
        let doc = r#"{"version": 99, "base_address": {"type": "no address", "value": null}, "sample_hashes": {"md5":"a","sha1":"b","sha256":"c"}, "flavor": "static", "extractor": {"name": "x"}, "features": {"global_": [], "file": [], "functions": []}}"#;
        assert!(matches!(
            loads(doc),
            Err(FreezeError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn rejects_unknown_feature_type() {
        let doc = format!(
            r#"{{"version": {CURRENT_VERSION}, "base_address": {{"type": "no address", "value": null}}, "sample_hashes": {{"md5":"a","sha1":"b","sha256":"c"}}, "flavor": "static", "extractor": {{"name": "x"}}, "features": {{"global_": [{{"feature": {{"type": "bogus"}}}}], "file": [], "functions": []}}}}"#
        );
        let err = loads(&doc).unwrap_err();
        assert!(err.to_string().contains("unknown freeze feature type"));
    }
}
