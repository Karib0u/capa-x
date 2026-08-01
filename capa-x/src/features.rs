//! Feature model, ported from `capa/features/{common,insn,file,basicblock}.py`.
//!
//! This module only models the *value* of a feature as parsed from a rule.
//! Extraction (finding features in a sample) and matching (comparing features
//! against a sample's feature set) live in `extract` and `engine`.

use std::fmt;

/// capa/features/common.py: MAX_BYTES_FEATURE_SIZE
pub const MAX_BYTES_FEATURE_SIZE: usize = 0x100;

/// capa/features/insn.py: MAX_OPERAND_COUNT (operand indices 0..=4 are legal)
pub const MAX_OPERAND_COUNT: u8 = 5;
/// capa/features/insn.py: MAX_OPERAND_INDEX
pub const MAX_OPERAND_INDEX: u8 = MAX_OPERAND_COUNT - 1;

/// shared by rule `bytes:` leaves and freeze `BytesFeature` values.
pub(crate) fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).ok_or(())?;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or(())?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

/// capa/features/common.py: FeatureAccess
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Access {
    Read,
    Write,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::Write => "write",
        }
    }

    pub fn parse(s: &str) -> Option<Access> {
        match s {
            "read" => Some(Access::Read),
            "write" => Some(Access::Write),
            _ => None,
        }
    }
}

/// capa/features/com.py: ComType (`com/class` vs `com/interface`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComKind {
    Class,
    Interface,
}

impl ComKind {
    pub fn parse(s: &str) -> Option<ComKind> {
        match s {
            "class" => Some(ComKind::Class),
            "interface" => Some(ComKind::Interface),
            _ => None,
        }
    }
}

/// capa/features/insn.py: `Number.value` / `OperandNumber.value` are typed
/// `Union[int, float]` -- almost always an integer, but .NET floating-point
/// immediates extract as a Python `float`. Python's numeric tower makes
/// `6 == 6.0` and `hash(6) == hash(6.0)`, so a rule's `number: 6` (always
/// parsed as an int leaf -- capa's rule grammar has no float literal syntax)
/// must still match an extracted whole-valued `Number(6.0)` feature. `Eq`/
/// `Hash` below canonicalize any whole-valued float to its `Int` form so
/// that invariant holds inside our own `FeatureSet` map; this only needs to
/// be internally consistent, not bit-identical to CPython's hash algorithm.
#[derive(Debug, Clone, Copy)]
pub enum NumberValue {
    Int(i128),
    Float(f64),
}

impl NumberValue {
    /// the whole-valued integer this represents, if it has one: always for
    /// `Int`, and for a `Float` with no fractional part that fits in `i128`.
    fn as_whole_int(&self) -> Option<i128> {
        match self {
            NumberValue::Int(v) => Some(*v),
            NumberValue::Float(v) => {
                if v.fract() == 0.0 && *v >= i128::MIN as f64 && *v <= i128::MAX as f64 {
                    Some(*v as i128)
                } else {
                    None
                }
            }
        }
    }
}

impl PartialEq for NumberValue {
    fn eq(&self, other: &Self) -> bool {
        match (self.as_whole_int(), other.as_whole_int()) {
            (Some(a), Some(b)) => a == b,
            _ => match (self, other) {
                (NumberValue::Float(a), NumberValue::Float(b)) => a == b,
                _ => false,
            },
        }
    }
}
impl Eq for NumberValue {}

impl std::hash::Hash for NumberValue {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self.as_whole_int() {
            Some(i) => i.hash(state),
            None => match self {
                NumberValue::Float(f) => f.to_bits().hash(state),
                NumberValue::Int(i) => i.hash(state),
            },
        }
    }
}

impl fmt::Display for NumberValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NumberValue::Int(v) => write!(f, "{v}"),
            NumberValue::Float(v) => write!(f, "{v}"),
        }
    }
}

/// A regular expression compiled from a rule's `string: /pattern/[i]` syntax.
///
/// Two backends are supported: the linear-time `regex` crate is tried first;
/// if it rejects the pattern (e.g. lookaround, which its automaton can't
/// support), we fall back to `fancy-regex`. Only 3 of
/// ~640 corpus regexes need the fallback.
#[derive(Debug, Clone)]
pub enum RegexEngine {
    Standard(Box<regex::Regex>),
    Fancy(Box<fancy_regex::Regex>),
}

#[derive(Debug, Clone)]
pub struct CompiledRegex {
    /// the raw rule text, including the surrounding `/.../ ` or `/.../i`
    pub raw: String,
    pub engine: RegexEngine,
}

impl CompiledRegex {
    /// Compile a capa regex feature value, e.g. `/foo.*bar/i`.
    ///
    /// Mirrors `capa.features.common.Regex.__init__`: strip the delimiters,
    /// always enable dot-matches-newline (Python's `re.DOTALL`), and add
    /// case-insensitivity for a trailing `i` flag. capa uses `re.search`
    /// (unanchored substring search), which is also the `regex`/`fancy-regex`
    /// default, so no anchoring is added here.
    pub fn compile(raw: &str) -> Result<Self, String> {
        let (pat, ignorecase) =
            if let Some(p) = raw.strip_prefix('/').and_then(|s| s.strip_suffix("/i")) {
                (p, true)
            } else if let Some(p) = raw.strip_prefix('/').and_then(|s| s.strip_suffix('/')) {
                (p, false)
            } else {
                return Err(format!("invalid regular expression syntax: {raw}"));
            };

        let mut pattern = String::from("(?s");
        if ignorecase {
            pattern.push('i');
        }
        pattern.push(')');
        pattern.push_str(pat);

        let engine = match regex::Regex::new(&pattern) {
            Ok(re) => RegexEngine::Standard(Box::new(re)),
            Err(_) => match fancy_regex::Regex::new(&pattern) {
                Ok(re) => RegexEngine::Fancy(Box::new(re)),
                Err(e) => {
                    return Err(format!(
                        "invalid regular expression: {raw} it should use Python syntax, try it at https://pythex.org ({e})"
                    ));
                }
            },
        };

        Ok(CompiledRegex {
            raw: raw.to_string(),
            engine,
        })
    }

    /// `re.search()` semantics: does the pattern match anywhere in `text`?
    /// A fancy-regex internal error (e.g. catastrophic backtracking guard)
    /// is treated as "no match" rather than propagated, matching the fact
    /// that this is only ever used at match time, never during parsing.
    pub fn is_match(&self, text: &str) -> bool {
        match &self.engine {
            RegexEngine::Standard(re) => re.is_match(text),
            RegexEngine::Fancy(re) => re.is_match(text).unwrap_or(false),
        }
    }
}

impl PartialEq for CompiledRegex {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}
impl Eq for CompiledRegex {}
impl std::hash::Hash for CompiledRegex {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

/// capa/features/common.py: String / Substring / Regex / StringFactory
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StringFeature {
    Plain(String),
    Substring(String),
    Regex(CompiledRegex),
}

/// capa/features/{common,insn,file,basicblock}.py feature classes, unified.
///
/// `Com` intentionally stores just the COM type + symbolic name: unlike
/// Python's `translate_com_feature`, which immediately expands a `com/class`
/// / `com/interface` rule leaf into an `Or` of GUID string/bytes checks
/// (requiring the capa-rules COM database), this port defers that expansion
/// to the matching engine by design. Scope-legality
/// checking is skipped for this feature, matching upstream (which never
/// scope-checks the expanded GUID statement either).
///
/// `BasicBlock` has no rule-level spelling of its own but is required:
/// `capa.features.basicblock.BasicBlock` is a real feature class, needed for
/// `count(basic blocks): N` (capa/features/basicblock.py).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Feature {
    Api(String),
    String(StringFeature),
    /// capped at MAX_BYTES_FEATURE_SIZE bytes
    Bytes(Vec<u8>),
    Number(NumberValue),
    Offset(i64),
    OperandNumber(u8, NumberValue),
    OperandOffset(u8, i64),
    Mnemonic(String),
    Characteristic(String),
    Section(String),
    Import(String),
    Export(String),
    FunctionName(String),
    Class(String),
    Namespace(String),
    Property {
        name: String,
        access: Option<Access>,
    },
    Os(String),
    Arch(String),
    Format(String),
    Com(ComKind, String),
    MatchedRule(String),
    BasicBlock,
}

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Feature::Api(v) => write!(f, "api({v})"),
            Feature::String(StringFeature::Plain(v)) => write!(f, "string({v})"),
            Feature::String(StringFeature::Substring(v)) => write!(f, "substring({v})"),
            Feature::String(StringFeature::Regex(re)) => write!(f, "regex(string =~ {})", re.raw),
            Feature::Bytes(_) => write!(f, "bytes"),
            Feature::Number(v) => write!(f, "number({v})"),
            Feature::Offset(v) => write!(f, "offset({v})"),
            Feature::OperandNumber(i, v) => write!(f, "operand[{i}].number({v})"),
            Feature::OperandOffset(i, v) => write!(f, "operand[{i}].offset({v})"),
            Feature::Mnemonic(v) => write!(f, "mnemonic({v})"),
            Feature::Characteristic(v) => write!(f, "characteristic({v})"),
            Feature::Section(v) => write!(f, "section({v})"),
            Feature::Import(v) => write!(f, "import({v})"),
            Feature::Export(v) => write!(f, "export({v})"),
            Feature::FunctionName(v) => write!(f, "function-name({v})"),
            Feature::Class(v) => write!(f, "class({v})"),
            Feature::Namespace(v) => write!(f, "namespace({v})"),
            Feature::Property {
                name,
                access: Some(a),
            } => write!(f, "property/{}({name})", a.as_str()),
            Feature::Property { name, access: None } => write!(f, "property({name})"),
            Feature::Os(v) => write!(f, "os({v})"),
            Feature::Arch(v) => write!(f, "arch({v})"),
            Feature::Format(v) => write!(f, "format({v})"),
            Feature::Com(ComKind::Class, v) => write!(f, "com/class({v})"),
            Feature::Com(ComKind::Interface, v) => write!(f, "com/interface({v})"),
            Feature::MatchedRule(v) => write!(f, "match({v})"),
            Feature::BasicBlock => write!(f, "basic block"),
        }
    }
}
