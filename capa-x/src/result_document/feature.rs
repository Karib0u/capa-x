//! JSON-facing feature model, ported from
//! `capa/features/freeze/features.py`. Dumped without `by_alias` (result
//! document, `capa/render/result_document.py`, calls `model_dump_json`
//! plainly) and with `exclude_none=True`, so every JSON key here is the
//! pydantic *attribute* name (e.g. `import_`, `class_`, `function_name`,
//! not their `Field(alias=...)` spelling) and `description` is omitted
//! rather than `null` when absent. The `type` discriminator values
//! themselves are literal defaults, unaffected by aliasing, and some do
//! contain spaces (`"function name"`, `"basic block"`, `"operand number"`).
//!
//! This is the render-only (output) counterpart to `freeze::RawFeature`,
//! which only ever reads this same wire shape.

use serde::{Deserialize, Serialize};

use crate::features::{Access, ComKind, Feature, NumberValue};

/// `Union[int, float]`, preserving the lexical int-vs-float distinction on
/// the wire (`6` vs `6.0`) the same way Python's `json` module does.
/// `Int` is `i128` (not `i64`) because a rule/extracted `number:` value can
/// exceed 64-bit signed range (e.g. `0xFFFFFFFFFFFFFFFF` read as unsigned),
/// matching `features::NumberValue::Int`'s own choice.
///
/// `Deserialize` is hand-written rather than `#[serde(untagged)]`: serde's
/// untagged-enum deserialization buffers the input through an internal
/// `Content` representation that (as of serde 1.0.229) has no first-class
/// i128 slot, so a plain JSON integer literal like `4294967285` silently
/// falls through to the `f64` variant instead of `i128` -- confirmed via
/// this module's schema round-trip test against real `capa
/// -j` output, which caught exactly this (an int rendered back as
/// `4294967285.0`). Serialize is unaffected (no buffering involved), so it
/// stays derived.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RdNumber {
    Int(i128),
    Float(f64),
}

impl From<NumberValue> for RdNumber {
    fn from(v: NumberValue) -> RdNumber {
        match v {
            NumberValue::Int(i) => RdNumber::Int(i),
            NumberValue::Float(f) => RdNumber::Float(f),
        }
    }
}

impl<'de> Deserialize<'de> for RdNumber {
    fn deserialize<D>(deserializer: D) -> Result<RdNumber, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RdNumberVisitor;

        impl serde::de::Visitor<'_> for RdNumberVisitor {
            type Value = RdNumber;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "an integer or floating point number")
            }

            fn visit_i64<E>(self, v: i64) -> Result<RdNumber, E> {
                Ok(RdNumber::Int(v as i128))
            }

            fn visit_u64<E>(self, v: u64) -> Result<RdNumber, E> {
                Ok(RdNumber::Int(v as i128))
            }

            fn visit_i128<E>(self, v: i128) -> Result<RdNumber, E> {
                Ok(RdNumber::Int(v))
            }

            fn visit_u128<E>(self, v: u128) -> Result<RdNumber, E>
            where
                E: serde::de::Error,
            {
                i128::try_from(v)
                    .map(RdNumber::Int)
                    .map_err(|_| E::custom("integer too large for i128"))
            }

            fn visit_f64<E>(self, v: f64) -> Result<RdNumber, E> {
                Ok(RdNumber::Float(v))
            }
        }

        deserializer.deserialize_any(RdNumberVisitor)
    }
}

/// mirrors `frzf.Feature`'s discriminated union (`Field(discriminator="type")`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RdFeature {
    #[serde(rename = "os")]
    Os {
        os: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "arch")]
    Arch {
        arch: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "format")]
    Format {
        format: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "match")]
    Match {
        #[serde(rename = "match")]
        match_: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "characteristic")]
    Characteristic {
        characteristic: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "export")]
    Export {
        export: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "import")]
    Import {
        // wire key is the attribute name `import_` (Field(alias="import")
        // is never applied -- see module doc).
        import_: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "section")]
    Section {
        section: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "function name")]
    FunctionName {
        function_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "substring")]
    Substring {
        substring: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "regex")]
    Regex {
        regex: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "string")]
    String {
        string: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "class")]
    Class {
        class_: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "namespace")]
    Namespace {
        namespace: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "basic block")]
    BasicBlock {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "api")]
    Api {
        api: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "property")]
    Property {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        access: Option<String>,
        property: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "number")]
    Number {
        number: RdNumber,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "bytes")]
    Bytes {
        /// lowercase hex, as produced by `bytes.hex()`.
        bytes: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "offset")]
    Offset {
        offset: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "mnemonic")]
    Mnemonic {
        mnemonic: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "operand number")]
    OperandNumber {
        index: i64,
        operand_number: RdNumber,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "operand offset")]
    OperandOffset {
        index: i64,
        operand_offset: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
}

impl RdFeature {
    /// the `type` discriminator's own value, e.g. `"function name"`.
    pub fn type_name(&self) -> &'static str {
        match self {
            RdFeature::Os { .. } => "os",
            RdFeature::Arch { .. } => "arch",
            RdFeature::Format { .. } => "format",
            RdFeature::Match { .. } => "match",
            RdFeature::Characteristic { .. } => "characteristic",
            RdFeature::Export { .. } => "export",
            RdFeature::Import { .. } => "import",
            RdFeature::Section { .. } => "section",
            RdFeature::FunctionName { .. } => "function name",
            RdFeature::Substring { .. } => "substring",
            RdFeature::Regex { .. } => "regex",
            RdFeature::String { .. } => "string",
            RdFeature::Class { .. } => "class",
            RdFeature::Namespace { .. } => "namespace",
            RdFeature::BasicBlock { .. } => "basic block",
            RdFeature::Api { .. } => "api",
            RdFeature::Property { .. } => "property",
            RdFeature::Number { .. } => "number",
            RdFeature::Bytes { .. } => "bytes",
            RdFeature::Offset { .. } => "offset",
            RdFeature::Mnemonic { .. } => "mnemonic",
            RdFeature::OperandNumber { .. } => "operand number",
            RdFeature::OperandOffset { .. } => "operand offset",
        }
    }

    pub fn description(&self) -> Option<&str> {
        match self {
            RdFeature::Os { description, .. }
            | RdFeature::Arch { description, .. }
            | RdFeature::Format { description, .. }
            | RdFeature::Match { description, .. }
            | RdFeature::Characteristic { description, .. }
            | RdFeature::Export { description, .. }
            | RdFeature::Import { description, .. }
            | RdFeature::Section { description, .. }
            | RdFeature::FunctionName { description, .. }
            | RdFeature::Substring { description, .. }
            | RdFeature::Regex { description, .. }
            | RdFeature::String { description, .. }
            | RdFeature::Class { description, .. }
            | RdFeature::Namespace { description, .. }
            | RdFeature::BasicBlock { description, .. }
            | RdFeature::Api { description, .. }
            | RdFeature::Property { description, .. }
            | RdFeature::Number { description, .. }
            | RdFeature::Bytes { description, .. }
            | RdFeature::Offset { description, .. }
            | RdFeature::Mnemonic { description, .. }
            | RdFeature::OperandNumber { description, .. }
            | RdFeature::OperandOffset { description, .. } => description.as_deref(),
        }
    }

    /// port of `feature_from_capa`. `description` comes from the enclosing
    /// match tree node (see module doc: our `Feature` doesn't carry its own
    /// description the way `capa.features.common.Feature` instances do; the
    /// engine threads it separately via `Node`/`MatchResult.description`).
    ///
    /// Errors on `Feature::Com`: COM leaves are always expanded into a
    /// GUID `Or` statement before matching (`capabilities::ruleset`), so a
    /// raw `Com` feature should never reach a match tree -- mirrors
    /// `feature_from_capa`'s `NotImplementedError` for unhandled cases
    /// rather than silently dropping it.
    pub fn from_engine(
        feature: &Feature,
        description: Option<String>,
    ) -> Result<RdFeature, String> {
        Ok(match feature {
            Feature::Api(v) => RdFeature::Api {
                api: v.clone(),
                description,
            },
            Feature::String(crate::features::StringFeature::Plain(v)) => RdFeature::String {
                string: v.clone(),
                description,
            },
            Feature::String(crate::features::StringFeature::Substring(v)) => RdFeature::Substring {
                substring: v.clone(),
                description,
            },
            Feature::String(crate::features::StringFeature::Regex(re)) => RdFeature::Regex {
                regex: re.raw.clone(),
                description,
            },
            Feature::Bytes(v) => RdFeature::Bytes {
                bytes: hex_encode(v),
                description,
            },
            Feature::Number(v) => RdFeature::Number {
                number: (*v).into(),
                description,
            },
            Feature::Offset(v) => RdFeature::Offset {
                offset: *v,
                description,
            },
            Feature::OperandNumber(index, v) => RdFeature::OperandNumber {
                index: *index as i64,
                operand_number: (*v).into(),
                description,
            },
            Feature::OperandOffset(index, v) => RdFeature::OperandOffset {
                index: *index as i64,
                operand_offset: *v,
                description,
            },
            Feature::Mnemonic(v) => RdFeature::Mnemonic {
                mnemonic: v.clone(),
                description,
            },
            Feature::Characteristic(v) => RdFeature::Characteristic {
                characteristic: v.clone(),
                description,
            },
            Feature::Section(v) => RdFeature::Section {
                section: v.clone(),
                description,
            },
            Feature::Import(v) => RdFeature::Import {
                import_: v.clone(),
                description,
            },
            Feature::Export(v) => RdFeature::Export {
                export: v.clone(),
                description,
            },
            Feature::FunctionName(v) => RdFeature::FunctionName {
                function_name: v.clone(),
                description,
            },
            Feature::Class(v) => RdFeature::Class {
                class_: v.clone(),
                description,
            },
            Feature::Namespace(v) => RdFeature::Namespace {
                namespace: v.clone(),
                description,
            },
            Feature::Property { name, access } => RdFeature::Property {
                access: access.map(|a: Access| a.as_str().to_string()),
                property: name.clone(),
                description,
            },
            Feature::Os(v) => RdFeature::Os {
                os: v.clone(),
                description,
            },
            Feature::Arch(v) => RdFeature::Arch {
                arch: v.clone(),
                description,
            },
            Feature::Format(v) => RdFeature::Format {
                format: v.clone(),
                description,
            },
            Feature::MatchedRule(v) => RdFeature::Match {
                match_: v.clone(),
                description,
            },
            Feature::BasicBlock => RdFeature::BasicBlock { description },
            Feature::Com(kind, _) => {
                return Err(format!(
                    "cannot render a `com/{}` feature directly -- COM features must be expanded before matching",
                    match kind {
                        ComKind::Class => "class",
                        ComKind::Interface => "interface",
                    }
                ))
            }
        })
    }
}

/// lowercase hex, matching Python's `bytes.hex()`.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::features::StringFeature;

    #[test]
    fn import_uses_attribute_name_not_alias() {
        let f =
            RdFeature::from_engine(&Feature::Import("kernel32.CreateFileA".into()), None).unwrap();
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(
            json,
            r#"{"type":"import","import_":"kernel32.CreateFileA"}"#
        );
    }

    #[test]
    fn description_is_omitted_when_none() {
        let f = RdFeature::from_engine(&Feature::Api("CreateFileA".into()), None).unwrap();
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"type":"api","api":"CreateFileA"}"#);
    }

    #[test]
    fn description_is_included_when_present() {
        let f = RdFeature::from_engine(
            &Feature::Api("CreateFileA".into()),
            Some("opens a file".into()),
        )
        .unwrap();
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(
            json,
            r#"{"type":"api","api":"CreateFileA","description":"opens a file"}"#
        );
    }

    #[test]
    fn number_preserves_int_vs_float_lexically() {
        let int_f =
            RdFeature::from_engine(&Feature::Number(crate::features::NumberValue::Int(6)), None)
                .unwrap();
        assert_eq!(
            serde_json::to_string(&int_f).unwrap(),
            r#"{"type":"number","number":6}"#
        );

        let float_f = RdFeature::from_engine(
            &Feature::Number(crate::features::NumberValue::Float(6.0)),
            None,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(&float_f).unwrap(),
            r#"{"type":"number","number":6.0}"#
        );
    }

    #[test]
    fn deserializing_a_large_plain_integer_does_not_become_a_float() {
        // regression: `#[serde(untagged)]`'s internal `Content` buffering
        // has no i128 slot (serde 1.0.229), so a naive untagged
        // `Deserialize` derive silently promoted plain integers like
        // `0xfffffff5` (4294967285, from a real capa-rules `number:`
        // literal) to `RdNumber::Float` on the way in -- caught by the
        // schema round-trip test against real `capa -j` output.
        let f: RdFeature =
            serde_json::from_str(r#"{"type":"number","number":4294967285}"#).unwrap();
        assert_eq!(
            f,
            RdFeature::Number {
                number: RdNumber::Int(4294967285),
                description: None,
            }
        );
    }

    #[test]
    fn com_feature_errors_instead_of_silently_dropping() {
        let err = RdFeature::from_engine(
            &Feature::Com(crate::features::ComKind::Class, "Foo".into()),
            None,
        )
        .unwrap_err();
        assert!(err.contains("com/class"));
    }

    #[test]
    fn basic_block_has_no_value_field() {
        let f = RdFeature::from_engine(&Feature::BasicBlock, None).unwrap();
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            r#"{"type":"basic block"}"#
        );
    }

    #[test]
    fn round_trips_regex_and_class_through_deserialize() {
        let re = crate::features::CompiledRegex::compile("/foo.*/i").unwrap();
        for f in [
            Feature::String(StringFeature::Regex(re)),
            Feature::Class("System.Net.WebClient".into()),
        ] {
            let rd = RdFeature::from_engine(&f, Some("d".into())).unwrap();
            let json = serde_json::to_string(&rd).unwrap();
            let back: RdFeature = serde_json::from_str(&json).unwrap();
            assert_eq!(rd, back);
        }
    }
}
