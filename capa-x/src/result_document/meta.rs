//! `meta` section of the result document: `Sample`, `*Layout`, `*FeatureCounts`,
//! `*Analysis`, `Metadata`. Ported from `capa/render/result_document.py`.

use serde::{Deserialize, Serialize};

use super::address::RdAddress;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicBlockLayout {
    pub address: RdAddress,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionLayout {
    pub address: RdAddress,
    pub matched_basic_blocks: Vec<BasicBlockLayout>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallLayout {
    pub address: RdAddress,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadLayout {
    pub address: RdAddress,
    pub matched_calls: Vec<CallLayout>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessLayout {
    pub address: RdAddress,
    pub name: String,
    pub matched_threads: Vec<ThreadLayout>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticLayout {
    pub functions: Vec<FunctionLayout>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicLayout {
    pub processes: Vec<ProcessLayout>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryFunction {
    pub address: RdAddress,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionFeatureCount {
    pub address: RdAddress,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessFeatureCount {
    pub address: RdAddress,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticFeatureCounts {
    pub file: u64,
    pub functions: Vec<FunctionFeatureCount>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicFeatureCounts {
    pub file: u64,
    pub processes: Vec<ProcessFeatureCount>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticAnalysis {
    pub format: String,
    pub arch: String,
    pub os: String,
    pub extractor: String,
    pub rules: Vec<String>,
    pub base_address: RdAddress,
    pub layout: StaticLayout,
    pub feature_counts: StaticFeatureCounts,
    pub library_functions: Vec<LibraryFunction>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicAnalysis {
    pub format: String,
    pub arch: String,
    pub os: String,
    pub extractor: String,
    pub rules: Vec<String>,
    pub layout: DynamicLayout,
    pub feature_counts: DynamicFeatureCounts,
}

/// `Union[StaticAnalysis, DynamicAnalysis]`, discriminated in practice by
/// the enclosing `Metadata.flavor` -- see that type.
#[derive(Debug, Clone, PartialEq)]
pub enum Analysis {
    Static(StaticAnalysis),
    Dynamic(DynamicAnalysis),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Flavor {
    #[serde(rename = "static")]
    Static,
    #[serde(rename = "dynamic")]
    Dynamic,
}

/// mirrors `StaticMetadata`/`DynamicMetadata` (subclasses of the base
/// `Metadata` pydantic model that fix `flavor`/`analysis`'s type). Modeled
/// here as a single Rust enum internally tagged by `flavor`, since that's
/// the only field whose value actually depends on which subclass produced
/// it -- `timestamp`/`version`/`argv`/`sample` are identical either way.
///
/// Field order on the wire differs from pydantic's (`timestamp, version,
/// argv, sample, flavor, analysis` -- `flavor` in the middle): serde always
/// emits an internally-tagged enum's tag first. This is invisible to any
/// JSON-object-based comparison (dict equality ignores key order), which is
/// the only way this document is ever consumed (`capa Explorer Web`,
/// `scripts/difftest.py`, `ResultDocument::from_json`), so it's not
/// replicated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "flavor", deny_unknown_fields)]
pub enum Metadata {
    #[serde(rename = "static")]
    Static {
        timestamp: String,
        version: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        argv: Option<Vec<String>>,
        sample: Sample,
        analysis: StaticAnalysis,
    },
    #[serde(rename = "dynamic")]
    Dynamic {
        timestamp: String,
        version: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        argv: Option<Vec<String>>,
        sample: Sample,
        analysis: DynamicAnalysis,
    },
}

impl Metadata {
    pub fn flavor(&self) -> Flavor {
        match self {
            Metadata::Static { .. } => Flavor::Static,
            Metadata::Dynamic { .. } => Flavor::Dynamic,
        }
    }

    pub fn sample(&self) -> &Sample {
        match self {
            Metadata::Static { sample, .. } => sample,
            Metadata::Dynamic { sample, .. } => sample,
        }
    }

    pub fn analysis(&self) -> Analysis {
        match self {
            Metadata::Static { analysis, .. } => Analysis::Static(analysis.clone()),
            Metadata::Dynamic { analysis, .. } => Analysis::Dynamic(analysis.clone()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn static_metadata_round_trips() {
        let meta = Metadata::Static {
            timestamp: "2024-01-01T00:00:00".to_string(),
            version: "0.1.0".to_string(),
            argv: Some(vec!["capa".to_string(), "sample.exe".to_string()]),
            sample: Sample {
                md5: "a".repeat(32),
                sha1: "b".repeat(40),
                sha256: "c".repeat(64),
                path: "/tmp/sample.exe".to_string(),
            },
            analysis: StaticAnalysis {
                format: "pe".to_string(),
                arch: "amd64".to_string(),
                os: "windows".to_string(),
                extractor: "NullStaticFeatureExtractor".to_string(),
                rules: vec!["/rules".to_string()],
                base_address: RdAddress::from(crate::address::Address::Absolute(0x400000)),
                layout: StaticLayout { functions: vec![] },
                feature_counts: StaticFeatureCounts {
                    file: 10,
                    functions: vec![],
                },
                library_functions: vec![],
            },
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: Metadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, back);
        assert_eq!(meta.flavor(), Flavor::Static);
    }
}
