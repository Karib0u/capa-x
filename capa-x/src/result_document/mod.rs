//! The JSON result document, ported from `capa/render/result_document.py`
//! (+ `capa/features/freeze/{__init__,features}.py` for the `Address`/
//! `Feature` shapes it embeds). This is capa-x's `-j` output schema.
//!
//! Every type here mirrors a pydantic model field-for-field, including its
//! exact wire spelling (`#[serde(deny_unknown_fields)]` everywhere, so a
//! schema drift is a hard parse error, not a silently-dropped field -- see
//! the round-trip parity test in `tests/schema_roundtrip.rs`). `from_capa`
//! builds these from the matching engine's output; everything else here is a
//! plain data model with no matching logic of its own.

mod address;
mod feature;
mod from_capa;
mod meta;
mod tree;

pub use address::{AddressValue, RdAddress};
pub use feature::{RdFeature, RdNumber};
pub use from_capa::{
    build_dynamic_metadata, build_match, build_result_document, build_static_metadata,
    compute_dynamic_layout, compute_static_layout, rule_metadata, DynamicCounts, FromCapaError,
    MetaInputs, StaticCounts, ARCH_AUTO, OS_AUTO,
};
pub use meta::{
    Analysis, BasicBlockLayout, CallLayout, DynamicAnalysis, DynamicFeatureCounts, DynamicLayout,
    Flavor, FunctionFeatureCount, FunctionLayout, LibraryFunction, Metadata, ProcessFeatureCount,
    ProcessLayout, Sample, StaticAnalysis, StaticFeatureCounts, StaticLayout, ThreadLayout,
};
pub use tree::{
    parse_parts_id, AttackSpec, CompoundStatementType, MBCSpec, MaecMetadata, Match, Node,
    RdScopes, ResultDocument, RuleMatches, RuleMetadata, Statement,
};
