//! Match tree (`Node`/`Statement`/`Match`) and rule metadata
//! (`RuleMetadata`/`AttackSpec`/`MBCSpec`/`MaecMetadata`/`RuleMatches`), plus
//! the top-level `ResultDocument`. Ported from
//! `capa/render/result_document.py`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::address::RdAddress;
use super::feature::RdFeature;
use super::meta::Metadata;

/// `capa.rules.Scopes`, dumped as a plain dataclass: field names `static`/
/// `dynamic` (not aliased), each the scope's string value or omitted when
/// `None` (`exclude_none` applies recursively).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RdScopes {
    #[serde(rename = "static", default, skip_serializing_if = "Option::is_none")]
    pub static_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic: Option<String>,
}

/// `CompoundStatementType`: the four `type` values a `CompoundStatement`
/// (i.e. not `some`/`range`/`subscope`) can carry.
pub struct CompoundStatementType;
impl CompoundStatementType {
    pub const AND: &'static str = "and";
    pub const OR: &'static str = "or";
    pub const NOT: &'static str = "not";
    pub const OPTIONAL: &'static str = "optional";
}

/// mirrors the `Statement` union (`StatementModel` subclasses). Represented
/// as one internally-tagged enum with a concrete variant per `type` value
/// upstream actually produces (`statement_from_capa` never emits a
/// `CompoundStatement` with any `type` other than these four), rather than
/// replicating pydantic's untagged `type: str` on `CompoundStatement`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Statement {
    #[serde(rename = "and")]
    And {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "or")]
    Or {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "not")]
    Not {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "optional")]
    Optional {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    #[serde(rename = "some")]
    Some {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        count: u64,
    },
    #[serde(rename = "range")]
    Range {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        min: u64,
        max: u64,
        child: RdFeature,
    },
    #[serde(rename = "subscope")]
    Subscope {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        scope: String,
    },
}

impl Statement {
    pub fn type_name(&self) -> &'static str {
        match self {
            Statement::And { .. } => CompoundStatementType::AND,
            Statement::Or { .. } => CompoundStatementType::OR,
            Statement::Not { .. } => CompoundStatementType::NOT,
            Statement::Optional { .. } => CompoundStatementType::OPTIONAL,
            Statement::Some { .. } => "some",
            Statement::Range { .. } => "range",
            Statement::Subscope { .. } => "subscope",
        }
    }

    pub fn description(&self) -> Option<&str> {
        match self {
            Statement::And { description }
            | Statement::Or { description }
            | Statement::Not { description }
            | Statement::Optional { description }
            | Statement::Some { description, .. }
            | Statement::Range { description, .. }
            | Statement::Subscope { description, .. } => description.as_deref(),
        }
    }
}

/// `Node = Union[StatementNode, FeatureNode]`. Both variants declare their
/// own `type: Literal[...]` field (`"statement"` / `"feature"`), which is
/// what actually disambiguates them on the wire even though upstream never
/// wraps the union in `Field(discriminator=...)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Node {
    #[serde(rename = "statement")]
    Statement { statement: Statement },
    #[serde(rename = "feature")]
    Feature { feature: RdFeature },
}

/// mirrors `rd.Match`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    pub success: bool,
    pub node: Node,
    pub children: Vec<Match>,
    pub locations: Vec<RdAddress>,
    pub captures: BTreeMap<String, Vec<RdAddress>>,
}

/// given `Tactic::Technique::Subtechnique [Identifier]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttackSpec {
    pub parts: Vec<String>,
    pub tactic: String,
    pub technique: String,
    pub subtechnique: String,
    pub id: String,
}

/// given `Objective::Behavior::Method [Identifier]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MBCSpec {
    pub parts: Vec<String>,
    pub objective: String,
    pub behavior: String,
    pub method: String,
    pub id: String,
}

/// port of `parse_parts_id`: given `"Tactic::Technique [T1234.005]"`, splits
/// into (`["Tactic", "Technique"]`, `"T1234.005"`).
pub fn parse_parts_id(s: &str) -> (Vec<String>, String) {
    let mut parts: Vec<String> = s.split("::").map(str::to_string).collect();
    let mut id = String::new();
    if let Some(last) = parts.pop() {
        let (rest, id_part) = match last.rfind(' ') {
            Some(idx) => (last[..idx].to_string(), last[idx + 1..].to_string()),
            None => (String::new(), last.clone()),
        };
        id = id_part
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        parts.push(rest);
    }
    (parts, id)
}

impl AttackSpec {
    /// port of `AttackSpec.from_str` (named to match upstream's classmethod,
    /// not `std::str::FromStr` -- this never fails, so that trait doesn't fit).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> AttackSpec {
        let (parts, id) = parse_parts_id(s);
        AttackSpec {
            tactic: parts.first().cloned().unwrap_or_default(),
            technique: parts.get(1).cloned().unwrap_or_default(),
            subtechnique: parts.get(2).cloned().unwrap_or_default(),
            parts,
            id,
        }
    }
}

impl MBCSpec {
    /// port of `MBCSpec.from_str` (see `AttackSpec::from_str`'s doc comment).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> MBCSpec {
        let (parts, id) = parse_parts_id(s);
        MBCSpec {
            objective: parts.first().cloned().unwrap_or_default(),
            behavior: parts.get(1).cloned().unwrap_or_default(),
            method: parts.get(2).cloned().unwrap_or_default(),
            parts,
            id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaecMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_conclusion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_conclusion_ov: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub malware_family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub malware_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub malware_category_ov: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMetadata {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub authors: Vec<String>,
    pub scopes: RdScopes,
    /// wire key is `attack` (the attribute name -- `Field(alias="att&ck")`
    /// is never applied on dump).
    pub attack: Vec<AttackSpec>,
    pub mbc: Vec<MBCSpec>,
    pub references: Vec<String>,
    pub examples: Vec<String>,
    pub description: String,
    pub lib: bool,
    pub is_subscope_rule: bool,
    pub maec: MaecMetadata,
}

/// mirrors `rd.RuleMatches`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMatches {
    pub meta: RuleMetadata,
    pub source: String,
    /// `tuple[tuple[frz.Address, Match], ...]` -- an array of `[address,
    /// match]` pairs, *not* a map (a rule can match the same address more
    /// than once isn't possible, but the wire shape is a list of pairs
    /// regardless, and pydantic tuples serialize as JSON arrays).
    pub matches: Vec<(RdAddress, Match)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultDocument {
    pub meta: Metadata,
    pub rules: BTreeMap<String, RuleMatches>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_attack_spec_with_subtechnique() {
        let spec = AttackSpec::from_str(
            "Execution::Command and Scripting Interpreter::Python [T1059.006]",
        );
        assert_eq!(spec.tactic, "Execution");
        assert_eq!(spec.technique, "Command and Scripting Interpreter");
        assert_eq!(spec.subtechnique, "Python");
        assert_eq!(spec.id, "T1059.006");
        assert_eq!(
            spec.parts,
            vec![
                "Execution".to_string(),
                "Command and Scripting Interpreter".to_string(),
                "Python".to_string()
            ]
        );
    }

    #[test]
    fn parses_attack_spec_without_subtechnique() {
        let spec = AttackSpec::from_str("Discovery::File and Directory Discovery [T1083]");
        assert_eq!(spec.tactic, "Discovery");
        assert_eq!(spec.technique, "File and Directory Discovery");
        assert_eq!(spec.subtechnique, "");
        assert_eq!(spec.id, "T1083");
    }

    #[test]
    fn parses_mbc_spec() {
        let spec = MBCSpec::from_str("Collection::Input Capture::Mouse Events [E1056.m01]");
        assert_eq!(spec.objective, "Collection");
        assert_eq!(spec.behavior, "Input Capture");
        assert_eq!(spec.method, "Mouse Events");
        assert_eq!(spec.id, "E1056.m01");
    }

    #[test]
    fn node_tag_disambiguates_statement_vs_feature() {
        let stmt = Node::Statement {
            statement: Statement::And { description: None },
        };
        let json = serde_json::to_string(&stmt).unwrap();
        assert_eq!(json, r#"{"type":"statement","statement":{"type":"and"}}"#);
        let back: Node = serde_json::from_str(&json).unwrap();
        assert_eq!(stmt, back);
    }

    #[test]
    fn range_statement_embeds_the_counted_feature() {
        let stmt = Statement::Range {
            description: None,
            min: 2,
            max: u64::MAX,
            child: RdFeature::Api {
                api: "CreateFileA".into(),
                description: None,
            },
        };
        let json = serde_json::to_string(&stmt).unwrap();
        let back: Statement = serde_json::from_str(&json).unwrap();
        assert_eq!(stmt, back);
    }
}
