//! `Rule::from_yaml` / `Rule::from_dict` + meta validation. Ported from
//! `capa.rules.Rule.from_yaml` / `Rule.from_dict` and the meta fields
//! `capa/render/result_document.py::RuleMetadata` requires.

use serde_yaml::Value;

use crate::rules::grammar::build_statements;
use crate::rules::{Rule, RuleError, RuleMeta, Scopes};

pub fn rule_from_yaml(s: &str) -> Result<Rule, RuleError> {
    let doc: Value = serde_yaml::from_str(s).map_err(|e| RuleError::Yaml(e.to_string()))?;

    let Value::Mapping(doc_map) = &doc else {
        return Err(RuleError::invalid("empty or invalid YAML document"));
    };
    let Some(Value::Mapping(rule_map)) = doc_map.get("rule") else {
        return Err(RuleError::invalid("empty or invalid YAML document"));
    };

    // upstream fetches `d["rule"]["meta"]` and `d["rule"]["features"]` with
    // bare indexing, which raises an uncaught `KeyError` if either is
    // missing -- a crash upstream never intends to be reachable (every real
    // rule has both). Per this project's "no panics on untrusted input"
    // rule, a missing key becomes a clean, contextual error here instead.
    let Some(Value::Mapping(meta_map)) = rule_map.get("meta") else {
        return Err(RuleError::invalid(
            "rule.meta is required and must be a mapping",
        ));
    };
    let Some(Value::Sequence(features)) = rule_map.get("features") else {
        return Err(RuleError::invalid(
            "rule.features is required and must be a list",
        ));
    };

    let name = string_field(meta_map, "name")?
        .ok_or_else(|| RuleError::invalid("rule.meta.name is required"))?;

    if meta_map.contains_key("scope") {
        return Err(RuleError::invalid(format!(
            "legacy rule detected (rule.meta.scope), please update to the new syntax: {name}"
        )));
    }
    let Some(scopes_value) = meta_map.get("scopes") else {
        return Err(RuleError::invalid(
            "please specify at least one of this rule's (static/dynamic) scopes",
        ));
    };
    let Value::Mapping(scopes_map) = scopes_value else {
        return Err(RuleError::invalid(
            "the scopes field must contain a dictionary specifying the scopes",
        ));
    };
    let scopes = Scopes::from_dict(scopes_map)?;

    if features.len() != 1 {
        return Err(RuleError::invalid(
            "rule must begin with a single top level statement",
        ));
    }
    // Note: upstream also has a check here -- `isinstance(statements[0], ceng.Subscope)`
    // -- meant to reject a top-level subscope. But at that point `statements[0]`
    // is still a raw YAML dict, never a built `Subscope` instance, so the
    // check is dead code that can never fire. Not replicated, to match
    // upstream's actual (permissive) behavior rather than its stated intent.
    let Value::Mapping(top_stmt) = &features[0] else {
        return Err(RuleError::invalid(
            "rule's top level statement must be a mapping",
        ));
    };

    let attack = list_of_strings_or_empty(meta_map, "att&ck", "ATT&CK mapping must be a list")?;
    let mbc = list_of_strings_or_empty(meta_map, "mbc", "MBC mapping must be a list")?;
    let authors = list_of_strings_or_empty(meta_map, "authors", "authors must be a list")?;
    let references = list_of_strings_or_empty(meta_map, "references", "references must be a list")?;
    let examples = list_of_strings_or_empty(meta_map, "examples", "examples must be a list")?;
    let namespace = string_field(meta_map, "namespace")?;
    let description = string_field(meta_map, "description")?.unwrap_or_default();
    let lib = meta_map
        .get("lib")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let body = build_statements(top_stmt, scopes)?;

    let meta = RuleMeta {
        name: name.clone(),
        namespace: namespace.clone(),
        authors,
        description,
        lib,
        attack,
        mbc,
        references,
        examples,
        raw: meta_map.clone(),
    };

    Ok(Rule {
        name,
        namespace,
        meta,
        scopes,
        body,
        is_lib: lib,
        source: s.to_string(),
    })
}

fn string_field(map: &serde_yaml::Mapping, key: &str) -> Result<Option<String>, RuleError> {
    match map.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(other) => Err(RuleError::invalid(format!(
            "rule.meta.{key} must be a string, got: {other:?}"
        ))),
    }
}

/// mirrors `if not isinstance(meta.get(key, []), list): raise InvalidRule(msg)`,
/// then converts every element to a string.
fn list_of_strings_or_empty(
    map: &serde_yaml::Mapping,
    key: &str,
    type_error_msg: &str,
) -> Result<Vec<String>, RuleError> {
    match map.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Sequence(items)) => items
            .iter()
            .map(|v| match v {
                Value::String(s) => Ok(s.clone()),
                Value::Number(n) => Ok(n.to_string()),
                other => Err(RuleError::invalid(format!(
                    "rule.meta.{key} entries must be strings, got: {other:?}"
                ))),
            })
            .collect(),
        Some(_) => Err(RuleError::invalid(type_error_msg)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::rules::Rule;

    const VALID: &str = "rule:\n  meta:\n    name: t\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - api: CreateFileA\n";

    #[test]
    fn valid_rule_parses() {
        let r = Rule::from_yaml(VALID).unwrap();
        assert_eq!(r.name, "t");
        assert_eq!(r.meta.authors, vec!["t".to_string()]);
        assert!(!r.is_lib);
    }

    #[test]
    fn missing_name_is_an_error() {
        let doc = "rule:\n  meta:\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - api: CreateFileA\n";
        assert!(Rule::from_yaml(doc).is_err());
    }

    #[test]
    fn legacy_scope_key_is_rejected() {
        let doc = "rule:\n  meta:\n    name: t\n    authors: [t]\n    scope: function\n  features:\n    - api: CreateFileA\n";
        let err = Rule::from_yaml(doc).unwrap_err();
        assert!(
            err.to_string().contains("legacy rule detected"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn missing_scopes_is_an_error() {
        let doc =
            "rule:\n  meta:\n    name: t\n    authors: [t]\n  features:\n    - api: CreateFileA\n";
        assert!(Rule::from_yaml(doc).is_err());
    }

    #[test]
    fn both_scopes_unsupported_is_an_error() {
        let doc =
            "rule:\n  meta:\n    name: t\n    authors: [t]\n    scopes:\n      static: unsupported\n      dynamic: unsupported\n  features:\n    - api: CreateFileA\n";
        assert!(Rule::from_yaml(doc).is_err());
    }

    #[test]
    fn attack_must_be_a_list() {
        let doc = "rule:\n  meta:\n    name: t\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n    att&ck: not-a-list\n  features:\n    - api: CreateFileA\n";
        let err = Rule::from_yaml(doc).unwrap_err();
        assert!(
            err.to_string().contains("ATT&CK"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wrong_top_level_statement_count_is_an_error() {
        let doc = "rule:\n  meta:\n    name: t\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - api: CreateFileA\n    - api: WriteFile\n";
        assert!(Rule::from_yaml(doc).is_err());
    }

    #[test]
    fn lib_flag_and_namespace_are_captured() {
        let doc = "rule:\n  meta:\n    name: t\n    namespace: a/b\n    authors: [t]\n    lib: true\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - api: CreateFileA\n";
        let r = Rule::from_yaml(doc).unwrap();
        assert!(r.is_lib);
        assert_eq!(r.namespace.as_deref(), Some("a/b"));
    }
}
