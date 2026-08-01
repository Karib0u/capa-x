//! Shared helpers for the text renderers, ported from `capa/render/utils.py`
//! and the `format_address`/`AttackSpec`/`MBCSpec` formatting bits of
//! `verbose.py`/`vverbose.py`.
//!
//! Text output is compared by content and order ("same
//! rules, same order, same addresses"), not exact box-drawing -- so this
//! renders plain indented text rather than reproducing `rich`'s tables.

use crate::rd::{AddressValue, AttackSpec, MBCSpec, RdAddress, ResultDocument, RuleMatches};

/// port of `capa.helpers.hex`: uppercase, `0x`-prefixed, `-0x`-prefixed if negative.
pub fn hex(n: i128) -> String {
    if n < 0 {
        format!("-0x{:X}", -n)
    } else {
        format!("0x{n:X}")
    }
}

fn int_value(addr: &RdAddress) -> i128 {
    match &addr.value {
        Some(AddressValue::Int(v)) => *v as i128,
        _ => 0,
    }
}

fn tuple_value(addr: &RdAddress) -> Vec<u64> {
    match &addr.value {
        Some(AddressValue::Tuple(v)) => v.clone(),
        _ => Vec::new(),
    }
}

/// port of `verbose.format_address`.
pub fn format_address(addr: &RdAddress) -> String {
    match addr.kind.as_str() {
        "absolute" => hex(int_value(addr)),
        "relative" => format!("base address+{}", hex(int_value(addr))),
        "file" => format!("file+{}", hex(int_value(addr))),
        "dn token" => format!("token({})", hex(int_value(addr))),
        "dn token offset" => {
            let t = tuple_value(addr);
            let token = t.first().copied().unwrap_or(0);
            let offset = t.get(1).copied().unwrap_or(0);
            format!("token({})+{}", hex(token as i128), hex(offset as i128))
        }
        "process" => {
            let t = tuple_value(addr);
            let pid = t.get(1).copied().unwrap_or(0);
            format!("process{{pid:{pid}}}")
        }
        "thread" => {
            let t = tuple_value(addr);
            let pid = t.get(1).copied().unwrap_or(0);
            let tid = t.get(2).copied().unwrap_or(0);
            format!("process{{pid:{pid},tid:{tid}}}")
        }
        "call" => {
            let t = tuple_value(addr);
            let pid = t.get(1).copied().unwrap_or(0);
            let tid = t.get(2).copied().unwrap_or(0);
            let id = t.get(3).copied().unwrap_or(0);
            format!("process{{pid:{pid},tid:{tid},call:{id}}}")
        }
        "no address" => "global".to_string(),
        other => format!("<unknown address type {other}>"),
    }
}

/// port of `rutils.format_parts_id`.
pub fn format_attack(spec: &AttackSpec) -> String {
    format!("{} [{}]", spec.parts.join("::"), spec.id)
}

pub fn format_mbc(spec: &MBCSpec) -> String {
    format!("{} [{}]", spec.parts.join("::"), spec.id)
}

/// port of `rutils.sort_rules`: (namespace, name) order.
pub fn sort_rules(doc: &ResultDocument) -> Vec<&RuleMatches> {
    let mut rules: Vec<&RuleMatches> = doc.rules.values().collect();
    rules.sort_by(|a, b| {
        let ka = (
            a.meta.namespace.as_deref().unwrap_or(""),
            a.meta.name.as_str(),
        );
        let kb = (
            b.meta.namespace.as_deref().unwrap_or(""),
            b.meta.name.as_str(),
        );
        ka.cmp(&kb)
    });
    rules
}

/// port of `rutils.capability_rules`.
pub fn capability_rules(doc: &ResultDocument) -> Vec<&RuleMatches> {
    sort_rules(doc)
        .into_iter()
        .filter(|r| {
            !r.meta.lib
                && !r
                    .meta
                    .namespace
                    .as_deref()
                    .unwrap_or("")
                    .starts_with("internal/")
                && !r.meta.is_subscope_rule
                && r.meta.maec.analysis_conclusion.is_none()
                && r.meta.maec.analysis_conclusion_ov.is_none()
                && r.meta.maec.malware_family.is_none()
                && r.meta.maec.malware_category.is_none()
                && r.meta.maec.malware_category_ov.is_none()
        })
        .collect()
}

/// port of `rutils.maec_rules`.
pub fn maec_rules(doc: &ResultDocument) -> Vec<&RuleMatches> {
    doc.rules
        .values()
        .filter(|r| {
            r.meta.maec.analysis_conclusion.is_some()
                || r.meta.maec.analysis_conclusion_ov.is_some()
                || r.meta.maec.malware_family.is_some()
                || r.meta.maec.malware_category.is_some()
                || r.meta.maec.malware_category_ov.is_some()
        })
        .collect()
}

/// port of `default.find_subrule_matches`: rule names referenced by a
/// successful `match:` feature elsewhere in the document, which the default
/// (non-verbose) view hides to cut down on redundant output (#224).
pub fn find_subrule_matches(doc: &ResultDocument) -> std::collections::HashSet<String> {
    use crate::rd::{Node, RdFeature};

    fn rec(m: &crate::rd::Match, out: &mut std::collections::HashSet<String>) {
        if !m.success {
            return;
        }
        match &m.node {
            Node::Statement { .. } => {
                for child in &m.children {
                    rec(child, out);
                }
            }
            Node::Feature {
                feature: RdFeature::Match { match_, .. },
            } => {
                out.insert(match_.clone());
            }
            Node::Feature { .. } => {}
        }
    }

    let mut out = std::collections::HashSet::new();
    for rule in capability_rules(doc) {
        for (_, m) in &rule.matches {
            rec(m, &mut out);
        }
    }
    out
}
