//! `-vv` text renderer, ported from `capa/render/vverbose.py`. Renders the
//! full match-logic tree per match location. See `render::utils`'s doc
//! comment: content/order/addresses match upstream, not exact `rich`
//! formatting (box-drawing, call-argument line-wrapping, etc.).

use std::fmt::Write as _;

use crate::rd::{
    DynamicLayout, Flavor, Match, Node, RdAddress, RdFeature, ResultDocument, Statement,
};

use super::utils;
use super::verbose::{render_meta, render_process, render_thread};

const MODE_SUCCESS: bool = true;
const MODE_FAILURE: bool = false;

fn render_locations(layout: Option<&DynamicLayout>, locations: &[RdAddress], out: &mut String) {
    if locations.is_empty() {
        return;
    }
    let mut sorted: Vec<&RdAddress> = locations.iter().collect();
    sorted.sort();
    let rendered: Vec<String> = sorted
        .iter()
        .map(|loc| match (layout, loc.kind.as_str()) {
            (Some(layout), "call") => render_thread(layout, &call_thread_addr(loc)),
            _ => utils::format_address(loc),
        })
        .collect();
    let _ = write!(out, " @ {}", rendered.join(", "));
}

fn call_thread_addr(addr: &RdAddress) -> RdAddress {
    match &addr.value {
        Some(crate::rd::AddressValue::Tuple(t)) if t.len() >= 3 => RdAddress {
            kind: "thread".to_string(),
            value: Some(crate::rd::AddressValue::Tuple(vec![t[0], t[1], t[2]])),
        },
        _ => addr.clone(),
    }
}

fn render_statement(
    layout: Option<&DynamicLayout>,
    m: &Match,
    statement: &Statement,
    indent: usize,
    out: &mut String,
) {
    let pad = "  ".repeat(indent);
    match statement {
        Statement::Subscope { description, scope } => {
            let _ = write!(out, "{pad}{scope}:");
            if let Some(d) = description {
                let _ = write!(out, " = {d}");
            }
            let _ = writeln!(out);
        }
        Statement::And { description }
        | Statement::Or { description }
        | Statement::Not { description }
        | Statement::Optional { description } => {
            let _ = write!(out, "{pad}{}:", statement.type_name());
            if let Some(d) = description {
                let _ = write!(out, " = {d}");
            }
            let _ = writeln!(out);
        }
        Statement::Some { description, count } => {
            let _ = write!(out, "{pad}{count} or more:");
            if let Some(d) = description {
                let _ = write!(out, " = {d}");
            }
            let _ = writeln!(out);
        }
        Statement::Range {
            description,
            min,
            max,
            child,
        } => {
            let value = feature_value_str(child);
            let _ = write!(out, "{pad}count({}", child.type_name());
            if let Some(v) = &value {
                let _ = write!(out, "({v})");
            }
            let _ = write!(out, "): ");
            if max == min {
                let _ = write!(out, "{min}");
            } else if *min == 0 {
                let _ = write!(out, "{max} or fewer");
            } else if *max == u64::MAX {
                let _ = write!(out, "{min} or more");
            } else {
                let _ = write!(out, "between {min} and {max}");
            }
            if let Some(d) = description {
                let _ = write!(out, " = {d}");
            }
            render_locations(layout, &m.locations, out);
            let _ = writeln!(out);
        }
    }
}

/// the feature's own value as a display string, if it has one (e.g.
/// `api(x)` -> `"x"`; `basic block` -> `None`).
fn feature_value_str(f: &RdFeature) -> Option<String> {
    Some(match f {
        RdFeature::Os { os, .. } => os.clone(),
        RdFeature::Arch { arch, .. } => arch.clone(),
        RdFeature::Format { format, .. } => format.clone(),
        RdFeature::Match { match_, .. } => match_.clone(),
        RdFeature::Characteristic { characteristic, .. } => characteristic.clone(),
        RdFeature::Export { export, .. } => export.clone(),
        RdFeature::Import { import_, .. } => import_.clone(),
        RdFeature::Section { section, .. } => section.clone(),
        RdFeature::FunctionName { function_name, .. } => function_name.clone(),
        RdFeature::Substring { substring, .. } => format!("\"{substring}\""),
        RdFeature::Regex { regex, .. } => regex.clone(),
        RdFeature::String { string, .. } => format!("\"{string}\""),
        RdFeature::Class { class_, .. } => class_.clone(),
        RdFeature::Namespace { namespace, .. } => namespace.clone(),
        RdFeature::BasicBlock { .. } => return None,
        RdFeature::Api { api, .. } => api.clone(),
        RdFeature::Property { property, .. } => property.clone(),
        RdFeature::Number { number, .. } => match number {
            crate::rd::RdNumber::Int(v) => utils::hex(*v),
            crate::rd::RdNumber::Float(v) => v.to_string(),
        },
        RdFeature::Bytes { bytes, .. } => bytes.clone(),
        RdFeature::Offset { offset, .. } => utils::hex(*offset as i128),
        RdFeature::Mnemonic { mnemonic, .. } => mnemonic.clone(),
        RdFeature::OperandNumber { operand_number, .. } => match operand_number {
            crate::rd::RdNumber::Int(v) => utils::hex(*v),
            crate::rd::RdNumber::Float(v) => v.to_string(),
        },
        RdFeature::OperandOffset { operand_offset, .. } => utils::hex(*operand_offset as i128),
    })
}

fn feature_key(f: &RdFeature) -> String {
    match f {
        RdFeature::Property {
            access: Some(a), ..
        } => format!("property/{a}"),
        RdFeature::OperandNumber { index, .. } => format!("operand[{index}].number"),
        RdFeature::OperandOffset { index, .. } => format!("operand[{index}].offset"),
        other => other.type_name().to_string(),
    }
}

fn render_feature(
    layout: Option<&DynamicLayout>,
    m: &Match,
    feature: &RdFeature,
    indent: usize,
    out: &mut String,
) {
    let pad = "  ".repeat(indent);
    let key = feature_key(feature);

    if let RdFeature::Regex { regex, description }
    | RdFeature::Substring {
        substring: regex,
        description,
    } = feature
    {
        let _ = write!(out, "{pad}{key}: ");
        let _ = writeln!(
            out,
            "\"{regex}\"{}",
            description
                .as_deref()
                .map(|d| format!(" = {d}"))
                .unwrap_or_default()
        );
        for (capture, locations) in &m.captures {
            let _ = write!(out, "{}  - \"{capture}\"", "  ".repeat(indent));
            render_locations(layout, locations, out);
            let _ = writeln!(out);
        }
        return;
    }

    let value = feature_value_str(feature);
    let _ = write!(out, "{pad}{key}: ");
    if let Some(v) = &value {
        let _ = write!(out, "{v}");
    }
    if let Some(d) = feature.description() {
        let _ = write!(out, " = {d}");
    }
    if !matches!(
        feature,
        RdFeature::Os { .. } | RdFeature::Arch { .. } | RdFeature::Format { .. }
    ) {
        render_locations(layout, &m.locations, out);
    }
    let _ = writeln!(out);
}

fn render_node(layout: Option<&DynamicLayout>, m: &Match, indent: usize, out: &mut String) {
    match &m.node {
        Node::Statement { statement } => render_statement(layout, m, statement, indent, out),
        Node::Feature { feature } => render_feature(layout, m, feature, indent, out),
    }
}

fn render_match(
    layout: Option<&DynamicLayout>,
    m: &Match,
    indent: usize,
    mode: bool,
    out: &mut String,
) {
    let mut child_mode = mode;
    if mode == MODE_SUCCESS {
        if !m.success {
            return;
        }
        if let Node::Statement {
            statement: Statement::Optional { .. },
        } = &m.node
        {
            if !m.children.iter().any(|c| c.success) {
                return;
            }
        }
        if let Node::Statement {
            statement: Statement::Not { .. },
        } = &m.node
        {
            child_mode = MODE_FAILURE;
        }
    } else {
        if m.success {
            return;
        }
        if let Node::Statement {
            statement: Statement::Optional { .. },
        } = &m.node
        {
            if m.children.iter().any(|c| c.success) {
                return;
            }
        }
        if let Node::Statement {
            statement: Statement::Not { .. },
        } = &m.node
        {
            child_mode = MODE_SUCCESS;
        }
    }

    render_node(layout, m, indent, out);
    for child in &m.children {
        render_match(layout, child, indent + 1, child_mode, out);
    }
}

fn render_rules(doc: &ResultDocument, out: &mut String) {
    let mut had_match = false;

    for rule in utils::sort_rules(doc) {
        if rule.meta.is_subscope_rule {
            continue;
        }

        let count = rule.matches.len();
        let lib_info = if rule.meta.lib {
            if count == 1 {
                " (library rule)".to_string()
            } else {
                ", only showing first match of library rule".to_string()
            }
        } else {
            String::new()
        };
        let capability = if count == 1 {
            format!("{}{lib_info}", rule.meta.name)
        } else {
            format!("{} ({count} matches{lib_info})", rule.meta.name)
        };
        let _ = writeln!(out, "{capability}");
        had_match = true;

        if !rule.meta.lib {
            if let Some(ns) = &rule.meta.namespace {
                let _ = writeln!(out, "  namespace              {ns}");
            }
        }
        if let Some(c) = rule.meta.maec.analysis_conclusion.as_ref().or(rule
            .meta
            .maec
            .analysis_conclusion_ov
            .as_ref())
        {
            let _ = writeln!(out, "  maec/analysis-conclusion {c}");
        }
        if let Some(f) = &rule.meta.maec.malware_family {
            let _ = writeln!(out, "  maec/malware-family    {f}");
        }
        if let Some(c) = rule.meta.maec.malware_category.as_ref().or(rule
            .meta
            .maec
            .malware_category_ov
            .as_ref())
        {
            let _ = writeln!(out, "  maec/malware-category  {c}");
        }
        let _ = writeln!(
            out,
            "  author                 {}",
            rule.meta.authors.join(", ")
        );

        let scope = match doc.meta.flavor() {
            Flavor::Static => rule.meta.scopes.static_.as_deref(),
            Flavor::Dynamic => rule.meta.scopes.dynamic.as_deref(),
        };
        if let Some(scope) = scope {
            let _ = writeln!(out, "  scope                  {scope}");
        }
        if !rule.meta.attack.is_empty() {
            let s: Vec<String> = rule.meta.attack.iter().map(utils::format_attack).collect();
            let _ = writeln!(out, "  att&ck                 {}", s.join(", "));
        }
        if !rule.meta.mbc.is_empty() {
            let s: Vec<String> = rule.meta.mbc.iter().map(utils::format_mbc).collect();
            let _ = writeln!(out, "  mbc                    {}", s.join(", "));
        }
        if !rule.meta.references.is_empty() {
            let _ = writeln!(
                out,
                "  references             {}",
                rule.meta.references.join(", ")
            );
        }
        if !rule.meta.description.is_empty() {
            let _ = writeln!(out, "  description            {}", rule.meta.description);
        }

        let is_file_scope = rule.meta.scopes.static_.as_deref() == Some("file")
            || rule.meta.scopes.dynamic.as_deref() == Some("file");

        let layout: Option<&DynamicLayout> = match &doc.meta {
            crate::rd::Metadata::Dynamic { analysis, .. } => Some(&analysis.layout),
            crate::rd::Metadata::Static { .. } => None,
        };

        if is_file_scope {
            if let Some((_, m)) = rule.matches.first() {
                render_match(layout, m, 0, MODE_SUCCESS, out);
            }
        } else {
            for (location, m) in &rule.matches {
                match doc.meta.flavor() {
                    Flavor::Static => {
                        let _ = write!(
                            out,
                            "{} @ {}",
                            rule.meta.scopes.static_.as_deref().unwrap_or(""),
                            utils::format_address(location)
                        );
                    }
                    Flavor::Dynamic => {
                        let scope = rule.meta.scopes.dynamic.as_deref().unwrap_or("");
                        let rendered = match (scope, layout) {
                            ("process", Some(l)) => render_process(l, location),
                            ("thread", Some(l)) => render_thread(l, location),
                            ("call", Some(l)) | ("span of calls", Some(l)) => {
                                render_thread(l, &call_thread_addr(location))
                            }
                            _ => utils::format_address(location),
                        };
                        let _ = write!(out, "{scope} @ {rendered}");
                    }
                }
                let _ = writeln!(out);
                render_match(layout, m, 1, MODE_SUCCESS, out);
                if rule.meta.lib {
                    break;
                }
            }
        }
        let _ = writeln!(out);
    }

    if !had_match {
        let _ = writeln!(out, "no capabilities found");
    }
}

/// port of `vverbose.render`.
pub fn render(doc: &ResultDocument) -> String {
    let mut out = String::new();
    render_meta(doc, &mut out);
    let _ = writeln!(out);
    render_rules(doc, &mut out);
    out
}
