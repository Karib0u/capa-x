//! Default (non-verbose) text renderer, ported from `capa/render/default.py`.
//! Plain indented text, not `rich` tables -- see `render::utils`'s doc
//! comment for why.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::rd::{Flavor, ResultDocument};

use super::utils;

fn render_meta(doc: &ResultDocument, out: &mut String) {
    let sample = doc.meta.sample();
    let analysis = doc.meta.analysis();
    let (os, format, arch) = match &analysis {
        crate::rd::Analysis::Static(a) => (&a.os, &a.format, &a.arch),
        crate::rd::Analysis::Dynamic(a) => (&a.os, &a.format, &a.arch),
    };
    let flavor = match doc.meta.flavor() {
        Flavor::Static => "static",
        Flavor::Dynamic => "dynamic",
    };

    let _ = writeln!(out, "md5      {}", sample.md5);
    let _ = writeln!(out, "sha1     {}", sample.sha1);
    let _ = writeln!(out, "sha256   {}", sample.sha256);
    let _ = writeln!(out, "analysis {flavor}");
    let _ = writeln!(out, "os       {os}");
    let _ = writeln!(out, "format   {format}");
    let _ = writeln!(out, "arch     {arch}");
    let _ = writeln!(out, "path     {}", sample.path);
}

fn render_attack(doc: &ResultDocument, out: &mut String) {
    let mut tactics: BTreeMap<String, std::collections::BTreeSet<(String, String, String)>> =
        BTreeMap::new();
    for rule in utils::capability_rules(doc) {
        for attack in &rule.meta.attack {
            tactics.entry(attack.tactic.clone()).or_default().insert((
                attack.technique.clone(),
                attack.subtechnique.clone(),
                attack
                    .id
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string(),
            ));
        }
    }
    if tactics.is_empty() {
        return;
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "ATT&CK Tactic           ATT&CK Technique");
    for (tactic, techniques) in tactics {
        for (technique, subtechnique, id) in techniques {
            let label = if subtechnique.is_empty() {
                format!("{technique} [{id}]")
            } else {
                format!("{technique}::{subtechnique} [{id}]")
            };
            let _ = writeln!(out, "{:<24}{label}", tactic.to_uppercase());
        }
    }
}

fn render_mbc(doc: &ResultDocument, out: &mut String) {
    let mut objectives: BTreeMap<String, std::collections::BTreeSet<(String, String, String)>> =
        BTreeMap::new();
    for rule in utils::capability_rules(doc) {
        for mbc in &rule.meta.mbc {
            objectives
                .entry(mbc.objective.clone())
                .or_default()
                .insert((
                    mbc.behavior.clone(),
                    mbc.method.clone(),
                    mbc.id
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .to_string(),
                ));
        }
    }
    if objectives.is_empty() {
        return;
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "MBC Objective           MBC Behavior");
    for (objective, behaviors) in objectives {
        for (behavior, method, id) in behaviors {
            let label = if method.is_empty() {
                format!("{behavior} [{id}]")
            } else {
                format!("{behavior}::{method} [{id}]")
            };
            let _ = writeln!(out, "{:<24}{label}", objective.to_uppercase());
        }
    }
}

type MaecGetter = fn(&crate::rd::RuleMetadata) -> Option<&str>;

fn render_maec(doc: &ResultDocument, out: &mut String) {
    let categories: [(&str, MaecGetter); 5] = [
        ("analysis-conclusion", |m| {
            m.maec.analysis_conclusion.as_deref()
        }),
        ("analysis-conclusion-ov", |m| {
            m.maec.analysis_conclusion_ov.as_deref()
        }),
        ("malware-family", |m| m.maec.malware_family.as_deref()),
        ("malware-category", |m| m.maec.malware_category.as_deref()),
        ("malware-category-ov", |m| {
            m.maec.malware_category_ov.as_deref()
        }),
    ];

    let mut table: BTreeMap<&str, std::collections::BTreeSet<String>> = BTreeMap::new();
    for rule in utils::maec_rules(doc) {
        for (name, getter) in &categories {
            if let Some(v) = getter(&rule.meta) {
                table.entry(name).or_default().insert(v.to_string());
            }
        }
    }
    if table.is_empty() {
        return;
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "MAEC Category           MAEC Value");
    for (category, values) in table {
        for v in values {
            let _ = writeln!(out, "{category:<24}{v}");
        }
    }
}

fn render_capabilities(doc: &ResultDocument, out: &mut String) {
    let subrule_matches = utils::find_subrule_matches(doc);

    let mut rows: Vec<(String, String)> = Vec::new();
    for rule in utils::capability_rules(doc) {
        if subrule_matches.contains(&rule.meta.name) {
            continue;
        }
        let count = rule.matches.len();
        let capability = if count == 1 {
            rule.meta.name.clone()
        } else {
            format!("{} ({count} matches)", rule.meta.name)
        };
        rows.push((capability, rule.meta.namespace.clone().unwrap_or_default()));
    }

    let _ = writeln!(out);
    if rows.is_empty() {
        let _ = writeln!(out, "no capabilities found");
        return;
    }
    let _ = writeln!(out, "{:<56}NAMESPACE", "CAPABILITY");
    for (capability, namespace) in rows {
        let _ = writeln!(out, "{capability:<56}{namespace}");
    }
}

/// port of `default.render`.
pub fn render(doc: &ResultDocument) -> String {
    let mut out = String::new();
    render_meta(doc, &mut out);
    render_attack(doc, &mut out);
    render_maec(doc, &mut out);
    render_mbc(doc, &mut out);
    render_capabilities(doc, &mut out);
    out
}
