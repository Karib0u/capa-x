//! `-v` text renderer, ported from `capa/render/verbose.py`.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::rd::{DynamicLayout, Flavor, RdAddress, ResultDocument};

use super::utils;

fn render_static_meta(doc: &ResultDocument, out: &mut String) {
    let sample = doc.meta.sample();
    let crate::rd::Metadata::Static {
        timestamp,
        version,
        analysis,
        ..
    } = &doc.meta
    else {
        return;
    };
    let _ = writeln!(out, "{:<23}{}", "md5", sample.md5);
    let _ = writeln!(out, "{:<23}{}", "sha1", sample.sha1);
    let _ = writeln!(out, "{:<23}{}", "sha256", sample.sha256);
    let _ = writeln!(out, "{:<23}{}", "path", sample.path);
    let _ = writeln!(out, "{:<23}{timestamp}", "timestamp");
    let _ = writeln!(out, "{:<23}{version}", "capa version");
    let _ = writeln!(out, "{:<23}{}", "os", analysis.os);
    let _ = writeln!(out, "{:<23}{}", "format", analysis.format);
    let _ = writeln!(out, "{:<23}{}", "arch", analysis.arch);
    let _ = writeln!(out, "{:<23}static", "analysis");
    let _ = writeln!(out, "{:<23}{}", "extractor", analysis.extractor);
    let _ = writeln!(
        out,
        "{:<23}{}",
        "base address",
        utils::format_address(&analysis.base_address)
    );
    let _ = writeln!(out, "{:<23}{}", "rules", analysis.rules.join(", "));
    let _ = writeln!(
        out,
        "{:<23}{}",
        "function count",
        analysis.feature_counts.functions.len()
    );
    let _ = writeln!(
        out,
        "{:<23}{}",
        "library function count",
        analysis.library_functions.len()
    );
    let total: u64 = analysis.feature_counts.file
        + analysis
            .feature_counts
            .functions
            .iter()
            .map(|f| f.count)
            .sum::<u64>();
    let _ = writeln!(out, "{:<23}{total}", "total feature count");
}

fn render_dynamic_meta(doc: &ResultDocument, out: &mut String) {
    let sample = doc.meta.sample();
    let crate::rd::Metadata::Dynamic {
        timestamp,
        version,
        analysis,
        ..
    } = &doc.meta
    else {
        return;
    };
    let _ = writeln!(out, "{:<23}{}", "md5", sample.md5);
    let _ = writeln!(out, "{:<23}{}", "sha1", sample.sha1);
    let _ = writeln!(out, "{:<23}{}", "sha256", sample.sha256);
    let _ = writeln!(out, "{:<23}{}", "path", sample.path);
    let _ = writeln!(out, "{:<23}{timestamp}", "timestamp");
    let _ = writeln!(out, "{:<23}{version}", "capa version");
    let _ = writeln!(out, "{:<23}{}", "os", analysis.os);
    let _ = writeln!(out, "{:<23}{}", "format", analysis.format);
    let _ = writeln!(out, "{:<23}{}", "arch", analysis.arch);
    let _ = writeln!(out, "{:<23}dynamic", "analysis");
    let _ = writeln!(out, "{:<23}{}", "extractor", analysis.extractor);
    let _ = writeln!(out, "{:<23}{}", "rules", analysis.rules.join(", "));
    let _ = writeln!(
        out,
        "{:<23}{}",
        "process count",
        analysis.feature_counts.processes.len()
    );
    let total: u64 = analysis.feature_counts.file
        + analysis
            .feature_counts
            .processes
            .iter()
            .map(|p| p.count)
            .sum::<u64>();
    let _ = writeln!(out, "{:<23}{total}", "total feature count");
}

pub(super) fn render_meta(doc: &ResultDocument, out: &mut String) {
    match doc.meta.flavor() {
        Flavor::Static => render_static_meta(doc, out),
        Flavor::Dynamic => render_dynamic_meta(doc, out),
    }
}

fn process_name(layout: &DynamicLayout, addr: &RdAddress) -> Option<String> {
    layout
        .processes
        .iter()
        .find(|p| &p.address == addr)
        .map(|p| p.name.clone())
}

fn thread_process_addr(addr: &RdAddress) -> RdAddress {
    // a thread/call address's tuple is `(ppid, pid, tid[, id])`; its
    // process address is the `(ppid, pid)` prefix.
    match &addr.value {
        Some(crate::rd::AddressValue::Tuple(t)) if t.len() >= 2 => RdAddress {
            kind: "process".to_string(),
            value: Some(crate::rd::AddressValue::Tuple(vec![t[0], t[1]])),
        },
        _ => addr.clone(),
    }
}

pub(super) fn render_process(layout: &DynamicLayout, addr: &RdAddress) -> String {
    let name = process_name(layout, addr).unwrap_or_default();
    let pid = match &addr.value {
        Some(crate::rd::AddressValue::Tuple(t)) => t.get(1).copied().unwrap_or(0),
        _ => 0,
    };
    format!("{name}{{pid:{pid}}}")
}

pub(super) fn render_thread(layout: &DynamicLayout, addr: &RdAddress) -> String {
    let name = process_name(layout, &thread_process_addr(addr)).unwrap_or_default();
    let (pid, tid) = match &addr.value {
        Some(crate::rd::AddressValue::Tuple(t)) => (
            t.get(1).copied().unwrap_or(0),
            t.get(2).copied().unwrap_or(0),
        ),
        _ => (0, 0),
    };
    format!("{name}{{pid:{pid},tid:{tid}}}")
}

fn render_rules(doc: &ResultDocument, out: &mut String) {
    let mut had_match = false;
    for rule in utils::capability_rules(doc) {
        let count = rule.matches.len();
        let capability = if count == 1 {
            rule.meta.name.clone()
        } else {
            format!("{} ({count} matches)", rule.meta.name)
        };
        let _ = writeln!(out, "{capability}");
        had_match = true;

        if let Some(ns) = &rule.meta.namespace {
            let _ = writeln!(out, "  namespace    {ns}");
        }
        if !rule.meta.description.is_empty() {
            let _ = writeln!(out, "  description  {}", rule.meta.description);
        }

        let scope = match doc.meta.flavor() {
            Flavor::Static => rule.meta.scopes.static_.as_deref(),
            Flavor::Dynamic => rule.meta.scopes.dynamic.as_deref(),
        };
        if let Some(scope) = scope {
            let _ = writeln!(out, "  scope        {scope}");
        }

        let is_file_scope = rule.meta.scopes.static_.as_deref() == Some("file")
            || rule.meta.scopes.dynamic.as_deref() == Some("file");
        if !is_file_scope {
            let locations: Vec<&RdAddress> = rule.matches.iter().map(|(a, _)| a).collect();
            let lines: Vec<String> = match &doc.meta {
                crate::rd::Metadata::Static { .. } => {
                    locations.iter().map(|l| utils::format_address(l)).collect()
                }
                crate::rd::Metadata::Dynamic { analysis, .. } => {
                    match rule.meta.scopes.dynamic.as_deref() {
                        Some("process") => locations
                            .iter()
                            .map(|l| render_process(&analysis.layout, l))
                            .collect(),
                        Some("thread") => locations
                            .iter()
                            .map(|l| render_thread(&analysis.layout, l))
                            .collect(),
                        Some("call") | Some("span of calls") => {
                            let threads: BTreeSet<String> = locations
                                .iter()
                                .map(|l| {
                                    render_thread(&analysis.layout, &thread_process_addr_of_call(l))
                                })
                                .collect();
                            threads.into_iter().collect()
                        }
                        _ => locations.iter().map(|l| utils::format_address(l)).collect(),
                    }
                }
            };
            let _ = writeln!(out, "  matches      {}", lines.join(", "));
        }
        let _ = writeln!(out);
    }

    if !had_match {
        let _ = writeln!(out, "no capabilities found");
    }
}

/// a call address's thread is its `(ppid, pid, tid)` prefix (drop `id`).
fn thread_process_addr_of_call(addr: &RdAddress) -> RdAddress {
    match &addr.value {
        Some(crate::rd::AddressValue::Tuple(t)) if t.len() >= 3 => RdAddress {
            kind: "thread".to_string(),
            value: Some(crate::rd::AddressValue::Tuple(vec![t[0], t[1], t[2]])),
        },
        _ => addr.clone(),
    }
}

/// port of `verbose.render`.
pub fn render(doc: &ResultDocument) -> String {
    let mut out = String::new();
    render_meta(doc, &mut out);
    let _ = writeln!(out);
    render_rules(doc, &mut out);
    out
}
