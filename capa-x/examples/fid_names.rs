//! Development tool: replay Function ID naming on Ghidra's own function hashes
//! and call graph (`scripts/decompiler_fid/DumpFidHashes.java`) and compare the
//! names with the ones Ghidra applied. Usage: fid_names PACK TRUTH.tsv...
use capa_x::fid::{hash::Quad, matcher, pack::Pack};
use std::collections::{BTreeMap, HashMap};

struct Func {
    name: String,
    quad: Quad,
    fid: bool,
    kids: Vec<String>,
}

fn main() {
    let mut args = std::env::args().skip(1);
    let pack_bytes = std::fs::read(args.next().unwrap_or_default()).unwrap_or_default();
    let pack = match Pack::parse(&pack_bytes) {
        Ok(pack) => pack,
        Err(error) => {
            eprintln!("{error}");
            return;
        }
    };
    let mut stats: BTreeMap<&str, usize> = BTreeMap::new();
    let mut shown = 0;
    for path in args {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let mut funcs: BTreeMap<String, Func> = BTreeMap::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            if f[0] != "F" || f.len() < 11 {
                continue;
            }
            let quad = Quad {
                code_units: f[3].parse().unwrap_or(0),
                full_hash: u64::from_str_radix(f[4], 16).unwrap_or(0),
                specific_additional: f[5].parse().unwrap_or(0),
                specific_hash: u64::from_str_radix(f[6], 16).unwrap_or(0),
            };
            funcs.insert(
                f[1].to_owned(),
                Func {
                    name: f[2].to_owned(),
                    quad,
                    fid: f[8] != "-",
                    kids: f[10]
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect(),
                },
            );
        }
        let mut parents: HashMap<&str, Vec<&str>> = HashMap::new();
        for (entry, func) in &funcs {
            for kid in &func.kids {
                if funcs.contains_key(kid) {
                    parents
                        .entry(kid.as_str())
                        .or_default()
                        .push(entry.as_str());
                }
            }
        }
        for (entry, func) in &funcs {
            let unique = |entries: Vec<&str>| -> Vec<Quad> {
                let mut seen = std::collections::HashSet::new();
                let mut out = Vec::new();
                for e in entries {
                    if let Some(f) = funcs.get(e) {
                        if seen.insert(f.quad.full_hash) {
                            out.push(f.quad);
                        }
                    }
                }
                out
            };
            let children = unique(func.kids.iter().map(String::as_str).collect());
            let parent = unique(parents.get(entry.as_str()).cloned().unwrap_or_default());
            let ours = matcher::match_name(
                &pack,
                &matcher::Family {
                    quad: func.quad,
                    children: &children,
                    parents: &parent,
                },
            );
            let key = match (func.fid, &ours) {
                (true, Some(n)) if n == &func.name => "fid: same name",
                (true, Some(_)) => "fid: different name",
                (true, None) => "fid: no name from us",
                (false, Some(_)) => "extra: named by us only",
                (false, None) => "other",
            };
            *stats.entry(key).or_default() += 1;
            if shown < 60 && matches!(key, "fid: no name from us") {
                shown += 1;
                let detail: Vec<String> = matcher::scored_candidates(
                    &pack,
                    &matcher::Family {
                        quad: func.quad,
                        children: &children,
                        parents: &parent,
                    },
                )
                .iter()
                .take(4)
                .map(|(s, r)| format!("{s:.1}:{}", pack.name(r.name).unwrap_or_default()))
                .collect();
                println!(
                    "{key}: {} ghidra={} ours={:?} cands={:?}",
                    entry, func.name, ours, detail
                );
            }
        }
    }
    for (key, count) in stats {
        println!("{count:7} {key}");
    }
}
