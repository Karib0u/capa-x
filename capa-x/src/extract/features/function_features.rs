//! Function-scope feature extraction, ported from
//! `capa/features/extractors/viv/function.py` (v9.4.0, see PINNED.md).
//! `capa/features/extractors/loops.py:has_loop` is also ported here, as an
//! iterative (not recursive) SCC computation -- a pathologically large
//! function's CFG must not risk overflowing the stack.
//!
//! `extract_function_calls_from`/`extract_function_indirect_call_*`/
//! recursive-call, despite being conceptually function-scope features, are
//! extracted at instruction scope upstream (and here, in
//! [`super::insn_features`]) "since it's most efficient" -- ported as-is,
//! not moved.

use std::collections::{BTreeMap, BTreeSet};

use crate::address::Address;
use crate::features::Feature;

use super::image::ImageFormat;
use super::recovery::{Analysis, EdgeKind, Function};

/// capa/features/extractors/viv/function.py: `extract_features` /
/// `FUNCTION_HANDLERS`.
pub fn extract_features(analysis: &Analysis, function: &Function) -> Vec<(Address, Feature)> {
    let mut out = Vec::new();
    out.extend(extract_function_symtab_names(analysis, function));
    out.extend(extract_function_calls_to(analysis, function));
    out.extend(extract_function_loop(function));
    out
}

/// port of `extract_function_symtab_names` (ELF only upstream;
/// reuses the same address-to-name map for Mach-O `LC_SYMTAB` names, which
/// has no upstream source at all -- see `recovery.rs::collect_macho_seeds`).
fn extract_function_symtab_names(
    analysis: &Analysis,
    function: &Function,
) -> Vec<(Address, Feature)> {
    if !matches!(analysis.image.format, ImageFormat::Elf | ImageFormat::Macho) {
        return Vec::new();
    }
    let Some(names) = analysis.elf_function_symbols.get(&function.addr) else {
        return Vec::new();
    };
    names
        .iter()
        .map(|name| {
            (
                Address::Absolute(function.addr),
                Feature::FunctionName(name.clone()),
            )
        })
        .collect()
}

/// port of `extract_function_calls_to`. Upstream iterates every `REF_CODE`
/// xref into the function's address (vivisect doesn't distinguish call vs.
/// jump/tail-call xrefs for this type); `Analysis::code_xrefs` is populated
/// from every branch kind recovery records (calls, conditional/
/// unconditional branches, jump tables) except unresolved indirect calls,
/// which is the closest available equivalent.
fn extract_function_calls_to(analysis: &Analysis, function: &Function) -> Vec<(Address, Feature)> {
    let Some(sources) = analysis.code_xrefs.get(&function.addr) else {
        return Vec::new();
    };
    sources
        .iter()
        .map(|&source| {
            (
                Address::Absolute(source),
                Feature::Characteristic("calls to".to_string()),
            )
        })
        .collect()
}

/// port of `extract_function_loop`. Builds the edge list from each block's
/// already-recovered successor edges (`Analysis`'s CFG), excluding
/// `TailCall` edges (a tail call leaves the function, so it can never be
/// part of an intra-function loop) -- the remaining kinds
/// (fallthrough/branch/jump-table) are exactly upstream's `BR_COND |
/// BR_FALL | BR_TABLE | mnem=="jmp"` inclusion criteria, since our recovery
/// model only records an edge for a block-terminating branch/fallthrough in
/// the first place (never for a call, which doesn't end a block here).
fn extract_function_loop(function: &Function) -> Vec<(Address, Feature)> {
    let mut edges = Vec::new();
    for block in &function.blocks {
        for edge in &block.succs {
            if edge.kind != EdgeKind::TailCall {
                edges.push((block.addr, edge.target));
            }
        }
    }
    if !edges.is_empty() && has_loop(&edges) {
        vec![(
            Address::Absolute(function.addr),
            Feature::Characteristic("loop".to_string()),
        )]
    } else {
        Vec::new()
    }
}

/// port of `capa.features.extractors.loops.has_loop` (always called with
/// its default `threshold=2`): does `edges` contain a cycle spanning at
/// least two distinct nodes? A single node with only a self-loop does
/// *not* count -- that's `viv/basicblock.py`'s "tight loop" (Phase 4), a
/// separate block-scope feature. Implemented as iterative Kosaraju's SCC
/// (not networkx's/a recursive Tarjan's) precisely to avoid recursion depth
/// scaling with an attacker-controlled function's block count.
fn has_loop(edges: &[(u64, u64)]) -> bool {
    if edges.is_empty() {
        return false;
    }
    let mut forward: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut backward: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut nodes: BTreeSet<u64> = BTreeSet::new();
    for &(src, dst) in edges {
        forward.entry(src).or_default().push(dst);
        backward.entry(dst).or_default().push(src);
        nodes.insert(src);
        nodes.insert(dst);
    }

    // pass 1: iterative post-order DFS over the forward graph.
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut finish_order: Vec<u64> = Vec::new();
    for &start in &nodes {
        if visited.contains(&start) {
            continue;
        }
        let mut stack = vec![(start, false)];
        while let Some((node, processed)) = stack.pop() {
            if processed {
                finish_order.push(node);
                continue;
            }
            if !visited.insert(node) {
                continue;
            }
            stack.push((node, true));
            if let Some(succs) = forward.get(&node) {
                for &next in succs {
                    if !visited.contains(&next) {
                        stack.push((next, false));
                    }
                }
            }
        }
    }

    // pass 2: DFS over the reverse graph in decreasing finish order; each
    // traversal collects exactly one SCC.
    let mut assigned: BTreeSet<u64> = BTreeSet::new();
    for &start in finish_order.iter().rev() {
        if assigned.contains(&start) {
            continue;
        }
        let mut component_size = 0usize;
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            if !assigned.insert(node) {
                continue;
            }
            component_size += 1;
            if let Some(preds) = backward.get(&node) {
                for &prev in preds {
                    if !assigned.contains(&prev) {
                        stack.push(prev);
                    }
                }
            }
        }
        if component_size >= 2 {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::extract::recovery::{BasicBlock, Edge};

    fn block(addr: u64, succs: Vec<Edge>) -> BasicBlock {
        BasicBlock {
            addr,
            insns: Vec::new(),
            succs,
        }
    }

    // ---- has_loop ----

    #[test]
    fn has_loop_false_for_empty_or_acyclic_edges() {
        assert!(!has_loop(&[]));
        assert!(!has_loop(&[(1, 2), (2, 3), (3, 4)]));
    }

    #[test]
    fn has_loop_false_for_a_lone_self_loop() {
        // a single node's self-loop is an SCC of size 1, not >=2 -- this is
        // "tight loop" territory (Phase 4), not function-scope "loop".
        assert!(!has_loop(&[(1, 1)]));
    }

    #[test]
    fn has_loop_true_for_a_two_node_cycle() {
        assert!(has_loop(&[(1, 2), (2, 1)]));
    }

    #[test]
    fn has_loop_true_for_a_cycle_reached_through_acyclic_edges() {
        // 1 -> 2 -> 3 -> 2 (the cycle is {2,3}; node 1 merely leads into it).
        assert!(has_loop(&[(1, 2), (2, 3), (3, 2)]));
    }

    // ---- extract_function_loop ----

    #[test]
    fn function_loop_detected_across_two_blocks() {
        let function = Function {
            addr: 0x1000,
            blocks: vec![
                block(
                    0x1000,
                    vec![Edge {
                        target: 0x1010,
                        kind: EdgeKind::Branch,
                    }],
                ),
                block(
                    0x1010,
                    vec![Edge {
                        target: 0x1000,
                        kind: EdgeKind::Branch,
                    }],
                ),
            ],
        };
        assert_eq!(
            extract_function_loop(&function),
            vec![(
                Address::Absolute(0x1000),
                Feature::Characteristic("loop".to_string())
            )]
        );
    }

    #[test]
    fn function_loop_not_detected_for_straight_line_or_tail_call_only() {
        let straight_line = Function {
            addr: 0x1000,
            blocks: vec![block(
                0x1000,
                vec![Edge {
                    target: 0x1010,
                    kind: EdgeKind::Fallthrough,
                }],
            )],
        };
        assert!(extract_function_loop(&straight_line).is_empty());

        // a tail call back to the function's own start doesn't count --
        // TailCall edges are excluded (the "call" leaves the function).
        let tail_call_only = Function {
            addr: 0x1000,
            blocks: vec![block(
                0x1000,
                vec![Edge {
                    target: 0x1000,
                    kind: EdgeKind::TailCall,
                }],
            )],
        };
        assert!(extract_function_loop(&tail_call_only).is_empty());
    }

    // ---- extract_function_calls_to ----

    #[test]
    fn calls_to_lists_every_code_xref_source() {
        let mut analysis = test_analysis();
        analysis.code_xrefs.insert(0x2000, vec![0x1000, 0x1500]);
        let function = Function {
            addr: 0x2000,
            blocks: Vec::new(),
        };
        assert_eq!(
            extract_function_calls_to(&analysis, &function),
            vec![
                (
                    Address::Absolute(0x1000),
                    Feature::Characteristic("calls to".to_string())
                ),
                (
                    Address::Absolute(0x1500),
                    Feature::Characteristic("calls to".to_string())
                ),
            ]
        );
    }

    #[test]
    fn calls_to_empty_when_no_xrefs() {
        let analysis = test_analysis();
        let function = Function {
            addr: 0x2000,
            blocks: Vec::new(),
        };
        assert!(extract_function_calls_to(&analysis, &function).is_empty());
    }

    // ---- extract_function_symtab_names ----

    #[test]
    fn symtab_names_only_for_elf() {
        let mut analysis = test_analysis();
        analysis
            .elf_function_symbols
            .insert(0x2000, vec!["sym_a".to_string(), "sym_b".to_string()]);
        let function = Function {
            addr: 0x2000,
            blocks: Vec::new(),
        };

        assert_eq!(
            extract_function_symtab_names(&analysis, &function),
            vec![
                (
                    Address::Absolute(0x2000),
                    Feature::FunctionName("sym_a".to_string())
                ),
                (
                    Address::Absolute(0x2000),
                    Feature::FunctionName("sym_b".to_string())
                ),
            ]
        );

        analysis.image.format = ImageFormat::Pe;
        assert!(extract_function_symtab_names(&analysis, &function).is_empty());
    }

    fn test_analysis() -> Analysis {
        use crate::extract::image::{Architecture, LoadedImage};
        Analysis {
            image: LoadedImage::for_test(
                ImageFormat::Elf,
                Architecture::X86,
                0x1000,
                Vec::new(),
                BTreeMap::new(),
                Vec::new(),
            ),
            seeds: BTreeMap::new(),
            functions: BTreeMap::new(),
            instructions: BTreeMap::new(),
            code_xrefs: BTreeMap::new(),
            data_xrefs: BTreeMap::new(),
            callers: BTreeMap::new(),
            callees: BTreeMap::new(),
            diagnostics: Vec::new(),
            elf_function_symbols: BTreeMap::new(),
            noreturn: BTreeSet::new(),
            noreturn_calls: BTreeSet::new(),
        }
    }
}
