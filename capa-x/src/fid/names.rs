//! Name recovered functions with Ghidra's Function ID databases.
//!
//! Mirrors `FidProgramSeeker`: every function with enough instructions is
//! hashed, its callees (thunks followed) and callers supply the relation
//! evidence, and each function is scored independently. Naming therefore does
//! not depend on request or iteration order.
use std::collections::{BTreeMap, BTreeSet};

use super::hash::{hash_function, Instruction, Quad};
use super::matcher::{match_candidates, match_name, Family};
use super::pack::Pack;
use super::x86::describe_in;
use crate::extract::decoder::Flow;
use crate::extract::recovery::{Analysis, Function};

struct Hashed {
    quad: Quad,
    instructions: usize,
}

fn instructions(function: &Function) -> Vec<&crate::extract::decoder::DecodedInstruction> {
    let mut all: Vec<_> = function
        .blocks
        .iter()
        .flat_map(|block| block.insns.iter())
        .collect();
    all.sort_by_key(|insn| insn.address);
    all.dedup_by_key(|insn| insn.address);
    all
}

/// A function that is only a direct jump to another function.
fn thunk_target(analysis: &Analysis, function: &Function) -> Option<u64> {
    let all = instructions(function);
    match all.as_slice() {
        [only] if only.flow == Flow::UnconditionalBranch => only
            .direct_target
            .filter(|target| *target != function.addr && analysis.functions.contains_key(target)),
        _ => None,
    }
}

/// Names for functions that no other source named. `named` says which
/// addresses already have a trusted name; thunks and those are skipped.
pub fn name_functions(
    analysis: &Analysis,
    pack: &Pack<'_>,
    named: &dyn Fn(u64) -> bool,
) -> BTreeMap<u64, String> {
    name_functions_with_conflicts(analysis, pack, named).0
}

/// Like [`name_functions`], and also the functions with several equally good names
/// that Ghidra would label `FID_conflict:`, with all of those names.
pub fn name_functions_with_conflicts(
    analysis: &Analysis,
    pack: &Pack<'_>,
    named: &dyn Fn(u64) -> bool,
) -> (BTreeMap<u64, String>, BTreeMap<u64, Vec<String>>) {
    let bits = analysis.image.architecture.bitness();
    let sections = &analysis.image.sections;
    // Ghidra types a 32-bit immediate as an address when it points into the program.
    let is_address = |value: u64| {
        sections.iter().any(|section| {
            section.address <= value && value - section.address < section.virtual_size
        })
    };
    let relocations = &analysis.image.relocation_locations;
    let has_relocation = |low: u64, high: u64| {
        let first = relocations.partition_point(|location| *location < low);
        relocations
            .get(first)
            .is_some_and(|location| *location <= high)
    };
    let thunks: BTreeMap<u64, u64> = analysis
        .functions
        .values()
        .filter_map(|function| {
            thunk_target(analysis, function).map(|target| (function.addr, target))
        })
        .collect();
    let resolve = |mut address: u64| {
        for _ in 0..16 {
            match thunks.get(&address) {
                Some(next) => address = *next,
                None => break,
            }
        }
        address
    };
    let mut hashes: BTreeMap<u64, Hashed> = BTreeMap::new();
    let mut calls: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (address, function) in &analysis.functions {
        let all = instructions(function);
        let mut targets = Vec::new();
        for insn in &all {
            if insn.flow == Flow::Call {
                if let Some(target) = insn
                    .direct_target
                    .filter(|t| analysis.functions.contains_key(t))
                {
                    targets.push(resolve(target));
                }
            }
        }
        calls.insert(*address, targets);
        // Ghidra reads `fwait` plus the no-wait x87 form (FSTSW, FSTCW...) as one
        // instruction; the decoder here yields two.
        let mut merged: Vec<(u64, Vec<u8>)> = Vec::with_capacity(all.len());
        let mut index = 0;
        while index < all.len() {
            let insn = all[index];
            match all.get(index + 1) {
                Some(next)
                    if insn.bytes == [0x9b]
                        && next.address == insn.address + 1
                        && matches!(next.bytes.first(), Some(0xd9 | 0xdb | 0xdd | 0xdf)) =>
                {
                    let mut bytes = insn.bytes.clone();
                    bytes.extend_from_slice(&next.bytes);
                    merged.push((insn.address, bytes));
                    index += 2;
                }
                _ => {
                    merged.push((insn.address, insn.bytes.clone()));
                    index += 1;
                }
            }
        }
        let described: Option<Vec<Instruction>> = merged
            .iter()
            .map(|(address, bytes)| describe_in(bits, *address, bytes, &is_address))
            .collect();
        if let Some(described) = described {
            if let Some(quad) = hash_function(&described, &has_relocation) {
                hashes.insert(
                    *address,
                    Hashed {
                        quad,
                        instructions: described.len(),
                    },
                );
            }
        }
    }
    let mut callers: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (caller, targets) in &calls {
        for target in targets {
            callers.entry(*target).or_default().push(*caller);
        }
    }
    let unique = |addresses: &[u64]| -> Vec<Quad> {
        let mut seen = BTreeSet::new();
        addresses
            .iter()
            .filter_map(|address| hashes.get(address))
            .filter(|hashed| seen.insert(hashed.quad.full_hash))
            .map(|hashed| hashed.quad)
            .collect()
    };
    let mut names = BTreeMap::new();
    let mut conflicts = BTreeMap::new();
    for (address, hashed) in &hashes {
        if thunks.contains_key(address) || named(*address) || hashed.instructions < 4 {
            continue;
        }
        let children = unique(calls.get(address).map_or(&[][..], Vec::as_slice));
        let parents = unique(callers.get(address).map_or(&[][..], Vec::as_slice));
        let family = Family {
            quad: hashed.quad,
            children: &children,
            parents: &parents,
        };
        if let Some(name) = match_name(pack, &family) {
            names.insert(*address, name);
        } else {
            let candidates = match_candidates(pack, &family);
            if candidates.len() > 1 {
                conflicts.insert(*address, candidates);
            }
        }
    }
    (names, conflicts)
}
