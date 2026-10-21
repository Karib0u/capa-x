//! Name recovered functions with Ghidra's Function ID databases.
//!
//! Mirrors `FidProgramSeeker`: every function with enough instructions is
//! hashed, its callees (thunks followed) and callers supply the relation
//! evidence, and each function is scored independently. Naming therefore does
//! not depend on request or iteration order.
use std::collections::{BTreeMap, BTreeSet};

use super::hash::{hash_function, Instruction, Quad};
use super::matcher::{match_name, Family};
use super::pack::Pack;
use super::x86::describe;
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
        let described: Option<Vec<Instruction>> = all
            .iter()
            .map(|insn| describe(insn.address, &insn.bytes))
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
        }
    }
    names
}
