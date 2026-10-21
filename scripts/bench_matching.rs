//! Same-process static matching benchmark, run from the workspace root.
//! Pass a sample path. Rules and extracted features are loaded once; run 0
//! warms the matcher and runs 1 through 5 are measured. Use release builds.
//! Compilation and comparison instructions are in docs/benchmarks.md.
#![forbid(unsafe_code)]
use capa_x::{
    api::{load_input, PhaseTimings},
    capabilities::{find_static_capabilities, MatchingRuleSet},
    freeze::Freeze,
    parallel::AnalysisOptions,
    rules::load_rule_directory,
};
use std::{error::Error, path::Path, time::Instant};
fn main() -> Result<(), Box<dyn Error>> {
    let sample = std::env::args().nth(1).ok_or("sample required")?;
    let options = AnalysisOptions::SERIAL;
    let rules = MatchingRuleSet::new(load_rule_directory(Path::new("rules"), &options)?)?;
    let bytes = std::fs::read(sample)?;
    let (input, _) = load_input(&bytes, &options, &mut PhaseTimings::default())?;
    let Freeze::Static(features) = input.freeze else {
        return Err("static sample required".into());
    };
    let blocks: usize = features
        .functions
        .values()
        .map(|f| f.basic_blocks.len())
        .sum();
    let instructions: usize = features
        .functions
        .values()
        .flat_map(|f| f.basic_blocks.values())
        .map(|b| b.instructions.len())
        .sum();
    eprintln!(
        "functions={} blocks={} instructions={}",
        features.functions.len(),
        blocks,
        instructions
    );
    for run in 0..6 {
        let start = Instant::now();
        let result = find_static_capabilities(&rules, &features, &options)?;
        let elapsed = start.elapsed().as_secs_f64();
        println!("{run}\t{elapsed:.6}\t{}", result.matches.len());
        std::hint::black_box(result);
    }
    Ok(())
}
