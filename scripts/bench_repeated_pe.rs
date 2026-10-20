//! Same-process PE loading benchmark. Run from the workspace root.
//! Compile against a release library as documented in docs/BENCHMARKS.md.
//! This measures loading, recovery and extraction, without rule matching.
#![forbid(unsafe_code)]

use capa_x::{
    api::{load_input, PhaseTimings},
    parallel::AnalysisOptions,
};
use std::{
    error::Error,
    hash::{Hash, Hasher},
    time::Instant,
};

fn main() -> Result<(), Box<dyn Error>> {
    let bytes = std::fs::read("tests/testfiles/Practical Malware Analysis Lab 01-02.exe_")?;
    let mut expected = None;
    for run in 0..5 {
        let start = Instant::now();
        let mut timings = PhaseTimings::default();
        let (input, _) = load_input(&bytes, &AnalysisOptions::SERIAL, &mut timings)?;
        let elapsed = start.elapsed().as_secs_f64();
        let output = format!("{:?} {:?}", input.freeze, input.library_functions);
        if let Some(ref previous) = expected {
            assert_eq!(previous, &output);
        }
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        output.hash(&mut hash);
        println!("{run}\t{elapsed:.6}\t{:016x}", hash.finish());
        expected = Some(output);
    }
    Ok(())
}
