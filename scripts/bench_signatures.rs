//! Cold signature loading benchmark. Build against each revision's release
//! library, then run each executable in a fresh process. Pass a job count.
//! With --wait, prints and flushes the load time before waiting for a newline,
//! allowing an external process to sample resident memory with the data live.
#![forbid(unsafe_code)]

use capa_x::{
    extract::recovery::flirt::Signatures,
    parallel::{AnalysisOptions, Jobs},
};
use std::{error::Error, io::Write, time::Instant};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let jobs = args.first().ok_or("job count required")?.parse()?;
    let options = AnalysisOptions {
        jobs: Jobs::new(jobs)?,
        ..AnalysisOptions::SERIAL
    };
    let start = Instant::now();
    let signatures = Signatures::embedded_with_options(&options)?;
    println!("load_seconds\t{:.6}", start.elapsed().as_secs_f64());
    std::io::stdout().flush()?;
    if args.iter().any(|arg| arg == "--wait") {
        std::io::stdin().read_line(&mut String::new())?;
    }
    std::hint::black_box(signatures);
    Ok(())
}
