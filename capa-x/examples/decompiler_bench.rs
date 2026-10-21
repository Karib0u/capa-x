//! Run with cargo run --release -p capa-x --features decompiler --example decompiler_bench.
#[cfg(feature = "decompiler")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use capa_x::decompiler::DecompilerSession;
    let bytes = include_bytes!("../../tests/decompiler/fixtures.dll");
    let pe = goblin::pe::PE::parse(bytes)?;
    let repetitions: usize = std::env::args()
        .nth(1)
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(100);
    if repetitions == 0 {
        return Err("repetitions must be positive".into());
    }
    let started = std::time::Instant::now();
    let mut session = DecompilerSession::from_pe(bytes)?;
    eprintln!(
        "cold session including recovery: {:.3} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );
    for export in &pe.exports {
        let mut times = Vec::new();
        let mut last = None;
        for _ in 0..repetitions {
            let result = session.decompile_function(pe.image_base + export.rva as u64)?;
            times.push(result.timings.decompilation_ms);
            last = Some(result);
        }
        times.sort_by(f64::total_cmp);
        if let Some(result) = last {
            eprintln!(
                "{}: init {:.3} ms; warm p50 {:.3} ms; p95 {:.3} ms; max {:.3} ms",
                export.name.unwrap_or("unnamed"),
                result.timings.initialization_ms,
                times.get(repetitions / 2).copied().unwrap_or_default(),
                times
                    .get(repetitions * 95 / 100)
                    .copied()
                    .unwrap_or_default(),
                times.last().copied().unwrap_or_default()
            );
            println!("{}", serde_json::to_string(&result)?);
        }
    }
    Ok(())
}
#[cfg(not(feature = "decompiler"))]
fn main() {
    eprintln!("requires --features decompiler");
}
