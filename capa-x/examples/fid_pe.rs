//! Development tool: print the Function ID names recovered for a PE.
//! Usage: fid_pe SAMPLE. Output lines: ADDRESS<TAB>NAME.
#[cfg(feature = "decompiler")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use capa_x::extract::recovery;
    use capa_x::fid::{names::name_functions, pack::Pack};
    let sample = std::env::args().nth(1).ok_or("missing sample path")?;
    let bytes = std::fs::read(sample)?;
    let analysis = recovery::analyze_partial_pe(&bytes)?;
    let data = std::fs::read(
        std::env::args()
            .nth(2)
            .unwrap_or_else(|| "capa-x/sigs/fid-x64.pack".into()),
    )?;
    let pack = Pack::parse(&data)?;
    let started = std::time::Instant::now();
    let names = name_functions(&analysis, &pack, &|_| false);
    eprintln!(
        "{} functions, {} named in {:?}",
        analysis.functions.len(),
        names.len(),
        started.elapsed()
    );
    if std::env::var_os("FID_DEBUG").is_some() {
        let mut failures: std::collections::BTreeMap<String, usize> = Default::default();
        for function in analysis.functions.values() {
            for block in &function.blocks {
                for insn in &block.insns {
                    if capa_x::fid::x86::describe(insn.address, &insn.bytes).is_none() {
                        let key: String = insn
                            .bytes
                            .iter()
                            .take(4)
                            .map(|b| format!("{b:02x}"))
                            .collect();
                        *failures.entry(key).or_default() += 1;
                    }
                }
            }
        }
        let mut sorted: Vec<_> = failures.into_iter().collect();
        sorted.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        for (key, count) in sorted.into_iter().take(25) {
            eprintln!("undescribed {key} x{count}");
        }
    }
    for (address, name) in names {
        println!("{address:x}\t{name}");
    }
    Ok(())
}
#[cfg(not(feature = "decompiler"))]
fn main() {
    eprintln!("requires --features decompiler");
}
