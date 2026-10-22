//! Development-only: print the function set the decompiler path sees for a PE
//! as JSON, to compare with Ghidra's (`scripts/decompiler_baseline/FunctionList.java`).
//! Usage: function_set SAMPLE [ADDRESS_JSON]
//! With an address list it also classifies each address: why recovery did or
//! did not make it a function (seed kinds, decoded, interior, xref counts).
use capa_x::extract::recovery;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("missing sample path")?;
    let analysis = recovery::analyze_partial_pe(&std::fs::read(path)?)?;
    let mut spans: Vec<(u64, u64)> = Vec::new();
    let functions: Vec<_> = analysis
        .functions
        .values()
        .map(|function| {
            let mut size = 0usize;
            let mut ranges = Vec::new();
            for block in &function.blocks {
                for insn in &block.insns {
                    size += insn.bytes.len();
                    ranges.push([insn.address, insn.next_address]);
                }
            }
            serde_json::json!({"entry": function.addr, "size": size, "ranges": ranges})
        })
        .collect();
    for insn in analysis.instructions.values() {
        spans.push((insn.address, insn.next_address));
    }
    let mut classes = serde_json::Map::new();
    if let Some(list) = args.next() {
        let addresses: Vec<u64> = serde_json::from_slice(&std::fs::read(list)?)?;
        for address in addresses {
            let seeds: Vec<String> = analysis
                .seeds
                .get(&address)
                .map(|kinds| kinds.iter().map(|k| format!("{k:?}")).collect())
                .unwrap_or_default();
            let interior = spans
                .iter()
                .any(|(start, end)| *start < address && address < *end);
            classes.insert(
                address.to_string(),
                serde_json::json!({
                    "seeds": seeds,
                    "insn": analysis.instructions.contains_key(&address),
                    "interior": interior,
                    "callers": analysis.callers.get(&address).map_or(0, |c| c.len()),
                    "code_xrefs": analysis.code_xrefs.get(&address).map_or(0, |c| c.len()),
                    "data_xrefs": analysis.data_xrefs.get(&address).map_or(0, |c| c.len()),
                }),
            );
        }
    }
    println!(
        "{}",
        serde_json::json!({"functions": functions, "classes": classes})
    );
    Ok(())
}
