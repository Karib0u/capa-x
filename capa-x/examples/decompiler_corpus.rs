//! Development-only corpus runner: SAMPLE ADDRESS_JSON, one reusable session.
#[cfg(feature = "decompiler")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use capa_x::decompiler::DecompilerSession;
    use std::io::{self, Write};
    let mut arguments = std::env::args().skip(1);
    let sample = arguments.next().ok_or("missing sample path")?;
    let addresses = arguments.next().ok_or("missing address JSON path")?;
    let bytes = std::fs::read(sample)?;
    let addresses: Vec<u64> = serde_json::from_slice(&std::fs::read(addresses)?)?;
    let mut session = None;
    for address in addresses {
        println!(
            "{}",
            serde_json::json!({"event":"start", "address":address})
        );
        io::stdout().flush()?;
        if session.is_none() {
            match DecompilerSession::from_pe(&bytes) {
                Ok(created) => session = Some(created),
                Err(error) => {
                    println!(
                        "{}",
                        serde_json::json!({"event":"initialization_error", "error":error.to_string()})
                    );
                    io::stdout().flush()?;
                    return Ok(());
                }
            }
        }
        let current = session.as_mut().ok_or("session was not initialized")?;
        // Development knob: CORPUS_LIMITS=timeout_ms,max_instructions,max_work
        if let Ok(limits) = std::env::var("CORPUS_LIMITS") {
            let values: Vec<u32> = limits.split(',').filter_map(|v| v.parse().ok()).collect();
            if let [timeout_ms, max_instructions, max_work] = values[..] {
                current.set_limits(capa_x::decompiler::ResourceLimits {
                    timeout_ms,
                    max_instructions,
                    max_work,
                })?;
            }
        }
        match current.decompile_function(address) {
            Ok(output) => println!(
                "{}",
                serde_json::json!({"event":"result", "address":address, "output":output})
            ),
            Err(error) => {
                println!(
                    "{}",
                    serde_json::json!({"event":"result", "address":address, "error":error.to_string()})
                );
                // Native errors poison a session. A fresh session lets the
                // remaining corpus requests still be independently assessed.
                session = None;
            }
        }
        io::stdout().flush()?;
    }
    Ok(())
}
#[cfg(not(feature = "decompiler"))]
fn main() {
    eprintln!("requires --features decompiler");
}
