//! Inspect parsed FLIRT storage capacities without adding an allocator wrapper.
//! Pass signature paths, for example capa-x/sigs/*.sig. Counts exclude allocator
//! overhead, tail bytes, and matcher indexes. See docs/BENCHMARKS.md.
#![forbid(unsafe_code)]

use lancelot_flirt::{FlirtSignature, SigElement, Symbol};
use std::{error::Error, mem::size_of, time::Instant};
fn main() -> Result<(), Box<dyn Error>> {
    for path in std::env::args().skip(1) {
        let bytes = std::fs::read(&path)?;
        let start = Instant::now();
        let unpacked = lancelot_flirt::sig::unpack_sig(&bytes)?;
        println!(
            "{path}: input={} unpacked={} capacity={} unpack_time={:.3}",
            bytes.len(),
            unpacked.len(),
            unpacked.capacity(),
            start.elapsed().as_secs_f64()
        );
        drop(unpacked);
        let start = Instant::now();
        let sigs = lancelot_flirt::sig::parse(&bytes)?;
        let mut heads = 0;
        let mut names = 0;
        let mut text = 0;
        for sig in &sigs {
            heads += sig.byte_sig.0.capacity() * size_of::<SigElement>();
            names += sig.names.capacity() * size_of::<Symbol>();
            for symbol in &sig.names {
                let (Symbol::Public(n) | Symbol::Local(n) | Symbol::Reference(n)) = symbol;
                text += n.name.capacity();
            }
        }
        println!(
            "count={} size={} capacity={} heads={} names={} text={} parse_time={:.3}",
            sigs.len(),
            size_of::<FlirtSignature>(),
            sigs.capacity(),
            heads,
            names,
            text,
            start.elapsed().as_secs_f64()
        );
    }
    Ok(())
}
