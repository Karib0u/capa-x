//! `dnstrings` — list every user string (`ldstr` operand) referenced by a
//! .NET PE, together with the function offset and the instruction offset
//! that referenced it.
//!
//! Mirrors the Python `dnstrings.py` example from `malwarefrank/dnfile` but
//! with structured columns. Useful for triaging .NET malware that hides
//! payloads/decoy text in `#US` user strings.

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use dnfile::DnPe;
use dnfile::lang::cil::instruction::Operand;

/// Dump every `ldstr` user string in a .NET PE with its call site.
#[derive(Parser, Debug)]
#[command(
    name = "dnstrings",
    version,
    about = "List every user string (ldstr) referenced by a .NET PE, with call-site context.",
    long_about = None,
)]
struct Args {
    /// Path to the .NET PE file.
    file: PathBuf,

    /// Print only strings of at least this many characters.
    #[arg(long, default_value_t = 0)]
    min_len: usize,

    /// Print as TSV (function-offset, instruction-offset, string) instead
    /// of the default `OFFSET:IP  string` format.
    #[arg(long)]
    tsv: bool,
}

fn main() -> ExitCode {
    reset_sigpipe();
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            let mut src = e.source();
            while let Some(cause) = src {
                eprintln!("caused by: {cause}");
                src = cause.source();
            }
            ExitCode::from(1)
        }
    }
}

/// Restore default SIGPIPE behaviour on Unix so that piping to `head` /
/// `less` causes a clean exit instead of an EPIPE panic. Belt-and-suspenders
/// with the BufWriter+BrokenPipe handling below (the SIGPIPE reset also
/// covers any internal `eprintln!`).
fn reset_sigpipe() {
    #[cfg(unix)]
    {
        unsafe extern "C" {
            fn signal(signum: i32, handler: usize) -> usize;
        }
        const SIGPIPE: i32 = 13;
        const SIG_DFL: usize = 0;
        unsafe {
            signal(SIGPIPE, SIG_DFL);
        }
    }
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let path = args.file.canonicalize().unwrap_or(args.file.clone());
    let data = std::fs::read(&path)?;
    let pe = DnPe::parse(&data)?;
    let clr = pe.net()?;

    // Buffered, explicit-error stdout: lets us exit cleanly when piped into
    // `head`/`less` instead of panicking on EPIPE the way `println!` does.
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    'outer: for func in clr.functions() {
        for insn in &func.instructions {
            if !insn.is_ldstr() {
                continue;
            }
            let Operand::StringToken(tok) = &insn.operand else {
                continue;
            };
            let Ok(s) = clr.get_us(tok.rid()) else {
                continue;
            };
            if s.chars().count() < args.min_len {
                continue;
            }
            let escaped = escape(&s);
            let write_result = if args.tsv {
                writeln!(
                    out,
                    "0x{:08X}\t0x{:08X}\t{}",
                    func.offset, insn.offset, escaped
                )
            } else {
                writeln!(
                    out,
                    "0x{:08X}:0x{:08X}  {}",
                    func.offset, insn.offset, escaped
                )
            };
            if let Err(e) = write_result {
                if e.kind() == io::ErrorKind::BrokenPipe {
                    break 'outer;
                }
                return Err(e.into());
            }
        }
    }
    // Drop the BufWriter so it flushes; swallow BrokenPipe here too.
    if let Err(e) = out.flush() {
        if e.kind() != io::ErrorKind::BrokenPipe {
            return Err(e.into());
        }
    }
    Ok(())
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\x{:02X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
