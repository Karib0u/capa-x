# dnfile

[![CI](https://github.com/marirs/dnfile-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/dnfile-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/dnfile.svg)](https://crates.io/crates/dnfile)
[![Docs.rs](https://docs.rs/dnfile/badge.svg)](https://docs.rs/dnfile)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](#requirements)

A Rust crate for parsing .NET executable files — PE files containing CLR (Common Language Runtime) metadata, streams, tables, and CIL (Common Intermediate Language) bytecode.

It is a Rust port of [malwarefrank/dnfile](https://github.com/malwarefrank/dnfile), the Python library used by tools like [Mandiant capa](https://github.com/mandiant/capa) for static analysis of .NET malware.

## What it does

Given a .NET PE file (an executable, DLL, or assembly compiled to MSIL), `dnfile` lets you:

- Parse the **CLR header** and verify .NET flags (IL-only, 32-bit-required, strong-named, etc.).
- Walk the **#~ / #- metadata stream** and access its ~50 ECMA-335 tables (`Module`, `TypeDef`, `MethodDef`, `MemberRef`, `Assembly`, `ManifestResource`, etc.) by name or index.
- Read **#Strings, #US, #GUID, #Blob** heaps.
- Resolve **coded indexes** (TypeDefOrRef, MemberRefParent, HasCustomAttribute, …) into typed table rows.
- Decode every **CIL instruction** in every method body, including operand types, branch targets, switch tables, and tokens.
- Detect **mixed-mode** (managed + native) and **P/Invoke** functions.

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
dnfile = "0.4"   # latest 0.4.x (0.4.1 adds resources() + assembly() helpers)
```

Then:

```rust
use dnfile::DnPe;

fn main() -> dnfile::Result<()> {
    // dnfile is zero-copy: the caller owns the buffer, the parser borrows it.
    let data = std::fs::read("MyAssembly.dll")?;
    let pe = DnPe::parse(&data)?;
    let clr = pe.net()?;

    // CLR header flags
    println!("flags: {:?}", clr.flags);

    // Iterate decoded method bodies
    for func in clr.functions() {
        println!("function with {} instructions", func.instructions.len());
    }

    // Direct metadata-table access by name
    let methods = clr.md_table("MethodDef")?;
    println!("MethodDef rows: {}", methods.row_count());

    // Read a user string by RID
    if let Ok(s) = clr.get_us(1) {
        println!("first user string: {}", s);
    }

    Ok(())
}
```

For very large binaries, back the buffer with `memmap2::Mmap` instead of `std::fs::read`:

```rust,no_run
let file = std::fs::File::open("Sample.exe")?;
let mmap = unsafe { memmap2::Mmap::map(&file)? };
let pe = dnfile::DnPe::parse(&mmap)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Command-line tool: `dndump`

`dndump` is a [Mandiant capa](https://github.com/mandiant/capa)-style inspector for .NET binaries. It prints the CLR header, metadata streams, populated tables, and the first methods discovered. Pre-built binaries for Linux / macOS / Windows are attached to each [GitHub release](https://github.com/marirs/dnfile-rs/releases).

Install from source:

```bash
cargo install dnfile --features cli
```

Or build locally:

```bash
cargo build --release --features cli --bin dndump
./target/release/dndump path/to/Sample.exe
```

Other useful invocations:

```bash
dndump --methods 100 Sample.exe        # show first 100 methods
dndump --strings Sample.exe            # also dump #US user strings
dndump --assembly Sample.exe           # Assembly identity (name/version/culture/...)
dndump --resources Sample.exe          # ManifestResource entries
dndump --show-rows 5 Sample.exe        # first 5 rows of each non-empty table
dndump --json Sample.exe > parsed.json # machine-readable output
```

For .NET-specific string triage there's a sibling binary `dnstrings`:

```bash
cargo install dnfile --features cli   # installs both dndump and dnstrings
dnstrings Sample.exe                  # function-offset:ip  string
dnstrings --tsv --min-len 8 Sample.exe
```

A minimal library-usage example lives in [`examples/dnfile.rs`](examples/dnfile.rs):

```bash
cargo run --example dnfile -- path/to/Sample.exe
```

## Feature coverage

Metadata tables supported (with full parse implementations):

`Module`, `TypeRef`, `TypeDef`, `Field`, `MethodDef`, `Param`, `InterfaceImpl`, `MemberRef`, `Constant`, `CustomAttribute`, `FieldMarshal`, `DeclSecurity`, `ClassLayout`, `FieldLayout`, `StandAloneSig`, `EventMap`, `Event`, `PropertyMap`, `Property`, `MethodSemantics`, `MethodImpl`, `ModuleRef`, `TypeSpec`, `ImplMap`, `FieldRva`, `EncLog`, `EncMap`, `Assembly`, `AssemblyProcessor`, `AssemblyOS`, `AssemblyRef`, `AssemblyRefProcessor`, `AssemblyRefOS`, `File`, `ExportedType`, `ManifestResource`, `NestedClass`, `GenericParam`, `GenericMethod`, `GenericParamConstraint`, `FieldPtr`, `MethodPtr`, `ParamPtr`.

Stubbed (returns `NotImplementedError`, does not panic): `EventPtr`, `PropertyPtr`, `Unused`, `MaxTable`. These appear only in uncompressed `#-` streams or are reserved by ECMA-335.

CIL: all one- and two-byte opcodes from ECMA-335 §III.

Not currently implemented: managed-resource (`ResourceSet`) parsing — only the `ManifestResource` metadata-table entry is exposed; the resource blob itself is not parsed.

## Requirements

- Rust **1.85** or newer (2024 edition).

## Why a Rust port?

`dnfile-rs` was originally written to power [capa-rs](https://github.com/marirs/capa-rs), the Rust port of Mandiant's capability extractor. It is suitable for any Rust-side static analysis of .NET binaries that does not require executing the IL.

## Used by

- [capa-rs](https://github.com/marirs/capa-rs) — static capability extractor for PE / ELF / shellcode / .NET binaries.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

## Acknowledgements

- [malwarefrank/dnfile](https://github.com/malwarefrank/dnfile) — the original Python implementation that this port is modelled on.
- [ECMA-335](https://ecma-international.org/publications-and-standards/standards/ecma-335/) — Common Language Infrastructure (CLI) specification.
