# Changelog

All notable changes to this project are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the caveat that 0.x minor versions can break.

## [0.5.1] — Additions

Closes four items. All additive; no breaking API changes.

### Fixed

- **`#US` (user-string) heap decoder now uses `String::from_utf16_lossy`
  instead of strict `String::from_utf16`.
  Some .NET malware deliberately stores invalid UTF-16 (unpaired
  surrogates, terminator-byte oddities) in `#US` entries as a
  poor-man's anti-analysis trick. Pre-0.5.1 every such entry
  returned `Err(FromUtf16Error)` and the calling tool (capa,
  string scanners) silently dropped the string from its feature
  set — rules looking for those strings never fired. Now the
  decoder replaces invalid surrogates with U+FFFD and surfaces
  the rest of the string, matching upstream behaviour. The raw
  bytes remain accessible via `UserStringHeap::get_ref` for
  callers that need strict-or-fail decoding.

### Added

- **`#Pdb` stream parser** (`stream::pdb_stream::PdbStream`).
  Parses the Portable PDB stream header (PdbId, EntryPoint
  token, ReferencedTypeSystemTables bitmap, per-table row
  counts). Surfaces `guid()` for symbol-server lookup and
  `stamp()` for the legacy-PDB-age equivalent. The full
  Portable PDB metadata tables (Document,
  MethodDebugInformation, LocalScope, LocalVariable,
  LocalConstant, ImportScope, StateMachineMethod,
  CustomDebugInformation) are intentionally NOT decoded —
  that's a substantial follow-up. The new `Stream::PdbStream`
  enum variant + `"#Pdb"` dispatch in `nnew_clr_stream` make
  the header visible end-to-end.

- **`signatures::CustomAttribute` decoder** (ECMA-335 II.23.3).
  Decodes attribute blobs from `CustomAttribute.Value` into
  typed `Value`s: primitives (`Boolean`/`Char`/`I1..U8`/`R4`/`R8`),
  `String` (SerString), `Type` (SerType), and `SZARRAY` of
  primitives. Covers `[DllImport]`, `[Obfuscation]`, `[Guid]`,
  `[AssemblyVersion]`, and the long tail of CLR attributes
  capa rules look for. Two entry points:
  `decode_with_types(blob, ctor_param_types)` for the typical
  case (caller has the constructor signature from `MemberRef`/
  `MethodDef`), `decode_raw_named(blob, fixed_blob_len)` for
  the named-args-only case when the caller can't recover the
  ctor types.

- **`signatures::MarshalSpec` decoder** (ECMA-335 II.23.4).
  Decodes `FieldMarshal.NativeType` blobs into typed enum:
  `Simple(NATIVE_TYPE_*)`, `Array { elem_type, param_num,
  num_elem, param_num_multiplier }`, `FixedSysString { size }`,
  `FixedArray { size, elem_type }`, `CustomMarshaler { guid,
  unmanaged_type, managed_type, cookie }`. Covers the
  `[MarshalAs(UnmanagedType.X)]` surface used in essentially
  every P/Invoke declaration.

- New `signatures::native_type` constant module with the
  common `NATIVE_TYPE_*` byte values.

## [0.5.0] — 2026-05-26 — Thread-safety supertrait bounds (breaking)

### Breaking changes

- **`MDTableTrait`, `MDTableTraitClone`, `MDTableRowTrait`,
  `MDTableRowTraitT`, and `CodedIndex` gained `Send + Sync`
  supertrait bounds.** This makes `Box<dyn MDTableTrait>` (and the
  whole `DnPe<'_>` reachability graph that wraps it) shareable
  across thread boundaries — required by downstream consumers
  (capa-rs 0.4.2 onwards) that parallelise function-level analysis
  via rayon.

  All `MDTableTrait`/`MDTableRowTrait`/etc. impls in dnfile-rs are
  plain-data structs (`Vec`, `String`, primitives) and naturally
  satisfy the new bounds — no internal code changes were needed
  beyond the supertrait declaration. Downstream consumers with
  *non-thread-safe* impls of these traits must add `Send + Sync`
  bounds to their types (or explain why their type is in fact
  thread-unsafe and split it into a non-shared variant).

### Migration

No source changes are required if your `MDTableTrait` /
`MDTableRowTrait` / `CodedIndex` impls already store only
thread-safe types (the common case). If you hit a compile error,
add `unsafe impl Send for MyType {}` / `unsafe impl Sync for
MyType {}` if you can prove thread-safety, or factor out the
non-thread-safe bits into a separate type.

## [0.4.2] — 2026-05

### Fixed

- **Broken-pipe panic in `dndump` and `dnstrings`.** Both binaries now
  reset `SIGPIPE` to `SIG_DFL` on Unix at startup, so piping into `head`,
  `less`, or `grep -m` exits cleanly with code 141 instead of panicking
  inside `println!`/`printstd()`. `dnstrings` additionally writes through
  a `BufWriter<StdoutLock>` and gracefully exits on `ErrorKind::BrokenPipe`
  for cross-platform safety (Windows doesn't deliver SIGPIPE).

### Security & robustness

Hardened against crafted-input panics, infinite loops, and oversized
allocations. dnfile-rs is intended to parse adversary-supplied malware;
the parser must not crash, hang, or eat the heap.

- **`utils::read_compressed_usize`** now bounds-checks every byte access;
  previously panicked on short inputs (reachable from blob / signature
  paths).
- **`DnPe::get_slice`** uses `checked_add` for `offset + size` so a
  wraparound can't bypass the upper bound and read at the wrong location.
- **`DnPe::get_nullterminated_string`** is bounds-checked, uses
  `checked_add` on the RVA, and caps the string at 1 KiB (real names are
  ≤ 31 chars).
- **`DnPe::new_metadata`, `new_streams`, `new_clr_stream`** — every
  intermediate RVA addition is `checked_add`; `number_of_streams` is
  capped at 64.
- **`BlobHeap::get_ref`, `UserStringHeap::get`, `GuidHeap::get`** — all
  index / length math uses `checked_add` / `checked_mul` / `checked_sub`;
  a crafted index can no longer wrap to a bypassing offset.
- **`MDTable::new`** — refuses to allocate more than 8 M rows per metadata
  table (a soft cap well above anything real; before this a crafted u32
  row count could request hundreds of GB).
- **`meta_data_tables::parse_meta_data_tables`** — `row_size * num_rows`
  via `checked_mul`, `curr_rva += ...` via `checked_add`.
- **`Reader::read_inline_switch`** — caps `num_branches` against
  remaining buffer bytes; previously a `0xFFFF_FFFF` switch count would
  attempt a ~16 GiB allocation.
- **`Function::parse_instructions`** — rejects zero-size instructions
  (would loop forever) and uses `checked_add` on offsets.
- **`Function::parse_fat_exception_handlers`** — clause count is computed
  per ECMA-335 II.25.4.6 as `(total_size - 4) / 24` and clamped against
  remaining bytes (was driving multi-MB Vec allocations on crafted
  `total_size`).
- **`DnPe::read_embedded_resource`** — clamps the length-prefix against
  the resources-directory size.
- **`ClrData::resolve_coded_index`** — uses `checked_sub` on the 1-based
  row index; a row-index-of-zero now returns an error instead of panicking
  in debug.
- **`resource::DotNetResource::with_capacity`** — pre-allocation is
  bounded so a crafted ManifestResource row count can't OOM the process.

## [0.4.1] — 2026-05

### Added

- **Managed-resource enumeration.** New module `dnfile::resource` with
  `DotNetResource`, `ResourceLocation`. `DnPe::resources()` walks the
  `ManifestResource` table and returns one entry per resource, with
  embedded resource bytes resolved as borrowed slices into the file
  buffer.
- **Assembly identity accessor.** `ClrData::assembly()` returns the
  `Assembly` table's row 0 (name / version / culture / public-key /
  flags / hash algorithm).
- **CLR resources directory accessors.** `DnPe::resources_rva()` and
  `DnPe::resources_size()` expose the bounds of the resources directory
  from the CLR header.
- **New CLI binary `dnstrings`** (behind the `cli` feature). Scans every
  function body for `ldstr` opcodes, resolves the `#US` user-string
  reference, and prints `function-offset:ip  string`. Useful for triaging
  .NET malware that hides payloads in user strings.
- **`dndump` new flags:**
  - `--assembly` — print Assembly identity (name, version, culture, public
    key size, flags).
  - `--resources` — list ManifestResource entries (name, location, size,
    flags).
  - `--show-rows N` — for the most analyst-relevant metadata tables, print
    the first `N` rows via each row type's `Debug` format.
- **Public field exposure.** `Assembly`, `AssemblyRef`, `File`, and
  `ManifestResource` row structs now have `pub` fields (was private).
- **`MDTableRowTrait: std::fmt::Debug`** — supertrait bound, so
  `&dyn MDTableRowTrait` can be `{:?}`-formatted. All existing impls
  already derive `Debug`; no consumer impact.

### Fixed

- **Coded-index resolution is now permissive at parse time.** ECMA-335
  rid-zero null references and references to unpopulated optional tables
  (`File`, `ExportedType`, `ManifestResource`) no longer abort the parse.
  Validation is deferred to `ClrData::resolve_coded_index`, which still
  returns a clean `Err` when a non-null reference points at a missing
  row. This unblocks parsing of real-world .NET binaries (including
  malware) that were previously rejected with a bare `"File"` error.
- **Error display chain.** `error::Error::ParseError`,
  `RegexError` (since removed), `IoError` now include the wrapped error's
  message instead of swallowing it. `dndump` walks the `source()` chain
  on failure.

### Removed (minor breaking)

- **`regex` dependency** — never used anywhere in this crate; declaration
  was stale.
- **`Error::RegexError` variant** — same reason. Removing it deletes the
  derived `From<regex::Error> for Error` impl. Any external code using
  `?` to convert a `regex::Error` into a `dnfile::Error` will need to
  convert manually. No in-tree caller is affected.
- **`walkdir` dependency** — never used anywhere in this crate; another
  stale declaration.

### Dependencies

- `serde_json` is now an optional dep, gated behind the `cli` feature
  (was previously a hard dep but only used by `dndump --json`). Library
  consumers without `--features cli` no longer pull serde_json into
  their dependency tree.

### Performance

- Resources are exposed as borrowed slices into the file buffer (`&'a
  [u8]`); listing 1000s of resources from a fat assembly is essentially
  free.

## [0.4.0] — 2026-05

### Changed (breaking)

- **`DnPe` is now zero-copy.** The struct gains a lifetime parameter
  (`DnPe<'a>`) and borrows the underlying file buffer rather than copying
  it. The caller now owns the bytes.
- **`DnPe::new(path: &str)` removed; replaced with `DnPe::parse(data: &'a [u8])`.**
  Two-line migration:

  ```rust
  // before (0.3)
  let pe = dnfile::DnPe::new("Sample.exe")?;

  // after (0.4)
  let data = std::fs::read("Sample.exe")?;
  let pe = dnfile::DnPe::parse(&data)?;
  ```

  Or, for large binaries, back the buffer with `memmap2::Mmap`:

  ```rust
  let file = std::fs::File::open("Sample.exe")?;
  let mmap = unsafe { memmap2::Mmap::map(&file)? };
  let pe = dnfile::DnPe::parse(&mmap)?;
  ```
- **Heap types now hold borrowed slices.** `StringHeap<'a>`, `BlobHeap<'a>`,
  `UserStringHeap<'a>`, `GuidHeap<'a>` no longer own `Vec<u8>`; they hold
  `&'a [u8]` into the parent file buffer.
- **`Stream`, `ClrStream`, `ClrData`, `MetaData` are now generic over `'a`.**
- The `name: String` field on `DnPe` is removed (the parser no longer owns
  the path — that's the caller's concern). Serialized JSON shape changes
  accordingly: top-level keys are reduced.

### Added

- **`StringHeap::get_cow(idx) -> Cow<'a, str>`** and **`get_bytes(idx) -> &'a [u8]`**
  — zero-allocation accessors alongside the existing owned `get()` method.
- **`BlobHeap::get_ref(idx) -> &'a [u8]`** — borrowed slice into the blob.
- **`UserStringHeap::get_ref(idx) -> &'a [u8]`** — borrowed UTF-16 bytes.
- **`#[must_use]`** on the public constructors of `StringHeap`, `BlobHeap`,
  `UserStringHeap`, `GuidHeap`, plus `Argument`, `Local`, `Token`,
  `ExceptionHandler`.

### Removed

- Dead `raw_bytes: Vec<u8>` field on `Function` (was initialized to
  `vec![]` and never written).

### Performance

- File buffer is no longer cloned at construction (previously read via
  `std::fs::read`, owned by `DnPe`). For a 10 MB .NET binary this saves
  10 MB of heap pressure.
- Heap streams (#Strings, #US, #Blob, #GUID) are no longer copied out of
  the file buffer — they're slices into the caller's bytes.
- Combined with the 0.3.0 wins (cached PE parse, borrowed CIL `Reader`,
  static `OPCODES`), parsing throughput on a representative .NET DLL is
  significantly higher than 0.2.x.

## [0.3.0] — 2026-05

### Changed (breaking)

- Bumped to Rust 2024 edition; MSRV set to **1.85**.
- Bumped `thiserror` 1 → 2.

### Added

- New `dndump` binary (capa-style CLI inspector) gated behind a `cli`
  feature. Install via `cargo install dnfile --features cli`.
- Unit tests for `utils`, `Token`, `ClrHeaderFlags`, the CIL `Reader`, and
  the `OPCODES` singleton (24 tests).
- CI workflow (fmt, clippy, test, docs, MSRV) and Release workflow
  (pre-built binaries for Linux/macOS/Windows on x86_64 and aarch64).

### Fixed

- Cached parsed PE structure in `DnPe` so `offset()`/`get_data()` no longer
  re-parse the binary on every call (previously called from every metadata
  row and every CIL instruction).
- CIL `Reader` now borrows the file slice (`Reader<'a>`) instead of cloning
  the entire buffer per method body.
- CIL `OPCODES` is now a `LazyLock<OpCodes>` singleton (was built ~512
  entries per `Reader::new`).
- The 4 `unimplemented!()` panics in metadata-table parsing (`EventPtr`,
  `PropertyPtr`, `Unused`, `MaxTable`) now return
  `Error::NotImplementedError`.
- `is_ldloc()` typo: was matching `Ldarg_1`/`Ldarg_2` where the surrounding
  list contains `Ldloc_0..3` — now correctly matches `Ldloc_1`/`Ldloc_2`.
- Removed two reachable `unwrap()` calls in `DnPe::offset` /
  `DnPe::get_data` that could panic on truncated PE headers.

### Removed

- Dead `bincode` and `clap` dependencies from the library.
- Dead `Error::Bincode` variant.

## [0.2.3] and earlier

Initial pre-zero-copy releases. See git history.
