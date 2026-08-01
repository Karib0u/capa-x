# capa-x patch record

Vendored from `dnfile` 0.5.1 ([crates.io](https://crates.io/crates/dnfile/0.5.1),
[upstream repo](https://github.com/marirs/dnfile-rs)), per
[ADR 0003](../../docs/decisions/0003-clr-metadata.md) option (b): a pinned,
mechanically-patched fork, since no upstream release had picked up the fix
when the managed backend needed the dependency.

## What changed

1. `src/stream/meta_data_tables/mdtables/codedindex.rs` (ADR 0003's own
   finding): all 14 `impl CodedIndex for ...` blocks' `get_table_name`
   indexed `self.table_names[index]` directly, where `index` is the tag-bit
   portion of a coded index decoded straight from untrusted file bytes
   (ECMA-335 II.24.2.6). An out-of-range tag panicked instead of returning
   the `Result` the method's own signature already promises. Changed to
   `self.table_names.get(index).copied().ok_or(Error::UndefinedMetaDataTableIndex(index as u32))`
   at all 14 sites — the crate's own error type already had the right
   variant, unused.

2. `src/stream/meta_data_tables/mdtables/mod.rs`, `TypeDef::parse2`: computing
   a `TypeDef` row's `FieldList`/`MethodList` range required the `Field`/
   `MethodDef` table to be present in the parsed-tables map, erroring
   (`IncorrectTableRequested`) when it wasn't. But ECMA-335's `mask_valid`
   bitmask simply omits a table with zero rows — a type with no fields (or no
   methods) is entirely ordinary, and upstream's code failed to parse *any*
   file containing one, which is not a rare shape in real-world .NET
   binaries. Found by managed-backend row-count validation against pinned
   Python `dnfile`, not by the ADR 0003 mutation fuzz. Changed both lookups
   from `.ok_or(Error::IncorrectTableRequested(...))?.row_count()` to
   `.map(|t| t.row_count()).unwrap_or(0)`.

3. `src/stream/meta_data_tables/mdtables/mod.rs`, `TypeDef::parse2` (a third,
   distinct bug from fix 2 above, in the same function): a `TypeDef`'s
   `FieldList`/`MethodList` run silently dropped the table's true last row
   whenever that row belonged to it -- both when it's the last `TypeDef` (no
   `next_row` at all) *and* when the next `TypeDef` owns nothing further (its
   own recorded start already points past the table's end). Pinned Python
   `dnfile` (`base.py _parse_struct_lists`) computes an inclusive
   `run_end_index`, consumed as `range(start, end + 1)`, where `end =
   min(next_row_start - 1, max_row)` if there's a next row and `max_row`
   otherwise. Restated for the *exclusive* Rust range this code feeds one line
   down, the value it needs is `end + 1`, i.e. `min(next_row_start, max_row +
   1)` (next row present) or `max_row + 1` (no next row) -- upstream computed
   `min(next_row_start, max_row)` and `max_row`, one short in both cases
   whenever the `min` picked `max_row`. Found by name-model
   comparison against pinned Python `dnfile`/capa
   (`scripts/gen_dotnet_name_model.py`) -- one sample's very last managed
   method was silently missing, owned by a `TypeDef` that wasn't even the
   table's last row. Changed both branches to add the `+ 1`.

   That `+ 1` also made an extra `first_index == last_index == row_count`
   clause upstream had (guarding the subsequent `if`, alongside the plain
   `first < last` check) actively wrong rather than merely redundant: with
   `last_*_index` now consistently "true inclusive end + 1", "owns at least
   one row" is exactly `first < last` on its own, and the extra clause instead
   started matching runs of consecutive `TypeDef`s that all share the same
   recorded (zero-owned) start, spuriously keeping the placeholder row
   `parse()` always pre-populates for every type regardless of whether it
   owns anything. Found the same way, on a second sample, once fix 3's first
   half was in: a file with exactly one real `Field` row had three unrelated
   `TypeDef`s all claiming it. Removed the extra clause; `first < last` alone
   matches pinned Python's own `if run_start_index <= run_end_index`.

4. `src/stream/meta_data_tables/mdtables/mod.rs`, `NestedClass`: both columns
   (`nested_class`, `enclosing_class`) were private with no accessor, so a
   consumer had no way to read either RID -- needed by the name
   model) to walk the nested-class chain the same way pinned Python `dnfile`
   does (`typedef.MethodList`/`resolve_nested_typedef_name` reads
   `NestedClass.NestedClass`/`.EnclosingClass` directly). Added
   `nested_class_row_index()`/`enclosing_class_row_index()` getters; no
   parsing behavior changed.

No other behavior changed in any of these fixes.

5. `src/lang/cil/opcode.rs`: the `ldarg.2` opcode's mnemonic string was
   `"ldarg::2"` (a typo -- `::` instead of `.`). Found by diffing every opcode's
   name/value/operand-type/flow-control/stack-behaviour against pinned
   `dncil`'s own `OpCodes` table, programmatically, entry for entry: all 229
   opcodes matched except this one. `insn.mnemonic` (a future `mnemonic`
   feature, task 4) would otherwise silently diverge for this one opcode.

6. `src/lang/cil/function/mod.rs`, `parse_tiny_exception_handlers`: the tiny
   exception-section header's data-size byte is the section's byte length,
   not the clause count -- pinned `dncil` divides it by
   `ExceptionHandler.TINY_SIZE` (12) to get the count
   (`cil/body/__init__.py::parse_tiny_exception_handlers`). This fork used
   the raw byte as the count directly, wildly overcounting tiny-format
   exception handlers (by ~12x) on every method that has any. Changed to
   divide by `exception::TINY_SIZE`.

7. `src/lang/cil/function/mod.rs`, `parse_fat_exception_handlers`: pinned
   `dncil` computes `num_exceptions = total_size // ExceptionHandler.FAT_SIZE`
   (24) with no adjustment for the 4-byte section header, even though
   ECMA-335 II.25.4.6 defines `total_size` as including it -- that's the
   pinned behavioral spec (AGENTS.md: "capa wins"), not a bug to "fix" here.
   This fork instead computed `(total_size - 4) / 24`, matching the ECMA
   spec more literally -- upstream's own `CHANGELOG.md` (0.4.2) records this
   as a deliberate security hardening, not an oversight ("clause count is
   computed per ECMA-335 II.25.4.6 as `(total_size - 4) / 24`"), alongside a
   clamp against the *whole file's* remaining byte count (a weak, misleading
   guard in practice: `Reader` wraps the entire file buffer, not just this
   method, so it never actually bounded anything meaningful). This capa-x
   fork reverts that one hardening choice specifically because it makes this
   fork's decoder disagree with the pinned behavioral spec, not because it
   was wrong on its own terms -- upstream's math is arguably *more* correct
   against the ECMA-335 text than pinned `dncil`'s. Changed to `total_size /
   FAT_SIZE` with no manual clamp -- the loop never pre-allocates and every
   field read below returns `Err` the moment the buffer actually runs out,
   so a crafted `total_size` can only spin through as many iterations as the
   file has bytes for.

8. `src/lib.rs`, `DnPe::parse_functions`: pinned `dnfile`/capa
   (`capa/features/extractors/dnfile/helpers.py::read_dotnet_method_body`)
   catches a malformed method body's `MethodBodyFormatError` and skips just
   that one `MethodDef`, continuing with the rest of the file. This fork's
   `parse_functions` propagated *any* single method's parse error out of
   `DnPe::parse` itself via `?`, aborting metadata parsing for the entire
   file over one bad method body. Changed to catch
   `Error::MethodBodyFormatError`/`Error::IoError` (this fork's `Reader`
   surfaces truncation as `IoError` where pinned `dncil`'s own reader
   funnels every short read into `MethodBodyFormatError` uniformly -- both
   mean "this one body is truncated/malformed" here) per method and
   continue; every other error variant still aborts the whole parse, same
   as an uncaught non-`MethodBodyFormatError` exception would propagate out
   of pinned `read_dotnet_method_body`. Also added a `token: Token` field to
   `Function`, populated here from the owning `MethodDef`'s table/rid, since
   `Function` itself has no metadata-table context to compute one -- needed
   by capa-x's call graph and, later, feature
   addressing.

9. `src/lang/cil/function/reader.rs`, four separate operand-decoding bugs,
   all the same shape (an unsigned read where pinned `dncil` reads signed),
   found by field-for-field comparison against a pinned
   `dncil` dump of every managed method in `tests/testfiles/dotnet/`
   (`scripts/gen_dotnet_cil_dump.py` -> `capa-x/tests/dotnet_cil_decoder.rs`):
   - `read_short_inline_br_target` (`br.s`/`brfalse.s`/`blt.s`/...) read the
     branch offset as `u8` instead of `i8`, turning every *backward* short
     branch -- i.e. essentially every loop -- into a wildly wrong forward
     target.
   - `read_inline_br_target` (the 4-byte branch forms) had the identical
     bug: `u32` instead of `i32`.
   - `read_inline_switch`'s per-branch offsets had the same bug for each
     entry in a `switch` jump table (the leading `num_branches` count is
     correctly unsigned in both).
   - `read_inline_i` (`ldc.i4`'s 32-bit constant) read `u32` and
     zero-extended it to `i64` instead of reading `i32` and sign-extending,
     turning every negative 32-bit constant positive.
   - `read_short_inline_i`: pinned `dncil` always reads a signed `int8` for
     every `ShortInlineI` opcode (`ldc.i4.s`, `unaligned.`, `no.`) -- this
     fork special-cased `ldc.i4.s` as signed and read the other two
     (`unaligned.`'s alignment hint, `no.`'s suppressed-check bitmask)
     unsigned.

   Also added `index()` getters to `Local`/`Argument` (both fields were
   private with no accessor at all) so this task's own test could read them
   for comparison; no parsing behavior changed by that addition.

10. `src/stream/meta_data_tables/mdtables/mod.rs`, `GenericMethod` (ECMA-335
    II.22.29 `MethodSpec`, labeled `GenericMethod` by this fork -- see
    `capa-x/src/extract/dotnet/mod.rs`'s `METHODSPEC_RUST_NAME`): both
    columns (`Method`, `Instantiation`) were private, named `unknown1`/
    `unknown2`, with no accessor. Feature extraction needs
    `Method` to resolve a CIL `call`/`callvirt`/`jmp`/`newobj` operand
    through a `MethodSpec` token to its underlying `MethodDef`/`MemberRef`,
    the same way pinned Python capa's `dnfile/insn.py::get_callee` does via
    `row.Method` -- without it, every call through a generic method
    instantiation resolves to nothing (no `api`/`property`/`namespace`/
    `class` feature), which is 99 of the ~1,500 `call`/`callvirt`/`jmp`/
    `newobj` instructions across the 8 pinned samples. Renamed both fields to
    `method: codedindex::MethodDefOrRef` and `instantiation: Vec<u8>` (both
    `pub`, matching every other row's field-naming convention in this file);
    no parsing behavior changed.

11. `src/lib.rs`, `DnPe::new_streams`: pinned Python `dnfile`
    (`__init__.py::MetaData.parse_stream_table`) treats an invalid
    stream-table entry as "this throws off further parsing, so stop" --
    it `break`s the loop but keeps every stream successfully parsed so far,
    rather than failing the whole file. Found by feature
    parity table (`capa-x/tests/dotnet_features_parity.rs`, transcribed
    from pinned `tests/fixtures.py`) on
    `0953cc3b77ed2974b09e3a00708f88de931d681e2d0cb64afbaf714610beabe6.exe_`
    -- this fork instead propagated a malformed trailing stream-table entry
    via `?`, aborting metadata parsing for the entire file. Changed to break
    out of the loop (keeping streams parsed so far) on either a
    `new_clr_stream` error or a `stream_entry_rva` overflow, instead of
    returning early with `?`.

12. `src/lib.rs`, `DnPe::offset`: a Windows PE loader maps the header region
    (every RVA below `SizeOfHeaders`) 1:1 to file offset, not through any
    section -- pinned Python `dnfile`'s own RVA resolver (`pefile.
    get_offset_from_rva`) special-cases this; `goblin::pe::utils::
    find_offset` (which this fork called directly, consulting only the
    section table) cannot resolve an RVA in that range at all. A `MethodDef`
    row can legitimately carry a header-region RVA (ECMA-335 II.22.26 only
    requires the RVA be nonzero when the method has an IL body; pinned
    `read_dotnet_method_body` always attempts the read and lets a malformed
    result fail gracefully per-method, rather than rejecting the RVA
    up front) -- this fork's `parse_functions` called `self.offset(row.rva)`
    unconditionally before attempting to read anything, so a legitimate
    small RVA aborted the *entire* file's metadata parse with
    `UnresolvedRvaError` instead of reaching the per-method malformed-body
    handling fix 8 already added. Same sample and same task as fix 11 above
    (found immediately after, once fix 11 let parsing reach this point).
    Added a `size_of_headers` field (cached at construction, same pattern as
    `sections`/`file_alignment`) and a header-region carve-out in `offset()`,
    matching `capa-x/src/extract/loader/pe.rs`'s own `rva_to_offset` helper,
    which already carries an identical carve-out with the same rationale.

## Verification

A mutation-fuzz harness (byte-flip mutants, deterministic seed, not committed
to this repo — see the capa-x PR that vendored this fork) ran 24,000
mutants (3,000 per pinned sample) across all 8 `tests/testfiles/dotnet/`
samples through `DnPe::parse`:

- unpatched 0.5.1: 137 panics, all `index out of bounds` in `codedindex.rs`
- this fork: 0 panics, same mutant sequence

Separately, `capa-x/tests/dotnet_metadata_reader.rs` parses all 8 pinned
samples and compares every ECMA-335 table's row count against a dump from
pinned Python `dnfile` (`scripts/gen_dotnet_table_counts.py`); fix 2 above was
required for `e8ea789b860e8354b3ef5058bea7ea98.exe_` (zero `Field` rows) to
parse at all, and all 8 samples now match exactly.

For fixes 5-9 (the CIL decoder), `capa-x/tests/
dotnet_cil_decoder.rs` decodes every managed method body (instructions,
operands, exception handlers) in all 8 pinned samples and compares
field-for-field against a pinned `dnfile`/`dncil` dump
(`scripts/gen_dotnet_cil_dump.py` -> `capa-x/tests/fixtures/dotnet/
cil_dump.json`), plus the calls-to/calls-from call graph
(`capa-x/src/extract/dotnet/function.rs`). Fixes 6-9 were each found by
this comparison failing on real methods in the pinned corpus, not by
inspection; without fix 9's branch-target sign bugs in particular, most
loop-bearing methods in the corpus would have every backward branch target
decoded wrong. `capa-x/tests/dotnet_dnfile_fuzz.rs`'s byte-flip mutation
regression (2,400 mutants) is still 0 panics on the now-far-more-patched
fork -- and, since fix 8 stops one malformed method from aborting the whole
file's parse, now exercises the CIL decoder across every surviving method
per mutant rather than stopping at the first one, deeper coverage than
before this task.

`cargo test` (35 unit tests + 1 doctest) is unchanged and green.

## Consequences

- File the same fixes upstream to `marirs/dnfile-rs` regardless of whether
  capa-x keeps vendoring this fork.
- Drop this vendored copy once upstream releases a version containing all
  of them, per ADR 0003.
