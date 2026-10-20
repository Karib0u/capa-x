# Full corpus validation, 2026-10-20

The expanded corpus disproves universal compatibility. Against Python capa
10.0.0, capa-x `385b24e` matches rule names on 358 of 376 analyzable native
inputs. Eighteen inputs differ, with 29 missing and three extra rules.
Exact rule names and match-address sets agree on 177 of those 376 inputs;
199 have at least one difference.

The earlier 200-sample result remains valid for that selection. It does not
describe the complete upstream corpus or exact match addresses.

## Durable reference dataset

[`tests/reference-results/capa-10.0.0/`](../../tests/reference-results/capa-10.0.0/README.md)
contains 376 complete original result documents and one reference failure
record for the 377 entries in
[`scripts/corpus-full-static.txt`](../../scripts/corpus-full-static.txt).
All input hashes, compressed result hashes, original JSON hashes, full
evidence trees, analysis metadata, and the compact match index were verified.
Only invocation paths are normalized.

The dataset covers 739 distinct matched rule names, 11,412 rule/sample
matches, and 85,783 matched addresses. Three corpus paths contain identical
bytes to another entry; all paths remain represented. The archive occupies
approximately 19.3 MiB.

Versions used:

- capa source: `85813ebc5b99ccdbe43147e46796d0bd6700f30a`, version 10.0.0.
- Rules: `805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5`.
- Project testfiles: `44e7363ac3a3fb1ffe1c36957188ad3e7683b57f`.
- Reference runtime: Python 3.13.14, Vivisect 1.3.2, viv-utils 0.8.1,
  python-flirt 0.10.0, pefile 2024.8.26.

The native selection includes every tracked x86/x64 PE without CLR metadata,
x86/x64 ELF, and explicitly named raw32/raw64 shellcode input. It includes
packed and malformed files; there are no known-difference exclusions.

## Results

| Check | Result |
|---|---|
| Rust workspace, including ignored gates | 468 passed |
| Python binding | 17 passed |
| Python harness and snapshot exporter | 10 passed |
| Determinism, jobs 1/2/4, two repetitions, five samples | 30 runs agree byte for byte after invocation-metadata normalization |
| Native rule-name comparison | 358 identical, 18 different, one reference rejection |
| Native rule and address comparison | 177 identical, 199 different, one reference rejection |
| Additional native input from capa's exact testfiles pin | Rule names match; one loop match address is missing |
| .NET inputs, including nested parser fixtures | 38 identical rule/address sets; two capa-x parser errors |
| AArch64 ELF/BinExport2 pairs | 3/3 rule-name sets match; all three differ at match addresses |
| Shared-feature result JSON corpus | 62/62 match |
| Frozen upstream snapshots from both testfiles revisions | 11/11 match |
| Dynamic reports through shared freezes | 11 result documents match; 10 reference-side rejections |
| Native/other-ELF file features and file-only JSON | 376 identical, two different, one reference rejection |
| .NET files using PE file extraction on both sides | 26/26 match |

The native rule-name discrepancy ratio is 32 differences across 11,412
reference rule/sample matches, or 99.72% agreement under the harness's
metric. This ratio must not replace the per-sample or address results.

Detailed results:

- [All 377 native rule-name comparisons](full-corpus-rule-names-2026-10-20.md).
- [All 376 successful-reference match-address comparisons](full-corpus-match-addresses-2026-10-20.md).
- [.NET parser cases](dotnet-parser-cases-2026-10-20.md).
- [AArch64 match-address differences](aarch64-match-addresses-2026-10-20.md).

## Failures and interpretation

Original capa rejects
`c2b2d7cea94179e6c2b6913205e37c45b67ccc0156d8f266548f7f1f95144285.elf_`
with exit 13: section zero is at offset 25,489,984, beyond the 65,536-byte
file. capa-x also rejects it with an ELF bad-offset error. The reference
manifest retains this rejection rather than treating it as an empty result.

The .NET nested fixtures `invalid-stream-name.exe` and `unknown-stream.exe`
produce reference results, but capa-x rejects both with
`extracting .NET features: blob`. They remain implementation differences.
The other 38 .NET inputs agree on rule names and match addresses.

Two native file-only comparisons differ:

- `0761142e...dll_`: the reference finds an embedded PE at file offset
  5,040,187 that capa-x misses.
- `3fdfb2d5...exe_`: file import features differ, including
  `GetModuleHandle`, `GetProcAddress`, and `LoadLibrary`.

The initial file-only sweep also reported 26 .NET differences because it
compared the reference's PE extractor with capa-x's automatic CLR selection.
Repeating those inputs with `--format pe` produced 26/26 agreement. Those
initial mismatched-profile observations are not counted as defects.

Ten dynamic inputs are rejected during original capa freeze generation:
two reports contain no captured processes, and eight are rejected with exit
16. They have no comparable reference result. Raw dynamic report loading is
not tested by the shared-freeze comparison; that comparison tests matching
and result construction from reference features.

## Original Python test suite

The original suite was run from an unchanged copy of the pinned source with
its exact testfiles commit, `4fa9a0448a1453a80bdcbcefb6dff870f6333b64`,
including the nested dnfile fixtures. This is a reference-environment check,
not a substitute for testing capa-x.

The first run collected 1,715 tests. Twelve initial failures were resolved
by completing the validation environment and rerunning only those failures:
Git metadata for development-mode detection, source imports for subprocesses,
optional SARIF dependencies, a wider terminal for the filename assertion,
and a longer timeout for the Vivisect hashing test.

Across the initial run and successful retries, the outcome is:

- 1,368 passed.
- 334 skipped by upstream backend/platform conditions.
- 11 expected failures and one unexpected pass.
- One unresolved IDA snapshot test:
  `test_feature_snapshot[mimikatz-exe-ida]` terminates its Python worker.
  It also exits 1 when run alone, without completing the pytest result.

The IDA worker termination is not a capa-x test failure and is not counted
as a passing original test.

The binding's CLI comparison initially skipped because its test still looked
for `target/release/capa`. Correcting it to `target/release/capa-x` enabled
the assertion; all 17 binding tests now pass. The binding was rebuilt with
Rust 1.98.1 after the default toolchain produced a macOS extension that the
loader rejected.

## Reproduction

```sh
scripts/check_env.sh
cargo build --release
cargo test --workspace -- --include-ignored
python3 -m unittest discover -s scripts -p 'test_*.py'
.venv/bin/python3 -m pytest capa-x-python/tests
python3 scripts/difftest.py --mode full \
  --samples scripts/corpus-full-static.txt \
  --capa-cli target/release/capa-x --jobs 6 --no-rust-cache --no-expected
python3 scripts/difftest.py --mode full-exact \
  --samples scripts/corpus-full-static.txt \
  --capa-cli target/release/capa-x --jobs 6 --no-rust-cache --no-expected
```

The recorded address comparison was split into the 376 inputs with reference
documents and the one malformed ELF while the final original analyses
finished. Together these cover all 377 corpus entries. The single command
above reproduces the combined scope.

Additional inventories, commands, logs, XML test results, and per-profile
reports from this run are under `target/full-validation/`. The durable
reference dataset and reports linked above remain outside that disposable
directory. The snapshot README explains how to restore the original outputs
into the harness cache without repeating original disassembly.
