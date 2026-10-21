# Compact decompiler runtime signatures

`decompiler-runtime.pat` is a generated subset of the existing Mandiant
`1_flare_msvc_rtf_32_64.sig`, under the same Apache-2.0 license as capa.
The upstream version is the `mandiant/capa` pin in `PINNED.md`. Every pattern
is derived from that pinned database without sample-specific byte matching.

- Source SIG SHA-256: `e0042918fa80d432a1914680816996ac397afc30b05d3161192f29de63e66e79`
- Generated PAT SHA-256: `21a275fce96cd9114bc4d4c9489ff33c744c8700ac6667588769c8bf84327b1b`
- 54 patterns, 6,091 bytes.

Regenerate from the repository root:

```sh
cargo run --release -p capa-x --example decompiler_runtime_signatures > /tmp/decompiler-runtime.pat
cmp /tmp/decompiler-runtime.pat capa-x/sigs/decompiler-runtime.pat
```

The generator selects security-cookie initialization/checking and DLL startup
routines. It excludes signatures with reference dependencies and any candidate
whose byte prefix overlaps a different root name in the source database.
The latter deliberately rejects even overlaps that CRC/tail bytes might have
disambiguated: removing other candidates must not create a newly unambiguous
name. Wildcard padding preserves the original CRC start, and all CRC and tail
constraints remain in the PAT output. Coverage is intentionally narrower than
full library recognition.

Only the optional decompiler loads this subset. Ordinary capability analysis
continues to use its unchanged three full databases. The small set avoids the
large cold allocation and startup cost of parsing the full corpus for a single
function request. The existing FLIRT matcher still validates the patterns.
