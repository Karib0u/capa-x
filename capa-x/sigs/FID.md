# Function ID data for the decompiler

`fid-x64.pack` is a compact, generated export of the Function ID databases that
ship with Ghidra 12.1.4 (`Ghidra_12.1.4_build`, commit
`8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc`, Apache-2.0, like the rest of the
vendored Ghidra material). Only the optional `decompiler` feature embeds it.

| Source database (`Ghidra/Features/FunctionID/data`) | SHA-256 |
|---|---|
| `vs2012_x64.fidbf` | `624ab5747c83363b856528fc8331fbc9bdac293184e94a363c63ee49e53188c3` |
| `vs2015_x64.fidbf` | `a81a628f05c93e8f9921d24e3767b74d73571fa3c0850b6daad44e3ae0e40466` |
| `vs2017_x64.fidbf` | `966d21ec7b194370d8ae6894daf163254b92b7ac6f356c98d3aec8a931277c75` |
| `vs2019_x64.fidbf` | `07bf18e1fcb9110c8a0f1eee2e42cda6b98b071c6e844dee3e7932313584bafd` |
| `vsOlder_x64.fidbf` | `57531edcd0e7d8a8e04e3231f8bf058da7f7f14141a2a2757fa9b878de0e6172` |

- Contents: 213,142 records (Release variants of Visual Studio 2005 to 2019 C and
  C++ runtimes, ATL/MFC pieces and the bundled static libraries), 58,332 distinct
  names and 1,195,431 call-relation keys. 9,880,200 bytes.
- Pack SHA-256: `119a1317dc817394dd1041926c0ba547d8c09283825a1b9faac02b229307d764`.
  Regeneration from the same Ghidra release is deterministic.
- Regenerate with `scripts/decompiler_fid/README.md`. File layout:
  `scripts/decompiler_fid/pack_fid.py`.

## What the matcher does

`capa-x/src/fid/` ports, from the Ghidra sources, `MessageDigestFidHasher` with the
FNV-1a 64 digest and x86 instruction skipper, the `FidProgramSeeker` scoring with
callee and caller relations (threshold 14.6, medium length 24, 500 parent limit),
and the unambiguous part of `ApplyFidEntriesCommand` naming (one name, or names that
differ only by leading underscores). The constants come from `FidService`,
`FidProgramSeeker` and `FidDBUtils`.

Ghidra gets each instruction's mask and operand objects from its Sleigh language.
Here they are derived with iced-x86 (`capa-x/src/fid/x86.rs`) and verified against
Ghidra's own output, not assumed: on 11,800 functions (797,197 instructions) from 23
PEs, every instruction mask and operand list agrees except 86 immediates that Ghidra
flags as addresses for reasons not reproduced, and 11,758 function hashes (99.6%)
agree. In an end-to-end replay on the same samples the recovered names equal
Ghidra's in 2,628 of 2,676 functions that both name (98.2%).

## Known differences from Ghidra

- No demangler. C++ operators, constructors, templates and compiler-generated names
  are not applied, and multi-name ambiguities that Ghidra resolves by demangling
  stay unnamed. Simple `?name@...` names are shortened to `name`.
- Debug-runtime variants are omitted (1.7% fewer matches, 4.8 MB smaller).
- Relation keys keep 36 bits, so a call-relation false positive has probability
  about 1.7e-5 per test.
- Functions are those capa-x recovery finds. Ghidra finds more; naming is only as
  complete as discovery (plan phase 3).
- FID never renames a function that already has an export, FLIRT or DLL entry name.
- Ghidra's bundled databases carry only names. Calling convention and no-return
  facts come from the prototype pack when the name matches.
