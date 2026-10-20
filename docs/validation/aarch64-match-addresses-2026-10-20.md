# Differential test report

Measured 2026-10-20 against capa-x `385b24e` and the reference pins in
`PINNED.md`. See [the validation summary](full-corpus-2026-10-20.md) for scope
and the distinction between reference failures and implementation differences.

- Mode: `full-exact`
- Samples: 3
- Identical: 0 (0.0%)
- Different or failed: 3

| Sample | Result | Diffs | Seconds | Details |
|---|---:|---:|---:|---|
| `687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf_` | diff | 3 | 0.2 | rule 'get current user on Linux': extra in capa-x: ['absolute:1073488']<br>rule 'print debug messages': extra in capa-x: ['absolute:1073488', 'absolute:1078656']<br>rule 'terminate process': extra in capa-x: ['absolute:1073488'] |
| `c7f38027552a3eca84e2bfc846ac1307fbf98657545426bb93a2d63555cbb486.elf_` | diff | 1 | 0.1 | rule 'contain loop': extra in capa-x: ['absolute:2163032'] |
| `d1e6506964edbfffb08c0dd32e1486b11fbced7a4bd870ffe79f110298f0efb8.elf_` | diff | 4 | 0.8 | rule 'contain loop': missing in capa-x: ['absolute:1194956', 'absolute:1198164', 'absolute:1199088', 'absolute:1199904', 'absolute:1232720', 'absolute:1242008']; extra in capa-x: ['absolute:1134236', 'absolute:1136428', 'absolute:1148448', 'absolute:1173140', 'absolute:1176740', 'absolute:1177040', 'absolute:1179856', 'absolute:1180860'] ...<br>rule 'create thread': missing in capa-x: ['absolute:1134056']; extra in capa-x: ['absolute:1134004']<br>rule 'delete file': missing in capa-x: ['absolute:1151828']<br>rule 'get file attributes': extra in capa-x: ['absolute:1137032'] |
