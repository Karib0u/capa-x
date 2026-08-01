# Pinned upstream versions

Single source of truth for the upstream versions this port targets. Bump
these only via a deliberate version-bump PR that updates the gitlinks below
and re-runs the full difftest suite.

| Component | Ref | Commit |
|---|---|---|
| `mandiant/capa` (`reference/capa`) | `v9.4.0` | `7a79f799a70f052e8382cdbeaec8115daba14a5b` |
| `mandiant/capa-rules` (`rules`) | `v9.4.0` | `2af9fbfc1c9b4634dbeb76b5d34fca9389fa7f80` |
| `mandiant/capa-testfiles` (`tests/testfiles`) | `master` | `44e7363ac3a3fb1ffe1c36957188ad3e7683b57f` |
| `flare-capa` (PyPI, `.venv`) | `9.4.0` | — |
| `dnfile` (`third_party/dnfile`, vendored fork) | `0.5.1-capa.5` | patched from [dnfile 0.5.1](https://crates.io/crates/dnfile/0.5.1) per [ADR 0003](docs/decisions/0003-clr-metadata.md); see `third_party/dnfile/PATCH.md` |

`capa-testfiles` has no release tags; pin a fixed commit and bump
deliberately since it's a large binary corpus.

The commits above must equal the gitlinks recorded in this repo's tree.
`scripts/check_env.sh` asserts that, so a submodule bump that forgets this
table fails the check instead of quietly making the table wrong.
