# Pinned upstream versions

Single source of truth for the upstream versions this port targets. Bump
these only via a deliberate version-bump PR that updates the gitlinks below
and re-runs the full difftest suite.

| Component | Ref | Commit |
|---|---|---|
| `mandiant/capa` (`reference/capa`) | `v10.0.0` | `85813ebc5b99ccdbe43147e46796d0bd6700f30a` |
| `mandiant/capa-rules` (`rules`) | `v10.0.0` | `805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5` |
| `mandiant/capa-testfiles` (`tests/testfiles`) | `master` | `44e7363ac3a3fb1ffe1c36957188ad3e7683b57f` |
| `flare-capa` (PyPI, `.venv`) | `10.0.0` | n/a |
| `dnfile` (`third_party/dnfile`, vendored fork) | `0.5.1-capa.5` | patched from [dnfile 0.5.1](https://crates.io/crates/dnfile/0.5.1) (unchecked-indexing fix); see `third_party/dnfile/PATCH.md` |

`capa-testfiles` has no release tags; pin a fixed commit and bump
deliberately since it's a large binary corpus.

The commits above must equal the gitlinks recorded in this repo's tree.
`scripts/check_env.sh` asserts that, so a submodule bump that forgets this
table fails the check instead of quietly making the table wrong.
