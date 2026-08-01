#!/usr/bin/env bash
# One-shot maintainer setup: everything the parity work needs that a plain
# clone deliberately does not fetch.
#
# Building and running capa-x needs only the `rules` submodule (~4 MB), so
# that is all the README asks a user for. Reproducing the difftest numbers
# additionally needs the pinned Python capa source, the ~190 MB testfiles
# corpus, and a .venv holding the pinned flare-capa release -- about 250 MB of
# checkout that is useless unless you are measuring agreement. This script
# fetches that side.
#
# Safe to re-run: every step is idempotent.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

pinned_version="$(grep -m1 'flare-capa' PINNED.md | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
if [[ -z "$pinned_version" ]]; then
    echo "error: could not find a pinned flare-capa version in PINNED.md" >&2
    exit 1
fi

echo "==> submodules (rules, tests/testfiles, reference/capa)"
# --depth 1 everywhere: the pinned commit is all any of these are read at, and
# testfiles' full history is far larger than its checkout.
git submodule update --init --depth 1 rules tests/testfiles reference/capa

echo "==> pinned Python reference: flare-capa==$pinned_version"
if ! command -v uv >/dev/null 2>&1; then
    echo "error: uv not found — install it from https://docs.astral.sh/uv/ and re-run" >&2
    exit 1
fi
uv venv .venv
uv pip install --python .venv/bin/python "flare-capa==$pinned_version"

echo "==> verifying"
scripts/check_env.sh

cat <<'EOF'

Setup complete. The three feedback loops (see AGENTS.md):

  inner   cargo test -p capa-x --test features_parity
  mid     python3 scripts/difftest.py --mode full \
              --samples scripts/corpus-smoke.txt \
              --capa-cli target/release/capa-x --jobs 6
  outer   ... same, with --samples scripts/corpus-outer.txt

Run `cargo build --release` first — the mid and outer loops compare against a
release binary.
EOF
