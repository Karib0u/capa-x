#!/usr/bin/env bash
# Verifies the pinned Python reference env (.venv) is set up and matches
# the version recorded in PINNED.md. Used by difftests and CI setup, never
# by capa-x-cli at runtime.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pinned_file="$repo_root/PINNED.md"
venv_capa="$repo_root/.venv/bin/capa"

if [[ ! -x "$venv_capa" ]]; then
    echo "error: $venv_capa not found — run: uv venv .venv && uv pip install --python .venv/bin/python flare-capa==<pinned>" >&2
    exit 1
fi

pinned_version="$(grep -m1 'flare-capa' "$pinned_file" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
if [[ -z "$pinned_version" ]]; then
    echo "error: could not find a pinned flare-capa version in $pinned_file" >&2
    exit 1
fi

actual_version="$("$venv_capa" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
if [[ -z "$actual_version" ]]; then
    echo "error: could not parse version from '$venv_capa --version'" >&2
    exit 1
fi

if [[ "$actual_version" != "$pinned_version" ]]; then
    echo "error: .venv has flare-capa $actual_version, PINNED.md wants $pinned_version" >&2
    exit 1
fi

echo "ok: .venv flare-capa $actual_version matches PINNED.md"

# PINNED.md is only a source of truth if it agrees with the gitlinks. It drifted
# once already -- a submodule bump landed without touching the table -- so check
# it rather than trust it.
gitlink_drift=0
while read -r _mode _type sha path; do
    [[ -z "${path:-}" ]] && continue
    # the table names each submodule by its path in backticks, e.g. (`rules`)
    needle="$(printf '`%s`' "$path")"
    recorded="$(grep -F -- "$needle" "$pinned_file" | grep -oE '\b[0-9a-f]{40}\b' | head -1 || true)"
    if [[ -z "$recorded" ]]; then
        echo "error: PINNED.md has no commit recorded for submodule $path" >&2
        gitlink_drift=1
    elif [[ "$recorded" != "$sha" ]]; then
        echo "error: $path gitlink is $sha, PINNED.md records $recorded" >&2
        gitlink_drift=1
    fi
done < <(git -C "$repo_root" ls-tree HEAD rules tests/testfiles reference/capa)

if [[ "$gitlink_drift" -ne 0 ]]; then
    echo "hint: bump the table in PINNED.md in the same commit as the gitlink" >&2
    exit 1
fi

echo "ok: submodule gitlinks match PINNED.md"
