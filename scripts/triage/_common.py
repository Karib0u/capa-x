"""Shared plumbing for the divergence-triage tools in this directory.

Each tool answers a different question about a *specific* divergence class, but
they all need the same four things: the repo root from two directories down,
the pinned Python environment, the difftest cache, and capa-x's own recovered
function layout. Those lived in three near-identical copies before this module.

Nothing here decides anything -- the analysis and classification logic stays in
the individual tools, because their output is cited by KNOWN_DIVERGENCES.md and
must keep meaning exactly what it meant when it was recorded.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# scripts/triage/_common.py -> scripts/triage -> scripts -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
CACHE_DIR = REPO_ROOT / ".cache" / "difftest"
VENV_PYTHON = REPO_ROOT / ".venv" / "bin" / "python3"

# The harness lives one directory up and owns the cache key and invocation
# conventions these tools reuse; import it the same way from every tool.
sys.path.insert(0, str(SCRIPTS_DIR))

import difftest  # noqa: E402


def rust_layout(sample: Path, capa_cli: Path) -> dict[int, set[int]]:
    """capa-x's recovered functions: {fva: set(instruction addresses)}.

    The same `--dump-code-layout` surface the layout oracle uses, so "capa-x
    does not have this function" means the same thing in every tool here.
    """
    command = [
        str(capa_cli),
        *difftest.shellcode_format_flag(sample),
        "--dump-code-layout",
        str(sample),
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    dump = json.loads(result.stdout)
    return {int(f["address"]): {int(i) for i in f["instructions"]} for f in dump["functions"]}
