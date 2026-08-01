#!/usr/bin/env python3
"""
Captures `llvm-readobj --all` output for each AArch64 PE fixture as
`<name>.oracle.json`. Run by build.sh
after the fixtures exist; never invoked at test time.

Same JSON-envelope-around-text-output approach as the Mach-O corpus's
capture_oracles.py (llvm-readobj's native `--output-style=JSON` is
ELF-only) -- see that file's docstring.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent

FIXTURES = [
    "exe-with-import.exe",
    "dll-with-export.dll",
]


def find_llvm_readobj() -> str:
    on_path = shutil.which("llvm-readobj")
    if on_path:
        return on_path
    brew_prefix = subprocess.run(
        ["brew", "--prefix", "llvm"], capture_output=True, text=True, check=True
    ).stdout.strip()
    candidate = Path(brew_prefix) / "bin" / "llvm-readobj"
    if candidate.is_file():
        return str(candidate)
    raise RuntimeError("llvm-readobj not found on PATH or via `brew --prefix llvm`")


def main() -> None:
    llvm_readobj = find_llvm_readobj()
    version = subprocess.run([llvm_readobj, "--version"], capture_output=True, text=True).stdout.strip()

    for name in FIXTURES:
        fixture_path = HERE / name
        if not fixture_path.is_file():
            raise FileNotFoundError(f"{fixture_path} does not exist -- run build.sh first")
        readobj = subprocess.run(
            [llvm_readobj, "--all", str(fixture_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        exports = subprocess.run(
            [llvm_readobj, "--coff-exports", str(fixture_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        oracle = {
            "tool": "llvm-readobj --all / --coff-exports",
            "tool_version": version,
            "fixture": name,
            "fixture_sha256": subprocess.run(
                ["shasum", "-a", "256", str(fixture_path)], capture_output=True, text=True, check=True
            ).stdout.split()[0],
            "output": readobj.stdout,
            "exports": exports.stdout,
        }
        oracle_path = HERE / f"{name}.oracle.json"
        oracle_path.write_text(json.dumps(oracle, indent=2) + "\n")
        print(f"{name} -> {oracle_path.name}")


if __name__ == "__main__":
    main()
