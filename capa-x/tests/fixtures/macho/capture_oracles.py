#!/usr/bin/env python3
"""
Captures `llvm-readobj --all` output for each clean (non-malformed) Mach-O
fixture as `<name>.oracle.json`: "capture
llvm-readobj output at build time... never invoked at test time." Run by
build.sh after the fixtures exist.

llvm-readobj's `--output-style=JSON` is ELF-only (confirmed against the
installed version's --help), so this wraps its LLVM-style text output in a
small JSON envelope instead of relying on a native Mach-O JSON dumper --
the fixture tests can parse/diff the `output` field as text.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent

CLEAN_FIXTURES = [
    "thin-x86_64-exe",
    "thin-arm64-exe",
    "thin-x86_64.dylib",
    "thin-arm64.dylib",
    "fat-x86_64-arm64-exe",
    "fat-x86_64-arm64.dylib",
    "symbols-x86_64-exe",
    "stripped-x86_64-exe",
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

    for name in CLEAN_FIXTURES:
        fixture_path = HERE / name
        if not fixture_path.is_file():
            raise FileNotFoundError(f"{fixture_path} does not exist -- run build.sh first")
        proc = subprocess.run(
            [llvm_readobj, "--all", str(fixture_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        oracle = {
            "tool": "llvm-readobj --all",
            "tool_version": version,
            "fixture": name,
            "fixture_sha256": subprocess.run(
                ["shasum", "-a", "256", str(fixture_path)], capture_output=True, text=True, check=True
            ).stdout.split()[0],
            "output": proc.stdout,
        }
        oracle_path = HERE / f"{name}.oracle.json"
        oracle_path.write_text(json.dumps(oracle, indent=2) + "\n")
        print(f"{name} -> {oracle_path.name}")


if __name__ == "__main__":
    main()
