#!/usr/bin/env python3
"""
One-off generator: extract the COM class/interface name -> GUID list
databases from the pinned Python capa checkout's plain literal-dict source
files and emit them as JSON data assets for capa-x (COM feature expansion,
capa/features/com/__init__.py::translate_com_feature).

This is a build-time (developer-run) step, not part of capa-x-cli's runtime --
capa-x never imports or shells out to Python (see AGENTS.md "no Python at
runtime"). Re-run this only when PINNED.md's `mandiant/capa` ref changes and
capa/features/com/{classes,interfaces}.py have been regenerated upstream.

usage: scripts/gen_com_db.py
"""

import ast
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REFERENCE = REPO_ROOT / "reference" / "capa" / "capa" / "features" / "com"
OUT_DIR = REPO_ROOT / "capa-x" / "data"


def load_dict_literal(path: Path, var_name: str) -> dict:
    """
    parse `<var_name>: dict[str, list[str]] = { ... }` out of a plain-literal
    python module without importing it (these files have no other imports,
    but capa's package __init__ does, and we don't want a full flare-capa
    install just to read two data files).
    """
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", None) == var_name:
            return ast.literal_eval(node.value)
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if getattr(target, "id", None) == var_name:
                    return ast.literal_eval(node.value)
    raise ValueError(f"{var_name} not found in {path}")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    classes = load_dict_literal(REFERENCE / "classes.py", "COM_CLASSES")
    interfaces = load_dict_literal(REFERENCE / "interfaces.py", "COM_INTERFACES")

    (OUT_DIR / "com_classes.json").write_text(
        json.dumps(classes, sort_keys=True, separators=(",", ":")) + "\n"
    )
    (OUT_DIR / "com_interfaces.json").write_text(
        json.dumps(interfaces, sort_keys=True, separators=(",", ":")) + "\n"
    )
    print(f"wrote {len(classes)} COM classes, {len(interfaces)} COM interfaces to {OUT_DIR}")


if __name__ == "__main__":
    main()
