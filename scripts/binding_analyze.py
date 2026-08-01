#!/usr/bin/env python3
"""
Binding parity helper: run the `capa_x` binding against a raw
sample, validate the returned document against pinned capa's own
`ResultDocument` pydantic model, and report the matched (top-level) rule
names -- everything `scripts/difftest.py --mode binding` needs, printed as
one JSON object so the harness doesn't need `capa_x` importable in its
own interpreter.

Run through the pinned `.venv` (same convention as
`scripts/dump_file_features.py`): that interpreter already has pinned
`flare-capa` installed for `capa.render.result_document.ResultDocument`,
and this script additionally needs `capa_x` installed into it (`pip
install capa-x-python/` or `maturin develop --release` from that venv --
`scripts/difftest.py --mode binding` raises with that instruction if the
import fails, rather than silently skipping the check).

`jobs=1`: matches every other difftest invocation's single-threaded
baseline (AGENTS.md "The three loops" -- comparisons run single-threaded
unless the comparison is *about* parallelism), so nothing about this
particular run's thread count can be a variable in a reported divergence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rules", type=Path, help="rules directory")
    parser.add_argument("sample", type=Path, help="raw sample to analyze")
    args = parser.parse_args(argv)

    try:
        import capa_x
    except ImportError as e:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": f"capa_x is not importable in this interpreter ({e}); "
                    f"install it: {sys.executable} -m pip install ./capa-x-python",
                }
            )
        )
        return 1

    from capa.render.result_document import ResultDocument

    try:
        rules = capa_x.Rules.from_directory(str(args.rules))
        doc = capa_x.analyze(str(args.sample), rules, jobs=1)
    except capa_x.CapaError as e:
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}))
        return 1

    doc_json = json.dumps(doc)
    try:
        ResultDocument.model_validate_json(doc_json)
        valid = True
        validation_error = None
    except Exception as e:  # pydantic's ValidationError, deliberately caught broadly:
        # any exception here means "does not validate", which is the fact
        # J14 checks -- not a specific pydantic version's exception type.
        valid = False
        validation_error = str(e)

    rule_names = sorted(doc.get("rules", {}).keys())

    print(
        json.dumps(
            {
                "ok": True,
                "valid": valid,
                "validation_error": validation_error,
                "rule_names": rule_names,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
