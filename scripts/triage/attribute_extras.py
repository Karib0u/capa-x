#!/usr/bin/env python3
"""Partition capa-x's *extra* rule matches by whether the reference
analysed the code they matched in.

The first triage split asks one question per extra rule:

    does the pinned Vivisect workspace have a location at the address
    capa-x matched the rule at?

  no  -> A.2, a **gap-driven** extra. capa-x walked code the reference
         never claimed as code at all, so the fix is a codeflow edge (or a
         seed that should not have re-entered the range), not a rule or a
         feature.
  yes -> A.3, a **shared-code** extra. Both sides analysed the bytes and
         disagreed about attribution or feature extraction -- a different,
         cheaper class.

A third bucket: a FILE-scope rule matches at
`no address`, so there is no code address to ask the question about. These
are file-feature divergences (packer signatures, embedded-PE detection) and
belong to neither A.2 nor A.3. They are counted and listed separately rather
than dropped, so the bucket totals always add up to the corpus extras count.

The reference side is `vw.getLocation(va)`, not "is this inside a recovered
function": Vivisect's `importcalls` pass defines loose code with `makeCode`
and never wraps it in a function, and treating that as unanalysed would
inflate the A.2 half with addresses the reference does know about. Function
membership is reported alongside, since it is what the layout oracle
compares.

Results are cached per sample sha256 under the shared difftest cache, keyed
by the queried address set, because building the workspace is the whole cost.

usage:
  .venv/bin/python3 scripts/triage/attribute_extras.py --samples scripts/corpus-outer.txt
  .venv/bin/python3 scripts/triage/attribute_extras.py --only 749cf36a --verbose
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import CACHE_DIR, REPO_ROOT, VENV_PYTHON, difftest, rust_layout  # noqa: E402,F401


def rust_matches_with_addresses(sample: Path, capa_cli: Path, rules_dir: Path) -> dict[str, set[int]]:
    """capa-x's matched (rule -> absolute addresses), from the same cached
    `--dump-matches` output the difftest harness compares.

    A rule with an empty address set matched only at non-code addresses --
    `no address` for a FILE-scope rule -- and the caller reports it as the
    third bucket rather than dropping it.
    """
    out: dict[str, set[int]] = {}
    raw = difftest.rust_matches(
        capa_cli,
        rules_dir,
        sample,
        extra_args=difftest.shellcode_format_flag(sample),
        rust_cache=CACHE_DIR / "rust",
    )
    for name, addresses in raw.items():
        out[name] = {
            int(value)
            for kind, _, value in (address.partition(":") for address in addresses)
            if kind == "absolute" and value
        }
    return out


def reference_locations(sample: Path, addresses: set[int]) -> dict[int, dict]:
    """For each address: whether the pinned Vivisect workspace has a location
    there, and which function (if any) owns it."""
    if not addresses:
        return {}

    key = hashlib.sha256(
        (",".join(str(a) for a in sorted(addresses))).encode()
    ).hexdigest()[:16]
    cache_path = CACHE_DIR / f"{difftest.sha256_of(sample)}.extras-{key}.json"
    if cache_path.exists():
        return {int(k): v for k, v in json.loads(cache_path.read_text()).items()}

    import capa.loader
    import capa.main
    from capa.features.common import FORMAT_AUTO

    workspace = capa.loader.get_workspace(sample, FORMAT_AUTO, sigpaths=[])
    result: dict[int, dict] = {}
    for address in sorted(addresses):
        location = workspace.getLocation(address)
        function = workspace.getFunction(address)
        result[address] = {
            "located": location is not None,
            "location_type": None if location is None else location[2],
            "function": function,
            "is_function_start": workspace.isFunction(address),
        }

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps({str(k): v for k, v in result.items()}))
    return result


def main(argv: list[str] | None = None) -> int:
    if Path(sys.prefix).resolve() != VENV_PYTHON.parent.parent.resolve():
        os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), str(Path(__file__).resolve()), *(argv or sys.argv[1:])])

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--samples", type=Path, default=REPO_ROOT / "scripts" / "corpus-outer.txt")
    parser.add_argument("--only", type=str, default=None)
    parser.add_argument("--rules", type=Path, default=REPO_ROOT / "rules")
    parser.add_argument("--capa-cli", type=Path, default=REPO_ROOT / "target" / "release" / "capa-x")
    parser.add_argument("--report", type=Path, default=REPO_ROOT / "target" / "extras-attribution.md")
    args = parser.parse_args(argv)

    samples = difftest.read_sample_list(args.samples)
    if args.only:
        samples = [s for s in samples if args.only in str(s)]

    rows: list[str] = []
    buckets: collections.Counter = collections.Counter()
    for sample in samples:
        reference_json = CACHE_DIR / f"{difftest.sha256_of(sample)}.full.json"
        if not reference_json.exists():
            print(f"skip {sample.name}: no cached reference -- run difftest --mode full first", file=sys.stderr)
            continue
        python = difftest.python_matches(reference_json)
        rust = rust_matches_with_addresses(sample, args.capa_cli, args.rules)
        extra_rules = {name: addrs for name, addrs in rust.items() if name not in python}
        if not extra_rules:
            continue

        queried = set().union(*extra_rules.values())
        located = reference_locations(sample, queried)

        for name in sorted(extra_rules):
            addresses = sorted(extra_rules[name])
            if not addresses:
                buckets["file-scope"] += 1
                rows.append(f"| `{sample.name}` | `{name}` | file-scope | no code address |")
                continue
            hits = [located[a] for a in addresses]
            # An extra rule is gap-driven only if the reference analysed *none*
            # of the addresses capa-x matched it at; one shared address is
            # enough to make it an attribution/extraction question instead.
            gap = not any(h["located"] for h in hits)
            buckets["A.2 gap-driven" if gap else "A.3 shared-code"] += 1
            detail = ", ".join(
                f"0x{a:x}{'' if h['located'] else ' (no reference location)'}"
                + ("" if h["function"] is None else f" in fn 0x{h['function']:x}")
                for a, h in zip(addresses, hits)
            )
            rows.append(f"| `{sample.name}` | `{name}` | {'A.2 gap' if gap else 'A.3 shared'} | {detail} |")

    report = [
        "# Extra-match attribution",
        "",
        "Each extra (false) rule capa-x reports, partitioned by whether the",
        "pinned Vivisect workspace has a location at the address it matched at.",
        "See `scripts/triage/attribute_extras.py` for the exact question asked.",
        "",
        f"- A.2 gap-driven (reference analysed none of the addresses): **{buckets['A.2 gap-driven']}**",
        f"- A.3 shared-code (reference analysed at least one): **{buckets['A.3 shared-code']}**",
        f"- file-scope (no code address to attribute): **{buckets['file-scope']}**",
        f"- Total extra rules: **{sum(buckets.values())}**",
        "",
        "| Sample | Extra rule | Bucket | capa-x match addresses |",
        "|---|---|---|---|",
        *rows,
    ]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(report) + "\n")
    print("\n".join(report[:10]))
    print(f"\nreport: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
