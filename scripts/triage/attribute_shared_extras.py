#!/usr/bin/env python3
"""Root-cause the *shared-code* extra matches -- the bucket
`scripts/triage/attribute_extras.py` leaves untriaged.

A shared-code extra is one capa-x reports at an address the pinned Vivisect
workspace also has a location for,
so neither "capa-x invented this code" (KD-005) nor "the reference never
analysed it" explains it. Something else does, and H4 needs that something
named per diff.

Four questions per extra, cheapest first; the first one that answers decides
the class:

  1. **Does the reference have a function there at all?** capa's viv extractor
     iterates `vw.getFunctions()`, so a location the workspace holds as loose
     code -- `importcalls` calls `makeCode` without ever calling
     `makeFunction` -- is code the reference decoded but never offered to the
     matcher at function scope. Reported as `no reference function`.

  2. **Is capa-x's function start inside a reference function?** Then the
     two sides split the same bytes differently and a function-scope rule sees
     a different unit. Reported as `reference mid-function`.

  3. **Do the two sides agree on the function's extent?** If capa-x's
     version owns instructions the reference assigns to some *other* function,
     a function-scope `N or more` rule accumulates features upstream keeps
     apart. Reported as `merged`, with the donors named.

  4. **Do the two sides extract the same features there?** With the same unit
     and the same extent the disagreement is extraction, not recovery. The
     features capa-x actually *matched on* (the successful leaf nodes of
     its own match tree) are checked one by one against everything the
     reference's `extract_function_features` /
     `extract_basic_block_features` / `extract_insn_features` yield anywhere
     in the owning function. Whatever capa-x matched and the reference
     never produced is the root cause, and it is named in the report.

Both sides are compared as capa result-document feature models
(`capa.features.freeze.features.feature_from_capa`), which is the shape
capa-x's `-j` already emits -- so this compares the two extractors, not two
renderings of them.

Results are cached per sample sha256 under the shared difftest cache, keyed by
the queried function set, because building the workspace is the whole cost.

usage:
  .venv/bin/python3 scripts/triage/attribute_shared_extras.py
  .venv/bin/python3 scripts/triage/attribute_shared_extras.py --only 10cd7afd
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import CACHE_DIR, REPO_ROOT, VENV_PYTHON, difftest, rust_layout  # noqa: E402,F401

MAX_LISTED = 8


def feature_key(node: dict) -> str:
    """A feature node as a stable comparison key.

    `description` is dropped: it is the rule author's label for the value
    (capa-x carries the matching rule's, the extractor carries none), so
    keeping it would report every feature as a difference.
    """
    return json.dumps(
        {k: v for k, v in sorted(node.items()) if k != "description"},
        separators=(",", ":"),
    )


def feature_str(node: dict) -> str:
    kind = node.get("type", "?")
    value = node.get(kind, "")
    if isinstance(value, str) and len(value) > 40:
        value = value[:40] + "..."
    return f"{kind}({value})"


def walk_matches(node: dict, out: list[dict]) -> None:
    """Every successful *feature* leaf of a match tree, with its locations."""
    if not node.get("success"):
        return
    inner = node.get("node", {})
    if inner.get("type") == "feature":
        out.append(
            {
                "feature": inner["feature"],
                "locations": [
                    int(loc["value"])
                    for loc in node.get("locations", [])
                    if loc.get("type") == "absolute" and loc.get("value") is not None
                ],
            }
        )
    for child in node.get("children", ()):
        walk_matches(child, out)


def rust_full_json(sample: Path, capa_cli: Path, rules_dir: Path) -> str:
    """capa-x's full result document for a raw sample.

    `difftest.rust_json_direct` is the file-only invocation, which
    carries no code-scope matches at all; this is the `--mode full` run's
    document, cached under the same convention.
    """
    extra_args = difftest.shellcode_format_flag(sample)

    def produce() -> str:
        command = [str(capa_cli), "--rules", str(rules_dir), *extra_args, "-j", str(sample)]
        proc = subprocess.run(command, capture_output=True, text=True)
        if not proc.stdout.strip():
            raise RuntimeError(f"capa-x-cli produced no output for {sample} (exit {proc.returncode}):\n{proc.stderr}")
        return proc.stdout

    return difftest.cached_rust_output(
        "full-json", sample, capa_cli, rules_dir, extra_args, CACHE_DIR / "rust", produce
    )


def rust_extras(sample: Path, capa_cli: Path, rules_dir: Path) -> dict[str, list[dict]]:
    """capa-x's extra rules -> one entry per match: scope address and the
    feature leaves that made it succeed."""
    reference_json = CACHE_DIR / f"{difftest.sha256_of(sample)}.full.json"
    python = difftest.python_matches(reference_json)
    document = json.loads(rust_full_json(sample, capa_cli, rules_dir))
    out: dict[str, list[dict]] = {}
    for name, rule in document.get("rules", {}).items():
        if name in python:
            continue
        entries = []
        for address, tree in rule["matches"]:
            if address.get("type") != "absolute" or address.get("value") is None:
                continue
            leaves: list[dict] = []
            walk_matches(tree, leaves)
            entries.append({"address": int(address["value"]), "leaves": leaves})
        if entries:
            out[name] = entries
    return out



def analyse(sample: Path, addresses: list[int]) -> dict:
    """The reference's own view of each contested address: which function owns
    it, what that function's extent is, and every feature the reference
    extracts inside it."""
    import capa.loader
    import capa.main
    import capa.features.freeze.features as frzf
    from capa.features.common import FORMAT_AUTO

    signatures = capa.main.get_default_signatures()
    extractor = capa.loader.get_extractor(
        sample, FORMAT_AUTO, capa.main.OS_AUTO, capa.main.BACKEND_VIV, signatures, False
    )
    workspace = extractor.vw

    owner: dict[int, int] = {}
    for fva in workspace.getFunctions():
        for bva, bsize, _ in workspace.getFunctionBlocks(fva):
            cur = bva
            while cur < bva + bsize:
                try:
                    op = workspace.parseOpcode(cur)
                except Exception:
                    break
                owner[cur] = fva
                cur += len(op)

    handles = {int(f.address): f for f in extractor.get_functions()}

    def features_of(fva: int) -> list[str]:
        handle = handles.get(fva)
        if handle is None:
            return []
        keys: set[str] = set()

        def add(feature):
            keys.add(feature_key(frzf.feature_from_capa(feature).model_dump(by_alias=True, exclude_none=True)))

        for feature, _ in extractor.extract_function_features(handle):
            add(feature)
        for bb in extractor.get_basic_blocks(handle):
            for feature, _ in extractor.extract_basic_block_features(handle, bb):
                add(feature)
            for insn in extractor.get_instructions(handle, bb):
                for feature, _ in extractor.extract_insn_features(handle, bb, insn):
                    add(feature)
        return sorted(keys)

    result: dict[str, dict] = {}
    feature_cache: dict[int, list[str]] = {}
    for address in addresses:
        fva = workspace.getFunction(address)
        if fva is not None and fva not in feature_cache:
            feature_cache[fva] = features_of(fva)
        result[str(address)] = {
            "located": workspace.getLocation(address) is not None,
            "is_function": bool(workspace.isFunction(address)),
            "owning_function": fva,
            "is_library": bool(extractor.is_library_function(fva)) if fva is not None else False,
            "extracted": fva in handles if fva is not None else False,
            "insns": sorted(va for va, f in owner.items() if fva is not None and f == fva),
            "features": feature_cache.get(fva, []),
        }
    result["_owner"] = {str(k): v for k, v in owner.items()}
    return result


def cached_analysis(sample: Path, addresses: list[int]) -> dict:
    key = hashlib.sha256(("v2;" + ",".join(str(a) for a in sorted(addresses))).encode()).hexdigest()[:16]
    cache_path = CACHE_DIR / f"{difftest.sha256_of(sample)}.shared-{key}.json"
    if cache_path.exists():
        return json.loads(cache_path.read_text())
    result = analyse(sample, sorted(addresses))
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(result))
    return result


def fmt(values, formatter=lambda v: f"0x{v:x}") -> str:
    values = list(values)
    shown = ", ".join(f"`{formatter(v)}`" for v in values[:MAX_LISTED])
    if len(values) > MAX_LISTED:
        shown += f" (+{len(values) - MAX_LISTED} more)"
    return shown or "none"


def classify(entry: dict, info: dict, owner: dict[int, int], layout: dict[int, set[int]]) -> tuple[str, str]:
    """Verdict and evidence for one (extra rule, match address)."""
    address = entry["address"]
    fva = info["owning_function"]

    if fva is None:
        return (
            "no reference function",
            "the workspace has a location here but never called `makeFunction`, "
            "so capa's viv extractor never offers it at function scope",
        )
    if info["is_library"]:
        return (
            "reference skips as library code",
            f"`is_library_function(0x{fva:x})` is true; "
            "`capa/capabilities/static.py` skips the function before matching",
        )
    if not info["is_function"]:
        return (
            "reference mid-function",
            f"capa-x starts a function at 0x{address:x}, which the reference holds "
            f"inside 0x{fva:x}",
        )

    reference_insns = set(info["insns"])
    rust_insns = layout.get(address, set())
    donated = {va: owner[va] for va in rust_insns - reference_insns if va in owner and owner[va] != fva}
    unowned = sorted(rust_insns - reference_insns - set(owner))
    if donated:
        # capa-x's function swallowed *other reference functions'* code, so a
        # function-scope rule sees features upstream keeps in separate units.
        donors = sorted(set(donated.values()))
        return (
            "merged extent",
            f"capa-x's function owns {len(donated)} instruction(s) the reference "
            f"assigns to {fmt(donors)}"
            + (f", plus {len(unowned)} in no reference function" if unowned else ""),
        )
    if unowned:
        # Same function start, same owner -- capa-x simply walks further,
        # into bytes that belong to no reference function. Note what this does
        # *not* say: the reference may well have decoded them (`makeCode`
        # without `makeFunction` leaves a location and no owner), and spot
        # checks say it usually has. Either way capa's viv extractor iterates
        # `vw.getFunctions()`, so the features there are never offered to the
        # matcher upstream -- see KD-009.
        return (
            "walks past the reference",
            f"both sides start at 0x{address:x}, but capa-x decodes {len(unowned)} "
            f"instruction(s) that belong to no reference function, starting at "
            f"{fmt(unowned[:3])}",
        )

    have = set(info["features"])
    unmatched = []
    for leaf in entry["leaves"]:
        key = feature_key(leaf["feature"])
        if key not in have:
            unmatched.append(leaf)
    if unmatched:
        return (
            "feature extraction",
            "the reference never yields "
            + fmt(
                sorted({feature_str(leaf["feature"]) for leaf in unmatched}),
                formatter=lambda v: v,
            )
            + " anywhere in this function; capa-x matched at "
            + fmt(sorted({a for leaf in unmatched for a in leaf["locations"]})),
        )

    missing_side = sorted(reference_insns - rust_insns)
    return (
        "same features, matching differs",
        f"every matched feature is present on both sides"
        + (f"; the reference has {len(missing_side)} instruction(s) capa-x lacks" if missing_side else ""),
    )


def main(argv: list[str] | None = None) -> int:
    if Path(sys.prefix).resolve() != VENV_PYTHON.parent.parent.resolve():
        os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), str(Path(__file__).resolve()), *(argv or sys.argv[1:])])

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--samples", type=Path, default=REPO_ROOT / "scripts" / "corpus-outer.txt")
    parser.add_argument("--only", type=str, default=None)
    parser.add_argument("--rules", type=Path, default=REPO_ROOT / "rules")
    parser.add_argument("--capa-cli", type=Path, default=REPO_ROOT / "target" / "release" / "capa-x")
    parser.add_argument("--report", type=Path, default=REPO_ROOT / "target" / "shared-extras-attribution.md")
    args = parser.parse_args(argv)

    samples = difftest.read_sample_list(args.samples)
    if args.only:
        samples = [s for s in samples if args.only in str(s)]

    rows: list[str] = []
    detail: list[str] = []
    verdicts: collections.Counter = collections.Counter()

    for sample in samples:
        if not (CACHE_DIR / f"{difftest.sha256_of(sample)}.full.json").exists():
            continue
        extras = rust_extras(sample, args.capa_cli, args.rules)
        if not extras:
            continue

        layout = rust_layout(sample, args.capa_cli)
        contested = sorted({e["address"] for entries in extras.values() for e in entries})
        analysis = cached_analysis(sample, contested)
        owner = {int(k): v for k, v in analysis["_owner"].items()}

        printed_header = False
        for rule in sorted(extras):
            # One row per rule, keyed on the verdicts its match addresses
            # produce: a rule matching at 39 addresses for one reason is one
            # finding, not 39.
            grouped: dict[tuple[str, str], list[int]] = collections.OrderedDict()
            skipped = 0
            for entry in extras[rule]:
                info = analysis[str(entry["address"])]
                if not info["located"]:
                    skipped += 1  # KD-005 territory; attribute_extras.py owns it
                    continue
                verdict, evidence = classify(entry, info, owner, layout)
                grouped.setdefault((verdict, evidence), []).append(entry["address"])
            if not grouped:
                continue
            for (verdict, evidence), addresses in grouped.items():
                verdicts[verdict] += 1
                rows.append(
                    f"| `{sample.name[:8]}` | `{rule}` | {fmt(sorted(addresses))} | {verdict} | {evidence} |"
                )
            if not printed_header:
                detail.append(f"\n### `{sample.name}`\n")
                printed_header = True
            detail.append(
                f"- `{rule}` — "
                + "; ".join(f"**{verdict}** at {len(addresses)} address(es)" for (verdict, _), addresses in grouped.items())
                + (f" ({skipped} address(es) unlocated, see KD-005)" if skipped else "")
                + "\n"
                + "".join(f"  - {evidence}\n" for (_, evidence) in grouped)
            )

    report = [
        "# Shared-code extra attribution",
        "",
        "Each extra capa-x reports at an address the pinned Vivisect workspace",
        "also has a location for, root-caused. See `scripts/triage/attribute_shared_extras.py`",
        "for the exact questions asked and the order they are asked in.",
        "",
        "Counted per (rule, verdict), not per address: a rule matching at 39 addresses",
        "for one reason is one finding.",
        "",
        *(f"- {verdict}: **{count}**" for verdict, count in sorted(verdicts.items())),
        "",
        "| Sample | Extra rule | Address(es) | Verdict | Evidence |",
        "|---|---|---|---|---|",
        *rows,
        "",
        "## Per-sample detail",
        *detail,
    ]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(report) + "\n")
    print("\n".join(report[: 12 + len(verdicts)]))
    print(f"\nreport: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
