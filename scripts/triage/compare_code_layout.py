#!/usr/bin/env python3
"""Compare capa-x's recovered code layout with the pinned Vivisect reference.

Unlike a global block-set diff (which cannot tell "Rust never recovered this
block" apart from "Rust put this block in the wrong function"), this oracle
compares *ownership per function*: for every function common to both sides it
diffs block, instruction, outgoing-edge, call, and -- when both sides expose
them -- no-return and thunk state. Every reported difference is classified with
evidence (misattributed to a named other function, absent entirely, or extra),
never blanket-labelled a "heuristic recovery gap".
"""

from __future__ import annotations

import json
import hashlib
import subprocess
import argparse
import collections
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TESTFILES = ROOT / "tests" / "testfiles"
CORPUS = ROOT / "scripts" / "corpus-layout.txt"
PYTHON = ROOT / ".venv" / "bin" / "python"
REFERENCE_DUMP = ROOT / "scripts" / "triage" / "dump_code_layout.py"
RUST = ROOT / "target" / "debug" / "capa"
REPORT = ROOT / "target" / "code-layout-report.md"
# The Vivisect dump is the expensive side (a full workspace build per sample);
# cache it by content hash so re-runs after a Rust-only change are cheap. Shares
# the difftest cache dir. The Rust dump is fast, so it is never cached.
CACHE_DIR = ROOT / ".cache" / "difftest"

# Fields compared only when *both* dumps expose them, so the oracle lights up
# automatically as capa-x gains no-return/thunk state (PR 4) without this
# script pretending to compare data one side does not yet produce.
OPTIONAL_SCALAR_FIELDS = ("noreturn", "thunk")

MAX_LISTED = 16  # cap per-difference lists so the report stays readable


def read_corpus_list(path: Path) -> list[str]:
    """Sample names from a corpus list, one per line.

    Same convention as `difftest.read_sample_list`: `#` starts a comment
    anywhere on the line, not only in column 0. The corpus lists annotate
    entries with the reason each sample earns its slot, and a reader that
    only skipped whole-line comments turned those annotations into part of
    the filename.
    """
    names = []
    for line in path.read_text().splitlines():
        name = line.split("#", 1)[0].strip()
        if name:
            names.append(name)
    return names


def load(command: list[str]) -> dict:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def load_reference(sample: Path, cache_dir: Path) -> dict:
    """Load the Vivisect layout dump, caching it by sample content hash."""
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    cache_path = cache_dir / f"{digest}.layout.json"
    if cache_path.exists():
        return json.loads(cache_path.read_text())
    dump = load([str(PYTHON), str(REFERENCE_DUMP), str(sample)])
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(dump, separators=(",", ":")))
    return dump


def by_address(layout: dict) -> dict[int, dict]:
    return {function["address"]: function for function in layout["functions"]}


def block_owners(layout: dict) -> dict[int, set[int]]:
    owners: dict[int, set[int]] = {}
    for function in layout["functions"]:
        for block in function["basic_blocks"]:
            owners.setdefault(block, set()).add(function["address"])
    return owners


def insn_owners(layout: dict) -> dict[int, set[int]]:
    owners: dict[int, set[int]] = {}
    for function in layout["functions"]:
        for insn in function.get("instructions", ()):
            owners.setdefault(insn, set()).add(function["address"])
    return owners


def edge_set(function: dict) -> set[tuple[int, int]]:
    result: set[tuple[int, int]] = set()
    for edge in function.get("edges", ()):
        if isinstance(edge, dict):  # Rust dump: {"source", "target", "kind"}
            result.add((edge["source"], edge["target"]))
        else:  # reference dump: [source, target]
            result.add((edge[0], edge[1]))
    return result


def fmt_addrs(values) -> str:
    values = sorted(values)
    shown = ", ".join(f"`0x{v:x}`" for v in values[:MAX_LISTED])
    if len(values) > MAX_LISTED:
        shown += f" ... (+{len(values) - MAX_LISTED} more)"
    return shown or "none"


def fmt_edges(edges) -> str:
    edges = sorted(edges)
    shown = ", ".join(f"`0x{s:x}->0x{t:x}`" for s, t in edges[:MAX_LISTED])
    if len(edges) > MAX_LISTED:
        shown += f" ... (+{len(edges) - MAX_LISTED} more)"
    return shown or "none"


def classify_owned(
    addresses: set[int], other_owners: dict[int, set[int]]
) -> tuple[dict[int, set[int]], set[int]]:
    """Split `addresses` into {addr: other-side owners} for misattributed ones
    (present on the other side but under a different function) and a set of
    genuinely-absent ones (not recovered on the other side at all)."""
    misattributed: dict[int, set[int]] = {}
    absent: set[int] = set()
    for addr in addresses:
        owners = other_owners.get(addr)
        if owners:
            misattributed[addr] = owners
        else:
            absent.add(addr)
    return misattributed, absent


def describe_ownership(
    label: str,
    ref_only: set[int],
    rust_only: set[int],
    ref_owners: dict[int, set[int]],
    rust_owners: dict[int, set[int]],
) -> list[str]:
    lines: list[str] = []
    mis, absent = classify_owned(ref_only, rust_owners)
    if mis:
        detail = "; ".join(
            f"`0x{addr:x}`->{fmt_addrs(owners)}" for addr, owners in sorted(mis.items())[:MAX_LISTED]
        )
        lines.append(f"  - {label} misattributed by Rust (ref addr -> Rust owner): {detail}")
    if absent:
        lines.append(f"  - {label} absent from Rust (recovery gap): {fmt_addrs(absent)}")
    extra_mis, extra_absent = classify_owned(rust_only, ref_owners)
    if extra_mis:
        detail = "; ".join(
            f"`0x{addr:x}`->{fmt_addrs(owners)}"
            for addr, owners in sorted(extra_mis.items())[:MAX_LISTED]
        )
        lines.append(f"  - {label} Rust attributes to a different function than ref (addr -> ref owner): {detail}")
    if extra_absent:
        lines.append(f"  - {label} extra in Rust (not in reference): {fmt_addrs(extra_absent)}")
    return lines


def bucket_boundaries(
    ref_addrs: set[int], rust_addrs: set[int],
    ref_insn_owners: dict[int, set[int]], rust_insn_owners: dict[int, set[int]],
) -> collections.Counter:
    """Classify function-start disagreements (the Layer-1 ownership gate):
    split  = Rust start interior to a Vivisect function (Rust cut it);
    merge  = Vivisect start Rust folded into another function;
    extra  = Rust start Vivisect has no instruction for;
    missing= Vivisect start Rust has no instruction for."""
    buckets: collections.Counter = collections.Counter()
    for a in rust_addrs - ref_addrs:
        buckets["split" if a in ref_insn_owners else "extra"] += 1
    for a in ref_addrs - rust_addrs:
        buckets["merge" if a in rust_insn_owners else "missing"] += 1
    return buckets


def compare_sample(sample_name: str, cache_dir: Path) -> tuple[list[str], dict[str, int]]:
    sample = TESTFILES / sample_name
    reference = load_reference(sample, cache_dir)
    rust_raw = load([str(RUST), str(sample), "--dump-code-layout"])

    ref_fns = by_address(reference)
    rust_fns = by_address(rust_raw)
    ref_block_owners = block_owners(reference)
    rust_block_owners = block_owners(rust_raw)
    ref_insn_owners = insn_owners(reference)
    rust_insn_owners = insn_owners(rust_raw)

    ref_addrs, rust_addrs = set(ref_fns), set(rust_fns)
    common = sorted(ref_addrs & rust_addrs)
    ref_only_fns = ref_addrs - rust_addrs
    rust_only_fns = rust_addrs - ref_addrs

    both_have_optional = {
        field: all(field in f for f in reference["functions"])
        and all(field in f for f in rust_raw["functions"])
        for field in OPTIONAL_SCALAR_FIELDS
    }

    buckets = bucket_boundaries(ref_addrs, rust_addrs, ref_insn_owners, rust_insn_owners)
    counts = {
        "functions_ref": len(ref_addrs),
        "functions_rust": len(rust_addrs),
        "functions_common": len(common),
        "block_diff_fns": 0,
        "insn_diff_fns": 0,
        "edge_diff_fns": 0,
        "call_diff_fns": 0,
        "split": buckets["split"],
        "merge": buckets["merge"],
        "missing": buckets["missing"],
        "extra": buckets["extra"],
    }

    detail: list[str] = [f"## {sample_name}", ""]
    if ref_only_fns:
        detail.append(f"- Functions only in reference (Rust missed the start): {fmt_addrs(ref_only_fns)}")
    if rust_only_fns:
        detail.append(f"- Functions only in Rust (invented start): {fmt_addrs(rust_only_fns)}")

    ownership_diff_common = 0
    for fva in common:
        ref_fn, rust_fn = ref_fns[fva], rust_fns[fva]
        fn_lines: list[str] = []
        ownership_divergent = False

        ref_blocks = set(ref_fn["basic_blocks"])
        rust_blocks = set(rust_fn["basic_blocks"])
        if ref_blocks != rust_blocks:
            counts["block_diff_fns"] += 1
            ownership_divergent = True
            fn_lines += describe_ownership(
                "block", ref_blocks - rust_blocks, rust_blocks - ref_blocks,
                ref_block_owners, rust_block_owners,
            )

        ref_insns = set(ref_fn.get("instructions", ()))
        rust_insns = set(rust_fn.get("instructions", ()))
        if ref_insns != rust_insns:
            counts["insn_diff_fns"] += 1
            ownership_divergent = True
            fn_lines += describe_ownership(
                "instruction", ref_insns - rust_insns, rust_insns - ref_insns,
                ref_insn_owners, rust_insn_owners,
            )
        ownership_diff_common += ownership_divergent

        ref_edges, rust_edges = edge_set(ref_fn), edge_set(rust_fn)
        if ref_edges != rust_edges:
            counts["edge_diff_fns"] += 1
            missing = ref_edges - rust_edges
            extra = rust_edges - ref_edges
            if missing:
                fn_lines.append(f"  - edges missing from Rust: {fmt_edges(missing)}")
            if extra:
                fn_lines.append(f"  - edges extra in Rust: {fmt_edges(extra)}")

        ref_calls = set(ref_fn.get("calls", ()))
        rust_calls = set(rust_fn.get("calls", ()))
        if ref_calls != rust_calls:
            counts["call_diff_fns"] += 1
            missing = ref_calls - rust_calls
            extra = rust_calls - ref_calls
            if missing:
                fn_lines.append(f"  - calls missing from Rust: {fmt_addrs(missing)}")
            if extra:
                fn_lines.append(f"  - calls extra in Rust: {fmt_addrs(extra)}")

        for field, comparable in both_have_optional.items():
            if comparable and ref_fn.get(field) != rust_fn.get(field):
                fn_lines.append(f"  - {field}: reference={ref_fn.get(field)} Rust={rust_fn.get(field)}")

        if fn_lines:
            detail.append(f"- function `0x{fva:x}`:")
            detail.extend(fn_lines)

    detail.append(f"- Recovery diagnostics: {len(rust_raw['diagnostics'])}.")
    detail.append("")

    # A function is ownership-divergent if its blocks/instructions disagree, or
    # if its start exists on only one side (split/merge/missing/extra). A sample
    # has ownership parity only when every function agrees on all three.
    boundary_diff = len(ref_only_fns) + len(rust_only_fns)
    counts["ownership_diff_fns"] = ownership_diff_common + boundary_diff
    counts["ownership_parity"] = int(counts["ownership_diff_fns"] == 0)
    # Finer than sample-level parity: a single bad helper fails a whole sample,
    # but this fraction shows incremental per-function progress. A function has
    # parity only if it exists on both sides with identical block+instruction
    # ownership; boundary-only functions (split/merge/missing/extra) never do.
    counts["functions_parity_ok"] = len(common) - ownership_diff_common
    counts["functions_total"] = len(ref_addrs | rust_addrs)

    # Preserve the recovery invariant: deterministic (non-heuristic) seeds must all
    # become recovered functions -- a seed must never silently vanish.
    seed_addresses = {
        seed["address"]
        for seed in rust_raw["seeds"]
        if any(
            kind
            not in {
                "CallTarget",
                "FunctionSignature",
                "Prologue",
            }
            for kind in seed["kinds"]
        )
    }
    missing_seeds = seed_addresses - rust_addrs
    if missing_seeds:
        raise RuntimeError(f"{sample_name}: deterministic seeds not recovered: {fmt_addrs(missing_seeds)}")

    return detail, counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    parser.add_argument("--no-detail", action="store_true", help="omit per-sample detail (summary only)")
    args = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "-p", "capa-x-cli"], cwd=ROOT, check=True)
    samples = read_corpus_list(args.corpus)

    rows: list[str] = []
    details: list[str] = []
    errors: list[str] = []
    total = collections.Counter()
    for sample_name in samples:
        try:
            sample_detail, counts = compare_sample(sample_name, args.cache_dir)
        except Exception as exc:  # record and continue -- an aborted 200-run yields no scorecard
            errors.append(f"| `{sample_name}` | ERROR | {str(exc)[:120].replace('|', '/')} |")
            details.append(f"\n## {sample_name}\n\n- ERROR: {exc}\n")
            continue
        for key, value in counts.items():
            total[key] += value
        rows.append(
            f"| `{sample_name}` "
            f"| {counts['functions_ref']}/{counts['functions_rust']}/{counts['functions_common']} "
            f"| {'yes' if counts['ownership_parity'] else 'NO'} | {counts['ownership_diff_fns']} "
            f"| {counts['split']}/{counts['merge']}/{counts['missing']}/{counts['extra']} "
            f"| {counts['edge_diff_fns']} | {counts['call_diff_fns']} |"
        )
        details.append("")
        details.extend(sample_detail)

    n = len(samples)
    processed = n - len(errors)
    summary = [
        "# Code-layout differential report",
        "",
        "Three-layer oracle vs pinned Vivisect. **Layer 1 (ownership gate)** is the "
        "priority signal: function starts + block/instruction ownership, the thing "
        "that decides function-scope capa matches. **Layer 2 (direct CFG)** -- edges "
        "and direct calls -- is tracked but not gating (feeds `loop`/`tight loop`). "
        "Indirect flow (`call [IAT]`, jump tables) is excluded here and lives in a "
        "separate backlog. Differences are classified with evidence, not blanket-"
        "labelled recovery gaps.",
        "",
        "## Layer 1 ownership scorecard",
        "",
        f"- Samples processed: {processed}/{n}" + (f" ({len(errors)} errored)" if errors else ""),
        f"- Samples with ownership parity: **{total['ownership_parity']}/{processed}**",
        f"- Functions with ownership parity: **{total['functions_parity_ok']}/{total['functions_total']}**"
        + (f" ({total['functions_parity_ok'] / total['functions_total']:.1%})" if total['functions_total'] else ""),
        f"- Total ownership-diff functions: **{total['ownership_diff_fns']}**",
        f"- Boundary buckets (across corpus): split={total['split']} merge={total['merge']} "
        f"missing={total['missing']} extra={total['extra']}",
        f"- Functions: reference {total['functions_ref']} / Rust {total['functions_rust']}",
        "",
        "| Sample | Funcs ref/rust/common | Ownership parity | Diff fns | split/merge/missing/extra | edge diff | call diff |",
        "|---|---:|:--:|---:|:--:|---:|---:|",
        *rows,
    ]
    if errors:
        summary += ["", "## Errored samples", "", "| Sample | Result | Error |", "|---|---|---|", *errors]

    body = summary if args.no_detail else summary + details
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(body) + "\n")
    print(args.report)
    print(f"ownership parity: {total['ownership_parity']}/{n}   ownership-diff fns: {total['ownership_diff_fns']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
