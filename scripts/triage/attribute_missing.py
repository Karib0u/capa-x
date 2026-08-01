#!/usr/bin/env python3
"""Attribute capa-x's *missing* rule matches to the reference function that
owns the feature, and that function to whatever created it.

This report reruns the earlier attribution method on four representative
samples. Two questions per missing rule:

  1. which Vivisect function owns the address the reference matched it at,
     and does capa-x have that function at all?
  2. if not, *who created it* -- an analysis module (named), or codeflow's own
     recursion from an entry point some module supplied?

(2) is answered by wrapping `envi.codeflow.CodeFlowContext.addEntryPoint`, not
`vw.makeFunction`: every function creation flows through `addEntryPoint`, while
`makeFunction` sees only the subset a module asked for by hand -- v1's residual
"created by codeflow, no makeFunction call" bucket was 27 of 84 functions, and
this patch point resolves those to the module that seeded the walk instead of
leaving them unattributed. `makeFunction` frames are still recorded, so the two
creation paths stay distinguishable.

The point of the exercise is which side is at fault, so the report also carries
the reference's *own* view of each absent function -- direct callers, CFG
predecessors, first-instruction mnemonic, symbol name. A function with a
reference caller that capa-x already has is a closable codeflow edge (B.2's
work). A function with no call, no branch, no prologue and no symbol is reached
only through a data pointer, i.e. `analyzePointer` -> `isProbablyCode`, which is
KD-003 and emulator-bound.

Results are cached per sample sha256 under the shared difftest cache, keyed by
the queried address set, because building the workspace is the whole cost.

usage:
  .venv/bin/python3 scripts/triage/attribute_missing.py                  # the four representative samples
  .venv/bin/python3 scripts/triage/attribute_missing.py --only 49a34cfb
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

# The four representative samples used by the missing-function analysis.
PHASE_B_SAMPLES = [
    "49a34cfbeed733c24392c9217ef46bb6.exe_",
    "512a5575ff395389fc952d7925e72be1ca4ba86a5d4f2da50f1cbbde0b208c92.elf_",
    "b5f0524e69b3a3cf636c7ac366ca57bf5e3a8fdc8a9f01caf196c611a7918a87.elf_",
    "276f691a3df25481f59d79781799e35f.exe_",
]


def python_matches_with_addresses(reference_json: Path) -> dict[str, set[int]]:
    """The reference's matched (rule -> absolute addresses), from the cached
    `capa -j` document the difftest harness already compares against."""
    doc = json.loads(reference_json.read_text())
    out: dict[str, set[int]] = {}
    for name, rule in doc.get("rules", {}).items():
        addresses = set()
        for match in rule["matches"]:
            address = match[0]
            if address.get("type") == "absolute" and address.get("value") is not None:
                addresses.add(int(address["value"]))
        out[name] = addresses
    return out



def _creator_of(frames: list[tuple[str, str]]) -> str:
    """The analysis module responsible for a function creation.

    Walks outward past the machinery that every creation goes through --
    `envi/codeflow.py`'s recursion and `VivWorkspace.makeFunction` /
    `followPointer` / `processEntryPoints` -- and names the first frame outside
    it. That frame is the analysis module (or capa's own loader).
    """
    # `addEntryPoint` recurses, so the instrumentation's own frame reappears at
    # every outer recursion level; it is machinery too, or the attribution
    # names this script instead of the module that started the walk.
    machinery = ("envi/codeflow.py", "vivisect/__init__.py", Path(__file__).name)
    for path, function in frames:
        if any(path.endswith(m) for m in machinery):
            continue
        return f"{path}:{function}"
    # Every frame was machinery: the walk started inside the workspace itself
    # (`processEntryPoints`, `followPointer`), which is worth naming as such.
    return f"{frames[-1][0]}:{frames[-1][1]}" if frames else "unknown"


def _instruction_addresses(workspace, bva: int, bsize: int) -> list[int]:
    """Every instruction address in a reference basic block."""
    out = []
    cur = bva
    while cur < bva + bsize:
        try:
            op = workspace.parseOpcode(cur)
        except Exception:
            break
        out.append(cur)
        cur += len(op)
    return out


def analyse(sample: Path, targets: dict[str, set[int]]) -> dict:
    """Build the pinned workspace under instrumentation and answer both
    questions for every address in `targets` (rule -> addresses)."""
    import traceback

    import envi.codeflow
    import capa.loader
    import capa.main
    from capa.features.common import FORMAT_AUTO

    site = str(Path(envi.codeflow.__file__).resolve().parent.parent) + "/"
    creations: dict[int, dict] = {}

    original = envi.codeflow.CodeFlowContext.addEntryPoint

    def instrumented(self, va, *args, **kwargs):
        # Record only creations that actually happen: `addEntryPoint` returns
        # early for a va it already knows, and re-attributing those would
        # credit whichever module happened to ask second.
        if self._funcs.get(va) is None and va not in creations:
            frames = []
            for frame in traceback.extract_stack()[:-1][::-1]:
                path = frame.filename
                frames.append((path[len(site):] if path.startswith(site) else path, frame.name))
            creations[va] = {
                "creator": _creator_of(frames),
                "via_makefunction": any(f == "makeFunction" for _, f in frames),
                "stack": [f"{p}:{f}" for p, f in frames[:8] if p != Path(__file__).name],
            }
        return original(self, va, *args, **kwargs)

    envi.codeflow.CodeFlowContext.addEntryPoint = instrumented
    try:
        signatures = capa.main.get_default_signatures()
        workspace = capa.loader.get_workspace(sample, FORMAT_AUTO, signatures)
    finally:
        envi.codeflow.CodeFlowContext.addEntryPoint = original

    # The reference's own call/branch graph, from the same branch model the
    # layout oracle uses: BR_PROC is a call, anything else a CFG edge.
    import envi

    callers: dict[int, set[int]] = collections.defaultdict(set)
    branches_to: dict[int, set[int]] = collections.defaultdict(set)
    for fva in workspace.getFunctions():
        for bva, bsize, _fva in workspace.getFunctionBlocks(fva):
            cur = bva
            while cur < bva + bsize:
                try:
                    op = workspace.parseOpcode(cur)
                except Exception:
                    break
                for tova, bflags in op.getBranches():
                    if tova is None or (bflags & envi.BR_DEREF):
                        continue
                    if bflags & envi.BR_PROC:
                        callers[tova].add(fva)
                    else:
                        branches_to[tova].add(fva)
                cur += len(op)

    functions: dict[int, dict] = {}
    rules: dict[str, list] = {}
    for rule, addresses in targets.items():
        entries = []
        for address in sorted(addresses):
            fva = workspace.getFunction(address)
            entries.append({"address": address, "function": fva})
            if fva is None or fva in functions:
                continue
            try:
                mnem = workspace.parseOpcode(fva).mnem
            except Exception:
                mnem = None
            functions[fva] = {
                "creator": creations.get(fva, {}).get("creator", "not observed"),
                "via_makefunction": creations.get(fva, {}).get("via_makefunction"),
                "stack": creations.get(fva, {}).get("stack", []),
                "callers": sorted(callers.get(fva, ())),
                "branch_preds": sorted(branches_to.get(fva, ())),
                "mnem": mnem,
                "name": workspace.getName(fva),
                "xrefs": len(workspace.getXrefsTo(fva)),
                # `isProbablyCode` is prologue-signature *or* emulation
                # (vivisect/__init__.py:1136-1158). Recording the signature
                # half separately keeps "a pointer target that looks like a
                # function" -- whose port v1 measured and reverted -- distinct
                # from "only emulation could have classified this".
                "signature": bool(workspace.isFunctionSignature(fva)),
                # Every instruction the reference puts in this function, so the
                # caller can tell "capa-x has the function" apart from
                # "capa-x has its first block and stops".
                "insns": sorted(
                    va
                    for bva, bsize, _ in workspace.getFunctionBlocks(fva)
                    for va in _instruction_addresses(workspace, bva, bsize)
                ),
            }
        rules[rule] = entries
    return {
        "rules": rules,
        "functions": {str(k): v for k, v in functions.items()},
        # The whole reverse-call graph and every creator, so the caller can ask
        # the transitive question -- "is this function reachable by *calls*
        # from anything capa-x has?" -- which is the one that decides
        # whether B.2 has an edge to close. A direct caller capa-x also
        # lacks says nothing on its own; the chain may still bottom out in
        # code both sides have.
        "callers": {str(k): sorted(v) for k, v in callers.items()},
        "creators": {str(fva): creations.get(fva, {}).get("creator", "not observed") for fva in workspace.getFunctions()},
    }


def cached_analysis(sample: Path, targets: dict[str, set[int]]) -> dict:
    # Keyed by the queried rule/address set *and* a schema version, so adding a
    # field to `analyse` invalidates rather than silently reads a stale shape.
    key = hashlib.sha256(
        ("v3;" + ";".join(f"{rule}={','.join(str(a) for a in sorted(addresses))}" for rule, addresses in sorted(targets.items()))).encode()
    ).hexdigest()[:16]
    cache_path = CACHE_DIR / f"{difftest.sha256_of(sample)}.missing-{key}.json"
    if cache_path.exists():
        return json.loads(cache_path.read_text())
    result = analyse(sample, targets)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(result))
    return result


def nearest_present_ancestor(
    target: int, callers: dict[int, list[int]], layout: dict[int, set[int]]
) -> list[int] | None:
    """Shortest call path from a function capa-x *has* down to `target`,
    walking the reference's call graph backwards.

    This is the question B.2 turns on. "capa-x lacks the direct caller too"
    is not an answer: if some ancestor is code both sides analysed, then there
    is a concrete call edge capa-x fails to follow, and closing it is
    ordinary codeflow work. If no ancestor is present, nothing capa-x
    recovered leads here by calls at all, and whatever created the region is
    the only way in.
    """
    seen = {target}
    queue: collections.deque = collections.deque([[target]])
    while queue:
        path = queue.popleft()
        for caller in callers.get(path[0], ()):
            if caller in seen:
                continue
            seen.add(caller)
            if caller in layout:
                return [caller, *path]
            queue.append([caller, *path])
    return None


def classify(fva: int | None, addresses: list[int], layout: dict[int, set[int]]) -> str:
    """Where capa-x stands on the reference function that owns the feature."""
    if fva is None:
        return "no reference function"
    if fva in layout:
        return "present"
    owned = {other for other, instructions in layout.items() if any(a in instructions for a in addresses)}
    if owned:
        return "merged into " + ", ".join(f"0x{o:x}" for o in sorted(owned))
    return "absent"


def main(argv: list[str] | None = None) -> int:
    if Path(sys.prefix).resolve() != VENV_PYTHON.parent.parent.resolve():
        os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), str(Path(__file__).resolve()), *(argv or sys.argv[1:])])

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--samples", type=Path, default=None, help="corpus list; defaults to the built-in four-sample set")
    parser.add_argument("--only", type=str, default=None)
    parser.add_argument("--rules", type=Path, default=REPO_ROOT / "rules")
    parser.add_argument("--capa-cli", type=Path, default=REPO_ROOT / "target" / "release" / "capa-x")
    parser.add_argument("--report", type=Path, default=REPO_ROOT / "target" / "missing-attribution.md")
    args = parser.parse_args(argv)

    if args.samples:
        samples = difftest.read_sample_list(args.samples)
    else:
        samples = [difftest.DEFAULT_SAMPLES_ROOT / name for name in PHASE_B_SAMPLES]
    if args.only:
        samples = [s for s in samples if args.only in str(s)]

    rows: list[str] = []
    detail: list[str] = []
    verdicts: collections.Counter = collections.Counter()
    for sample in samples:
        reference_json = CACHE_DIR / f"{difftest.sha256_of(sample)}.full.json"
        if not reference_json.exists():
            print(f"skip {sample.name}: no cached reference -- run difftest --mode full first", file=sys.stderr)
            continue
        python = python_matches_with_addresses(reference_json)
        rust = difftest.rust_matches(
            args.capa_cli,
            args.rules,
            sample,
            extra_args=difftest.shellcode_format_flag(sample),
            rust_cache=CACHE_DIR / "rust",
        )
        missing = {name: addresses for name, addresses in python.items() if name not in rust}
        if not missing:
            print(f"{sample.name}: no missing rules", file=sys.stderr)
            continue

        layout = rust_layout(sample, args.capa_cli)
        analysis = cached_analysis(sample, missing)
        functions = {int(k): v for k, v in analysis["functions"].items()}
        callers = {int(k): v for k, v in analysis["callers"].items()}
        creators = {int(k): v for k, v in analysis["creators"].items()}

        detail.append(f"\n### `{sample.name}`\n")
        detail.append(f"- capa-x recovered {len(layout)} functions\n")
        for rule in sorted(missing):
            entries = analysis["rules"][rule]
            for entry in entries:
                fva = entry["function"]
                verdict = classify(fva, [entry["address"]], layout)
                verdicts[verdict.split(" into ")[0]] += 1
                if verdict == "present":
                    # "capa-x has the function" is not the same as "capa-x
                    # walked it": a function whose tail is unrecovered has no
                    # features there to match, so report the coverage.
                    reference_insns = set(functions[fva]["insns"])
                    covered = len(reference_insns & layout[fva])
                    verdict = f"present, {covered}/{len(reference_insns)} insns"
                info = functions.get(fva, {}) if fva is not None else {}
                creator = info.get("creator", "-")
                path = None if fva is None or fva in layout else nearest_present_ancestor(fva, callers, layout)
                if verdict.startswith("absent"):
                    reach = "call path from capa-x code" if path else "no call path from capa-x code"
                    verdicts[f"  of which: {reach}"] += 1
                rows.append(
                    f"| `{sample.name[:8]}` | `{rule}` | 0x{entry['address']:x} | "
                    + (f"0x{fva:x}" if fva is not None else "-")
                    + f" | {verdict} | `{creator}` | "
                    + (" -> ".join(f"0x{v:x}" for v in path) if path else "—")
                    + " |"
                )
                if verdict.startswith("absent") and info:
                    reachable = [
                        f"caller 0x{c:x}{' (capa-x HAS it)' if c in layout else ' (capa-x lacks it)'}"
                        for c in info["callers"]
                    ] or ["no direct caller in the reference's own graph"]
                    branch = [f"branch pred 0x{b:x}" for b in info["branch_preds"]] or ["no CFG predecessor"]
                    if path:
                        # The first hop is the edge B.2 would have to close, so
                        # name it and what created its target.
                        chain = " -> ".join(f"0x{v:x}" for v in path)
                        walk = f"reachable by calls from capa-x's 0x{path[0]:x}: {chain}; first missing target 0x{path[1]:x} created by `{creators.get(path[1], '?')}`"
                    else:
                        walk = "no call path from any function capa-x recovered"
                    detail.append(
                        f"- **0x{fva:x}** (`{rule}`) — creator `{creator}`"
                        f" (via makeFunction: {info['via_makefunction']}), first insn `{info['mnem']}`,"
                        f" name `{info['name']}`, {info['xrefs']} xrefs,"
                        f" prologue signature: {info['signature']}\n"
                        f"  - {'; '.join(reachable)}\n"
                        f"  - {'; '.join(branch)}\n"
                        f"  - {walk}\n"
                        f"  - stack: {' <- '.join(info['stack'][:5])}\n"
                    )

    report = [
        "# Missing-match attribution",
        "",
        "Each rule the reference matches and capa-x does not, on the four",
        "samples: the reference function that owns the matched address, whether",
        "capa-x has that function, and what created it.",
        "See `scripts/triage/attribute_missing.py` for the exact questions asked.",
        "",
        *(f"- {verdict}: **{count}**" for verdict, count in sorted(verdicts.items())),
        "",
        "| Sample | Missing rule | Reference match address | Owning function | capa-x | Creator | Call path from capa-x code |",
        "|---|---|---|---|---|---|---|",
        *rows,
        "",
        "## Absent functions, in the reference's own words",
        *detail,
    ]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(report) + "\n")
    print("\n".join(report[: 12 + len(verdicts)]))
    print(f"\nreport: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
