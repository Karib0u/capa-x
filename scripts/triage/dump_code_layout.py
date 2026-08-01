#!/usr/bin/env python3
"""Dump pinned Vivisect function layout for the code-layout gate.

Emits, per function: basic-block starts, instruction addresses, outgoing CFG
edges, call targets, and no-return/thunk state -- everything the layout oracle
needs to compare *ownership* per function rather than a global flattened set.
Edges and calls come from Vivisect's own branch model (`op.getBranches()`), so
the reference stays authoritative: `envi.BR_PROC` branches are calls, every
other branch is a CFG edge.
"""

from __future__ import annotations

import json
import sys
import argparse
from pathlib import Path

import envi

import capa.loader
import capa.main
from capa.features.common import FORMAT_AUTO


def function_layout(workspace, fva: int) -> dict:
    blocks = sorted(workspace.getFunctionBlocks(fva))
    block_starts: list[int] = []
    instructions: list[int] = []
    calls: set[int] = set()
    edges: set[tuple[int, int]] = set()

    for bva, bsize, _fva in blocks:
        block_starts.append(bva)
        cur = bva
        last_op = None
        while cur < bva + bsize:
            try:
                op = workspace.parseOpcode(cur)
            except Exception:
                # A block byte range that will not decode is a genuine
                # reference-side defect; surface it rather than skip silently.
                raise RuntimeError(f"0x{fva:x}: cannot decode instruction at 0x{cur:x}")
            instructions.append(cur)
            for tova, bflags in op.getBranches():
                # Skip memory-indirect branches (`call [IAT]`, `jmp [IAT]`
                # import thunks): their deref target is a data pointer, not a
                # code address capa-x's direct-only dump can emit, so
                # comparing them is pure noise until indirect-flow tracking
                # lands (the plan's final, post-residue step).
                if tova is None or (bflags & envi.BR_DEREF):
                    continue
                if bflags & envi.BR_PROC:
                    calls.add(tova)
            last_op = op
            cur += len(op)
        # Outgoing CFG edges belong to the block's terminating instruction;
        # a mid-block call's fallthrough stays inside the block, so calls are
        # excluded here (collected above across every instruction instead).
        if last_op is not None:
            for tova, bflags in last_op.getBranches():
                if tova is None or (bflags & (envi.BR_PROC | envi.BR_DEREF)):
                    continue
                edges.add((bva, tova))

    return {
        "address": fva,
        "basic_blocks": sorted(block_starts),
        "instructions": sorted(instructions),
        "calls": sorted(calls),
        "edges": sorted(edges),
        # Vivisect records no-return not as function meta but in its no-return
        # VA set (seeded from no-return APIs, propagated through thunks); this
        # is the property PR 4 ports into capa-x's `Analysis`.
        "noreturn": bool(workspace.isNoReturnVa(fva)),
        "thunk": workspace.getFunctionMeta(fva, "Thunk") is not None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sample", type=Path)
    args = parser.parse_args()

    signatures = capa.main.get_default_signatures()
    workspace = capa.loader.get_workspace(args.sample, FORMAT_AUTO, signatures)
    functions = [function_layout(workspace, fva) for fva in sorted(workspace.getFunctions())]
    json.dump({"functions": functions}, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
