#!/usr/bin/env python3
"""Development-only: cluster function-set differences by first cause.

usage: classify_functions.py TESTFILES NAMES GHIDRA_DIR FUNCTION_SET_BIN OUT_DIR
Writes OUT_DIR/NAME.json (native function set) and prints G-only and N-only
clusters. A G-only function is classified by what recovery knew about it; an
N-only function by how it sits against Ghidra's function bodies.
"""
import json, subprocess, sys, pathlib, collections, tempfile

testfiles, names, g_dir, binary, out_dir = sys.argv[1:6]
out_dir = pathlib.Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)
gcl, ncl = collections.Counter(), collections.Counter()
per = {}
for name in pathlib.Path(names).read_text().split():
    g = json.loads((pathlib.Path(g_dir) / f"{name}.json").read_text())["functions"]
    gm = {f["entry"]: f for f in g}
    base = subprocess.run([binary, f"{testfiles}/{name}"], capture_output=True, text=True, check=True)
    n0 = {f["entry"] for f in json.loads(base.stdout)["functions"]}
    g_only = sorted(set(gm) - n0)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as t:
        json.dump(g_only, t)
    res = subprocess.run([binary, f"{testfiles}/{name}", t.name], capture_output=True, text=True, check=True)
    data = json.loads(res.stdout)
    (out_dir / f"{name}.json").write_text(res.stdout)
    n = {f["entry"]: f for f in data["functions"]}
    ncov = [(r[0], r[1], f["entry"]) for f in n.values() for r in f["ranges"]]
    ncov.sort()
    gcov = sorted((a, b + 1) for f in g for a, b in f["ranges"])
    def inside(spans, addr):
        import bisect
        i = bisect.bisect_right([s[0] for s in spans], addr) - 1
        return i >= 0 and spans[i][0] <= addr < spans[i][1]
    cls = collections.Counter()
    for a in g_only:
        c = data["classes"][str(a)]
        f = gm[a]
        if f["thunk"]:
            k = "thunk"
        elif inside(ncov, a):
            k = "inside_native_function" if c["insn"] else "interior_of_insn"
        elif c["insn"]:
            k = "decoded_not_function"
        elif c["seeds"]:
            k = "seeded_not_decoded"
        elif c["code_xrefs"] or c["callers"]:
            k = "has_xref_not_decoded"
        else:
            k = "undiscovered"
        cls[k] += 1; gcl[k] += 1
    ncls = collections.Counter()
    for a in sorted(set(n) - set(gm)):
        k = "inside_ghidra_function" if inside(gcov, a) else "not_in_ghidra"
        ncls[k] += 1; ncl[k] += 1
    per[name] = dict(g_only=dict(cls), n_only=dict(ncls))
    print(name[:14], dict(cls), dict(ncls))
print("G-only:", dict(gcl)); print("N-only:", dict(ncl))
(out_dir / "summary.json").write_text(json.dumps(per, indent=1))
