#!/usr/bin/env python3
"""Development-only: function-set agreement between Ghidra and capa-x recovery.

usage: compare_functions.py GHIDRA_DIR NATIVE_DIR OUT_JSON   (NAME.json in each)
Ghidra files come from FunctionList.java, native files from the function_set example.
"""
import json, sys, pathlib

g_dir, n_dir, out = map(pathlib.Path, sys.argv[1:4])
rows, tot = [], dict(g=0, n=0, both=0, g_only=0, n_only=0, g_only_thunk=0, thunk_ok=0)
for gf in sorted(g_dir.glob("*.json")):
    nf = n_dir / gf.name
    if not nf.exists():
        continue
    g = {f["entry"]: f for f in json.loads(gf.read_text())["functions"]}
    n = {f["entry"]: f for f in json.loads(nf.read_text())["functions"]}
    both, g_only, n_only = g.keys() & n.keys(), g.keys() - n.keys(), n.keys() - g.keys()
    thunks = {a for a in g_only if g[a]["thunk"]}
    rows.append(dict(sample=gf.stem, g=len(g), n=len(n), both=len(both), g_only=len(g_only),
                     n_only=len(n_only), g_only_thunk=len(thunks),
                     g_only_addrs=sorted(g_only)[:50], n_only_addrs=sorted(n_only)[:50]))
    for k, v in (("g", len(g)), ("n", len(n)), ("both", len(both)), ("g_only", len(g_only)),
                 ("n_only", len(n_only)), ("g_only_thunk", len(thunks))):
        tot[k] += v
out.write_text(json.dumps(dict(total=tot, samples=rows), indent=1))
print(f"{'sample':14} {'G':>6} {'N':>6} {'both':>6} {'G-only':>7} {'(thunk)':>8} {'N-only':>7}")
for r in rows:
    print(f"{r['sample'][:14]:14} {r['g']:6} {r['n']:6} {r['both']:6} {r['g_only']:7} {r['g_only_thunk']:8} {r['n_only']:7}")
t = tot
print(f"{'TOTAL':14} {t['g']:6} {t['n']:6} {t['both']:6} {t['g_only']:7} {t['g_only_thunk']:8} {t['n_only']:7}")
print(f"recall of G {t['both']/t['g']:.1%}  precision vs G {t['both']/t['n']:.1%}")
