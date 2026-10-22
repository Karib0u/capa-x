#!/usr/bin/env python3
"""Development-only: draw the held-out decompiler selection from NATIVE's function set.

usage: select_heldout.py TESTFILES COUNT SEED FUNCTION_SET_BINARY EXCLUDE_SAMPLES_JSON OUT_JSON [x86]

Eligible: native AMD64 PE files (x86-32 with a seventh argument "x86"; no CLR directory,
8 KiB..6 MiB) that are not in the baseline selection. Strata are (EXE|DLL) x size tercile, spread evenly. Functions come from
capa-x's own recovery (the `function_set` example), not from Ghidra, so functions Ghidra
does not recover are part of the sample: per sample the entry point plus functions of at
least 8 bytes at size percentiles 5, 10, 25, 50, 60, 75, 90, 99 and 100. No decompiler
output is consulted.
"""
import hashlib, json, os, random, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util
spec = importlib.util.spec_from_file_location("sel", os.path.join(os.path.dirname(os.path.abspath(__file__)), "select_samples.py"))
src = open(spec.origin).read().replace("\nmain()\n", "\n")
sel = {}
exec(compile(src, "select_samples", "exec"), sel)

root, count, seed, fsbin, excl, out = sys.argv[1:7]
arch = sys.argv[7] if len(sys.argv) > 7 else "amd64"
count, seed = int(count), int(seed)
skip = {s["name"] for s in json.load(open(excl))["samples"]}
cands = []
for name in sorted(os.listdir(root)):
    p = os.path.join(root, name)
    if name in skip or not os.path.isfile(p) or not 8192 <= os.path.getsize(p) <= 6 * 1024 * 1024:
        continue
    info = sel["pe_info"](p, arch)
    if info and not info["clr"]:
        cands.append({"name": name, "size": os.path.getsize(p), "dll": info["dll"]})
sizes = sorted(c["size"] for c in cands)
t1, t2 = sizes[len(sizes) // 3], sizes[2 * len(sizes) // 3]
strata = {}
for c in cands:
    tier = 0 if c["size"] < t1 else 1 if c["size"] < t2 else 2
    strata.setdefault(("dll" if c["dll"] else "exe", tier), []).append(c)
rng = random.Random(seed)
keys = sorted(strata)
pools = {k: rng.sample(strata[k], len(strata[k])) for k in keys}
chosen = []
while len(chosen) < count and any(pools.values()):
    for k in keys:
        if pools[k] and len(chosen) < count:
            chosen.append(pools[k].pop())
samples = []
for c in sorted(chosen, key=lambda c: c["name"]):
    path = os.path.join(root, c["name"])
    r = subprocess.run([fsbin, path], capture_output=True, timeout=300)
    try:
        funcs = json.loads(r.stdout)["functions"]
    except ValueError:
        continue
    funcs = sorted((f for f in funcs if f["size"] >= 8), key=lambda f: (f["size"], f["entry"]))
    if not funcs:
        continue
    picks = {}
    for p in (10, 50, 90, 100, 25, 75, 99, 5, 60):
        f = funcs[min(len(funcs) - 1, round((len(funcs) - 1) * p / 100))]
        picks.setdefault(f["entry"], "p%d" % p)
    with open(path, "rb") as fh:
        c["sha256"] = hashlib.sha256(fh.read()).hexdigest()
    c["native_functions"] = len(funcs)
    c["addresses"] = [{"address": a, "role": r} for a, r in list(picks.items())[:8]]
    samples.append(c)
json.dump({"eligible": len(cands), "seed": seed, "tiers": [t1, t2], "samples": samples},
          open(out, "w"), indent=1)
print(len(cands), "eligible;", len(samples), "selected;", sum(len(s["addresses"]) for s in samples), "functions")
