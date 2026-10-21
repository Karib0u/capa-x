#!/usr/bin/env python3
"""Development-only: pick the baseline samples from PE headers alone.

Eligible: native AMD64 PE files (no CLR directory) of 8 KiB..6 MiB. Strata are
(EXE|DLL) x size tercile; the seeded sample is spread evenly over the strata.
No decompiler output is consulted.
"""
import hashlib, json, os, random, struct, sys

def pe_info(path):
    with open(path, "rb") as f:
        head = f.read(4096)
        if head[:2] != b"MZ" or len(head) < 64:
            return None
        e = struct.unpack_from("<I", head, 0x3C)[0]
        f.seek(e)
        nt = f.read(24 + 240)
    if len(nt) < 24 + 112 or nt[:4] != b"PE\0\0":
        return None
    machine, = struct.unpack_from("<H", nt, 4)
    chars, = struct.unpack_from("<H", nt, 22)
    magic, = struct.unpack_from("<H", nt, 24)
    if machine != 0x8664 or magic != 0x20B:
        return None
    nrva, = struct.unpack_from("<I", nt, 24 + 108)
    clr = (0, 0)
    if nrva > 14:
        clr = struct.unpack_from("<II", nt, 24 + 112 + 14 * 8)
    return {"dll": bool(chars & 0x2000), "clr": clr[0] != 0}

def main():
    root, count, seed, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    cands = []
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if not os.path.isfile(p):
            continue
        size = os.path.getsize(p)
        if not 8192 <= size <= 6 * 1024 * 1024:
            continue
        info = pe_info(p)
        if info and not info["clr"]:
            cands.append({"name": name, "size": size, "dll": info["dll"]})
    sizes = sorted(c["size"] for c in cands)
    t1, t2 = sizes[len(sizes) // 3], sizes[2 * len(sizes) // 3]
    strata = {}
    for c in cands:
        tier = 0 if c["size"] < t1 else 1 if c["size"] < t2 else 2
        strata.setdefault(("dll" if c["dll"] else "exe", tier), []).append(c)
    rng = random.Random(seed)
    keys = sorted(strata)
    chosen = []
    pools = {k: rng.sample(strata[k], len(strata[k])) for k in keys}
    while len(chosen) < count and any(pools.values()):
        for k in keys:
            if pools[k] and len(chosen) < count:
                chosen.append(pools[k].pop())
    for c in chosen:
        with open(os.path.join(root, c["name"]), "rb") as f:
            c["sha256"] = hashlib.sha256(f.read()).hexdigest()
    json.dump({"eligible": len(cands), "seed": seed, "tiers": [t1, t2],
               "samples": sorted(chosen, key=lambda c: c["name"])},
              open(out, "w"), indent=1)
    print(len(cands), "eligible;", len(chosen), "selected")

main()
