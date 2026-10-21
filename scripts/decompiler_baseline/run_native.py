#!/usr/bin/env python3
"""Development-only: run the native decompiler_corpus example on Ghidra's selected addresses.

usage: run_native.py TESTFILES GHIDRA_DIR OUT_DIR EXAMPLE_BINARY
"""
import json, os, subprocess, sys, tempfile, time

testfiles, gdir, out, binary = sys.argv[1:5]
os.makedirs(out, exist_ok=True)
for name in sorted(os.listdir(gdir)):
    if not name.endswith(".json"):
        continue
    sample = name[:-5]
    ghidra = json.load(open(os.path.join(gdir, name)))
    addrs = [int(f["address"], 16) for f in ghidra["functions"]]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as t:
        json.dump(addrs, t)
    t0 = time.time()
    try:
        p = subprocess.run([binary, os.path.join(testfiles, sample), t.name],
                           capture_output=True, text=True, timeout=300)
        stdout, rc = p.stdout, p.returncode
        stderr = p.stderr[-2000:]
    except subprocess.TimeoutExpired as e:
        stdout, rc, stderr = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""), -9, "timeout 300s"
    os.unlink(t.name)
    events = []
    for line in stdout.splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            pass
    json.dump({"sample": sample, "returncode": rc, "stderr": stderr,
               "wall_s": round(time.time() - t0, 2), "events": events},
              open(os.path.join(out, sample + ".json"), "w"))
    print(sample[:30], rc, len(events), flush=True)
