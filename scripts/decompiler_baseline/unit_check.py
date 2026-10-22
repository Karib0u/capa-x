#!/usr/bin/env python3
"""Development-only (Step 13): do the self-contained units compile?

usage: unit_check.py SAMPLES_DIR SELECTION_JSON CAPA_X_CLI [--x86] [--set N] [-j N] [--out FILE]

SELECTION_JSON is heldout.json, heldout-x86.json, samples.json or samples-x86.json. For every
selected function the CLI is run as `capa-x SAMPLE --decompile-function ADDR --unit --json` and
the unit text is compiled with `clang -fsyntax-only` for a Windows target, with only the unit as
input: no stubs added here, which is the point. With `--set N`, the selected functions of one sample
are also grouped N at a time into one unit each, to test the set path.

Reported: how many units compile; how many compile and rest on the archive alone (no GUESS
declaration, no unrewritten sub-piece); the guess kinds; what fails. Compiling is not running, and a
pass does not say the function is right. Sample bytes are only read by the CLI.
"""
import collections
import json
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

STD = ["-x", "c", "-std=gnu11", "-fms-extensions", "-fsyntax-only", "-ferror-limit=0", "-Wno-everything",
       "-Werror=implicit-function-declaration", "-Wno-error=int-conversion",
       "-Wno-error=incompatible-pointer-types", "-Wno-error=incompatible-function-pointer-types",
       "-Wno-error=pointer-sign"]


def compile_unit(text, x86):
    target = "i686-pc-windows-msvc" if x86 else "x86_64-pc-windows-msvc"
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
        f.write(text)
        path = f.name
    try:
        r = subprocess.run(["clang", "--target=" + target, *STD, path], capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(path)
    m = re.search(r"error: ([^\n]*)", r.stderr)
    return r.returncode == 0, (re.sub(r"'[^']*'", "'X'", m.group(1))[:90] if m else None)


def run(job):
    cli, path, addrs, x86 = job
    cmd = [cli, path, "--json", "--unit"]
    for a in addrs:
        cmd += ["--decompile-function", hex(a)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        return dict(status="request_error", error=r.stderr.strip()[:120], addrs=addrs, path=path)
    unit = json.loads(r.stdout)
    ok, err = compile_unit(unit["text"], x86)
    return dict(status="compiles" if ok else "fail", error=err, addrs=addrs, path=path,
                archive_only=ok and not unit["guesses"] and unit["unrewritten"] == 0,
                guesses=collections.Counter(g["kind"] for g in unit["guesses"]),
                rewrites=unit["rewrites"], unrewritten=unit["unrewritten"],
                unknown=any(f["unknown_callees"] for f in unit["functions"]),
                unresolved_types=unit["unresolved_types"])


def main():
    args = sys.argv[1:]
    opts = {"--set": "0", "-j": "6", "--out": None}
    pos = []
    i = 0
    while i < len(args):
        if args[i] in opts:
            opts[args[i]] = args[i + 1]
            i += 2
        else:
            pos.append(args[i])
            i += 1
    x86 = "--x86" in pos
    pos = [p for p in pos if p != "--x86"]
    samples_dir, selection, cli = pos
    sel = json.load(open(selection))["samples"]
    jobs = []
    group = int(opts["--set"])
    for s in sel:
        path = os.path.join(samples_dir, s["name"])
        addrs = [a["address"] for a in s["addresses"]]
        if group:
            for k in range(0, len(addrs), group):
                jobs.append((cli, path, addrs[k:k + group], x86))
        else:
            jobs += [(cli, path, [a], x86) for a in addrs]
    with ThreadPoolExecutor(int(opts["-j"])) as ex:
        res = list(ex.map(run, jobs))
    n = len(res)
    err = [r for r in res if r["status"] == "request_error"]
    ok = [r for r in res if r["status"] == "compiles"]
    arch = [r for r in ok if r["archive_only"]]
    print(f"{os.path.basename(selection)}{' (sets of %d)' % group if group else ''}: units={n} "
          f"compiles={len(ok)} ({100*len(ok)/max(n,1):.0f}%) archive-only={len(arch)} request-errors={len(err)}")
    g = collections.Counter()
    for r in ok:
        g.update(r["guesses"])
    print("   guesses in compiling units:", dict(g.most_common()))
    print("   sub-pieces rewritten", sum(r.get("rewrites", 0) for r in res), "left", sum(r.get("unrewritten", 0) for r in res))
    why = collections.Counter(r["error"] for r in res if r["status"] == "fail")
    print("   still failing (first error):")
    for k, v in why.most_common(10):
        print(f"     {v:4d}  {k}")
    if err:
        print("   request errors:", collections.Counter(r["error"] for r in err).most_common(4))
    ut = collections.Counter(t for r in res for t in r.get("unresolved_types", []))
    if ut:
        print("   archive types without a definition:", ut.most_common(8))
    kn = [r for r in ok if not r["unknown"]]
    allk = [r for r in res if r["status"] != "request_error" and not r["unknown"]]
    print(f"   units with no unknown callees: {len(allk)}, compile {len(kn)}")
    if opts["--out"]:
        json.dump(res, open(opts["--out"], "w"), indent=1, default=dict)


main()
