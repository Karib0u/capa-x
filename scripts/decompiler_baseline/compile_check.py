#!/usr/bin/env python3
"""Development-only (Step 12): does decompiler text compile as C against a real header?

usage: compile_check.py LABEL COMPARISON_JSON PACK [--x86] [--ghidra] [--out FILE.json] [-j N]

COMPARISON_JSON is the file compare.py writes; PACK is capa-x-ghidra/data/winapi64.pack (or
winapi32.pack with --x86). Each function is compiled alone with `clang -fsyntax-only` for a Windows
target, behind the header from compile_header.py: Ghidra's pseudo-types and pseudo-operations, the
types the function names (from the pack), and the pack's prototype for every callee the pack knows.
Anything still undeclared is stubbed (`FUN_` callees, data symbols) and counted, because the text
passes on a guess about it. The output is never run.

Three results per function:
  compiles   clang accepts the text once every undeclared identifier is stubbed
             (the stand-in for the old crude number)
  clean      compiles, and the text has no construct that needs a decision before it can be
             recompiled: register reads (`unaff_*`, `in_*`, `extraout_*`), `stack0x` addresses,
             `UNRECOVERED_JUMPTABLE`, `halt_*`, `swi`, calls through `pcRam*` globals
  strict     clean, and it still compiles when integer/pointer conversions are errors again

A pass means well-formed C, not that the function is right: a dropped argument still compiles.
`--ghidra` checks Ghidra's text (`g_c`) instead of native's (`n_c`).
"""
import collections
import json
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compile_header import Emitter, Pack, prelude  # noqa: E402

BLOCKERS = [
    ("register read (unaff_/in_/extraout_)", re.compile(r"\b(?:unaff_\w+|in_[A-Za-z]\w*|extraout_\w+)")),
    ("sub-piece member (x._0_4_)", re.compile(r"\._\d+_\d+_")),
    ("stack0x address", re.compile(r"\bstack0x[0-9a-f]+")),
    ("UNRECOVERED_JUMPTABLE", re.compile(r"\bUNRECOVERED_JUMPTABLE\b")),
    ("halt_*", re.compile(r"\bhalt_\w+")),
    ("swi", re.compile(r"\bswi\s*\(")),
    ("call through pcRam global", re.compile(r"\(\*\s*(?:\(code\s*\*+\))?\s*pcRam\w*\s*\)|\bpcRam\w*\s*\(")),
]
DATA_NAME = re.compile(r"^(?:DAT_|PTR_|_DAT_|s_|u_|[a-z]+Ram|_?[uc]Ram|[a-z]?Ram)")
LENIENT = ["-Wno-everything", "-Werror=implicit-function-declaration","-Wno-error=int-conversion", "-Wno-error=incompatible-pointer-types",
           "-Wno-error=incompatible-function-pointer-types", "-Wno-error=pointer-sign"]
ERR = re.compile(r"error: ([^\n]*)")


def clang(src, target, extra):
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
        f.write(src)
        path = f.name
    try:
        r = subprocess.run(["clang", "--target=" + target, "-x", "c", "-std=gnu11", "-fms-extensions",
                            "-fsyntax-only", "-ferror-limit=0", *extra, path],
                           capture_output=True, text=True, timeout=60)
    finally:
        os.unlink(path)
    return r.returncode == 0, r.stderr


def data_stub(name, text):
    """A declaration for an undeclared data symbol, guessed from how the text uses it."""
    n = re.escape(name)
    if re.search(rf"\(\s*\*\s*{n}\s*\)\s*\(", text):
        return f"extern code *{name};"
    if re.search(rf"\b{n}\s*(->|\.)", text):
        return f"extern struct {{ char _[4096]; }} {name};"      # a struct whose layout the text names
    if re.search(rf"\b{n}\s*\[", text):
        return f"extern unsigned int {name}[];"
    if re.search(rf"\*\s*{n}\b", text):
        return f"extern unsigned int *{name};"
    return f"extern long long {name};"


def blockers_in(text):
    return [name for name, rx in BLOCKERS if rx.search(text)]


def check(text, pack, is64):
    target = "x86_64-pc-windows-msvc" if is64 else "i686-pc-windows-msvc"
    pre = prelude(is64)
    em = Emitter(pack, is64)
    fn_stubs, var_stubs, type_stubs = set(), set(), set()
    known_callees = set()
    err = ""
    for _ in range(14):
        stubs = "".join(f"typedef unsigned int {t};\n" for t in sorted(type_stubs))
        stubs += "".join(f"extern long long {s}();\n" for s in sorted(fn_stubs))
        stubs += "".join(data_stub(s, text) + "\n" for s in sorted(var_stubs))
        ok, err = clang(pre + em.text() + stubs + text, target, LENIENT)
        if ok:
            return dict(status="compiles", fn_stubs=sorted(fn_stubs), var_stubs=sorted(var_stubs),
                        type_stubs=sorted(type_stubs), known=sorted(known_callees),
                        source=pre + em.text() + stubs + text)
        progress = False
        for line in err.splitlines():
            m = ERR.search(line)
            if not m:
                continue
            msg = m.group(1)
            if (g := re.match(r"unknown type name '(\w+)'", msg)):
                n = g.group(1)
                if n in type_stubs:
                    continue
                if not em.want(n):
                    type_stubs.add(n)
                progress = True
            elif (g := re.match(r"call to undeclared (?:library )?function '(\w+)'", msg)):
                n = g.group(1)
                if n in fn_stubs or n in known_callees:
                    continue
                if em.prototype(n):
                    known_callees.add(n)
                else:
                    fn_stubs.add(n)
                progress = True
            elif (g := re.match(r"use of undeclared identifier '(\w+)'", msg)):
                n = g.group(1)
                if n in var_stubs or n in fn_stubs or n in known_callees:
                    continue
                if n in pack.by_name and em.want(n):      # a type name written in a cast
                    progress = True
                    continue
                var_stubs.add(n)
                progress = True
            elif "incomplete" in msg:
                for q in re.findall(r"'(?:struct |union )?(\w+)'", msg):
                    if em.want(q, full=True):
                        progress = True
        if not progress:
            break
    return dict(status="fail", error=first_error(err), fn_stubs=sorted(fn_stubs), var_stubs=sorted(var_stubs),
                type_stubs=sorted(type_stubs), known=sorted(known_callees))


def first_error(err):
    m = ERR.search(err or "")
    return re.sub(r"'[^']*'", "'X'", m.group(1))[:90] if m else "?"


def classify(row, text, pack, is64):
    res = check(text, pack, is64)
    res["blockers"] = blockers_in(text)
    if res["status"] == "compiles":
        # A blocker is a construct that will not recompile as it is, even if clang accepted it once
        # its identifier was stubbed.
        res["clean"] = not res["blockers"]
        if res["clean"]:
            target = "x86_64-pc-windows-msvc" if is64 else "i686-pc-windows-msvc"
            res["strict"] = clang(res["source"], target, ["-w"])[0]
        res.pop("source")
    return res


def main():
    args = sys.argv[1:]
    flags = {"--x86", "--ghidra"}
    opts = {"--out": None, "-j": "8"}
    pos = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in opts:
            opts[a] = args[i + 1]
            i += 2
        else:
            (pos if a not in flags else []).append(a)
            i += 1
    label, path, packpath = pos
    is64 = "--x86" not in args
    key = "g_c" if "--ghidra" in args else "n_c"
    pack = Pack(packpath)
    rows = [x for x in json.load(open(path)) if x.get(key)]
    with ThreadPoolExecutor(int(opts["-j"])) as ex:
        results = list(ex.map(lambda x: classify(x, x[key], pack, is64), rows))

    n = len(rows)
    comp = [r for r in results if r["status"] == "compiles"]
    clean = [r for r in comp if r["clean"]]
    strict = [r for r in clean if r.get("strict")]
    print(f"{label} [{key}]  functions={n}  compiles={len(comp)} ({100*len(comp)/max(n,1):.0f}%)  "
          f"clean={len(clean)} ({100*len(clean)/max(n,1):.0f}%)  strict={len(strict)} ({100*len(strict)/max(n,1):.0f}%)")
    if key == "n_c":
        unk = [(x, r) for x, r in zip(rows, results) if x.get("n_unknown_callees")]
        kn = [(x, r) for x, r in zip(rows, results) if not x.get("n_unknown_callees")]
        for name, grp in (("with unknown callees", unk), ("no unknown callees", kn)):
            if grp:
                c = sum(r["status"] == "compiles" for _, r in grp)
                cl = sum(r["status"] == "compiles" and r["clean"] for _, r in grp)
                print(f"   {name}: {len(grp)} functions, compiles {c}, clean {cl}")
    b = collections.Counter(x for r in results for x in r["blockers"])
    print("   constructs that need a decision (functions containing each):")
    for k, v in b.most_common():
        print(f"     {v:4d}  {k}")
    why = collections.Counter(r["error"] for r in results if r["status"] == "fail")
    print("   still failing (first error):")
    for k, v in why.most_common(10):
        print(f"     {v:4d}  {k}")
    ts = collections.Counter(t for r in results for t in r["type_stubs"])
    if ts:
        print("   type names the pack lacks:", ts.most_common(12))
    print("   functions needing stubs: callee stubs", sum(bool(r["fn_stubs"]) for r in results),
          "data/pseudo-variable stubs", sum(bool(r["var_stubs"]) for r in results),
          "| callees given a pack prototype", sum(len(r["known"]) for r in results))
    if opts["--out"]:
        json.dump([dict(sample=x.get("sample"), address=x.get("address"), **r) for x, r in zip(rows, results)],
                  open(opts["--out"], "w"), indent=1)


main()
