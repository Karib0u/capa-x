#!/usr/bin/env python3
"""Development-only: compare native capa-x pseudocode with full Ghidra, per function.

usage: compare.py GHIDRA_DIR NATIVE_DIR OUT_JSON
"""
import json, os, re, sys, collections

KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof", "do", "else", "case"}
# Ghidra pseudo-operations and type casts that look like calls but are not callees.
PSEUDO = re.compile(r"^(undefined\d*|CONCAT\d+|SUB\d+|ZEXT\d+|SEXT\d+|CARRY\d|SCARRY\d|SBORROW\d|POPCOUNT|LZCOUNT|BADSPACEBASE|UNRECOVERED_JUMPTABLE|halt_baddata|swi|CALLIND|FUN_.*|thunk_FUN_.*|SUB_.*|Ordinal_\d+|code|func_0x.*|\(\*.*)$")
CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_:~$@?]*)\s*\(")

def strip(c):
    c = re.sub(r"/\*.*?\*/", "", c, flags=re.S)
    return re.sub(r"//[^\n]*", "", c)

def signature(c):
    """The declaration, joined across lines: a long parameter list wraps after a comma."""
    lines = c.splitlines()
    for i, line in enumerate(lines):
        if "(" in line and not line.strip().startswith(("/*", "//", "#")):
            sig = line
            for more in lines[i + 1:]:
                if sig.count("(") <= sig.count(")"):
                    break
                sig += " " + more.strip()
            return sig
    return ""

def calls(c):
    """name -> argument count of the first call, ignoring the declaration line."""
    body = strip(c)
    lines = body.splitlines()
    skip = next((i for i, l in enumerate(lines) if "{" in l), 0)
    text = "\n".join(lines[skip + 1:])
    found = {}
    for m in CALL.finditer(text):
        n = m.group(1)
        if n in KEYWORDS:
            continue
        i, depth, args, seen = m.end(), 1, 0, False
        while i < len(text) and depth:
            ch = text[i]
            if ch in "([{": depth += 1
            elif ch in ")]}": depth -= 1
            elif ch == "," and depth == 1: args += 1
            elif depth == 1 and not ch.isspace(): seen = True
            i += 1
        found.setdefault(n, args + 1 if seen or args else 0)
    return found

# With --any-module, a native call also matches a Ghidra name when it is `<module>_<name>` for any
# imported DLL (lowercase module), not only for the DLL list in base() below.
ANY_MODULE = "--any-module" in sys.argv
if ANY_MODULE:
    sys.argv.remove("--any-module")

def lookup(nbase, k):
    if k in nbase:
        return nbase[k]
    if ANY_MODULE:
        for n, v in nbase.items():
            if n.endswith("_" + k) and re.fullmatch(r"[a-z0-9][a-z0-9\-\.]*", n[: -len(k) - 1]):
                return v
    return None

def base(n):
    # native prefixes imports with the module, e.g. kernel32_ExitProcess
    return n.split("_", 1)[1] if re.match(r"^(kernel32|kernelbase|advapi32|user32|ntdll|msvcrt|ws2_32|shell32|ole32|gdi32|shlwapi|wininet|oleaut32)_", n, re.I) else n

def shape(c):
    sig = signature(c)
    params = sig[sig.find("(") + 1: sig.rfind(")")].strip() if "(" in sig else ""
    n = 0 if params in ("", "void") else params.count(",") + 1
    return {"void": bool(re.match(r"\s*(?:[A-Za-z_]+\s+)*void\s", sig)) and "*" not in sig.split("(")[0], "params": n}

def metrics(c):
    s = strip(c)
    return {"lines": len([l for l in s.splitlines() if l.strip()]),
            "gotos": len(re.findall(r"\bgoto\b", s)),
            "labels": len(re.findall(r"^\s*[A-Za-z_]\w*:\s*$", s, re.M)),
            "unnamed_calls": len(re.findall(r"\b(?:FUN_|func_|sub_|thunk_FUN_)\w+\s*\(", s))}

rows = []
gdir_ = sys.argv[1]
for name in sorted(n for n in os.listdir(gdir_) if n.endswith(".json")):
    g = json.load(open(os.path.join(gdir_, name)))
    npath = os.path.join(sys.argv[2], name)
    n = json.load(open(npath)) if os.path.exists(npath) else {"events": [], "returncode": None}
    results = {e["address"]: e for e in n["events"] if e.get("event") == "result"}
    init_err = next((e["error"] for e in n["events"] if e.get("event") == "initialization_error"), None)
    for f in g["functions"]:
        a = int(f["address"], 16)
        r = results.get(a)
        row = {"sample": name[:-5], "address": f["address"], "role": f["role"], "gsize": f["size"],
               "g_ok": f["ok"], "g_ms": f["ms"]}
        if init_err:
            row["n_status"] = "init_error"; row["n_error"] = init_err
        elif r is None:
            row["n_status"] = "not_run"; row["n_error"] = f"rc={n.get('returncode')}"
        elif "error" in r:
            row["n_status"] = "error"; row["n_error"] = r["error"]
        else:
            out = r["output"]
            row["n_status"] = "incomplete" if out["incomplete"] else "ok"
            row["n_unknown_callees"] = out.get("unknown_callees", False)
            row["n_warnings"] = out["warnings"]
            row["n_ms"] = out["timings"]["decompilation_ms"]
            if f["ok"]:
                gc, nc = f["c"], out["text"]
                gm, nm = metrics(gc), metrics(nc)
                gs, ns = shape(gc), shape(nc)
                gcalls, ncalls = calls(gc), calls(nc)
                nbase = {base(k): v for k, v in ncalls.items()}
                gnamed = {k: v for k, v in gcalls.items() if not PSEUDO.match(k)}
                match = [k for k in gnamed if lookup(nbase, k) is not None]
                row.update({"g_metrics": gm, "n_metrics": nm,
                            "ret_void_g": gs["void"], "ret_void_n": ns["void"],
                            "params_g": gs["params"], "params_n": ns["params"],
                            "g_named_callees": len(gnamed), "n_matched_callees": len(match),
                            "arity_match": sum(1 for k in match if gnamed[k] == lookup(nbase, k)),
                            "missing_callees": sorted(k for k in gnamed if lookup(nbase, k) is None)[:10],
                            "g_c": gc, "n_c": nc})
        rows.append(row)
json.dump(rows, open(sys.argv[3], "w"), indent=1)

def pct(a, b): return "n/a" if not b else f"{100 * a / b:.1f}% ({a}/{b})"
tot = len(rows)
stat = collections.Counter(r["n_status"] for r in rows)
both = [r for r in rows if r.get("g_metrics")]
print(f"functions: {tot}; Ghidra ok: {sum(r['g_ok'] for r in rows)}")
print("native status:", dict(stat))
errs = collections.Counter(re.sub(r"0x[0-9a-fA-F]+", "ADDR", r["n_error"])[:90] for r in rows if "n_error" in r)
for e, c in errs.most_common(8): print(f"  {c:3d}  {e}")
print("flagged incomplete among outputs:", pct(stat["incomplete"], stat["ok"] + stat["incomplete"]))
outputs = [r for r in rows if r["n_status"] in ("ok", "incomplete")]
print("  of which unknown callee prototypes:", pct(sum(1 for r in outputs if r.get("n_unknown_callees")), len(outputs)))
print("  incomplete for another reason:", pct(sum(1 for r in outputs if r["n_status"] == "incomplete" and not r.get("n_unknown_callees")), len(outputs)))
warn = collections.Counter(re.sub(r"0x[0-9a-fA-F]+", "ADDR", w)[:80] for r in rows for w in r.get("n_warnings", []))
for w, c in warn.most_common(6): print(f"  warn {c:3d}  {w}")
print("compared (both produced text):", len(both))
print("return void/non-void agree:", pct(sum(r["ret_void_g"] == r["ret_void_n"] for r in both), len(both)))
print("param count agree:", pct(sum(r["params_g"] == r["params_n"] for r in both), len(both)))
print("named callees found:", pct(sum(r["n_matched_callees"] for r in both), sum(r["g_named_callees"] for r in both)))
print("call arity agrees (matched):", pct(sum(r["arity_match"] for r in both), sum(r["n_matched_callees"] for r in both)))
print("gotos G/N:", sum(r["g_metrics"]["gotos"] for r in both), sum(r["n_metrics"]["gotos"] for r in both))
print("lines G/N:", sum(r["g_metrics"]["lines"] for r in both), sum(r["n_metrics"]["lines"] for r in both))
print("unnamed calls G/N:", sum(r["g_metrics"]["unnamed_calls"] for r in both), sum(r["n_metrics"]["unnamed_calls"] for r in both))
def med(xs):
    xs = sorted(xs); return xs[len(xs) // 2] if xs else None
print("median ms G/N:", med([r["g_ms"] for r in both]), med([r["n_ms"] for r in both if "n_ms" in r]))
