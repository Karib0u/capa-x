#!/usr/bin/env python3
"""Development-only: score data and string symbols in native output against full Ghidra.

usage: data_symbols.py COMPARISON_JSON [COMPARISON_JSON ...]

Input is the file compare.py writes (it carries both texts). Ghidra names the data a
function reads: `DAT_<addr>` globals, `PTR_...` pointer cells, and string literals as
`s_<text>_<addr>` or `u_<text>_<addr>` (narrow and wide). The address is the suffix. For
each distinct such address in Ghidra's text the script asks, of native's text for the same
function:

  referenced  the address appears at all (a `0x...` constant or a `...Ram<16 hex>` name)
  named       native prints a symbolic name for it (same naming forms as Ghidra's)

`referenced` measures recovery of the reference, `named` measures naming. Both are textual
proxies. Precision runs the other way: every symbol native prints is checked against Ghidra's text
for the same function. `agreed` means Ghidra names that address; `unnamed in Ghidra` means
the address appears in Ghidra's text only as a raw constant or placeholder (Ghidra had no
label); `near` means Ghidra has a reference within 32 bytes below it (a field or element of a bigger
Ghidra symbol); `absent` means Ghidra's text mentions nothing close. Inline `"..."` literals are also counted on both sides. Kinds: string (`s_`/`u_`), pointer (`PTR_`), global (`DAT_`).
"""
import collections, json, re, sys

# A pointer cell is named after its target (`PTR_DAT_`, `PTR_FUN_`, `PTR_s_...`, `PTR_PTR__fmode_`).
SYM = re.compile(r"\b(?:((?:PTR_)+)([\w<>%.:\\-]+?)|(_?DAT|[su]_[\w<>%.:\\-]*))_([0-9a-f]{8,16})\b")
RAM = re.compile(r"\b[a-z]{0,3}Ram([0-9a-f]{16})\b")
HEX = re.compile(r"\b0x([0-9a-f]+)\b", re.I)

def strip(c):
    c = re.sub(r"/\*.*?\*/", "", c, flags=re.S)
    return re.sub(r"//[^\n]*", "", c)

def kind(m):
    if m.group(1):
        return "pointer"
    return "string" if m.group(3)[1:2] == "_" and m.group(3)[0] in "su" else "global"

def ghidra_symbols(text):
    out = {}
    for m in SYM.finditer(strip(text)):
        out.setdefault(int(m.group(4), 16), kind(m))
    return out

def native_view(text):
    t = strip(text)
    addrs = {int(m.group(1), 16) for m in RAM.finditer(t)} | {int(m.group(1), 16) for m in HEX.finditer(t)}
    named = {int(m.group(4), 16) for m in SYM.finditer(t)}
    return addrs, named

LITERAL = re.compile(r'"(?:[^"\\\n]|\\.)*"')
literals = collections.Counter()
total = collections.Counter()
extra = collections.defaultdict(list)
examples = collections.defaultdict(list)
functions = with_symbols = 0
for path in [a for a in sys.argv[1:] if not a.startswith('--')]:
    for r in json.load(open(path)):
        if not r.get("g_c") or not r.get("n_c"):
            continue
        functions += 1
        literals["ghidra"] += len(LITERAL.findall(strip(r["g_c"])))
        literals["native"] += len(LITERAL.findall(strip(r["n_c"])))
        syms = ghidra_symbols(r["g_c"])
        g_addrs, _ = native_view(r["g_c"])
        n_syms = ghidra_symbols(r["n_c"])
        for a, k in n_syms.items():
            total[k, "native"] += 1
            if a in syms:
                total[k, "agreed"] += 1
            elif any(a - 32 <= b <= a for b in syms) or any(a - 32 <= b < a for b in g_addrs):
                total[k, "near"] += 1
            elif a in g_addrs:
                total[k, "unnamed"] += 1
                extra[k, "unnamed"].append((r["sample"][:8], r["address"], hex(a)))
            else:
                total[k, "absent"] += 1
                extra[k, "absent"].append((r["sample"][:8], r["address"], hex(a)))
        if not syms:
            continue
        with_symbols += 1
        addrs, named = native_view(r["n_c"])
        for a, k in syms.items():
            total[k, "ghidra"] += 1
            if a in addrs or a in named:
                total[k, "referenced"] += 1
            else:
                if len(examples[k]) < 3:
                    examples[k].append((r["sample"][:8], r["address"], hex(a)))
            if a in named:
                total[k, "named"] += 1

def pct(a, b):
    return "n/a" if not b else f"{100 * a / b:.1f}% ({a}/{b})"

print(f"functions compared: {functions}; with a Ghidra data or string symbol: {with_symbols}")
allk = {"ghidra": 0, "referenced": 0, "named": 0}
for k in ("string", "pointer", "global"):
    g = total[k, "ghidra"]
    for f in allk:
        allk[f] += total[k, f]
    print(f"{k:8s} symbols {g:5d}   referenced {pct(total[k, 'referenced'], g):16s} named {pct(total[k, 'named'], g)}")
print(f"{'all':8s} symbols {allk['ghidra']:5d}   referenced {pct(allk['referenced'], allk['ghidra']):16s} named {pct(allk['named'], allk['ghidra'])}")
print("precision (symbols native prints):")
for k in ("string", "pointer", "global"):
    n = total[k, "native"]
    print(f"{k:8s} native {n:5d}   agreed {pct(total[k, 'agreed'], n):16s} near {total[k, 'near']:4d}   unnamed in Ghidra {total[k, 'unnamed']:4d}   absent {total[k, 'absent']:4d}")
print(f"inline string literals in the text: Ghidra {literals['ghidra']}, native {literals['native']}")
for k, ex in examples.items():
    print(f"not referenced ({k}):", ex)
if "--examples" in sys.argv:
    for key, ex in sorted(extra.items()):
        print(key, ex[:12])
