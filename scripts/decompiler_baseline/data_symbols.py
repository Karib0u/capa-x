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
proxies. Inline `"..."` literals are also counted on both sides. Kinds: string (`s_`/`u_`), pointer (`PTR_`), global (`DAT_`).
"""
import collections, json, re, sys

SYM = re.compile(r"\b((?:PTR_)*)(_?DAT|[su]_[\w<>%.:\\-]*)_([0-9a-f]{8,16})\b")
RAM = re.compile(r"\b[a-z]{0,3}Ram([0-9a-f]{16})\b")
HEX = re.compile(r"\b0x([0-9a-f]+)\b", re.I)

def strip(c):
    c = re.sub(r"/\*.*?\*/", "", c, flags=re.S)
    return re.sub(r"//[^\n]*", "", c)

def kind(prefix, base):
    if base[0] in "su" and base[1] == "_":
        return "string"
    return "pointer" if prefix else "global"

def ghidra_symbols(text):
    out = {}
    for m in SYM.finditer(strip(text)):
        out.setdefault(int(m.group(3), 16), kind(m.group(1), m.group(2)))
    return out

def native_view(text):
    t = strip(text)
    addrs = {int(m.group(1), 16) for m in RAM.finditer(t)} | {int(m.group(1), 16) for m in HEX.finditer(t)}
    named = {int(m.group(3), 16) for m in SYM.finditer(t)}
    return addrs, named

LITERAL = re.compile(r'"(?:[^"\\\n]|\\.)*"')
literals = collections.Counter()
total = collections.Counter()
examples = collections.defaultdict(list)
functions = with_symbols = 0
for path in sys.argv[1:]:
    for r in json.load(open(path)):
        if not r.get("g_c") or not r.get("n_c"):
            continue
        functions += 1
        literals["ghidra"] += len(LITERAL.findall(strip(r["g_c"])))
        literals["native"] += len(LITERAL.findall(strip(r["n_c"])))
        syms = ghidra_symbols(r["g_c"])
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
print(f"inline string literals in the text: Ghidra {literals['ghidra']}, native {literals['native']}")
for k, ex in examples.items():
    print(f"not referenced ({k}):", ex)
