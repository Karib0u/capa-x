"""Differential test: decompiled function against its source (development only).

python3 -I difftest.py OUT_DIR CAPA_X_CLI [BUILD ...]

For each scalar function of src/arith.c, decompiles it from the stripped
ks.exe as a self-contained unit (`--unit`), compiles that unit for the host
and runs it against the same function compiled from the source, on the same
inputs. Arguments are packed in the Windows ABI's slots (4-byte stack slots
on x86-32, one 8-byte slot per parameter on x64), so a decompiled prototype
that reads a different slot gives a different answer. Only our own builds of
our own sources run; nothing taken from a sample is ever executed.

Writes OUT_DIR/difftest.json and prints one line per function that differs.
"""
import json
import os
import random
import re
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
CC = ["/usr/bin/clang", "-std=gnu11", "-O0", "-fwrapv", "-w"]
TRIALS = 400

# Source parameter types and how to draw a value for each.
EDGE32 = [0, 1, -1, 2, 7, 31, 32, 33, 100, 255, 256, -5, 1000, 65536, 0x7FFFFFFF, -0x80000000]
EDGE64 = [0, 1, -1, 2, 63, 64, 1 << 32, -(1 << 32), (1 << 63) - 1, -(1 << 63), 0x123456789]


def draw(kind, rng):
    if kind in ("int", "unsigned int", "uint32_t"):
        value = rng.choice(EDGE32) if rng.random() < 0.4 else rng.randrange(-(1 << 31), 1 << 31)
        return value & 0xFFFFFFFF if kind != "int" else value
    if kind in ("short", "short int"):
        return rng.randrange(-(1 << 15), 1 << 15)
    if kind in ("signed char", "char"):
        return rng.randrange(-128, 128)
    if kind == "unsigned char":
        return rng.randrange(256)
    if kind == "int64_t":
        return rng.choice(EDGE64) if rng.random() < 0.4 else rng.randrange(-(1 << 63), 1 << 63)
    if kind == "uint64_t":
        return (rng.choice(EDGE64) if rng.random() < 0.4 else rng.randrange(1 << 64)) & (2**64 - 1)
    if kind in ("double", "float"):
        return rng.choice([0.0, 0.5, -0.5, 2.5, -3.75, 1e6]) if rng.random() < 0.3 else round(rng.uniform(-1e6, 1e6), 3)
    raise SystemExit(f"no generator for {kind}")


# Inputs that keep the source well defined and the run short.
RANGES = {
    "ks_fact": (-5, 20), "ks_fib_iter": (-5, 90), "ks_nested_loops": (-3, 60),
}
C_TYPE = {"_Bool": "_Bool", "short int": "short", "long long int": "long long"}


def literal(kind, value):
    if kind in ("double", "float"):
        return repr(float(value)) + ("f" if kind == "float" else "")
    if kind in ("int64_t",):
        return f"(int64_t){value}LL" if value != -(1 << 63) else "INT64_MIN"
    if kind == "uint64_t":
        return f"(uint64_t){value}ULL"
    if kind == "int" and value == -0x80000000:
        return "INT_MIN"
    return f"({C_TYPE.get(kind, kind)}){value}"


def harness(function, bits, rng):
    """C source that calls the reference and the decompiled function on TRIALS inputs."""
    name, params, returns = function["name"], [p["type"] for p in function["params"]], function["returns"]
    lines = ['#include <limits.h>', '#include <stdint.h>', '#include <stdio.h>', '#include <string.h>',
             '#include <math.h>', '#include "ks.h"',
             "int ks_call(const unsigned char *args, unsigned char *ret);",
             "int main(void) {", "  int bad = 0;"]
    for trial in range(TRIALS):
        values = []
        for kind in params:
            if name in RANGES:
                values.append(rng.randrange(*RANGES[name]))
            else:
                values.append(draw(kind, rng))
        lines.append("  {")
        lines.append("    unsigned char a[128] = {0}, r[16] = {0}; size_t off = 0;")
        args = []
        for i, (kind, value) in enumerate(zip(params, values)):
            ctype = C_TYPE.get(kind, kind)
            lines.append(f"    {ctype} v{i} = {literal(kind, value)};")
            args.append(f"v{i}")
            if bits == 64:
                lines.append(f"    memcpy(a + {8 * i}, &v{i}, sizeof v{i});")
            else:
                lines.append(f"    memcpy(a + off, &v{i}, sizeof v{i}); off += (sizeof v{i} + 3) & ~3u;")
        rtype = C_TYPE.get(returns, returns)
        lines.append(f"    {rtype} want = {name}({', '.join(args)});")
        lines.append("    int size = ks_call(a, r);")
        shown = " ".join(f"{v!r}" for v in values)
        if returns in ("double", "float"):
            lines.append("    double got = size == 4 ? (double)*(float *)r : size == 8 ? *(double *)r : NAN;")
            lines.append("    int same = size != 0 && (got == want || fabs(got - want) <= 1e-6 * fabs((double)want));")
            fmt, show_want = "%.17g", "(double)want"
        else:
            lines.append("    unsigned long long w = 0, g = 0; memcpy(&w, &want, sizeof want);")
            lines.append("    size_t n = sizeof want < (size_t)size ? sizeof want : (size_t)size; memcpy(&g, r, n);")
            lines.append("    if (n < sizeof want) memcpy(&w, &want, n), w &= n ? (~0ULL >> (64 - 8 * n)) : 0;")
            lines.append("    int same = size != 0 && w == g;")
            fmt, show_want = "%llx", "w"
        got = "got" if returns in ("double", "float") else "g"
        lines.append(f'    if (!same && bad++ < 3) printf("args {shown}: source {fmt}, decompiled {fmt} (%d bytes)\\n", {show_want}, {got}, size);')
        lines.append("  }")
    lines.append(f'  printf("%d/{TRIALS} differ\\n", bad);')
    lines.append("  return 0;\n}")
    return "\n".join(lines) + "\n"


def wrapper(unit, entry, bits):
    """Appends ks_call to the unit: unpacks the ABI slots into the decompiled prototype."""
    name = f"FUN_{entry:08x}"
    # The printer wraps long prototypes, so the parameter list may span lines.
    match = re.search(r"^([^\n;{}]*?)\b" + name + r"\(([^;{}]*?)\);", unit, re.M)
    if not match:
        return None, "no prototype in unit"
    returns = re.sub(r"\b__\w+\b", "", match.group(1)).strip()
    params = [] if match.group(2).strip() in ("", "void") else [" ".join(p.split()) for p in match.group(2).split(",")]
    if "..." in params:
        return None, "variadic decompiled prototype"
    body = ["int ks_call(const unsigned char *args, unsigned char *ret) {", "  unsigned off = 0; (void)off;"]
    names = []
    for i, param in enumerate(params):
        ptype = re.sub(r"\s*\b\w+$", "", param) if re.search(r"[\w*]\s+\**\w+$", param) else param
        body.append(f"  {ptype} p{i}; memset(&p{i}, 0, sizeof p{i});")
        if bits == 64:
            body.append(f"  memcpy(&p{i}, args + {8 * i}, sizeof p{i} < 8 ? sizeof p{i} : 8);")
        else:
            body.append(f"  memcpy(&p{i}, args + off, sizeof p{i}); off += (sizeof p{i} + 3) & ~3u;")
        names.append(f"p{i}")
    call = f"{name}({', '.join(names)})"
    if returns == "void":
        body += [f"  {call};", "  (void)ret; return 0;", "}"]
    else:
        # float10 is long double; the host's long double may be wider than a double.
        body += [f"  {returns} v = {call};",
                 "  if (sizeof v > 8) { double d = (double)v; memcpy(ret, &d, 8); return 8; }",
                 "  memcpy(ret, &v, sizeof v); return sizeof v;", "}"]
    return unit + "\n#include <string.h>\n" + "\n".join(body) + "\n", None


LIBGCC = {  # x86-32 helpers the unit calls by address, as the unit calls them
    "__divdi3": "long long {n}(unsigned a0, unsigned a1, unsigned b0, unsigned b1) { long long a = (long long)(((unsigned long long)a1 << 32) | a0), b = (long long)(((unsigned long long)b1 << 32) | b0); return a / b; }",
    "__moddi3": "long long {n}(unsigned a0, unsigned a1, unsigned b0, unsigned b1) { long long a = (long long)(((unsigned long long)a1 << 32) | a0), b = (long long)(((unsigned long long)b1 << 32) | b0); return a % b; }",
    "__udivdi3": "unsigned long long {n}(unsigned a0, unsigned a1, unsigned b0, unsigned b1) { return (((unsigned long long)a1 << 32) | a0) / (((unsigned long long)b1 << 32) | b0); }",
    "__umoddi3": "unsigned long long {n}(unsigned a0, unsigned a1, unsigned b0, unsigned b1) { return (((unsigned long long)a1 << 32) | a0) % (((unsigned long long)b1 << 32) | b0); }",
}


def image_reader(path):
    """bytes(va, n) for a PE image file: the unit gets no data bytes, the harness supplies them."""
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count, optional = struct.unpack_from("<HxxxxxxxxxxxxH", data, pe + 6)
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    base = struct.unpack_from("<Q", data, pe + 48)[0] if magic == 0x20B else struct.unpack_from("<I", data, pe + 52)[0]
    sections = []
    for i in range(count):
        at = pe + 24 + optional + 40 * i
        vsize, rva, rawsize, raw = struct.unpack_from("<IIII", data, at + 8)
        sections.append((base + rva, max(vsize, rawsize), raw, rawsize))

    def read(va, n):
        for start, size, raw, rawsize in sections:
            if start <= va < start + size:
                n = min(n, start + size - va)
                offset = va - start
                return bytes(data[raw + offset: raw + min(offset + n, rawsize)]).ljust(n, b"\0")
        return None
    return read


def shims(unit, truth, read):
    """Definitions for the unit's GUESS externs: runtime helpers we can name, and data
    symbols with their bytes from the image."""
    out, missing = [], []
    for match in re.finditer(r"^extern ([^;]*?)\b((?:DAT|s|u)_([0-9a-f]{6,}))\b", unit, re.M):
        raw = read(int(match.group(3), 16), 256)
        if raw is None:
            missing.append(match.group(2))
            continue
        if match.group(1).strip() == "float10":
            # The host has no 80-bit long double: give it the x87 value as a double.
            raw = struct.pack("<d", x87(raw[:10]))
        out.append(f"unsigned char {match.group(2)}[{len(raw)}] __attribute__((aligned(16))) = {{{', '.join(str(b) for b in raw)}}};")
    for match in re.finditer(r"^extern .*\b(FUN_([0-9a-f]+))\(\);", unit, re.M):
        symbol = truth["symbols"].get(f"0x{int(match.group(2), 16):x}", "")
        key = "__" + symbol.lstrip("_")
        if key in LIBGCC:
            out.append(LIBGCC[key].replace("{n}", match.group(1)))
        else:
            missing.append(symbol or match.group(1))
    return "\n".join(out) + "\n", missing


def x87(raw):
    """An x87 80-bit extended value as a Python float."""
    mantissa = int.from_bytes(raw[:8], "little")
    top = int.from_bytes(raw[8:10], "little")
    sign, exponent = -1.0 if top >> 15 else 1.0, top & 0x7FFF
    if exponent == 0x7FFF:
        return sign * float("inf") if mantissa << 1 == 0 else float("nan")
    return sign * mantissa * 2.0 ** (exponent - 16383 - 63)


def one(job):
    out_dir, cli, build, truth, function, seed = job
    work = os.path.join(out_dir, build, "difftest", function["name"])
    os.makedirs(work, exist_ok=True)
    bits = truth["bits"]
    result = {"build": build, "function": function["name"]}
    unit = subprocess.run([cli, os.path.join(out_dir, build, "ks.exe"), "--decompile-function",
                           hex(function["entry"]), "--unit"], capture_output=True, text=True)
    if unit.returncode != 0:
        return {**result, "status": "decompile-error", "detail": unit.stderr.strip()[-300:]}
    full, error = wrapper(unit.stdout, function["entry"], bits)
    if error:
        return {**result, "status": "skipped", "detail": error}
    shim, missing = shims(unit.stdout, truth, image_reader(os.path.join(out_dir, build, "ks.exe")))
    if missing:
        return {**result, "status": "skipped", "detail": "callee without a shim: " + ", ".join(missing)}
    open(os.path.join(work, "unit.c"), "w").write(full)
    open(os.path.join(work, "shim.c"), "w").write(shim)
    open(os.path.join(work, "harness.c"), "w").write(harness(function, bits, random.Random(seed)))
    exe = os.path.join(work, "run")
    build_cmd = CC + ["-fms-extensions", "-I", os.path.join(HERE, "src"), os.path.join(work, "unit.c"),
                      os.path.join(work, "shim.c"), os.path.join(work, "harness.c"),
                      os.path.join(HERE, "src", "arith.c"), "-o", exe]
    compiled = subprocess.run(build_cmd, capture_output=True, text=True)
    if compiled.returncode != 0:
        first = next((l for l in compiled.stderr.splitlines() if "error" in l), compiled.stderr[:300])
        return {**result, "status": "compile-error", "detail": first.strip()}
    try:
        ran = subprocess.run([exe], capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return {**result, "status": "hang", "detail": "did not finish in 20 s (the source takes milliseconds)"}
    if ran.returncode != 0:
        return {**result, "status": "crash", "detail": f"exit {ran.returncode}"}
    tail = ran.stdout.strip().splitlines()
    differ = int(tail[-1].split("/")[0])
    guesses = sorted(set(re.findall(r"/\* GUESS: ([^*]*?)\s*\*/", unit.stdout)))
    return {**result, "status": "differs" if differ else "same", "differ": differ,
            "examples": tail[:-1], "guesses": guesses}


def main():
    out_dir, cli = sys.argv[1], sys.argv[2]
    builds = sys.argv[3:] or sorted(d for d in os.listdir(out_dir) if os.path.isfile(os.path.join(out_dir, d, "truth.json")))
    jobs = []
    for build in builds:
        truth = json.load(open(os.path.join(out_dir, build, "truth.json")))
        for i, function in enumerate(f for f in truth["functions"] if f["file"] == "arith.c"):
            jobs.append((out_dir, cli, build, truth, function, 20261023 + i))
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(one, jobs))
    json.dump(results, open(os.path.join(out_dir, "difftest.json"), "w"), indent=1)
    by_build = {}
    for r in results:
        by_build.setdefault(r["build"], {}).setdefault(r["status"], 0)
        by_build[r["build"]][r["status"]] += 1
    for build, counts in by_build.items():
        print(f"{build:18} {counts}")
    for r in results:
        if r["status"] != "same":
            print(f"  {r['build']:18} {r['function']:16} {r['status']:15} {r.get('detail', '')}{r.get('differ', '')}"
                  + (f"  [unit guesses: {'; '.join(r['guesses'])}]" if r.get("guesses") else ""))
            for example in r.get("examples", []):
                print(f"      {example}")


if __name__ == "__main__":
    main()
