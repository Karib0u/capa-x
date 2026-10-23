"""Compares native decompiler output with the source truth (development only).

python3 -I compare.py OUT_DIR TARGET_DIR   (TARGET_DIR holds the release examples)

For every build under OUT_DIR with a truth.json: runs function_set and
decompiler_corpus on the stripped ks.exe, then checks each source function.
When the build has a ghidra.json (run_ghidra_addresses.sh on the stripped ks.exe),
full Ghidra gets the same checks, and each mismatch says who has it: N (native
only), B (both) or G (Ghidra only).
Writes OUT_DIR/report.json and prints a summary and every mismatch.
"""
import json
import os
import re
import subprocess
import sys

TRUTH_SIZE = {
    "char": 1, "signed char": 1, "unsigned char": 1, "_Bool": 1,
    "short": 2, "short int": 2, "unsigned short": 2, "short unsigned int": 2,
    "long long int": 8, "long long unsigned int": 8,
    "int": 4, "unsigned int": 4, "uint32_t": 4, "int32_t": 4,
    "int64_t": 8, "uint64_t": 8, "long long": 8,
    "float": 4, "double": 8,
    "ks_point": 8, "ks_big": 32,
}
NATIVE_SIZE = {
    1: "bool char uchar byte undefined1 xunknown1 int1 uint1 undefined BYTE CHAR BOOLEAN",
    2: "short ushort int2 uint2 xunknown2 undefined2 wchar2 wchar_t WORD",
    4: "int uint int4 uint4 xunknown4 undefined4 ulong long float float4 DWORD BOOL UINT LONG",
    8: "longlong ulonglong int8 uint8 xunknown8 undefined8 double float8",
    10: "float10",
}
NATIVE_SIZE = {name: size for size, names in NATIVE_SIZE.items() for name in names.split()}
KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof", "do"}


def truth_type(name, ptr):
    """(size, class) of a source type; class is int, fp, ptr or struct."""
    base = re.sub(r"\b(const|volatile|struct)\b", "", name or "").strip()
    if "*" in base or base in ("ks_binop", "va_list", "__gnuc_va_list", "__builtin_va_list"):
        return ptr, "ptr"
    if base not in TRUTH_SIZE:
        raise SystemExit(f"unknown source type {name!r}: add it to TRUTH_SIZE")
    if base.startswith("ks_"):
        return TRUTH_SIZE[base], "struct"
    return TRUTH_SIZE[base], "fp" if base in ("float", "double") else "int"


def native_type(name, ptr):
    base = re.sub(r"\b(const|volatile|struct|enum|union)\b", "", name).strip()
    if "*" in base or re.fullmatch(r"(LP|P|H)[A-Z]\w*", base):
        return ptr, "ptr"  # pointer and handle typedefs of the Windows archive
    size = NATIVE_SIZE.get(base)
    return size, "fp" if base in ("float", "double", "float4", "float8", "float10") else "int"


def signature(text):
    """(return type, convention, name, [param types], noreturn) from the text."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "{":
            header = " ".join(l.strip() for l in lines[:index] if l.strip() and not l.strip().startswith("/*"))
            break
    else:
        return None
    match = re.match(r"^(.*?)\s*\b(\w+)\((.*)\)$", header)
    if not match:
        return None
    head, name, params = match.groups()
    convention = None
    words = head.split()
    if words and words[-1].startswith("__"):
        convention = words.pop()
    returns = " ".join(words)
    params = [] if params.strip() in ("", "void") else [p.strip() for p in params.split(",")]
    types = []
    for p in params:
        if p == "...":
            types.append("...")
            continue
        types.append(re.sub(r"\s*\b\w+$", "", p) if re.search(r"\w\s*$", p) and " " in p or "*" in p else p)
    # The text marks a call that does not return, not the function: a function never
    # returns when its body has no return statement and ends in such a call.
    body = "\n".join(lines[index:])
    return returns, convention, name, types, "does not return" in body and not re.search(r"\breturn\b", re.sub(r"/\*.*?\*/", "", body, flags=re.S))


def called_names(text, own):
    names = []
    body = text[text.find("{"):] if "{" in text else text
    for match in re.finditer(r"\b([A-Za-z_][\w@]*)\s*\(", body):
        name = match.group(1)
        if name in KEYWORDS or name.startswith("builtin_") or (re.fullmatch(r"[A-Z0-9_]+", name) and not name.startswith("FUN_")):
            continue
        names.append(name)
    return names


def resolve(name, symbols, wanted):
    """A native callee name as a source name: FUN_ addresses through the symbols,
    and a `<module>_` prefix (`kernel32_`, `api_ms_win_crt_string_l1_1_0_`) dropped."""
    match = re.fullmatch(r"(?:thunk_)?FUN_([0-9a-f]+)", name)
    if match:
        return symbols.get(f"0x{int(match.group(1), 16):x}", f"?{name}")
    for want in wanted:
        prefix = name[: -len(want) - 1]
        if name.endswith("_" + want) and re.fullmatch(r"[a-z][a-z0-9_]*", prefix):
            return want
    return name


def check(build, truth, native, found):
    ptr = truth["bits"] // 8
    symbols = truth["symbols"]
    rows = []
    for f in truth["functions"]:
        row = {"build": build, "function": f["name"], "entry": f"0x{f['entry']:x}", "issues": []}
        rows.append(row)
        issues = row["issues"]
        if f["entry"] not in found:
            issues.append(("discovery", "not in native's function set"))
        result = native.get(f["entry"])
        if result is None or "error" in result:
            issues.append(("error", (result or {}).get("error", "no result")))
            continue
        out = result["output"]
        row["incomplete"] = out["incomplete"]
        row["unknown_callees"] = out["unknown_callees"]
        row["warnings"] = out["warnings"]
        sig = signature(out["text"])
        if sig is None:
            issues.append(("parse", "no signature in text"))
            continue
        returns, convention, own, params, noreturn = sig
        row["native"] = f"{returns} {convention or ''} {own}({', '.join(params)})".replace("  ", " ")
        row["source"] = f"{f['returns']} {f['name']}({', '.join(p['type'] for p in f['params'])}{', ...' if f['variadic'] else ''})"
        # Return value. A struct that does not fit a register pair comes back
        # through a hidden pointer, which the binary returns as a pointer.
        src_params = [truth_type(p["type"], ptr) for p in f["params"]]
        sret = False
        if f["returns"] == "void":
            want = None
        else:
            want = truth_type(f["returns"], ptr)
            if want[1] == "struct" and want[0] > 8:
                sret, want = True, (ptr, "ptr")
            elif want[1] == "struct":
                want = (want[0], "int")
        got_void = returns == "void"
        if f["noreturn"] != noreturn:
            issues.append(("noreturn", f"source noreturn={f['noreturn']}, native says {noreturn}"))
        if want is None and not got_void and not f["noreturn"]:
            issues.append(("return", f"source returns void, native {returns}"))
        elif want is not None and got_void:
            issues.append(("return", f"source returns {f['returns']}, native void"))
        elif want is not None:
            size, kind = native_type(returns, ptr)
            if kind == "fp" and want[1] != "fp" or want[1] == "fp" and kind != "fp":
                issues.append(("return-class", f"source {f['returns']}, native {returns}"))
            elif want[1] != "fp" and size is not None and size != want[0] and not (want[1] == "ptr" and kind == "ptr"):
                issues.append(("return-size", f"source {f['returns']} ({want[0]}), native {returns} ({size})"))
        # Parameters: x64 passes one slot per parameter; x86-32 passes 4-byte stack slots.
        fixed = [p for p in params if p != "..."]
        native_params = [native_type(p, ptr) for p in fixed]
        if sret:
            src_params = [(ptr, "ptr")] + src_params
        if f["name"] == "main":
            pass  # main's parameters come from the CRT; checked through its calls
        elif ptr == 8:
            if len(fixed) < len(src_params) or (len(fixed) > len(src_params) and not f["variadic"]):
                issues.append(("params", f"source {len(src_params)} slots, native {len(fixed)}"))
            else:
                for i, ((ws, wk), (gs, gk)) in enumerate(zip(src_params, native_params)):
                    if (wk == "fp") != (gk == "fp"):
                        issues.append(("param-class", f"param {i + 1}: source {wk}, native {fixed[i]}"))
        else:
            def slots(size):
                return (size + 3) // 4
            want_bytes = 4 * sum(slots(s) for s, _ in src_params)
            got = [s for s, _ in native_params]
            if None in got:
                issues.append(("param-type", f"unknown native type in {fixed}"))
            else:
                got_bytes = 4 * sum(slots(s) for s in got)
                if got_bytes < want_bytes or (got_bytes > want_bytes and not f["variadic"]):
                    issues.append(("params", f"source {want_bytes} argument bytes, native {got_bytes}"))
            src_fp = [k == "fp" for _, k in src_params]
            got_fp = [k == "fp" for _, k in native_params]
            if any(src_fp) != any(got_fp):
                issues.append(("param-class", f"source fp params {src_fp}, native {got_fp}"))
        # Calling convention on x86-32.
        if ptr == 4 and f["linkage"]:
            want_conv = "__fastcall" if f["linkage"].startswith("@") else "__stdcall"
            if convention != want_conv:
                issues.append(("convention", f"source {want_conv}, native {convention or 'default'}"))
        # Callees.
        # A stack probe is replaced by its modeled effect, as in Ghidra.
        probes = {"chkstk", "chkstk_ms", "alloca"}
        want_names = {n.lstrip("_") for n in f["callees"]} - probes
        got_names = {resolve(name, symbols, want_names).lstrip("_") for name in called_names(out["text"], own)} - probes
        missing = sorted(want_names - got_names)
        extra = sorted(n for n in got_names - want_names if not n.startswith("?"))
        unresolved = sorted(n for n in got_names if n.startswith("?"))
        if missing:
            issues.append(("callee-missing", ", ".join(missing)))
        if extra:
            issues.append(("callee-extra", ", ".join(extra)))
        if unresolved:
            issues.append(("callee-target", "call to a non-function address: " + ", ".join(unresolved)))
        row["text"] = out["text"]
    return rows


def main():
    out_dir, examples = sys.argv[1], sys.argv[2]
    rows, summary = [], {}
    for build in sorted(os.listdir(out_dir)):
        path = os.path.join(out_dir, build)
        if not os.path.isfile(os.path.join(path, "truth.json")):
            continue
        truth = json.load(open(os.path.join(path, "truth.json")))
        exe = os.path.join(path, "ks.exe")
        found = {f["entry"] for f in json.loads(
            subprocess.run([f"{examples}/function_set", exe], check=True, capture_output=True).stdout
        )["functions"]}
        addresses = os.path.join(path, "addresses.json")
        json.dump([f["entry"] for f in truth["functions"]], open(addresses, "w"))
        native = {}
        lines = subprocess.run([f"{examples}/decompiler_corpus", exe, addresses],
                               check=True, capture_output=True, text=True).stdout
        for line in lines.splitlines():
            event = json.loads(line)
            if event["event"] == "result":
                native[event["address"]] = event
            elif event["event"] == "initialization_error":
                raise SystemExit(f"{build}: {event['error']}")
        build_rows = check(build, truth, native, found)
        ghidra_path = os.path.join(path, "ghidra.json")
        if os.path.isfile(ghidra_path):
            ghidra, ghidra_found = {}, set()
            for g in json.load(open(ghidra_path))["functions"]:
                entry = int(g["address"], 16)
                if g["name"] is not None:
                    ghidra_found.add(entry)
                ghidra[entry] = {"output": {"text": g["c"], "incomplete": False, "unknown_callees": False,
                                            "warnings": []}} if g["ok"] else {"error": g["error"]}
            for row, g in zip(build_rows, check(build, truth, ghidra, ghidra_found)):
                row["ghidra_issues"] = g["issues"]
                row["ghidra_native"] = g.get("native")
                row["ghidra_text"] = g.get("text")
        rows += build_rows
        text_symbols = {int(a, 16) for a, n in truth["symbols"].items() if not n.startswith("__imp_") and a}
        counts = {}
        for row in build_rows:
            for kind, _ in row["issues"]:
                counts[kind] = counts.get(kind, 0) + 1
        ghidra_clean = sum(1 for r in build_rows if "ghidra_issues" in r and not r["ghidra_issues"])
        summary[build] = {
            "functions": len(build_rows),
            "clean": sum(1 for r in build_rows if not r["issues"]),
            "ghidra_clean": ghidra_clean,
            "incomplete": sum(1 for r in build_rows if r.get("incomplete")),
            "native_functions": len(found),
            "native_not_at_a_symbol": len(found - text_symbols),
            "issues": counts,
        }
    json.dump({"summary": summary, "rows": rows}, open(os.path.join(out_dir, "report.json"), "w"), indent=1)
    for build, s in summary.items():
        print(f"{build:18} clean {s['clean']:2}/{s['functions']} (Ghidra {s['ghidra_clean']:2})  incomplete {s['incomplete']:2}  "
              f"found {s['native_functions']} (not at a symbol {s['native_not_at_a_symbol']})  {s['issues']}")
    for row in rows:
        ghidra_kinds = {kind for kind, _ in row.get("ghidra_issues", [])}
        native_kinds = {kind for kind, _ in row["issues"]}
        for kind, detail in row["issues"]:
            who = "B" if kind in ghidra_kinds else "N"
            print(f"  {who} {row['build']:18} {row['function']:16} {kind:15} {detail}")
        for kind, detail in row.get("ghidra_issues", []):
            if kind not in native_kinds:
                print(f"  G {row['build']:18} {row['function']:16} {kind:15} {detail}")


if __name__ == "__main__":
    main()
