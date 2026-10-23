"""Ground truth for one known-source build, from its debug copy (development only).

python3 -I truth.py out/<build>/ks.debug.exe out/<build>/truth.json

Functions: every DWARF subprogram with code that comes from src/, with its
prototype. Symbols: every COFF text and import symbol (address to name).
Callees: the direct and import calls in each function's range, from llvm-objdump.
"""
import json
import os
import re
import subprocess
import sys

LLVM = os.environ.get("LLVM", "/opt/homebrew/opt/llvm/bin")
SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
DIE = re.compile(r"^0x[0-9a-f]+:( +)(DW_TAG_\w+|NULL)")
ATTR = re.compile(r"^\s+(DW_AT_\w+)\s+\((.*)\)$")


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def dies(path):
    """Yields (depth, tag, attributes) for every DIE of the debug info."""
    current = None
    for line in run(f"{LLVM}/llvm-dwarfdump", "--debug-info", path).splitlines():
        match = DIE.match(line)
        if match:
            if current:
                yield current
            current = (len(match.group(1)), match.group(2), {})
            continue
        match = ATTR.match(line)
        if match and current:
            current[2][match.group(1)] = match.group(2)
    if current:
        yield current


def quoted(value):
    match = re.search(r'"(.*)"', value or "")
    return match.group(1) if match else None


def functions(path):
    result, open_function = [], None
    for depth, tag, attrs in dies(path):
        if open_function and depth <= open_function[0]:
            open_function = None
        if tag == "DW_TAG_subprogram":
            source = quoted(attrs.get("DW_AT_decl_file")) or ""
            if "DW_AT_low_pc" not in attrs or not source.startswith(SRC):
                continue
            if "DW_AT_name" not in attrs:
                raise SystemExit(f"subprogram without a name (an out-of-line clone?) in {path}")
            entry = {
                "name": quoted(attrs["DW_AT_name"]),
                "linkage": quoted(attrs.get("DW_AT_linkage_name")),
                "entry": int(attrs["DW_AT_low_pc"], 16),
                "end": int(attrs["DW_AT_high_pc"], 16),
                "file": os.path.basename(source),
                "returns": quoted(attrs.get("DW_AT_type")) or "void",
                "noreturn": "DW_AT_noreturn" in attrs,
                "params": [],
                "variadic": False,
            }
            result.append(entry)
            open_function = (depth, entry)
        elif open_function and depth == open_function[0] + 2:
            if tag == "DW_TAG_formal_parameter":
                open_function[1]["params"].append(
                    {"name": quoted(attrs.get("DW_AT_name")), "type": quoted(attrs.get("DW_AT_type"))}
                )
            elif tag == "DW_TAG_unspecified_parameters":
                open_function[1]["variadic"] = True
    return sorted(result, key=lambda f: f["entry"])


def symbols(path, bits):
    """Address to name for text symbols and import address table slots."""
    table = {}
    for line in run(f"{LLVM}/llvm-nm", "--defined-only", path).splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "Tt" and not parts[2].startswith("."):
            table.setdefault(int(parts[0], 16), parts[2])
    headers = run(f"{LLVM}/llvm-readobj", "--file-headers", path)
    base = int(re.search(r"ImageBase: (0x[0-9A-Fa-f]+)", headers).group(1), 16)
    slot, iat = bits // 8, None
    for line in run(f"{LLVM}/llvm-readobj", "--coff-imports", path).splitlines():
        line = line.strip()
        if line.startswith("ImportAddressTableRVA:"):
            iat = base + int(line.split()[1], 16)
        elif line.startswith("Symbol:") and iat is not None:
            table[iat] = "__imp_" + line.split()[1]
            iat += slot
        elif line == "}":
            iat = None
    return table


CALL = re.compile(r"^\s*([0-9a-f]+):\s+(call|jmp|mov)\w*\s+(.*)$")


def callees(path, funcs, table, bits):
    """Names called (or tail-jumped to) from each function's range."""
    out = {f["name"]: set() for f in funcs}
    spans = [(f["entry"], f["end"], f["name"]) for f in funcs]
    text = run(f"{LLVM}/llvm-objdump", "-d", "--no-show-raw-insn", path)
    loaded = {}
    for line in text.splitlines():
        match = CALL.match(line)
        if not match:
            continue
        address, kind, operand = int(match.group(1), 16), match.group(2), match.group(3)
        owner = next((name for lo, hi, name in spans if lo <= address < hi), None)
        if owner is None:
            continue
        if kind == "mov":
            # `mov slot, %reg` then `call *%reg`: unoptimized import calls.
            source = operand.split(",")[0].strip()
            register = operand.split(",")[-1].split("#")[0].strip().lstrip("%")
            slot = re.search(r"#\s*0x([0-9a-f]+)", operand)
            if slot is None and re.fullmatch(r"0x[0-9a-f]+", source):
                slot = re.match(r"0x([0-9a-f]+)", source)
            loaded[register] = int(slot.group(1), 16) if slot else None
            continue
        target = None
        register = re.fullmatch(r"\*%(\w+)", operand.strip())
        if register:
            target = loaded.get(register.group(1))
        comment = re.search(r"#\s*0x([0-9a-f]+)", operand)
        memory = re.match(r"\*0x([0-9a-f]+)$", operand.strip())
        direct = re.match(r"0x([0-9a-f]+)", operand.strip())
        if target is not None:
            pass
        elif comment:
            target = int(comment.group(1), 16)
        elif memory:
            target = int(memory.group(1), 16)
        elif direct:
            target = int(direct.group(1), 16)
        if target is None:
            continue  # call through a register: an indirect call, named by nothing
        lo, hi = next((lo, hi) for lo, hi, name in spans if name == owner)
        if kind == "jmp" and lo <= target < hi:
            continue  # a branch inside the function
        if target in table:
            out[owner].add(normal(table[target], bits))
        elif kind == "call":
            out[owner].add(f"0x{target:x}")
    return {name: sorted(names) for name, names in out.items()}


def normal(symbol, bits):
    """`__imp_MessageBoxA`, `_ks_abs`, `@ks_fastcall3@12` -> plain C name."""
    if symbol.startswith("__imp_"):
        return symbol[len("__imp_"):]
    name = re.sub(r"@\d+$", "", symbol)
    if name.startswith("@"):
        return name[1:]
    if bits == 32 and name.startswith("_"):
        return name[1:]  # the x86-32 C decoration
    return name


def main():
    debug, target = sys.argv[1], sys.argv[2]
    machine = run(f"{LLVM}/llvm-readobj", "--file-headers", debug)
    bits = 64 if "AMD64" in machine else 32
    funcs = functions(debug)
    table = symbols(debug, bits)
    calls = callees(debug, funcs, table, bits)
    for f in funcs:
        f["callees"] = calls[f["name"]]
    json.dump(
        {
            "bits": bits,
            "functions": funcs,
            "symbols": {f"0x{a:x}": normal(n, bits) for a, n in sorted(table.items())},
        },
        open(target, "w"),
        indent=1,
    )


if __name__ == "__main__":
    main()
