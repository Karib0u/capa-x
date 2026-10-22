#!/usr/bin/env python3
"""Development-only: build the C header that decompiler text is compiled against (Step 12).

Two parts:
  * a fixed prelude for Ghidra's pseudo-types (`undefined4`, `xunknown8`, `int4`, `code`, ...) and
    pseudo-operations (`CONCAT44`, `SUB84`, `ZEXT48`, `SEXT48`, `CARRY4`, `SCARRY4`, `SBORROW4`,
    `POPCOUNT`, `LZCOUNT`). These are decompiler built-ins, not part of any archive, so they are
    written here. They define what each operation means for a C compiler; they do not model flags.
  * Win32 and C library types and callee prototypes, read from the prototype pack
    (`capa-x-ghidra/data/winapi{64,32}.pack`), never typed by hand. A type is emitted only when a
    function names it, together with what it needs by value. Pointer targets get a forward
    declaration, and a body only when the compiler reports an incomplete type.

Enumerations become integer typedefs: their constants are global in C and collide across archives,
and decompiler text writes numbers, not constants.
"""
import re
import struct
import sys
import zlib
import xml.etree.ElementTree as ET

KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum",
    "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return",
    "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned",
    "void", "volatile", "while", "_Bool", "_Complex", "_Imaginary",
}

UTYPE = {1: "unsigned char", 2: "unsigned short", 4: "unsigned int", 8: "unsigned long long"}
ITYPE = {1: "signed char", 2: "short", 4: "int", 8: "long long"}


_PRELUDE = {}


def prelude(is64):
    if is64 not in _PRELUDE:
        _PRELUDE[is64] = _prelude(is64)
    return _PRELUDE[is64]


def _prelude(is64):
    """Pseudo-types and pseudo-operations. 16-byte forms need __int128, which only the x64 target has."""
    top = 16 if is64 else 8
    ut, it = dict(UTYPE), dict(ITYPE)
    if is64:
        ut[16], it[16] = "unsigned __int128", "__int128"
    out = ["typedef _Bool bool;", "typedef long long code();"]
    for n in (1, 2, 4, 8):
        out.append(f"typedef {ut[n]} undefined{n}, xunknown{n}, uint{n};")
        out.append(f"typedef {it[n]} int{n};")
    out.append("typedef unsigned short wchar2; typedef unsigned int wchar4;")
    out.append("typedef unsigned char undefined, byte; typedef unsigned char uchar; typedef unsigned short ushort;")
    out.append("typedef unsigned int uint; typedef unsigned int ulong; typedef long long longlong;")
    out.append("typedef unsigned long long ulonglong; typedef long double float10;")
    if is64:
        out.append(f"typedef {ut[16]} undefined16, xunknown16, uint16; typedef {it[16]} int16;")
    for n in (3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15):      # odd widths: carried in the next integer size up
        big = 4 if n < 4 else 8 if n < 8 else 16
        if big > top:
            big = 8
        for pre in ("unkbyte", "unkuint"):
            out.append(f"typedef {ut[big]} {pre}{n};")
        out.append(f"typedef {it[big]} unkint{n};")
    out.append("typedef float unkfloat4, float4; typedef double unkfloat8, float8; typedef signed char sbyte;")

    def U(n):
        return ut[next(k for k in sorted(ut) if k >= n)]

    def I(n):
        return it[next(k for k in sorted(it) if k >= n)]

    for n in range(1, top):
        for m in range(1, top - n + 1):
            out.append(f"#define CONCAT{n}{m}(a,b) (({U(n + m)})(({U(n + m)})({U(n)})(a) << {8 * m}) | ({U(n + m)})({U(m)})(b))")
    for n in range(1, top + 1):
        for m in range(1, top + 1):
            if m <= n:
                out.append(f"#define SUB{n}{m}(a,off) (({U(m)})((({U(n)})(a)) >> (8*(off))))")
            else:
                out.append(f"#define ZEXT{n}{m}(a) (({U(m)})({U(n)})(a))")
                out.append(f"#define SEXT{n}{m}(a) (({I(m)})({I(n)})(a))")
    for n in range(1, top + 1):
        out.append(f"static inline int CARRY{n}({U(n)} a,{U(n)} b){{ return (({U(n)})(a+b)) < a; }}")
        out.append(f"static inline int SCARRY{n}({I(n)} a,{I(n)} b){{ {I(n)} r; return __builtin_add_overflow(a,b,&r); }}")
        out.append(f"static inline int SBORROW{n}({I(n)} a,{I(n)} b){{ {I(n)} r; return __builtin_sub_overflow(a,b,&r); }}")
    out.append("#define POPCOUNT(x) ((int)__builtin_popcountll((unsigned long long)(x)))")
    out.append("#define LZCOUNT(x) ((int)__builtin_clzll((unsigned long long)(x) | 1))")
    return "\n".join(out) + "\n"


class Pack:
    def __init__(self, path):
        b = open(path, "rb").read()
        if b[:8] != b"CXPROTO1":
            raise SystemExit(f"{path}: not a CXPROTO1 pack")
        n = struct.unpack("<I", b[8:12])[0]
        p, idx = 12, []
        for _ in range(n):
            off, clen, rlen, klen = struct.unpack("<IIIH", b[p:p + 14])
            p += 14 + klen
            idx.append((off, clen))
        self.funcs, self.types, self.by_name = {}, {}, {}
        for off, clen in idx:
            for line in zlib.decompress(b[p + off:p + off + clen]).decode().split("\n"):
                if line.startswith("F:"):
                    k, v = line.split("\t", 1)
                    self.funcs[k[2:]] = v
                elif line.startswith("T:"):
                    k, name, xml = line.split("\t", 2)
                    self.types[k[2:]] = (name, xml)
                    self.by_name.setdefault(name, k[2:])
        self._parsed = {}

    def node(self, tid):
        if tid not in self._parsed:
            self._parsed[tid] = ET.fromstring(self.types[tid][1])
        return self._parsed[tid]

    def callee(self, name):
        """Prototype key for an identifier, allowing a lowercase `<module>_` prefix."""
        if name in self.funcs:
            return name
        for m in re.finditer("_", name):
            head, tail = name[:m.start()], name[m.end():]
            if head and re.fullmatch(r"[a-z0-9_\-]+", head) and tail in self.funcs:
                return tail
        return None


class Emitter:
    """Declarations for one translation unit, in dependency order."""

    def __init__(self, pack, is64):
        self.pack, self.is64 = pack, is64
        self.forward, self.body, self.done, self.busy = [], [], set(), set()
        self.full = set()       # type ids that need a body, not only a forward declaration
        self.protos = []
        self.unresolved = set()

    # --- names -------------------------------------------------------------------------
    @staticmethod
    def cname(name):
        n = re.sub(r"\W", "_", name) or "anon"
        return n + "_" if n in KEYWORDS else n

    # --- type rendering ------------------------------------------------------------------
    def builtin(self, node):
        mt, size = node.get("metatype"), int(node.get("size", "0") or 0)
        if mt == "int":
            if node.get("utf") == "true" or node.get("name") == "wchar_t":
                return "unsigned short"
            return ITYPE.get(size, "int") if node.get("char") != "true" else "char"
        if mt == "uint":
            return UTYPE.get(size, "unsigned int")
        if mt == "float":
            return {4: "float", 8: "double", 10: "long double", 16: "long double"}.get(size, "double")
        if mt == "bool":
            return "_Bool"
        if mt == "unknown":
            return UTYPE.get(size, "unsigned char")
        return None

    def render(self, node, inner="", by_value=True):
        """C declarator text for a type node wrapped around `inner`."""
        tag = node.tag
        if tag == "void":
            return ("void " + inner).rstrip()
        if tag == "typeref":
            tid = node.get("id")
            if tid in self.pack.types:
                nm = self.use(tid, by_value)
                return (nm + " " + inner).rstrip()
            self.unresolved.add(node.get("name", "?"))
            return ("unsigned int " + inner).rstrip()
        mt = node.get("metatype")
        if mt == "ptr":
            kids = list(node)
            child = kids[0] if kids else ET.Element("void")
            wrap = "*" + inner
            if child.get("metatype") in ("array", "code"):
                wrap = "(" + wrap + ")"
            return self.render(child, wrap, by_value=False)
        if mt == "array":
            kids = list(node)
            child = kids[0] if kids else ET.Element("void")
            return self.render(child, f"{inner}[{node.get('arraysize', '')}]", by_value)
        if mt == "code":
            proto = node.find("prototype")
            return self.render_proto(proto, inner) if proto is not None else ("void " + inner + "()")
        if mt in ("struct", "union", "enum_uint", "enum_int"):
            tid = node.get("id")
            if tid in self.pack.types:
                return (self.use(tid, by_value) + " " + inner).rstrip()
            return ("unsigned int " + inner).rstrip()
        b = self.builtin(node)
        if b is not None:
            return (b + " " + inner).rstrip()
        return ("unsigned int " + inner).rstrip()

    def render_proto(self, proto, name):
        ret = proto.find("returnsym")
        rnode = list(ret)[1] if ret is not None and len(list(ret)) > 1 else ET.Element("void")
        params = []
        lst = proto.find("internallist")
        for i, p in enumerate(list(lst) if lst is not None else []):
            kids = [k for k in p if k.tag != "addr"]
            if kids:
                params.append(self.render(kids[0], "", by_value=False))
        if proto.get("dotdotdot") == "true":
            params.append("...")
        plist = ", ".join(params) if params else "void"
        if proto.get("dotdotdot") == "true" and not params[:-1]:
            plist = ""         # C before C23 has no variadic function without a named parameter
        return self.render(rnode, f"{name}({plist})", by_value=False)

    # --- named types ---------------------------------------------------------------------
    def use(self, tid, by_value):
        """Make type `tid` available and return the name to write for it."""
        name, _ = self.pack.types[tid]
        node = self.pack.node(tid)
        mt = node.get("metatype")
        if node.tag == "type" and mt in ("struct", "union"):
            cn = self.cname(name)
            if tid not in self.done:
                self.done.add(tid)
                self.forward.append(f"typedef {mt} {cn} {cn};")
            if (by_value or tid in self.full) and tid not in self.busy:
                self.ensure_body(tid)
            return cn
        if node.tag == "type" and mt in ("enum_uint", "enum_int"):
            cn = self.cname(name)
            if tid not in self.done:
                self.done.add(tid)
                self.body.append(f"typedef {'unsigned int' if mt == 'enum_uint' else 'int'} {cn};")
            return cn
        if node.tag == "def":
            cn = self.cname(name)
            if tid in self.done:
                return cn
            if tid in self.busy:
                return "void"
            self.busy.add(tid)
            kids = list(node)
            text = self.render(kids[0], cn, by_value) if kids else f"unsigned int {cn}"
            self.busy.discard(tid)
            self.done.add(tid)
            self.body.append(f"typedef {text};")
            return cn
        b = self.builtin(node)
        if b:
            return b
        self.unresolved.add(name)
        return "unsigned int"

    def ensure_body(self, tid):
        key = ("body", tid)
        if key in self.done:
            return
        self.done.add(key)
        self.busy.add(tid)
        name, _ = self.pack.types[tid]
        node = self.pack.node(tid)
        cn = self.cname(name)
        fields = []
        for i, f in enumerate(node.findall("field")):
            kids = list(f)
            if not kids:
                continue
            fname = self.cname(f.get("name") or f"_f{i}")
            tnode = kids[0]
            bit = None
            if tnode.tag == "type" and tnode.get("metatype") == "unknown" and re.fullmatch(r"\w+:\d+", tnode.get("name", "")):
                base, width = tnode.get("name").split(":")
                bit = (width, base)
            if bit:
                fields.append(f"unsigned int {fname} : {bit[0]};")
            else:
                fields.append(self.render(tnode, fname, by_value=True) + ";")
        self.busy.discard(tid)
        self.body.append(f"{node.get('metatype')} {cn} {{ {' '.join(fields)} }};")

    def want(self, name, full=False):
        """Type named by an 'unknown type name' error. Returns False when the pack has no such type."""
        tid = self.pack.by_name.get(name)
        if tid is None:
            return False
        if full:
            self.full.add(tid)
        self.use(tid, by_value=full or True)
        return True

    def prototype(self, ident):
        key = self.pack.callee(ident)
        if key is None:
            return False
        proto = ET.fromstring(self.pack.funcs[key])
        cc = proto.get("model", "")
        decl = self.render_proto(proto, self.cname(ident))
        if proto.get("noreturn") == "true":
            decl = "__declspec(noreturn) " + decl
        self.protos.append(f"extern {decl};")
        return True

    def text(self):
        return "\n".join(self.forward + self.body + self.protos) + "\n"
