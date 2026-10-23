//! C declarations from the packed Ghidra type archive, for the self-contained unit.
//!
//! The pack (`capa-x-ghidra/data/winapi{64,32}.pack`, format in
//! `scripts/decompiler_types/pack_prototypes.py`) holds Ghidra's marshalled XML for every function
//! prototype (`F:<name>`) and named type (`T:<id>`). This module reads it and writes C. It is the
//! shipped counterpart of the development tool `scripts/decompiler_baseline/compile_header.py`,
//! which measured the same approach (Step 12).
//!
//! Enumerations become integer typedefs: their constants are global in C and collide across
//! archives, and decompiler text writes numbers, not constants. Struct and union pointers get a
//! forward declaration, and a body only when a value of the type is needed.
//!
//! The pack is embedded data, not untrusted input, but the reader still never indexes unchecked
//! and bounds nesting, because a damaged pack must not crash a decompile request.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::rc::Rc;

use flate2::read::ZlibDecoder;

const MAX_BLOCK: u64 = 4 * 1024 * 1024;
const MAX_DEPTH: usize = 64;
const KEYWORDS: &[&str] = &[
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum",
    "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict",
    "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "_Bool", "_Complex", "_Imaginary",
];

/// Type names the prelude defines; the pack's own definition of one of these is not emitted.
pub fn is_prelude_type(name: &str) -> bool {
    const FIXED: &[&str] = &[
        "bool", "code", "byte", "uchar", "ushort", "uint", "ulong", "longlong", "ulonglong",
        "float10", "wchar2", "wchar4", "undefined", "sbyte", "float4", "float8", "unkfloat4",
        "unkfloat8",
    ];
    if FIXED.contains(&name) {
        return true;
    }
    for prefix in ["undefined", "xunknown", "uint", "int", "unkbyte", "unkuint", "unkint", "xbits"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
                return true;
            }
        }
    }
    false
}

// --- a small XML reader: the pack's marshalling uses elements and attributes only -----------

#[derive(Debug, Default)]
pub struct Node {
    pub tag: String,
    attrs: Vec<(String, String)>,
    pub children: Vec<Node>,
}
impl Node {
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
    fn child(&self, tag: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.tag == tag)
    }
}

fn unescape(text: &str) -> String {
    if !text.contains('&') {
        return text.to_owned();
    }
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

pub fn parse_xml(text: &str) -> Result<Node, String> {
    let bytes = text.as_bytes();
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Node> = None;
    let mut i = 0;
    while let Some(offset) = bytes.get(i..).and_then(|rest| rest.iter().position(|b| *b == b'<')) {
        i += offset + 1;
        match bytes.get(i) {
            Some(b'/') => {
                let end = find(bytes, i, b'>').ok_or("unterminated closing tag")?;
                i = end + 1;
                let node = stack.pop().ok_or("unbalanced closing tag")?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => root = Some(node),
                }
            }
            Some(b'?') | Some(b'!') => {
                i = find(bytes, i, b'>').ok_or("unterminated declaration")? + 1;
            }
            Some(_) => {
                let start = i;
                while bytes
                    .get(i)
                    .is_some_and(|b| !b.is_ascii_whitespace() && *b != b'/' && *b != b'>')
                {
                    i += 1;
                }
                let tag = text.get(start..i).ok_or("bad tag name")?.to_owned();
                let mut node = Node {
                    tag,
                    ..Node::default()
                };
                let mut self_closed = false;
                loop {
                    while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
                        i += 1;
                    }
                    match bytes.get(i) {
                        Some(b'>') => {
                            i += 1;
                            break;
                        }
                        Some(b'/') => {
                            self_closed = true;
                            i = find(bytes, i, b'>').ok_or("unterminated tag")? + 1;
                            break;
                        }
                        Some(_) => {
                            let key_start = i;
                            while bytes.get(i).is_some_and(|b| *b != b'=') {
                                i += 1;
                            }
                            let key = text.get(key_start..i).ok_or("bad attribute")?.trim();
                            let quote = *bytes.get(i + 1).ok_or("missing attribute value")?;
                            if quote != b'"' && quote != b'\'' {
                                return Err("unquoted attribute value".into());
                            }
                            let value_start = i + 2;
                            let value_end =
                                find(bytes, value_start, quote).ok_or("unterminated attribute")?;
                            let value = text.get(value_start..value_end).ok_or("bad attribute")?;
                            node.attrs.push((key.to_owned(), unescape(value)));
                            i = value_end + 1;
                        }
                        None => return Err("unterminated tag".into()),
                    }
                }
                if self_closed {
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(node),
                        None => root = Some(node),
                    }
                } else {
                    if stack.len() >= MAX_DEPTH {
                        return Err("markup nests too deeply".into());
                    }
                    stack.push(node);
                }
            }
            None => break,
        }
    }
    root.ok_or_else(|| "empty markup".into())
}

fn find(bytes: &[u8], from: usize, needle: u8) -> Option<usize> {
    bytes
        .get(from..)?
        .iter()
        .position(|b| *b == needle)
        .map(|p| from + p)
}

// --- the pack ---------------------------------------------------------------------------------

pub struct Pack {
    funcs: HashMap<String, String>,
    types: HashMap<String, (String, String)>,
    by_name: HashMap<String, String>,
    parsed: RefCell<HashMap<String, Rc<Node>>>,
}
impl Pack {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.get(..8) != Some(b"CXPROTO1") {
            return Err("prototype pack: bad magic".into());
        }
        let u32_at = |at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
        };
        let count = u32_at(8).ok_or("prototype pack: truncated header")? as usize;
        let mut position = 12usize;
        let mut blocks = Vec::new();
        for _ in 0..count {
            let offset = u32_at(position).ok_or("prototype pack: truncated index")? as usize;
            let clen = u32_at(position + 4).ok_or("prototype pack: truncated index")? as usize;
            let rlen = u32_at(position + 8).ok_or("prototype pack: truncated index")?;
            let klen = data
                .get(position + 12..position + 14)
                .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
                .ok_or("prototype pack: truncated index")?;
            position += 14 + klen;
            if u64::from(rlen) > MAX_BLOCK {
                return Err("prototype pack: block too large".into());
            }
            blocks.push((offset, clen));
        }
        let mut pack = Self {
            funcs: HashMap::new(),
            types: HashMap::new(),
            by_name: HashMap::new(),
            parsed: RefCell::new(HashMap::new()),
        };
        for (offset, clen) in blocks {
            let start = position
                .checked_add(offset)
                .ok_or("prototype pack: offset overflow")?;
            let compressed = data
                .get(start..start.checked_add(clen).ok_or("prototype pack: overflow")?)
                .ok_or("prototype pack: block out of range")?;
            let mut raw = String::new();
            ZlibDecoder::new(compressed)
                .take(MAX_BLOCK)
                .read_to_string(&mut raw)
                .map_err(|e| format!("prototype pack: {e}"))?;
            for line in raw.lines() {
                if let Some(rest) = line.strip_prefix("F:") {
                    if let Some((name, xml)) = rest.split_once('\t') {
                        pack.funcs.insert(name.to_owned(), xml.to_owned());
                    }
                } else if let Some(rest) = line.strip_prefix("T:") {
                    let mut parts = rest.splitn(3, '\t');
                    if let (Some(id), Some(name), Some(xml)) =
                        (parts.next(), parts.next(), parts.next())
                    {
                        pack.by_name
                            .entry(name.to_owned())
                            .or_insert_with(|| id.to_owned());
                        pack.types
                            .insert(id.to_owned(), (name.to_owned(), xml.to_owned()));
                    }
                }
            }
        }
        Ok(pack)
    }

    pub fn has_type(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    fn node(&self, id: &str) -> Option<Rc<Node>> {
        if let Some(node) = self.parsed.borrow().get(id) {
            return Some(Rc::clone(node));
        }
        let (_, xml) = self.types.get(id)?;
        let node = Rc::new(parse_xml(xml).ok()?);
        self.parsed
            .borrow_mut()
            .insert(id.to_owned(), Rc::clone(&node));
        Some(node)
    }

    /// Prototype key for an identifier, allowing a lowercase `<module>_` prefix, or one leading
    /// `_` as the native session allows (Ghidra's rule for archive signatures).
    pub fn callee(&self, ident: &str) -> Option<&str> {
        if let Some((key, _)) = self.funcs.get_key_value(ident) {
            return Some(key);
        }
        if let Some((key, _)) = ident
            .strip_prefix('_')
            .and_then(|plain| self.funcs.get_key_value(plain))
        {
            return Some(key);
        }
        for (at, _) in ident.match_indices('_') {
            let (head, tail) = (ident.get(..at)?, ident.get(at + 1..)?);
            let module = !head.is_empty()
                && head
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
            if module {
                if let Some((key, _)) = self.funcs.get_key_value(tail) {
                    return Some(key);
                }
            }
        }
        None
    }
}

// --- emitter ----------------------------------------------------------------------------------

fn c_name(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if out.is_empty() {
        out.push_str("anon");
    }
    if KEYWORDS.contains(&out.as_str()) {
        out.push('_');
    }
    out
}

fn int_type(size: u32) -> &'static str {
    match size {
        1 => "signed char",
        2 => "short",
        8 => "long long",
        _ => "int",
    }
}
fn uint_type(size: u32) -> &'static str {
    match size {
        1 => "unsigned char",
        2 => "unsigned short",
        8 => "unsigned long long",
        _ => "unsigned int",
    }
}

/// Declarations for one translation unit, in dependency order.
pub struct Emitter<'a> {
    pack: &'a Pack,
    forward: Vec<String>,
    body: Vec<String>,
    protos: Vec<String>,
    done: HashSet<String>,
    busy: HashSet<String>,
    full: HashSet<String>,
    pub unresolved: BTreeSet<String>,
}
impl<'a> Emitter<'a> {
    pub fn new(pack: &'a Pack) -> Self {
        Self {
            pack,
            forward: Vec::new(),
            body: Vec::new(),
            protos: Vec::new(),
            done: HashSet::new(),
            busy: HashSet::new(),
            full: HashSet::new(),
            unresolved: BTreeSet::new(),
        }
    }

    fn builtin(node: &Node) -> Option<String> {
        let size = node.attr("size").and_then(|s| s.parse().ok()).unwrap_or(0);
        Some(match node.attr("metatype")? {
            "int" if node.attr("utf") == Some("true") || node.attr("name") == Some("wchar_t") => {
                "unsigned short".into()
            }
            "int" if node.attr("char") == Some("true") => "char".into(),
            "int" => int_type(size).into(),
            "uint" => uint_type(size).into(),
            "float" => match size {
                4 => "float".into(),
                10 | 16 => "long double".into(),
                _ => "double".into(),
            },
            "bool" => "_Bool".into(),
            "unknown" => match size {
                1 | 2 | 4 | 8 => uint_type(size).into(),
                _ => "unsigned char".into(),
            },
            _ => return None,
        })
    }

    fn join(base: &str, inner: &str) -> String {
        if inner.is_empty() {
            base.to_owned()
        } else {
            format!("{base} {inner}")
        }
    }

    fn render(&mut self, node: &Node, inner: &str, by_value: bool, depth: usize) -> String {
        if depth > MAX_DEPTH {
            return Self::join("unsigned int", inner);
        }
        match node.tag.as_str() {
            "void" => return Self::join("void", inner),
            "typeref" => {
                let id = node.attr("id").unwrap_or("");
                let name = self.use_type(id, by_value, depth + 1);
                return match name {
                    Some(n) => Self::join(&n, inner),
                    None => {
                        self.unresolved
                            .insert(node.attr("name").unwrap_or("?").to_owned());
                        Self::join("unsigned int", inner)
                    }
                };
            }
            _ => {}
        }
        match node.attr("metatype") {
            Some("ptr") => {
                let void = Node {
                    tag: "void".into(),
                    ..Node::default()
                };
                let child = node.children.first().unwrap_or(&void);
                let mut wrap = format!("*{inner}");
                if matches!(child.attr("metatype"), Some("array") | Some("code")) {
                    wrap = format!("({wrap})");
                }
                self.render(child, &wrap, false, depth + 1)
            }
            Some("array") => {
                let void = Node {
                    tag: "void".into(),
                    ..Node::default()
                };
                let child = node.children.first().unwrap_or(&void);
                let dims = format!("{inner}[{}]", node.attr("arraysize").unwrap_or(""));
                self.render(child, &dims, by_value, depth + 1)
            }
            Some("code") => match node.child("prototype") {
                Some(proto) => self.render_proto(proto, inner, depth + 1),
                None => format!("void {inner}()"),
            },
            Some("struct") | Some("union") | Some("enum_uint") | Some("enum_int") => {
                let id = node.attr("id").unwrap_or("");
                match self.use_type(id, by_value, depth + 1) {
                    Some(n) => Self::join(&n, inner),
                    None => Self::join("unsigned int", inner),
                }
            }
            _ => Self::join(
                &Self::builtin(node).unwrap_or_else(|| "unsigned int".into()),
                inner,
            ),
        }
    }

    fn render_proto(&mut self, proto: &Node, name: &str, depth: usize) -> String {
        let void = Node {
            tag: "void".into(),
            ..Node::default()
        };
        let ret = proto
            .child("returnsym")
            .and_then(|r| r.children.get(1))
            .unwrap_or(&void);
        let mut params = Vec::new();
        if let Some(list) = proto.child("internallist") {
            for param in &list.children {
                if let Some(kid) = param.children.iter().find(|k| k.tag != "addr") {
                    params.push(self.render(kid, "", false, depth + 1));
                }
            }
        }
        let variadic = proto.attr("dotdotdot") == Some("true");
        let list = if variadic {
            // C before C23 has no variadic function without a named parameter.
            if params.is_empty() {
                String::new()
            } else {
                params.push("...".into());
                params.join(", ")
            }
        } else if params.is_empty() {
            "void".into()
        } else {
            params.join(", ")
        };
        self.render(ret, &format!("{name}({list})"), false, depth + 1)
    }

    /// Make type `id` available and return the name to write for it.
    fn use_type(&mut self, id: &str, by_value: bool, depth: usize) -> Option<String> {
        let (name, _) = self.pack.types.get(id)?;
        let node = self.pack.node(id)?;
        let cname = c_name(name);
        if is_prelude_type(name) {
            return Some(cname);
        }
        let meta = node.attr("metatype");
        if node.tag == "type" && matches!(meta, Some("struct") | Some("union")) {
            let keyword = meta.unwrap_or("struct");
            if self.done.insert(id.to_owned()) {
                self.forward
                    .push(format!("typedef {keyword} {cname} {cname};"));
            }
            if (by_value || self.full.contains(id)) && !self.busy.contains(id) {
                self.ensure_body(id, depth);
            }
            return Some(cname);
        }
        if node.tag == "type" && matches!(meta, Some("enum_uint") | Some("enum_int")) {
            if self.done.insert(id.to_owned()) {
                let base = if meta == Some("enum_uint") { "unsigned int" } else { "int" };
                self.body.push(format!("typedef {base} {cname};"));
            }
            return Some(cname);
        }
        if node.tag == "def" {
            if self.done.contains(id) {
                return Some(cname);
            }
            if self.busy.contains(id) {
                return Some("void".into());
            }
            self.busy.insert(id.to_owned());
            let text = match node.children.first() {
                Some(kid) => self.render(kid, &cname, by_value, depth + 1),
                None => format!("unsigned int {cname}"),
            };
            self.busy.remove(id);
            self.done.insert(id.to_owned());
            self.body.push(format!("typedef {text};"));
            return Some(cname);
        }
        if let Some(b) = Self::builtin(&node) {
            return Some(b);
        }
        self.unresolved.insert(name.clone());
        None
    }

    fn ensure_body(&mut self, id: &str, depth: usize) {
        if depth > MAX_DEPTH || !self.done.insert(format!("body:{id}")) {
            return;
        }
        let (Some((name, _)), Some(node)) = (self.pack.types.get(id), self.pack.node(id)) else {
            return;
        };
        self.busy.insert(id.to_owned());
        let cname = c_name(name);
        let mut fields = Vec::new();
        for (index, field) in node
            .children
            .iter()
            .filter(|c| c.tag == "field")
            .enumerate()
        {
            let Some(kind) = field.children.first() else {
                continue;
            };
            let fname = c_name(field.attr("name").filter(|n| !n.is_empty()).unwrap_or(&format!("_f{index}")));
            let bits = (kind.tag == "type" && kind.attr("metatype") == Some("unknown"))
                .then(|| kind.attr("name"))
                .flatten()
                .and_then(|n| n.split_once(':'))
                .filter(|(base, width)| {
                    !base.is_empty() && !width.is_empty() && width.bytes().all(|b| b.is_ascii_digit())
                })
                .map(|(_, width)| width.to_owned());
            match bits {
                Some(width) => fields.push(format!("unsigned int {fname} : {width};")),
                None => {
                    let text = self.render(kind, &fname, true, depth + 1);
                    fields.push(format!("{text};"));
                }
            }
        }
        self.busy.remove(id);
        let keyword = node.attr("metatype").unwrap_or("struct");
        self.body
            .push(format!("{keyword} {cname} {{ {} }};", fields.join(" ")));
    }

    /// A type named in the text. Returns false when the pack has no such type.
    pub fn want(&mut self, name: &str, full: bool) -> bool {
        let Some(id) = self.pack.by_name.get(name).cloned() else {
            return false;
        };
        if full {
            self.full.insert(id.clone());
        }
        let used = self.use_type(&id, true, 0).is_some();
        // A basic type the text names, such as `wchar_t`, is a typedef in C.
        if let (Some(node), Some((name, _))) = (self.pack.node(&id), self.pack.types.get(&id)) {
            let cname = c_name(name);
            if let (true, Some(base)) = (node.tag == "type", Self::builtin(&node)) {
                if cname == *name
                    && !KEYWORDS.contains(&cname.as_str())
                    && !is_prelude_type(&cname)
                    && self.done.insert(format!("basic:{id}"))
                {
                    self.body.push(format!("typedef {base} {cname};"));
                }
            }
        }
        used
    }

    /// The pack's prototype for a callee, written under the name the text uses.
    pub fn prototype(&mut self, ident: &str) -> bool {
        let Some(key) = self.pack.callee(ident) else {
            return false;
        };
        let Some(xml) = self.pack.funcs.get(key) else {
            return false;
        };
        let Ok(proto) = parse_xml(xml) else {
            return false;
        };
        let decl = self.render_proto(&proto, &c_name(ident), 0);
        self.protos.push(format!("extern {decl};"));
        true
    }

    pub fn text(&self) -> String {
        let mut out = String::new();
        for line in self.forward.iter().chain(&self.body).chain(&self.protos) {
            out.push_str(line);
            out.push('\n');
        }
        out
    }
}

// --- the fixed prelude ----------------------------------------------------------------------

/// Ghidra's pseudo-types and pseudo-operations. They are decompiler built-ins and in no archive.
/// The operations mean what Ghidra's p-code operations mean for a C compiler; flags are modeled
/// by the `CARRY`, `SCARRY` and `SBORROW` helpers, not by anything else. 16-byte forms need
/// `__int128`, which only the 64-bit target has.
pub fn prelude(wide: bool) -> String {
    let top: u32 = if wide { 16 } else { 8 };
    let unsigned = |n: u32| -> &'static str {
        match n {
            0..=1 => "unsigned char",
            2 => "unsigned short",
            3..=4 => "unsigned int",
            5..=8 => "unsigned long long",
            _ => "unsigned __int128",
        }
    };
    let signed = |n: u32| -> &'static str {
        match n {
            0..=1 => "signed char",
            2 => "short",
            3..=4 => "int",
            5..=8 => "long long",
            _ => "__int128",
        }
    };
    let mut out = String::from("typedef _Bool bool;\ntypedef long long code();\n");
    for n in [1u32, 2, 4, 8] {
        out.push_str(&format!(
            "typedef {u} undefined{n}, xunknown{n}, uint{n};\ntypedef {s} int{n};\n",
            u = unsigned(n),
            s = signed(n)
        ));
    }
    out.push_str("typedef unsigned short wchar2; typedef unsigned int wchar4;\n");
    out.push_str("typedef unsigned char undefined, byte; typedef unsigned char uchar; typedef unsigned short ushort;\n");
    out.push_str("typedef unsigned int uint; typedef unsigned int ulong; typedef long long longlong;\n");
    out.push_str("typedef unsigned long long ulonglong; typedef long double float10;\n");
    if wide {
        out.push_str("typedef unsigned __int128 undefined16, xunknown16, uint16; typedef __int128 int16;\n");
    }
    for n in [3u32, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15] {
        let big = if n < 4 { 4 } else if n < 8 { 8 } else if wide { 16 } else { 8 };
        out.push_str(&format!(
            "typedef {u} unkbyte{n}; typedef {u} unkuint{n}; typedef {s} unkint{n};\n",
            u = unsigned(big),
            s = signed(big)
        ));
    }
    // Exact-width views for the sub-piece rewrite: reading or writing `.v` touches `n` bytes only.
    for n in [3u32, 5, 6, 7] {
        out.push_str(&format!(
            "typedef struct {{ unsigned long long v : {bits}; }} __attribute__((packed)) xbits{n};\n",
            bits = 8 * n
        ));
    }
    out.push_str("typedef float unkfloat4, float4; typedef double unkfloat8, float8; typedef signed char sbyte;\n");
    for n in 1..top {
        for m in 1..=(top - n) {
            out.push_str(&format!(
                "#define CONCAT{n}{m}(a,b) (({t})(({t})({un})(a) << {sh}) | ({t})({um})(b))\n",
                t = unsigned(n + m),
                un = unsigned(n),
                um = unsigned(m),
                sh = 8 * m
            ));
        }
    }
    for n in 1..=top {
        for m in 1..=top {
            if m <= n {
                out.push_str(&format!(
                    "#define SUB{n}{m}(a,off) (({um})((({un})(a)) >> (8*(off))))\n",
                    um = unsigned(m),
                    un = unsigned(n)
                ));
            } else {
                out.push_str(&format!(
                    "#define ZEXT{n}{m}(a) (({um})({un})(a))\n#define SEXT{n}{m}(a) (({sm})({sn})(a))\n",
                    um = unsigned(m),
                    un = unsigned(n),
                    sm = signed(m),
                    sn = signed(n)
                ));
            }
        }
    }
    for n in 1..=top {
        out.push_str(&format!(
            "static inline int CARRY{n}({u} a,{u} b){{ return (({u})(a+b)) < a; }}\n\
             static inline int SCARRY{n}({s} a,{s} b){{ {s} r; return __builtin_add_overflow(a,b,&r); }}\n\
             static inline int SBORROW{n}({s} a,{s} b){{ {s} r; return __builtin_sub_overflow(a,b,&r); }}\n",
            u = unsigned(n),
            s = signed(n)
        ));
    }
    out.push_str("#define true 1\n#define false 0\n");
    out.push_str("#define POPCOUNT(x) ((int)__builtin_popcountll((unsigned long long)(x)))\n");
    out.push_str("#define LZCOUNT(x) ((int)__builtin_clzll((unsigned long long)(x) | 1))\n");
    out
}
