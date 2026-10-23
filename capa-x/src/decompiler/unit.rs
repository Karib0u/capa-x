//! The self-contained unit: decompiled text for one function or a set, plus the declarations that
//! let a C compiler accept it.
//!
//! A unit is a translation unit with, in order: a prelude (Ghidra's pseudo-types and
//! pseudo-operations), the pack's types and the pack's prototype for every callee it knows, a
//! declaration for everything else the text names, a forward declaration of every function in the
//! unit, and the function bodies. Every declaration that is a guess rather than a fact from the
//! archive carries a `GUESS` comment and is listed in [`Unit::guesses`]. A unit whose list is empty
//! compiles on the strength of the archive alone.
//!
//! Compiling means well-formed C, not that the function is right: a dropped argument still
//! compiles. The unit is never run. Measured by `scripts/decompiler_baseline/compile_check.py`
//! and recorded in `docs/decompiler-baseline-results.md` (Step 13).
//!
//! The rules for constructs that cannot compile as printed:
//!
//! | Construct | Rule |
//! |---|---|
//! | `x._0_4_` sub-piece of a variable | rewritten to a read or write of that byte range, `(*(xunknown4 *)((byte *)&x + 0))` (little endian); widths 3, 5, 6 and 7 go through a packed bit-field view, and wider ones are left and reported |
//! | `unaff_*`, `in_*`, `extraout_*` register reads | declared as unit-level variables; a guess, because the value comes from the caller |
//! | `stack0x...` addresses | declared as unit-level bytes; a guess, because the address is a frame offset |
//! | `UNRECOVERED_JUMPTABLE` | declared as a function pointer; a guess |
//! | `halt_baddata()`, `swi(n)` | defined as a trap |
//! | callee with no archive prototype (`FUN_...`) | `extern long long f();`, unspecified parameters; a guess |
//! | data symbol (`DAT_...`, `PTR_...`, `s_...`, `u_...`) | an `extern` without a definition; its shape (called through, a structure, an array, a pointer, only its address as `byte`) from how the text uses it, otherwise the scalar type the decompiler gave it; a guess |
//! | 16-byte value declared `xunknown1 x [16]` (x86-64) | `int16`, unless the text indexes it |
//! | `ROUND`, `NAN`, `ABS`, `SQRT`, `CEIL`, `FLOOR` | defined in the prelude as Ghidra's emulator computes them |

use std::collections::BTreeSet;

use regex::Regex;
use serde::Serialize;

use super::ctypes::{is_prelude_type, prelude, Emitter, Pack};
use super::{GlobalSymbol, ValueKind};

#[derive(Debug, Serialize)]
pub struct Guess {
    pub kind: &'static str,
    pub name: String,
    pub note: &'static str,
}

#[derive(Debug, Serialize)]
pub struct UnitFunction {
    pub address: u64,
    pub name: String,
    pub incomplete: bool,
    pub unknown_callees: bool,
}

#[derive(Debug, Serialize)]
pub struct Unit {
    pub text: String,
    pub functions: Vec<UnitFunction>,
    pub guesses: Vec<Guess>,
    /// Sub-piece accesses rewritten in the function bodies.
    pub rewrites: usize,
    /// Sub-piece accesses of a width that cannot be rewritten; they stay in the text and will not compile.
    pub unrewritten: usize,
    /// Names that archive types did not describe.
    pub unresolved_types: Vec<String>,
}
impl Unit {
    /// True when nothing in the unit rests on a guess.
    pub fn archive_only(&self) -> bool {
        self.guesses.is_empty() && self.unrewritten == 0
    }
}

/// One decompiled function, ready to be placed in a unit.
pub struct Body {
    pub address: u64,
    pub text: String,
    pub incomplete: bool,
    pub unknown_callees: bool,
    /// The data symbols the text names, typed by the decompiler.
    pub globals: Vec<GlobalSymbol>,
}

const C_WORDS: &[&str] = &[
    "if", "else", "while", "for", "do", "switch", "case", "default", "return", "goto", "break",
    "continue", "sizeof", "struct", "union", "enum", "typedef", "void", "char", "short", "int",
    "long", "float", "double", "signed", "unsigned", "const", "volatile", "static", "extern",
    "inline", "register", "true", "false", "__cdecl", "__stdcall", "__fastcall", "__thiscall",
    "__declspec", "bool",
];

/// Blank out comments and string and character literals, keeping offsets, so a name inside a
/// string is never mistaken for an identifier.
fn mask_literals(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let next = bytes.get(i + 1).copied();
        if b == b'/' && next == Some(b'/') {
            while bytes.get(i).is_some_and(|c| *c != b'\n') {
                out.push(b' ');
                i += 1;
            }
        } else if b == b'/' && next == Some(b'*') {
            out.extend_from_slice(b"  ");
            i += 2;
            while let Some(&c) = bytes.get(i) {
                if c == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    out.extend_from_slice(b"  ");
                    i += 2;
                    break;
                }
                out.push(if c == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
        } else if b == b'"' || b == b'\'' {
            out.push(b);
            i += 1;
            while let Some(&c) = bytes.get(i) {
                if c == b'\\' {
                    out.extend_from_slice(b"  ");
                    i += 2;
                    continue;
                }
                i += 1;
                if c == b {
                    out.push(b);
                    break;
                }
                out.push(if c == b'\n' { b'\n' } else { b' ' });
            }
        } else {
            out.push(b);
            i += 1;
        }
    }
    // Only ASCII bytes were replaced by ASCII bytes, so the result is still UTF-8 where the input was.
    String::from_utf8(out).unwrap_or_default()
}

fn is_register_read(name: &str) -> bool {
    name.starts_with("unaff_")
        || name.starts_with("extraout_")
        || name
            .strip_prefix("in_")
            .and_then(|rest| rest.chars().next())
            .is_some_and(|c| c.is_ascii_alphabetic())
}
fn is_stack_address(name: &str) -> bool {
    name.strip_prefix("stack0x")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit()))
}
fn is_data_symbol(name: &str) -> bool {
    ["DAT_", "PTR_", "_DAT_", "s_", "u_"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || name
            .find("Ram")
            .is_some_and(|at| {
                let (head, tail) = name.split_at(at);
                head.bytes().all(|b| b.is_ascii_lowercase())
                    && tail.get(3..).is_some_and(|hex| {
                        !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
                    })
            })
}
/// Ghidra's names for locals and parameters, which the function text declares itself.
fn is_local_name(name: &str) -> bool {
    let tail = name.trim_start_matches('_');
    let numbered = |stem: &str| {
        tail.strip_prefix(stem)
            .is_some_and(|rest| rest.trim_start_matches('_').chars().next().is_some_and(|c| c.is_ascii_hexdigit()))
    };
    numbered("param") || numbered("local")
        || tail.find("Var").is_some_and(|at| {
            tail.get(..at).is_some_and(|h| h.bytes().all(|b| b.is_ascii_lowercase()))
        })
        || tail.find("Stack_").is_some_and(|at| {
            tail.get(..at).is_some_and(|h| h.bytes().all(|b| b.is_ascii_alphabetic()))
        })
        || name.starts_with("LAB_")
}

/// Whether the text declares `name` itself: a type word, optional stars, the name, then a
/// declarator ending.
fn is_declared(text: &str, name: &str) -> Result<bool, String> {
    let n = regex::escape(name);
    Regex::new(&format!(r"[\w\*]\s+\**\s*{n}\s*(?:;|\[|,|\)|=)"))
        .map(|re| re.is_match(text))
        .map_err(|e| e.to_string())
}

fn is_pseudo_operation(name: &str) -> bool {
    let digits = |rest: &str| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
    ["CONCAT", "SUB", "ZEXT", "SEXT", "CARRY", "SCARRY", "SBORROW"]
        .iter()
        .any(|p| name.strip_prefix(p).is_some_and(digits))
        || matches!(
            name,
            "POPCOUNT" | "LZCOUNT" | "NAN" | "ABS" | "SQRT" | "CEIL" | "FLOOR" | "ROUND"
        )
}

/// The declaration for a data symbol: its shape (called through, a structure, an array, a pointer,
/// only its address) from how the text uses it, otherwise the scalar type the decompiler gave it.
fn data_declaration(name: &str, text: &str, global: Option<&GlobalSymbol>) -> Result<String, String> {
    let n = regex::escape(name);
    let uses = |pattern: String| -> Result<bool, String> {
        Regex::new(&pattern)
            .map(|re| re.is_match(text))
            .map_err(|e| e.to_string())
    };
    Ok(if name.starts_with("s_") {
        format!("extern char {name}[];")
    } else if name.starts_with("u_") {
        format!("extern unsigned short {name}[];")
    } else if uses(format!(r"\(\s*\*\s*{n}\s*\)\s*\("))? {
        format!("extern code *{name};")
    } else if uses(format!(r"\b{n}\s*(->|\.)"))? {
        format!("extern struct {{ char _[4096]; }} {name};")
    } else if uses(format!(r"\b{n}\s*\["))? {
        format!("extern unsigned int {name}[];")
    } else if uses(format!(r"{UNARY}\*\s*{n}\b"))? {
        format!("extern unsigned int *{name};")
    } else if count(&format!(r"{UNARY}&\s*{n}\b"), text)? == count(&format!(r"\b{n}\b"), text)? {
        // Only its address is used: Ghidra's `&DAT_x + n` counts bytes.
        format!("extern byte {name};")
    } else if let Some(word) = global.and_then(scalar_type) {
        format!("extern {word} {name};")
    } else {
        format!("extern long long {name};")
    })
}

/// The prelude type for a data symbol's analyzed scalar type, if it has one.
fn scalar_type(global: &GlobalSymbol) -> Option<String> {
    let size = global.size;
    let sized = matches!(size, 1 | 2 | 4 | 8);
    Some(match global.kind {
        ValueKind::Float => match size {
            4 => "float4".into(),
            8 => "float8".into(),
            10 | 12 | 16 => "float10".into(),
            _ => return None,
        },
        ValueKind::Bool if size == 1 => "bool".into(),
        ValueKind::Signed if sized => format!("int{size}"),
        ValueKind::Unsigned if sized => format!("uint{size}"),
        // A pointer of unknown target, or an untyped value of known size: an integer of that size,
        // which the text's casts convert.
        ValueKind::Pointer | ValueKind::Unknown | ValueKind::Bool if sized => format!("xunknown{size}"),
        _ => return None,
    })
}

/// What may stand before a unary operator: the start, an operator or an opening bracket, not an
/// operand, so `a * DAT_x` is a product and `= *DAT_x` a dereference.
const UNARY: &str = r"(?:^|[^\w)\]\s]|\breturn)\s*";

fn count(pattern: &str, text: &str) -> Result<usize, String> {
    Regex::new(pattern)
        .map(|re| re.find_iter(text).count())
        .map_err(|e| e.to_string())
}

/// Rewrite `x._0_4_` (bytes 0 to 3 of `x`) as a memory access of that range. Returns the new text
/// and how many were rewritten and how many left alone.
fn rewrite_sub_pieces(text: &str, wide: bool) -> Result<(String, usize, usize), String> {
    // A `)` before the name is a cast, `(uint8)x._12_4_`; only `.` and `->` make it a field.
    let re = Regex::new(r"(^|[^\w.>\]])([A-Za-z_]\w*(?:\[[^\[\]]*\])*)\._(\d+)_(\d+)_")
        .map_err(|e| e.to_string())?;
    let (mut done, mut left) = (0, 0);
    let out = re.replace_all(text, |caps: &regex::Captures| {
        let field = |i: usize| caps.get(i).map_or("", |m| m.as_str());
        match field(4) {
            width @ ("1" | "2" | "4" | "8" | "16") if width != "16" || wide => {
                done += 1;
                format!(
                    "{}(*(xunknown{width} *)((byte *)&{} + {}))",
                    field(1),
                    field(2),
                    field(3)
                )
            }
            width @ ("3" | "5" | "6" | "7") => {
                done += 1;
                format!(
                    "{}(*(xbits{width} *)((byte *)&{} + {})).v",
                    field(1),
                    field(2),
                    field(3)
                )
            }
            _ => {
                left += 1;
                field(0).to_owned()
            }
        }
    });
    Ok((out.into_owned(), done, left))
}

/// On the 64-bit target, a 16-byte value that the text declares as a byte array,
/// `xunknown1 axVar1 [16];`, and computes with becomes `int16` (`__int128`), unless the text
/// indexes it. Signed, because the text marks the signedness of an operation on the other
/// operand: `axVar1 / SEXT816(x)` (`idiv`) stays signed and `axVar1 / ZEXT816(x)` (`div`) becomes
/// unsigned under C's conversions. A cast to the array type, `(xunknown1 [16])0x0`, is never
/// valid C and becomes a cast to `int16`. Returns the new text and the number of rewrites.
fn rewrite_vector_locals(text: &str, wide: bool) -> Result<(String, usize), String> {
    if !wide {
        return Ok((text.to_owned(), 0));
    }
    let declaration = Regex::new(r"\b(?:xunknown1|undefined1)\s+([A-Za-z_]\w*)\s*\[16\];")
        .map_err(|e| e.to_string())?;
    let masked = mask_literals(text);
    let mut scalar = BTreeSet::new();
    for caps in declaration.captures_iter(&masked) {
        let name = caps.get(1).map_or("", |m| m.as_str());
        // The declaration itself is the one `name [` allowed.
        if count(&format!(r"\b{}\s*\[", regex::escape(name)), &masked)? == 1 {
            scalar.insert(name.to_owned());
        }
    }
    let mut done = 0;
    let out = declaration.replace_all(text, |caps: &regex::Captures| {
        let name = caps.get(1).map_or("", |m| m.as_str());
        if scalar.contains(name) {
            done += 1;
            format!("int16 {name};")
        } else {
            caps.get(0).map_or("", |m| m.as_str()).to_owned()
        }
    });
    let cast = Regex::new(r"\(\s*(?:xunknown1|undefined1)\s*\[16\]\s*\)").map_err(|e| e.to_string())?;
    let out = cast.replace_all(&out, |_: &regex::Captures| {
        done += 1;
        "(int16)".to_owned()
    });
    Ok((out.into_owned(), done))
}

/// The name a function body defines: the identifier before the first `(` of its signature.
fn defined_name(text: &str) -> Option<String> {
    let masked = mask_literals(text);
    let head = masked.get(..masked.find('(')?)?;
    let name: String = head
        .trim_end()
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    (!name.is_empty()).then_some(name)
}

fn signature(text: &str) -> Option<String> {
    let masked = mask_literals(text);
    let head = text.get(..masked.find('{')?)?;
    Some(head.trim().to_owned())
}

pub fn build(pack: &Pack, wide: bool, bodies: &[Body]) -> Result<Unit, String> {
    let ident = Regex::new(r"\b[A-Za-z_]\w*\b").map_err(|e| e.to_string())?;
    let mut texts = Vec::new();
    let (mut rewrites, mut unrewritten) = (0, 0);
    for body in bodies {
        let (text, vectors) = rewrite_vector_locals(&body.text, wide)?;
        let (text, done, left) = rewrite_sub_pieces(&text, wide)?;
        rewrites += done + vectors;
        unrewritten += left;
        texts.push(text);
    }
    let defined: BTreeSet<String> = texts.iter().filter_map(|t| defined_name(t)).collect();
    // A symbol named by several functions takes the type the first of them gave it.
    let globals: Vec<&GlobalSymbol> = bodies.iter().flat_map(|body| &body.globals).collect();

    let mut emitter = Emitter::new(pack);
    let mut guesses: Vec<Guess> = Vec::new();
    let mut declarations: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut traps = false;
    let word = if wide { "xunknown8" } else { "xunknown4" };

    for text in &texts {
        let masked = mask_literals(text);
        for found in ident.find_iter(&masked) {
            let name = found.as_str();
            if !seen.insert(name.to_owned()) {
                continue;
            }
            let after = masked
                .get(found.end()..)
                .and_then(|rest| rest.trim_start().chars().next());
            let called = after == Some('(');
            // The prefix of a wide or UTF string literal, `L"..."`.
            if matches!(name, "L" | "u" | "U" | "u8") && matches!(after, Some('"' | '\'')) {
                continue;
            }
            // A field of a structure shares names with archive types and functions.
            let before = masked.get(..found.start()).map(str::trim_end).unwrap_or("");
            if before.ends_with('.') || before.ends_with("->") {
                continue;
            }
            if defined.contains(name)
                || C_WORDS.contains(&name)
                || is_pseudo_operation(name)
                || is_prelude_type(name)
            {
                continue;
            }
            if matches!(name, "halt_baddata" | "swi") || name.starts_with("halt_") {
                traps = true;
                continue;
            }
            if is_register_read(name) {
                declarations.push(format!(
                    "extern {word} {name}; /* GUESS: register read, the value comes from the caller */"
                ));
                guesses.push(Guess {
                    kind: "register_read",
                    name: name.into(),
                    note: "the value of this register on entry is not known",
                });
            } else if is_stack_address(name) {
                declarations.push(format!(
                    "extern byte {name}; /* GUESS: address of a frame offset */"
                ));
                guesses.push(Guess {
                    kind: "stack_address",
                    name: name.into(),
                    note: "a frame offset with no variable of its own",
                });
            } else if name == "UNRECOVERED_JUMPTABLE" {
                declarations.push(format!(
                    "extern code *{name}; /* GUESS: indirect jump the decompiler could not resolve */"
                ));
                guesses.push(Guess {
                    kind: "unrecovered_jump",
                    name: name.into(),
                    note: "an indirect jump whose targets were not recovered",
                });
            } else if is_data_symbol(name) {
                let global = globals.iter().copied().find(|g| g.name == name);
                let declaration = data_declaration(name, &masked, global)?;
                declarations.push(format!(
                    "{declaration} /* GUESS: no definition; type taken from how the text uses it and from the analysis */"
                ));
                guesses.push(Guess {
                    kind: "data_symbol",
                    name: name.into(),
                    note: "declared without a definition; type from how the text uses it and from the analysis",
                });
            } else if pack.has_type(name) && !called {
                emitter.want(name, false);
            } else if pack.callee(name).is_some() {
                emitter.prototype(name);
            } else if !called && !is_declared(&masked, name)? && !is_local_name(name) {
                let declaration = data_declaration(name, &masked, None)?;
                declarations.push(format!(
                    "{declaration} /* GUESS: global the text uses but the archive does not describe */"
                ));
                guesses.push(Guess {
                    kind: "undeclared_global",
                    name: name.into(),
                    note: "an imported or recovered global; type taken from how the text uses it",
                });
            } else if called
                || name.starts_with("FUN_")
                || name.starts_with("thunk_FUN_")
                || name.starts_with("SUB_")
            {
                declarations.push(format!(
                    "extern long long {name}(); /* GUESS: no archive prototype */"
                ));
                guesses.push(Guess {
                    kind: "callee_without_prototype",
                    name: name.into(),
                    note: "no archive prototype; parameters unspecified, result assumed to be 64 bits",
                });
            }
        }
    }

    let mut out = String::new();
    out.push_str("/* capa-x self-contained unit: compile as C, never run.\n");
    out.push_str(" * Windows target (for example clang --target=x86_64-pc-windows-msvc -std=gnu11 -fms-extensions).\n");
    out.push_str(" * Declarations marked GUESS are not from the type archive; see the list in the JSON form. */\n");
    out.push_str(&prelude(wide));
    out.push_str("#if !defined(_MSC_VER)\n#define __cdecl\n#define __stdcall\n#define __fastcall\n#define __thiscall\n#endif\n");
    if traps {
        out.push_str("#define halt_baddata() __builtin_trap()\n#define swi(n) __builtin_trap()\n#define halt_unimplemented() __builtin_trap()\n");
    }
    out.push_str(&emitter.text());
    for line in &declarations {
        out.push_str(line);
        out.push('\n');
    }
    for text in &texts {
        if let Some(sig) = signature(text) {
            out.push_str(&sig);
            out.push_str(";\n");
        }
    }
    for text in &texts {
        out.push('\n');
        out.push_str(text.trim_end());
        out.push('\n');
    }

    Ok(Unit {
        text: out,
        functions: bodies
            .iter()
            .zip(&texts)
            .map(|(body, text)| UnitFunction {
                address: body.address,
                name: defined_name(text).unwrap_or_default(),
                incomplete: body.incomplete,
                unknown_callees: body.unknown_callees,
            })
            .collect(),
        guesses,
        rewrites,
        unrewritten,
        unresolved_types: emitter.unresolved.iter().cloned().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_comments_are_masked() {
        let masked = mask_literals("a(\"DAT_1 \\\" x\"); /* FUN_2 */ b('c'); // unaff_x\nd");
        assert!(!masked.contains("DAT_1") && !masked.contains("FUN_2") && !masked.contains("unaff_x"));
        assert!(masked.contains('a') && masked.contains('d'));
        assert_eq!(mask_literals("\"unterminated").len() >= 1, true);
    }

    #[test]
    fn sub_pieces_become_memory_accesses_of_that_width() -> Result<(), String> {
        let (out, done, left) = rewrite_sub_pieces("x = uVar1._0_4_; aStack[2]._1_1_ = 3; y = p->f._0_4_; z = w._0_9_;", true)?;
        assert_eq!((done, left), (2, 1), "{out}");
        assert!(out.contains("(*(xunknown4 *)((byte *)&uVar1 + 0))"), "{out}");
        assert!(out.contains("(*(xunknown1 *)((byte *)&aStack[2] + 1)) = 3"), "{out}");
        assert!(out.contains("p->f._0_4_"), "{out}");
        let (odd, done, _) = rewrite_sub_pieces("v = q._2_6_;", false)?;
        assert_eq!(done, 1);
        assert!(odd.contains("(*(xbits6 *)((byte *)&q + 2)).v"), "{odd}");
        let (wide, _, left) = rewrite_sub_pieces("v = q._0_16_;", false)?;
        assert_eq!(left, 1, "{wide}");
        let (cast, done, _) = rewrite_sub_pieces("y = (uint8)axVar15._12_4_;", false)?;
        assert_eq!(done, 1);
        assert!(cast.contains("(uint8)(*(xunknown4 *)((byte *)&axVar15 + 12))"), "{cast}");
        Ok(())
    }

    #[test]
    fn vector_locals_become_signed_128_bit_values() -> Result<(), String> {
        let text = "  xunknown1 axVar1 [16];\n  xunknown1 axVar2 [16];\n  axVar1 = (xunknown1  [16])0x0;\n  \
                    axVar2[3] = 1;\n  return SUB168(axVar1 / SEXT816(x),0);\n";
        let (out, done) = rewrite_vector_locals(text, true)?;
        assert_eq!(done, 2, "{out}");
        assert!(out.contains("int16 axVar1;") && out.contains("axVar1 = (int16)0x0;"), "{out}");
        assert!(out.contains("xunknown1 axVar2 [16];"), "indexed arrays stay arrays: {out}");
        assert_eq!(rewrite_vector_locals(text, false)?, (text.to_owned(), 0));
        Ok(())
    }

    #[test]
    fn symbol_kinds() {
        assert!(is_data_symbol("DAT_00401000") && is_data_symbol("s_hello_00401000"));
        assert!(is_data_symbol("uRam0000000140001000") && !is_data_symbol("Random"));
        assert!(is_register_read("unaff_RBX") && is_register_read("in_XMM0") && !is_register_read("in"));
        assert!(is_stack_address("stack0xfffffffc") && !is_stack_address("stack0x"));
        assert!(is_local_name("iVar1") && is_local_name("param_2") && is_local_name("local_10"));
        assert!(is_local_name("pcStack_20") && !is_local_name("python38__PyRuntime"));
        assert!(is_pseudo_operation("CONCAT44") && is_pseudo_operation("SBORROW4") && !is_pseudo_operation("SUBSYSTEM"));
        assert!(is_pseudo_operation("ROUND") && is_pseudo_operation("SQRT") && !is_pseudo_operation("ROUNDS"));
    }

    #[test]
    fn data_symbols_are_typed_from_their_use() -> Result<(), String> {
        let decl = |text: &str| data_declaration("DAT_1400", text, None);
        assert_eq!(decl("return (a + b) * DAT_1400;")?, "extern long long DAT_1400;");
        assert_eq!(decl("x = a*DAT_1400;")?, "extern long long DAT_1400;");
        assert_eq!(decl("x = *DAT_1400;")?, "extern unsigned int *DAT_1400;");
        assert_eq!(decl("  return *DAT_1400;")?, "extern unsigned int *DAT_1400;");
        assert_eq!(decl("{\n  *DAT_1400 = 0;")?, "extern unsigned int *DAT_1400;");
        assert_eq!(decl("return *(int4 *)(&DAT_1400 + i * 4);")?, "extern byte DAT_1400;");
        assert_eq!(decl("p = &DAT_1400; DAT_1400 = 1;")?, "extern long long DAT_1400;");
        assert_eq!(decl("if (a && DAT_1400) b = c & DAT_1400;")?, "extern long long DAT_1400;");
        let typed = |kind, size| GlobalSymbol { name: "DAT_1400".into(), address: 0x1400, size, kind };
        let product = "return (a + b) * DAT_1400;";
        assert_eq!(data_declaration("DAT_1400", product, Some(&typed(ValueKind::Float, 4)))?, "extern float4 DAT_1400;");
        assert_eq!(data_declaration("DAT_1400", product, Some(&typed(ValueKind::Float, 10)))?, "extern float10 DAT_1400;");
        let counter = "DAT_1400 = DAT_1400 + 1;";
        assert_eq!(data_declaration("DAT_1400", counter, Some(&typed(ValueKind::Signed, 4)))?, "extern int4 DAT_1400;");
        assert_eq!(data_declaration("DAT_1400", counter, Some(&typed(ValueKind::Unknown, 2)))?, "extern xunknown2 DAT_1400;");
        assert_eq!(data_declaration("DAT_1400", counter, Some(&typed(ValueKind::Unknown, 3)))?, "extern long long DAT_1400;");
        // The text's shape wins over the scalar type.
        let table = "return *(int4 *)(&DAT_1400 + i * 4);";
        assert_eq!(data_declaration("DAT_1400", table, Some(&typed(ValueKind::Signed, 4)))?, "extern byte DAT_1400;");
        Ok(())
    }

    #[test]
    fn defined_names_and_signatures() {
        let text = "void __cdecl FUN_00401000(int param_1)\n\n{\n  return;\n}\n";
        assert_eq!(defined_name(text).as_deref(), Some("FUN_00401000"));
        assert_eq!(signature(text).as_deref(), Some("void __cdecl FUN_00401000(int param_1)"));
    }
}
