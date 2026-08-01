//! CIL decoder acceptance: instruction and block counts per method match a
//! committed `dncil` dump.
//! The oracle (`capa-x/tests/fixtures/dotnet/cil_dump.json`) is generated
//! by `scripts/gen_dotnet_cil_dump.py` against pinned Python `dnfile`/
//! `dncil`/capa (never invoked at test time -- AGENTS.md "No Python at
//! runtime") and committed.
//!
//! Compares every managed method's full decoded body -- header fields,
//! every instruction's offset/mnemonic/size/operand, every exception
//! handler -- plus the calls-to/calls-from call graph, field-for-field
//! against the pinned dump. "Block counts" is upstream's own trivial model:
//! `extractor.py get_basic_blocks` yields exactly one basic block per
//! method, so a method-count match *is* the block-count match; there is no
//! separate CFG split to verify (see `function.rs`'s module docs).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use capa_x::extract::dotnet;
use capa_x::extract::dotnet::function::{call_graph, managed_method_bodies, DnFunction};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum OracleOperand {
    None,
    Token { value: u64 },
    StringToken { value: u64 },
    Local { value: u64 },
    Argument { value: u64 },
    Switch { value: Vec<i64> },
    Int { value: i64 },
    Float { bits64: u64, bits32: u32 },
}

#[derive(Debug, Deserialize)]
struct OracleInstruction {
    offset: usize,
    mnemonic: String,
    size: usize,
    operand: OracleOperand,
}

#[derive(Debug, Deserialize)]
struct OracleExceptionHandler {
    exception_type: i64,
    try_start: i64,
    try_end: i64,
    filter_start: i64,
    handler_start: i64,
    handler_end: i64,
    catch_type: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OracleFunction {
    token: u32,
    offset: usize,
    header_size: usize,
    code_size: usize,
    max_stack: usize,
    size: usize,
    is_tiny: bool,
    is_fat: bool,
    more_sects: bool,
    instructions: Vec<OracleInstruction>,
    exception_handlers: Vec<OracleExceptionHandler>,
}

#[derive(Debug, Deserialize)]
struct OracleSample {
    order: Vec<u32>,
    functions: BTreeMap<String, OracleFunction>,
    calls_to: BTreeMap<String, Vec<u32>>,
    calls_from: BTreeMap<String, Vec<u32>>,
}

fn oracle() -> BTreeMap<String, OracleSample> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dotnet/cil_dump.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()))
}

fn assert_operand_matches(
    sample: &str,
    token: u32,
    offset: usize,
    expected: &OracleOperand,
    actual: &dnfile::lang::cil::instruction::Operand,
) {
    use dnfile::lang::cil::instruction::Operand;

    let ctx = || format!("{sample}: method 0x{token:08X} @ offset 0x{offset:X}");
    match (expected, actual) {
        (OracleOperand::None, Operand::None) => {}
        (OracleOperand::Token { value }, Operand::Token(t)) => {
            assert_eq!(*value, t.value as u64, "{}: token operand", ctx());
        }
        (OracleOperand::StringToken { value }, Operand::StringToken(t)) => {
            assert_eq!(*value, t.value as u64, "{}: string token operand", ctx());
        }
        (OracleOperand::Local { value }, Operand::Local(l)) => {
            assert_eq!(*value, l.index() as u64, "{}: local operand", ctx());
        }
        (OracleOperand::Argument { value }, Operand::Argument(a)) => {
            assert_eq!(*value, a.index() as u64, "{}: argument operand", ctx());
        }
        (OracleOperand::Switch { value }, Operand::Arguments(v)) => {
            let actual_targets: Vec<i64> = v
                .iter()
                .map(|o| match o {
                    Operand::Int(i) => *i,
                    other => panic!("{}: switch branch not Int: {other:?}", ctx()),
                })
                .collect();
            assert_eq!(value, &actual_targets, "{}: switch targets", ctx());
        }
        (OracleOperand::Int { value }, Operand::Int(i)) => {
            assert_eq!(*value, *i, "{}: int operand", ctx());
        }
        (OracleOperand::Float { bits64, bits32 }, Operand::Float(f)) => {
            // ldc.r4 is read as a 32-bit float (widened to f64); ldc.r8 as a
            // full 64-bit double. Either bit pattern round-tripping exactly
            // is an acceptable match -- the oracle provides both because it
            // can't see which width *this* instruction used without also
            // checking the opcode, which the caller already did implicitly
            // by only comparing r4/r8 loads here.
            let as_f32_bits = (*f as f32).to_bits();
            let as_f64_bits = f.to_bits();
            assert!(
                as_f64_bits == *bits64 || as_f32_bits == *bits32,
                "{}: float operand bits mismatch (got f64 bits {as_f64_bits:#018X}, f32 bits {as_f32_bits:#010X}; want f64 bits {bits64:#018X} or f32 bits {bits32:#010X})",
                ctx()
            );
        }
        (expected, actual) => panic!(
            "{}: operand kind mismatch: expected {expected:?}, got {actual:?}",
            ctx()
        ),
    }
}

fn assert_function_matches(sample: &str, expected: &OracleFunction, actual: &DnFunction<'_>) {
    let token = actual.token;
    assert_eq!(expected.token, token, "{sample}: token");

    let body = actual.body;
    assert_eq!(
        expected.offset, body.offset,
        "{sample}: 0x{token:08X} offset"
    );
    assert_eq!(
        expected.header_size,
        body.header_size(),
        "{sample}: 0x{token:08X} header_size"
    );
    assert_eq!(
        expected.code_size,
        body.code_size(),
        "{sample}: 0x{token:08X} code_size"
    );
    assert_eq!(
        expected.max_stack,
        body.max_stack(),
        "{sample}: 0x{token:08X} max_stack"
    );
    assert_eq!(expected.size, body.size(), "{sample}: 0x{token:08X} size");
    assert_eq!(
        expected.is_tiny,
        body.is_tiny(),
        "{sample}: 0x{token:08X} is_tiny"
    );
    assert_eq!(
        expected.is_fat,
        body.is_fat(),
        "{sample}: 0x{token:08X} is_fat"
    );
    assert_eq!(
        expected.more_sects,
        body.more_sects(),
        "{sample}: 0x{token:08X} more_sects"
    );

    assert_eq!(
        expected.instructions.len(),
        body.instructions.len(),
        "{sample}: 0x{token:08X} instruction count"
    );
    for (exp_insn, act_insn) in expected.instructions.iter().zip(&body.instructions) {
        assert_eq!(
            exp_insn.offset, act_insn.offset,
            "{sample}: 0x{token:08X} instruction offset"
        );
        assert_eq!(
            exp_insn.mnemonic, act_insn.opcode.name,
            "{sample}: 0x{token:08X} @ 0x{:X} mnemonic",
            exp_insn.offset
        );
        assert_eq!(
            exp_insn.size,
            act_insn.size(),
            "{sample}: 0x{token:08X} @ 0x{:X} size",
            exp_insn.offset
        );
        assert_operand_matches(
            sample,
            token,
            exp_insn.offset,
            &exp_insn.operand,
            &act_insn.operand,
        );
    }

    assert_eq!(
        expected.exception_handlers.len(),
        body.exception_handlers().len(),
        "{sample}: 0x{token:08X} exception handler count"
    );
    for (exp_eh, act_eh) in expected
        .exception_handlers
        .iter()
        .zip(body.exception_handlers())
    {
        assert_eq!(
            exp_eh.exception_type, act_eh.exception_type as i64,
            "{sample}: 0x{token:08X} EH exception_type"
        );
        assert_eq!(
            exp_eh.try_start, act_eh.try_start,
            "{sample}: 0x{token:08X} EH try_start"
        );
        assert_eq!(
            exp_eh.try_end, act_eh.try_end,
            "{sample}: 0x{token:08X} EH try_end"
        );
        assert_eq!(
            exp_eh.filter_start, act_eh.filter_start,
            "{sample}: 0x{token:08X} EH filter_start"
        );
        assert_eq!(
            exp_eh.handler_start, act_eh.handler_start,
            "{sample}: 0x{token:08X} EH handler_start"
        );
        assert_eq!(
            exp_eh.handler_end, act_eh.handler_end,
            "{sample}: 0x{token:08X} EH handler_end"
        );
        let act_catch = act_eh.catch_type.as_ref().map(|t| t.value as u64);
        assert_eq!(
            exp_eh.catch_type, act_catch,
            "{sample}: 0x{token:08X} EH catch_type"
        );
    }
}

#[test]
fn cil_decoder_matches_pinned_dncil() {
    let oracle = oracle();
    let corpus_dir = root().join("tests/testfiles/dotnet");

    let mut checked = 0usize;
    for (sample_name, expected) in &oracle {
        let sample_path = corpus_dir.join(sample_name);
        let bytes = std::fs::read(&sample_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", sample_path.display()));
        let pe = dotnet::load(&bytes).unwrap_or_else(|e| panic!("{sample_name}: parsing: {e}"));

        let functions = managed_method_bodies(&pe)
            .unwrap_or_else(|e| panic!("{sample_name}: managed_method_bodies: {e}"));

        let actual_order: Vec<u32> = functions.iter().map(|f| f.token).collect();
        assert_eq!(
            &actual_order, &expected.order,
            "{sample_name}: method token order diverges from pinned dnfile"
        );

        for (exp_fn, act_fn) in expected.order.iter().zip(&functions) {
            let expected_fn = &expected.functions[&exp_fn.to_string()];
            assert_function_matches(sample_name, expected_fn, act_fn);
        }

        let graph = call_graph(&functions);
        for token in &expected.order {
            let exp_to: Vec<u32> = expected.calls_to[&token.to_string()].clone();
            let act_to: Vec<u32> = graph.calls_to(*token).iter().copied().collect();
            assert_eq!(
                exp_to, act_to,
                "{sample_name}: 0x{token:08X} calls_to diverges from pinned dnfile"
            );

            let exp_from: Vec<u32> = expected.calls_from[&token.to_string()].clone();
            let act_from: Vec<u32> = graph.calls_from(*token).iter().copied().collect();
            assert_eq!(
                exp_from, act_from,
                "{sample_name}: 0x{token:08X} calls_from diverges from pinned dnfile"
            );
        }

        checked += 1;
    }

    // Guards against a silently-empty oracle passing this test vacuously.
    assert_eq!(
        checked, 8,
        "expected 8 pinned .NET samples, oracle covered {checked}"
    );
}
