//! CIL decoder integration and call-graph construction.
//!
//! The CIL decoder itself -- opcode tables, tiny/fat method headers,
//! instruction/operand decoding, exception regions -- is the vendored
//! `dnfile` fork's job (`third_party/dnfile/src/lang/cil/`, a port of pinned
//! `dncil`). `dnfile::DnPe::parse` already runs it eagerly over every
//! `MethodDef` with a body as part of loading (`ClrData::functions`),
//! applying the exact same filter as `helpers.py
//! get_dotnet_managed_method_bodies` (has IL, not abstract, not a
//! PInvoke-forwarded stub) and skipping -- never aborting the whole file
//! over -- a single malformed body, matching
//! `read_dotnet_method_body`'s `except MethodBodyFormatError: return None`.
//! This module is the integration point: token bookkeeping, the trivial
//! "one basic block per method" model upstream itself uses, instruction
//! addressing, and the calls-to/calls-from call graph
//! (`extractor.py DnfileFeatureExtractor.get_functions`).
//!
//! Auditing the vendored port against pinned `dncil` for this task found and
//! fixed three real defects (`third_party/dnfile/PATCH.md`): an `ldarg.2`
//! mnemonic typo, a missing `/ TINY_SIZE` division that wildly overcounted
//! tiny-format exception handlers, and `parse_functions` aborting the
//! *entire* file's parse on one method's malformed body instead of skipping
//! just that method.
//!
//! Upstream treats every managed method as exactly one basic block
//! (`extractor.py get_basic_blocks`: "each dotnet method is considered 1
//! basic block") and never implements `extract_function_loop` (raises
//! `NotImplementedError`). There is no CIL control-flow-graph split to port
//! for .NET -- building one here would be scope neither upstream nor any
//! .NET rule depends on. `insn.py get_callee`'s `MethodSpec` ->
//! `MethodDef`/`MemberRef` resolution (task 3's own brief calls this out) is
//! deferred to task 4: it needs a `MethodSpecRow.Method` accessor the
//! vendored crate doesn't expose yet (its `GenericMethod` row keeps that
//! coded index private, unlike every other row task 2 already reads), and
//! upstream's own calls-to/calls-from graph built here never resolves it
//! either -- `DNTokenAddress(insn.operand.value)` in `extractor.py` uses the
//! raw operand token, so a call through a `MethodSpec` operand becomes a
//! "calls from" entry under that raw token and is never matched as a "calls
//! to" edge (`methods.get(address)` only ever contains `MethodDef` tokens).

use std::collections::{BTreeSet, HashMap};

use dnfile::lang::cil::enums::OpCodeValue;
use dnfile::lang::cil::function::Function as CilFunction;
use dnfile::DnPe;

use super::ExtractError;
use crate::address::Address;

/// One managed method's decoded CIL body, keyed by its `MethodDef` token.
/// `helpers.py get_dotnet_managed_method_bodies`.
#[derive(Debug, Clone, Copy)]
pub struct DnFunction<'a> {
    pub token: u32,
    pub body: &'a CilFunction,
}

impl DnFunction<'_> {
    /// `extractor.py get_functions`: `FunctionHandle.address`.
    #[must_use]
    pub fn address(&self) -> Address {
        Address::DnToken(self.token)
    }

    /// `extractor.py get_basic_blocks`: "each dotnet method is considered 1
    /// basic block" -- the block's address is the function's own address.
    #[must_use]
    pub fn basic_block_address(&self) -> Address {
        self.address()
    }

    /// `extractor.py get_instructions`: `DNTokenOffsetAddress(bbh.address,
    /// insn.offset - (fh.inner.offset + fh.inner.header_size))` -- the
    /// instruction's offset from the *first opcode byte*, i.e. past the
    /// tiny/fat method header.
    #[must_use]
    pub fn instruction_address(
        &self,
        insn: &dnfile::lang::cil::instruction::Instruction,
    ) -> Address {
        let code_start = self.body.offset + self.body.header_size();
        let offset = insn.offset.saturating_sub(code_start) as u32;
        Address::DnTokenOffset {
            token: self.token,
            offset,
        }
    }
}

/// `helpers.py get_dotnet_managed_method_bodies`: every `MethodDef` with a
/// method body, in `MethodDef` table order. The vendored crate applies the
/// upstream filter (has IL, not abstract, not PInvoke) and the
/// skip-malformed-bodies behavior eagerly in `DnPe::parse`, so this is a
/// thin view over `ClrData::functions`, not a second parse pass.
pub fn managed_method_bodies<'a>(pe: &'a DnPe<'_>) -> Result<Vec<DnFunction<'a>>, ExtractError> {
    let net = pe.net().map_err(|e| ExtractError::Parse(e.to_string()))?;
    Ok(net
        .functions()
        .iter()
        .map(|body| DnFunction {
            token: body.token.value as u32,
            body,
        })
        .collect())
}

/// `extractor.py get_functions`'s calls-to/calls-from bookkeeping: unique
/// calls between managed methods, keyed by `MethodDef` token. Every function
/// in `functions` gets an entry (possibly empty), matching upstream
/// initializing both sets for every `FunctionHandle` up front.
#[derive(Debug, Default)]
pub struct CallGraph {
    pub calls_to: HashMap<u32, BTreeSet<u32>>,
    pub calls_from: HashMap<u32, BTreeSet<u32>>,
}

impl CallGraph {
    #[must_use]
    pub fn calls_to(&self, token: u32) -> &BTreeSet<u32> {
        static EMPTY: BTreeSet<u32> = BTreeSet::new();
        self.calls_to.get(&token).unwrap_or(&EMPTY)
    }

    #[must_use]
    pub fn calls_from(&self, token: u32) -> &BTreeSet<u32> {
        static EMPTY: BTreeSet<u32> = BTreeSet::new();
        self.calls_from.get(&token).unwrap_or(&EMPTY)
    }

    /// `function.py extract_recursive_call`: `fh.address in fh.ctx["calls_to"]`.
    #[must_use]
    pub fn is_recursive(&self, token: u32) -> bool {
        self.calls_to(token).contains(&token)
    }
}

/// `extractor.py get_functions`: for every `Call`/`Callvirt`/`Jmp`/`Newobj`
/// instruction, record the callee token as a "call from" of its caller, and
/// -- only when that token names one of `functions` (a `MethodDef` with a
/// body) -- the caller as a "call to" of the callee. A call through a
/// `MemberRef`/`MethodSpec`/native-import operand still becomes a raw "call
/// from" entry, exactly as upstream's `DNTokenAddress(insn.operand.value)`
/// does with no resolution; it just never becomes anyone's "call to" since
/// `methods.get(address)` (the `tokens` set here) only holds `MethodDef`
/// tokens with bodies.
#[must_use]
pub fn call_graph(functions: &[DnFunction<'_>]) -> CallGraph {
    let tokens: std::collections::HashSet<u32> = functions.iter().map(|f| f.token).collect();

    let mut graph = CallGraph::default();
    for f in functions {
        graph.calls_to.entry(f.token).or_default();
        graph.calls_from.entry(f.token).or_default();
    }

    for f in functions {
        for insn in &f.body.instructions {
            if !matches!(
                insn.opcode.value,
                OpCodeValue::Call | OpCodeValue::Callvirt | OpCodeValue::Jmp | OpCodeValue::Newobj
            ) {
                continue;
            }
            let Ok(target) = insn.operand.value() else {
                continue;
            };
            let target = target as u32;

            if tokens.contains(&target) {
                graph.calls_to.entry(target).or_default().insert(f.token);
            }
            graph.calls_from.entry(f.token).or_default().insert(target);
        }
    }

    graph
}
