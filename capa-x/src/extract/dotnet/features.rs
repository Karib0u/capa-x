//! File/global/function/instruction feature extraction, assembled directly into
//! a [`crate::freeze::StaticFeatures`] the same way `extract/{pe,elf}.rs` do
//! for their backends.
//!
//! Ported from `capa/features/extractors/dotnetfile.py` (file/global scope)
//! and `capa/features/extractors/dnfile/{file,insn,function}.py`
//! (`DnfileFeatureExtractor`'s file/instruction/function scope). Name
//! resolution (task 2, `names`/`types`) and CIL decoding plus the
//! calls-to/calls-from call graph (task 3, `function`) are reused as-is; this
//! module is where they turn into features.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use dnfile::lang::cil::enums::OpCodeValue;
use dnfile::lang::cil::instruction::{Instruction, Operand};
use dnfile::stream::meta_data_tables::mdtables::{self as mdtable, table_name_2_index};
use dnfile::{ClrData, DnPe};

use super::function::{call_graph, managed_method_bodies, CallGraph};
use super::names;
use super::types::{DnType, DnUnmanagedMethod};
use super::ExtractError;
use crate::address::Address;
use crate::extract::helpers::generate_symbols;
use crate::extract::strings::{extract_ascii_strings, extract_unicode_strings};
use crate::features::{Access, Feature, NumberValue, StringFeature};
use crate::freeze::{BasicBlockFeatures, FunctionFeatures, InstructionFeatures, StaticFeatures};
use crate::parallel::{self, AnalysisOptions};

/// `capa/features/extractors/strings.py` callers always use the default
/// minimum length (mirrors `extract/pe.rs`'s own constant).
const MIN_STRING_LEN: usize = 4;

/// ECMA-335 table numbers `get_callee`/`extract_unmanaged_call_characteristic_
/// features` compare a raw token's table byte against.
const METHODSPEC_TABLE_NUM: usize = 0x2B;
const METHODDEF_TABLE_NUM: usize = 0x06;

fn parse_err(e: dnfile::error::Error) -> ExtractError {
    ExtractError::Parse(e.to_string())
}

/// `helpers.py calculate_dotnet_token_value`.
fn calculate_token_value(table: usize, rid: usize) -> u32 {
    ((table as u32) & 0xFF) << 24 | (rid as u32 & 0x00FF_FFFF)
}

/// `Union[DnType, DnUnmanagedMethod]`, the value type of every
/// `DnFileFeatureExtractorCache` lookup table.
#[derive(Debug, Clone)]
enum DnEntity {
    Managed(DnType),
    Unmanaged(DnUnmanagedMethod),
}

impl std::fmt::Display for DnEntity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnEntity::Managed(t) => write!(f, "{t}"),
            DnEntity::Unmanaged(m) => write!(f, "{m}"),
        }
    }
}

/// `dnfile/extractor.py DnFileFeatureExtractorCache`: token -> un/managed
/// entity lookup tables, built once and shared by every instruction's
/// feature extraction.
struct TokenCache {
    imports: HashMap<u32, DnEntity>,
    native_imports: HashMap<u32, DnEntity>,
    methods: HashMap<u32, DnEntity>,
    fields: HashMap<u32, DnEntity>,
    types: HashMap<u32, DnEntity>,
}

impl TokenCache {
    fn build(net: &ClrData<'_>) -> Result<Self, ExtractError> {
        let mut imports = HashMap::new();
        for t in names::managed_imports(net)? {
            imports.insert(t.token, DnEntity::Managed(t));
        }
        let mut native_imports = HashMap::new();
        for m in names::unmanaged_imports(net)? {
            native_imports.insert(m.token, DnEntity::Unmanaged(m));
        }
        let mut methods = HashMap::new();
        for t in names::managed_methods(net)? {
            methods.insert(t.token, DnEntity::Managed(t));
        }
        let mut fields = HashMap::new();
        for t in names::fields(net)? {
            fields.insert(t.token, DnEntity::Managed(t));
        }
        let mut types = HashMap::new();
        for t in names::types(net)? {
            types.insert(t.token, DnEntity::Managed(t));
        }
        Ok(Self {
            imports,
            native_imports,
            methods,
            fields,
            types,
        })
    }

    fn get_import(&self, token: u32) -> Option<DnEntity> {
        self.imports.get(&token).cloned()
    }
    fn get_native_import(&self, token: u32) -> Option<DnEntity> {
        self.native_imports.get(&token).cloned()
    }
    fn get_method(&self, token: u32) -> Option<DnEntity> {
        self.methods.get(&token).cloned()
    }
    fn get_field(&self, token: u32) -> Option<DnEntity> {
        self.fields.get(&token).cloned()
    }
    fn get_type(&self, token: u32) -> Option<DnEntity> {
        self.types.get(&token).cloned()
    }
}

/// `insn.py get_callee`'s `MethodSpec` branch: resolve a `GenericMethod`
/// (this fork's name for ECMA-335's `MethodSpec`) row's `Method` coded index
/// to the token it names, without materializing the target row -- callers
/// only ever look the resulting token back up in [`TokenCache`].
fn resolve_methodspec_target(net: &ClrData<'_>, token_value: u32) -> Option<u32> {
    let rid = (token_value & 0x00FF_FFFF) as usize;
    let row_idx = rid.checked_sub(1)?;
    let table = net.md_table(super::METHODSPEC_RUST_NAME).ok()?;
    let row = table.row::<mdtable::GenericMethod>(row_idx).ok()?;
    if row.method.table.is_empty() {
        return None;
    }
    let target_table_num = table_name_2_index(row.method.table).ok()?;
    Some(calculate_token_value(
        target_table_num,
        row.method.row_index,
    ))
}

/// `insn.py get_callee`: map a .NET token to an un/managed (generic) method.
fn get_callee(net: &ClrData<'_>, cache: &TokenCache, token_value: u32) -> Option<DnEntity> {
    let table_num = (token_value >> 24) as usize & 0xFF;
    let token_ = if table_num == METHODSPEC_TABLE_NUM {
        resolve_methodspec_target(net, token_value)?
    } else {
        token_value
    };
    cache
        .get_import(token_)
        .or_else(|| cache.get_native_import(token_))
        .or_else(|| cache.get_method(token_))
}

// ---------------------------------------------------------------------
// instruction scope: `dnfile/insn.py`
// ---------------------------------------------------------------------

/// `insn.py extract_insn_api_features`.
fn extract_insn_api_features(
    net: &ClrData<'_>,
    cache: &TokenCache,
    insn: &Instruction,
    addr: Address,
    out: &mut Vec<(Address, Feature)>,
) {
    if !matches!(
        insn.opcode.value,
        OpCodeValue::Call | OpCodeValue::Callvirt | OpCodeValue::Jmp | OpCodeValue::Newobj
    ) {
        return;
    }
    let Ok(token_value) = insn.operand.value() else {
        return;
    };
    let Some(callee) = get_callee(net, cache, token_value as u32) else {
        return;
    };
    match callee {
        DnEntity::Managed(t) => {
            // ignore methods used to access properties
            if t.access.is_none() {
                out.push((addr, Feature::Api(t.to_string())));
            }
        }
        DnEntity::Unmanaged(m) => {
            for name in generate_symbols(&m.module, &m.method, false) {
                out.push((addr, Feature::Api(name)));
            }
        }
    }
}

/// `insn.py extract_insn_property_features`.
fn extract_insn_property_features(
    net: &ClrData<'_>,
    cache: &TokenCache,
    insn: &Instruction,
    addr: Address,
    out: &mut Vec<(Address, Feature)>,
) {
    let mut name: Option<String> = None;
    let mut access: Option<Access> = None;

    match insn.opcode.value {
        OpCodeValue::Call | OpCodeValue::Callvirt | OpCodeValue::Jmp => {
            if let Ok(token_value) = insn.operand.value() {
                if let Some(DnEntity::Managed(t)) = get_callee(net, cache, token_value as u32) {
                    if let Some(a) = t.access {
                        name = Some(t.to_string());
                        access = Some(a);
                    }
                }
            }
        }
        OpCodeValue::Ldfld | OpCodeValue::Ldflda | OpCodeValue::Ldsfld | OpCodeValue::Ldsflda => {
            if let Ok(token_value) = insn.operand.value() {
                if let Some(DnEntity::Managed(t)) = cache.get_field(token_value as u32) {
                    name = Some(t.to_string());
                    access = Some(Access::Read);
                }
            }
        }
        OpCodeValue::Stfld | OpCodeValue::Stsfld => {
            if let Ok(token_value) = insn.operand.value() {
                if let Some(DnEntity::Managed(t)) = cache.get_field(token_value as u32) {
                    name = Some(t.to_string());
                    access = Some(Access::Write);
                }
            }
        }
        _ => {}
    }

    if let Some(name) = name {
        if let Some(access) = access {
            out.push((
                addr,
                Feature::Property {
                    name: name.clone(),
                    access: Some(access),
                },
            ));
        }
        out.push((addr, Feature::Property { name, access: None }));
    }
}

/// `insn.py extract_insn_namespace_class_features`.
fn extract_insn_namespace_class_features(
    net: &ClrData<'_>,
    cache: &TokenCache,
    insn: &Instruction,
    addr: Address,
    out: &mut Vec<(Address, Feature)>,
) {
    let type_: Option<DnEntity> = match insn.opcode.value {
        OpCodeValue::Call
        | OpCodeValue::Callvirt
        | OpCodeValue::Jmp
        | OpCodeValue::Ldvirtftn
        | OpCodeValue::Ldftn
        | OpCodeValue::Newobj => insn
            .operand
            .value()
            .ok()
            .and_then(|v| get_callee(net, cache, v as u32)),
        OpCodeValue::Ldfld
        | OpCodeValue::Ldflda
        | OpCodeValue::Ldsfld
        | OpCodeValue::Ldsflda
        | OpCodeValue::Stfld
        | OpCodeValue::Stsfld => insn
            .operand
            .value()
            .ok()
            .and_then(|v| cache.get_field(v as u32)),
        // ECMA 335 VI.C.4.10
        OpCodeValue::Initobj
        | OpCodeValue::Box
        | OpCodeValue::Castclass
        | OpCodeValue::Cpobj
        | OpCodeValue::Isinst
        | OpCodeValue::Ldelem
        | OpCodeValue::Ldelema
        | OpCodeValue::Ldobj
        | OpCodeValue::Mkrefany
        | OpCodeValue::Newarr
        | OpCodeValue::Refanyval
        | OpCodeValue::Sizeof
        | OpCodeValue::Stobj
        | OpCodeValue::Unbox
        | OpCodeValue::Constrained
        | OpCodeValue::Stelem
        | OpCodeValue::Unbox_Any => insn
            .operand
            .value()
            .ok()
            .and_then(|v| cache.get_type(v as u32)),
        _ => None,
    };

    if let Some(DnEntity::Managed(t)) = type_ {
        out.push((
            addr,
            Feature::Class(DnType::format_name(&t.class, &t.namespace, "")),
        ));
        if !t.namespace.is_empty() {
            out.push((addr, Feature::Namespace(t.namespace)));
        }
    }
}

/// `insn.py extract_insn_number_features`.
fn extract_insn_number_features(
    insn: &Instruction,
    addr: Address,
    out: &mut Vec<(Address, Feature)>,
) {
    if insn.is_ldc() {
        if let Some(v) = insn.get_ldc() {
            out.push((addr, Feature::Number(NumberValue::Float(v))));
        }
    }
}

/// `insn.py extract_insn_string_features`.
fn extract_insn_string_features(
    net: &ClrData<'_>,
    insn: &Instruction,
    addr: Address,
    out: &mut Vec<(Address, Feature)>,
) {
    if !insn.is_ldstr() {
        return;
    }
    let Operand::StringToken(token) = &insn.operand else {
        return;
    };
    let Ok(user_string) = net.get_us(token.rid()) else {
        return;
    };
    // `len(user_string) >= 4` in Python counts Unicode code points, not
    // UTF-16 units or bytes -- `.chars().count()` matches.
    if user_string.chars().count() >= 4 {
        out.push((addr, Feature::String(StringFeature::Plain(user_string))));
    }
}

/// `insn.py extract_unmanaged_call_characteristic_features`.
fn extract_unmanaged_call_characteristic_features(
    net: &ClrData<'_>,
    insn: &Instruction,
    addr: Address,
    out: &mut Vec<(Address, Feature)>,
) {
    if !matches!(
        insn.opcode.value,
        OpCodeValue::Call | OpCodeValue::Callvirt | OpCodeValue::Jmp
    ) {
        return;
    }
    let Ok(token_value) = insn.operand.value() else {
        return;
    };
    let token_value = token_value as u32;
    let table_num = (token_value >> 24) as usize & 0xFF;
    if table_num != METHODDEF_TABLE_NUM {
        return;
    }
    let rid = (token_value & 0x00FF_FFFF) as usize;
    let Some(row_idx) = rid.checked_sub(1) else {
        return;
    };
    let Ok(table) = net.md_table("MethodDef") else {
        return;
    };
    let Ok(row) = table.row::<mdtable::MethodDef>(row_idx) else {
        return;
    };

    let pinvoke = row.flags.iter().any(|f| {
        matches!(
            f,
            mdtable::enums::ClrMethodAttr::AttrFlag(mdtable::enums::CorMethodAttrFlag::PinvokeImpl)
        )
    });
    let unmanaged = row.impl_flags.iter().any(|f| {
        matches!(
            f,
            mdtable::enums::ClrMethodImpl::MethodManaged(
                mdtable::enums::CorMethodManaged::Unmanaged
            )
        )
    });
    let native = row.impl_flags.iter().any(|f| {
        matches!(
            f,
            mdtable::enums::ClrMethodImpl::MethodCodeType(
                mdtable::enums::CorMethodCodeType::Native
            )
        )
    });
    if pinvoke || unmanaged || native {
        out.push((addr, Feature::Characteristic("unmanaged call".to_string())));
    }
}

/// `insn.py INSTRUCTION_HANDLERS`, in order.
fn extract_instruction_features(
    net: &ClrData<'_>,
    cache: &TokenCache,
    insn: &Instruction,
    addr: Address,
) -> Vec<(Address, Feature)> {
    let mut out = Vec::new();
    extract_insn_api_features(net, cache, insn, addr, &mut out);
    extract_insn_property_features(net, cache, insn, addr, &mut out);
    extract_insn_number_features(insn, addr, &mut out);
    extract_insn_string_features(net, insn, addr, &mut out);
    extract_insn_namespace_class_features(net, cache, insn, addr, &mut out);
    extract_unmanaged_call_characteristic_features(net, insn, addr, &mut out);
    out
}

// ---------------------------------------------------------------------
// function scope: `dnfile/function.py`
// ---------------------------------------------------------------------

/// `function.py FUNCTION_HANDLERS`, in order: calls to, calls from,
/// recursive call. `extract_function_loop` is upstream `NotImplementedError`
/// (no .NET codeflow graph -- see `function.rs`'s module doc) and is not
/// ported.
fn extract_function_features(token: u32, graph: &CallGraph, out: &mut Vec<(Address, Feature)>) {
    for &caller in graph.calls_to(token) {
        out.push((
            Address::DnToken(caller),
            Feature::Characteristic("calls to".to_string()),
        ));
    }
    for &callee in graph.calls_from(token) {
        out.push((
            Address::DnToken(callee),
            Feature::Characteristic("calls from".to_string()),
        ));
    }
    if graph.is_recursive(token) {
        out.push((
            Address::DnToken(token),
            Feature::Characteristic("recursive call".to_string()),
        ));
    }
}

// ---------------------------------------------------------------------
// file/global scope: `dotnetfile.py` + `dnfile/file.py`
// ---------------------------------------------------------------------

/// `DnfileFeatureExtractor.__init__`'s precomputed `self.global_features`:
/// `extract_file_format` + `extract_file_os` + `extract_file_arch`, in that
/// order.
fn global_features(pe: &DnPe<'_>, net: &ClrData<'_>) -> Result<Vec<Feature>, ExtractError> {
    let mut out = vec![
        Feature::Format("dotnet".to_string()),
        Feature::Format("pe".to_string()),
        Feature::Os("any".to_string()),
    ];

    // `dotnetfile.py extract_file_arch`: distinguishes i386/amd64 by the
    // CLR header's 32-bit-required flag combined with the PE optional
    // header's own bitness; anything else (e.g. "any CPU" with neither/both
    // signals set) falls back to `ARCH_ANY`.
    let is_64 = pe.pe().map_err(parse_err)?.is_64;
    let bit32_required = net.flags.contains(&dnfile::ClrHeaderFlags::BitRequired32);
    let arch = if bit32_required && !is_64 {
        "i386"
    } else if !bit32_required && is_64 {
        "amd64"
    } else {
        "any"
    };
    out.push(Feature::Arch(arch.to_string()));

    Ok(out)
}

/// `dnfile/file.py FILE_HANDLERS`, in order: import names, function names,
/// strings, format (yielded again here -- see the module doc's note on
/// upstream's own duplicate global/file `Format` emission, confirmed against
/// a live run of pinned Python capa), mixed-mode characteristic, namespace,
/// class.
fn extract_file_features(
    net: &ClrData<'_>,
    buf: &[u8],
) -> Result<Vec<(Address, Feature)>, ExtractError> {
    let mut out = Vec::new();

    for t in names::managed_imports(net)? {
        out.push((Address::DnToken(t.token), Feature::Import(t.to_string())));
    }
    for m in names::unmanaged_imports(net)? {
        for name in generate_symbols(&m.module, &m.method, true) {
            out.push((Address::DnToken(m.token), Feature::Import(name)));
        }
    }

    for t in names::managed_methods(net)? {
        out.push((
            Address::DnToken(t.token),
            Feature::FunctionName(t.to_string()),
        ));
    }

    for s in extract_ascii_strings(buf, MIN_STRING_LEN) {
        out.push((
            Address::File(s.offset as u64),
            Feature::String(StringFeature::Plain(s.s)),
        ));
    }
    for s in extract_unicode_strings(buf, MIN_STRING_LEN) {
        out.push((
            Address::File(s.offset as u64),
            Feature::String(StringFeature::Plain(s.s)),
        ));
    }

    out.push((Address::NoAddress, Feature::Format("dotnet".to_string())));
    out.push((Address::NoAddress, Feature::Format("pe".to_string())));

    if names::is_mixed_mode(net) {
        out.push((
            Address::NoAddress,
            Feature::Characteristic("mixed mode".to_string()),
        ));
    }

    // `extract_file_namespace_features`: raw (non-nested-resolved)
    // `TypeNamespace` off every `TypeDef` then every `TypeRef` row, deduped,
    // empty string discarded -- deliberately *not* `names::types()`'s
    // nested-chain-resolved namespace (that's what `extract_file_class_
    // features` below needs instead).
    let mut namespaces: BTreeSet<String> = BTreeSet::new();
    if let Ok(table) = net.md_table("TypeDef") {
        for i in 0..table.row_count() {
            let row = table.row::<mdtable::TypeDef>(i).map_err(parse_err)?;
            namespaces.insert(row.type_namespace.clone());
        }
    }
    if let Ok(table) = net.md_table("TypeRef") {
        for i in 0..table.row_count() {
            let row = table.row::<mdtable::TypeRef>(i).map_err(parse_err)?;
            namespaces.insert(row.type_namespace.clone());
        }
    }
    namespaces.remove("");
    for namespace in namespaces {
        out.push((Address::NoAddress, Feature::Namespace(namespace)));
    }

    // `extract_file_class_features`: every `TypeDef` then every `TypeRef`,
    // nested-chain-resolved -- exactly `names::types()`'s own output.
    for t in names::types(net)? {
        out.push((Address::DnToken(t.token), Feature::Class(t.to_string())));
    }

    Ok(out)
}

// ---------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------

/// `DnfileFeatureExtractor`, assembled directly into a `StaticFeatures`
/// (matching how `extract/{pe,elf}.rs` build their own backends) rather than
/// staying behind capa's `StaticFeatureExtractor` trait.
///
/// Thin wrapper around [`extract_dotnet_from_pe`] that also does the parse
/// (`super::load`) -- convenient for callers (tests, and any caller that has
/// no reason to keep the parsed `DnPe` around) that don't need to time the
/// parse separately from feature synthesis. `capa_x::api` calls
/// [`extract_dotnet_from_pe`] directly instead, so its `--timing` phases stay
/// meaningful: parsing (which includes the vendored fork's eager CIL decode,
/// `function.rs`'s module doc) accrues to `load_and_recover` same as PE/ELF's
/// own parse+recovery step, while this function's own per-method loop -- the
/// `--jobs` parallel seam -- accrues to `extraction`.
pub fn extract_dotnet(
    buf: &[u8],
    options: &AnalysisOptions,
) -> Result<StaticFeatures, ExtractError> {
    let pe = super::load(buf)?;
    extract_dotnet_from_pe(&pe, buf, options)
}

/// Per-method extraction is the parallel seam (`options.jobs`), same shape as
/// `flirt::enrich_static_features`'s per-function one: every method reads the
/// same immutable `net`/`cache`/`graph` and writes only its own owned
/// `FunctionFeatures`, and [`parallel::map`] returns results in input --
/// `MethodDef` table -- order before they're inserted into the `BTreeMap`, so
/// the produced `StaticFeatures` does not depend on how many threads ran.
pub fn extract_dotnet_from_pe(
    pe: &DnPe<'_>,
    buf: &[u8],
    options: &AnalysisOptions,
) -> Result<StaticFeatures, ExtractError> {
    let net = pe.net().map_err(parse_err)?;

    let global = global_features(pe, net)?;
    let file = extract_file_features(net, buf)?;

    let cache = TokenCache::build(net)?;
    let bodies = managed_method_bodies(pe)?;
    let graph = call_graph(&bodies);

    let functions: BTreeMap<Address, FunctionFeatures> =
        parallel::map(options.jobs, &bodies, |f| {
            let mut ffeatures = Vec::new();
            extract_function_features(f.token, &graph, &mut ffeatures);

            let mut instructions: BTreeMap<Address, InstructionFeatures> = BTreeMap::new();
            for insn in &f.body.instructions {
                let addr = f.instruction_address(insn);
                let ifeatures = extract_instruction_features(net, &cache, insn, addr);
                instructions.insert(
                    addr,
                    InstructionFeatures {
                        features: ifeatures,
                    },
                );
            }

            let mut basic_blocks: BTreeMap<Address, BasicBlockFeatures> = BTreeMap::new();
            basic_blocks.insert(
                f.basic_block_address(),
                // `get_basic_block_features`: "we don't support basic block
                // features" -- always empty.
                BasicBlockFeatures {
                    features: Vec::new(),
                    instructions,
                },
            );

            (
                f.address(),
                FunctionFeatures {
                    features: ffeatures,
                    basic_blocks,
                },
            )
        })
        .into_iter()
        .collect();

    Ok(StaticFeatures {
        base_address: Address::NoAddress,
        sample_hashes: crate::extract::sample_hashes(buf),
        global_features: global,
        file_features: file,
        functions,
    })
}
