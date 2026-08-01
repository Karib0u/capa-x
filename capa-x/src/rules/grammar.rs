//! Rule body grammar: YAML -> `Node`/`Statement`/`Feature`. Ported from
//! `capa/rules/__init__.py`'s `build_statements`, `parse_feature`,
//! `parse_description`, `parse_bytes`, `parse_int`, `parse_range`,
//! `pop_statement_description_entry`, `trim_dll_part`, `unique`.

use serde_yaml::Value;

use crate::features::{
    Access, ComKind, CompiledRegex, Feature, StringFeature, MAX_BYTES_FEATURE_SIZE,
    MAX_OPERAND_INDEX,
};
use crate::rules::scope::ensure_feature_valid_for_scopes;
use crate::rules::{Node, RuleError, Scope, Scopes, Statement};

const DESCRIPTION_SEPARATOR: &str = " = ";

/// capa/rules/__init__.py: VALID_ARCH
const VALID_ARCH: &[&str] = &["i386", "amd64", "aarch64", "any"];
/// capa/rules/__init__.py: VALID_FORMAT, extended with `macho`
/// -- a capa-x extension, since pinned capa 9.4.0 has no raw Mach-O
/// input at all. Official capa-rules never reference it (they stay
/// unmodified, forever); this only lets capa-x's own rules and this
/// crate's synthetic-rule tests use `format: macho`. Any other value is
/// still a hard error, per this crate's "never silently skip" rule.
const VALID_FORMAT: &[&str] = &["pe", "elf", "dotnet", "macho"];
/// capa/features/common.py: VALID_OS (ELF `OS` enum values, plus windows/linux/macos/any/android)
const VALID_OS: &[&str] = &[
    "hpux",
    "netbsd",
    "linux",
    "hurd",
    "86open",
    "solaris",
    "aix",
    "irix",
    "freebsd",
    "tru64",
    "modesto",
    "openbsd",
    "openvms",
    "nsk",
    "aros",
    "fenixos",
    "cloud",
    "syllable",
    "nacl",
    "android",
    "dragonfly BSD",
    "illumos",
    "z/os",
    "unix",
    "windows",
    "macos",
    "any",
];

/// an already-typed scalar value, the result of `parse_description`.
#[derive(Debug, Clone)]
enum RawScalar {
    Str(String),
    Int(i128),
    Bytes(Vec<u8>),
}

/// entry point: build a `Node` from one list item of a rule's `features:`
/// list (or a nested statement's children) -- a YAML mapping with 1-2 keys
/// (the statement/feature key, and optionally a sibling `description`).
pub fn build_statements(d: &serde_yaml::Mapping, scopes: Scopes) -> Result<Node, RuleError> {
    if d.len() > 2 {
        return Err(RuleError::invalid("too many statements"));
    }

    let (key_value, raw_value) = d
        .iter()
        .next()
        .ok_or_else(|| RuleError::invalid("empty statement"))?;
    let key = key_value
        .as_str()
        .ok_or_else(|| RuleError::invalid("statement key must be a string"))?
        .to_string();

    // `pop_statement_description_entry`: a no-op unless raw_value is a
    // sequence, in which case a lone `{description: ...}` child is stripped
    // out and returned. Leaf (scalar) features never take this path; their
    // description comes from a sibling `description:` key instead (below).
    let mut seq_children: Option<Vec<Value>> = match raw_value {
        Value::Sequence(s) => Some(s.clone()),
        _ => None,
    };
    let popped_description = match &mut seq_children {
        Some(children) => pop_statement_description_entry(children)?,
        None => None,
    };

    match key.as_str() {
        "and" => {
            let built = build_children(require_seq(seq_children, &key)?, scopes)?;
            Ok(Node {
                stmt: Statement::And(built),
                description: popped_description,
            })
        }
        "or" => {
            let built = build_children(require_seq(seq_children, &key)?, scopes)?;
            Ok(Node {
                stmt: Statement::Or(built),
                description: popped_description,
            })
        }
        "not" => {
            let children = require_seq(seq_children, &key)?;
            if children.len() != 1 {
                return Err(RuleError::invalid(
                    "not statement must have exactly one child statement",
                ));
            }
            let child = build_statements(&as_feature_mapping(&children[0])?, scopes)?;
            Ok(Node {
                stmt: Statement::Not(Box::new(child)),
                description: popped_description,
            })
        }
        "optional" => {
            // `optional` is an alias for `0 or more`.
            let built = build_children(require_seq(seq_children, &key)?, scopes)?;
            Ok(Node {
                stmt: Statement::Some {
                    count: 0,
                    children: built,
                },
                description: popped_description,
            })
        }
        "process" => build_subscope(
            &key,
            Scope::Process,
            seq_children,
            scopes,
            scopes.dynamic,
            "`process` subscope supported only for `file` scope",
            popped_description,
        ),
        "thread" => build_subscope(
            &key,
            Scope::Thread,
            seq_children,
            scopes,
            scopes.dynamic,
            "`thread` subscope supported only for the `process` scope",
            popped_description,
        ),
        "span of calls" => build_subscope(
            &key,
            Scope::SpanOfCalls,
            seq_children,
            scopes,
            scopes.dynamic,
            "`span of calls` subscope supported only for the `process` and `thread` scopes",
            popped_description,
        ),
        "call" => build_subscope(
            &key,
            Scope::Call,
            seq_children,
            scopes,
            scopes.dynamic,
            "`call` subscope supported only for the `process`, `thread`, and `call` scopes",
            popped_description,
        ),
        "function" => build_subscope(
            &key,
            Scope::Function,
            seq_children,
            scopes,
            scopes.static_,
            "`function` subscope supported only for `file` scope",
            popped_description,
        ),
        "basic block" => build_subscope(
            &key,
            Scope::BasicBlock,
            seq_children,
            scopes,
            scopes.static_,
            "`basic block` subscope supported only for `function` scope",
            popped_description,
        ),
        "instruction" => build_instruction_subscope(seq_children, scopes, popped_description),
        "string" => {
            // `string:` requires an explicit string value; a bare numeric- or
            // boolean-looking scalar is ambiguous and rejected (rather than
            // silently coerced), matching upstream's dedicated check.
            match raw_value {
                Value::String(_) => build_default_leaf(&key, d, scopes),
                other => Err(RuleError::invalid(format!(
                    "ambiguous string value {other:?}, must be defined as explicit string"
                ))),
            }
        }
        _ if key.starts_with("count(") && key.ends_with(')') => {
            build_count(&key, raw_value, scopes, popped_description)
        }
        _ if key.ends_with(" or more") => {
            let prefix = key.strip_suffix(" or more").unwrap_or(&key);
            let count = parse_u32(prefix.trim())?;
            let built = build_children(require_seq(seq_children, &key)?, scopes)?;
            Ok(Node {
                stmt: Statement::Some {
                    count,
                    children: built,
                },
                description: popped_description,
            })
        }
        _ if key.starts_with("operand[") && key.ends_with("].number") => {
            build_operand(&key, "].number", d, scopes, |i, v| {
                Ok(Feature::OperandNumber(
                    i,
                    crate::features::NumberValue::Int(v),
                ))
            })
        }
        _ if key.starts_with("operand[") && key.ends_with("].offset") => {
            build_operand(&key, "].offset", d, scopes, |i, v| {
                Ok(Feature::OperandOffset(
                    i,
                    i64::try_from(v).map_err(|_| {
                        RuleError::invalid(format!("operand offset value out of range: {v}"))
                    })?,
                ))
            })
        }
        "os" if !value_as_plain_str(raw_value).is_some_and(|s| VALID_OS.contains(&s.as_str())) => {
            Err(RuleError::invalid(format!(
                "unexpected os value {raw_value:?}"
            )))
        }
        "format"
            if !value_as_plain_str(raw_value)
                .is_some_and(|s| VALID_FORMAT.contains(&s.as_str())) =>
        {
            Err(RuleError::invalid(format!(
                "unexpected format value {raw_value:?}"
            )))
        }
        "arch"
            if !value_as_plain_str(raw_value).is_some_and(|s| VALID_ARCH.contains(&s.as_str())) =>
        {
            Err(RuleError::invalid(format!(
                "unexpected arch value {raw_value:?}"
            )))
        }
        _ if key.starts_with("property/") => {
            let access_str = key.strip_prefix("property/").unwrap_or_default();
            let access = Access::parse(access_str).ok_or_else(|| {
                RuleError::invalid(format!("unexpected {key} access {access_str}"))
            })?;
            let sibling = sibling_description(d)?;
            let (value, description) = parse_description(raw_value, &key, sibling)?;
            let name = expect_string(value, &key)?;
            let feature = Feature::Property {
                name,
                access: Some(access),
            };
            ensure_feature_valid_for_scopes(scopes, &feature)?;
            Ok(Node {
                stmt: Statement::Leaf(feature),
                description,
            })
        }
        _ if key.starts_with("com/") => {
            let com_type_name = key.strip_prefix("com/").unwrap_or_default();
            let com_kind = ComKind::parse(com_type_name).ok_or_else(|| {
                RuleError::invalid(format!("unexpected COM type: {com_type_name}"))
            })?;
            let sibling = sibling_description(d)?;
            let (value, description) = parse_description(raw_value, &key, sibling)?;
            let name = expect_string(value, &key)?;
            // upstream expands `com/class`/`com/interface` into an `Or` of
            // GUID string/bytes checks at rule-parse time (`translate_com_feature`,
            // which requires the capa-rules COM database) and never
            // scope-checks the result. By design, this port
            // keeps the COM symbol as a single feature and defers GUID
            // expansion to the matching engine; scope-legality is
            // likewise skipped for it (see `ensure_feature_valid_for_scopes`).
            Ok(Node {
                stmt: Statement::Leaf(Feature::Com(com_kind, name)),
                description,
            })
        }
        _ => build_default_leaf(&key, d, scopes),
    }
}

fn require_seq(seq: Option<Vec<Value>>, key: &str) -> Result<Vec<Value>, RuleError> {
    seq.ok_or_else(|| RuleError::invalid(format!("`{key}` must be a list of child statements")))
}

fn build_children(children: Vec<Value>, scopes: Scopes) -> Result<Vec<Node>, RuleError> {
    let mut built = Vec::with_capacity(children.len());
    for c in children {
        built.push(build_statements(&as_feature_mapping(&c)?, scopes)?);
    }
    Ok(unique_nodes(built))
}

#[allow(clippy::too_many_arguments)]
fn build_subscope(
    key: &str,
    scope: Scope,
    seq_children: Option<Vec<Value>>,
    outer_scopes: Scopes,
    check_against: Option<Scope>,
    incompatible_msg: &str,
    description: Option<String>,
) -> Result<Node, RuleError> {
    let _ = outer_scopes;
    if !super::is_subscope_compatible(check_against, scope) {
        return Err(RuleError::invalid(incompatible_msg));
    }
    let children = require_seq(seq_children, key)?;
    if children.len() != 1 {
        return Err(RuleError::invalid(
            "subscope must have exactly one child statement",
        ));
    }
    let new_scopes = if matches!(
        scope,
        Scope::Process | Scope::Thread | Scope::SpanOfCalls | Scope::Call
    ) {
        Scopes {
            static_: None,
            dynamic: Some(scope),
        }
    } else {
        Scopes {
            static_: Some(scope),
            dynamic: None,
        }
    };
    let body = build_statements(&as_feature_mapping(&children[0])?, new_scopes)?;
    Ok(Node {
        stmt: Statement::Subscope {
            scope,
            body: Box::new(body),
        },
        description,
    })
}

fn build_instruction_subscope(
    seq_children: Option<Vec<Value>>,
    outer_scopes: Scopes,
    description: Option<String>,
) -> Result<Node, RuleError> {
    if !super::is_subscope_compatible(outer_scopes.static_, Scope::Instruction) {
        return Err(RuleError::invalid(
            "`instruction` subscope supported only for `function` and `basic block` scope",
        ));
    }
    let children = require_seq(seq_children, "instruction")?;
    let new_scopes = Scopes {
        static_: Some(Scope::Instruction),
        dynamic: None,
    };
    let body = if children.len() == 1 {
        build_statements(&as_feature_mapping(&children[0])?, new_scopes)?
    } else {
        // shorthand: the top-level AND is implied when there's more than one
        // child directly under `instruction:`.
        let built = build_children(children, new_scopes)?;
        Node {
            stmt: Statement::And(built),
            description: None,
        }
    };
    Ok(Node {
        stmt: Statement::Subscope {
            scope: Scope::Instruction,
            body: Box::new(body),
        },
        description,
    })
}

fn build_operand(
    key: &str,
    suffix: &str,
    d: &serde_yaml::Mapping,
    scopes: Scopes,
    ctor: impl Fn(u8, i128) -> Result<Feature, RuleError>,
) -> Result<Node, RuleError> {
    let index_str = &key["operand[".len()..key.len() - suffix.len()];
    let index: i128 = index_str
        .parse()
        .map_err(|_| RuleError::invalid("operand index must be an integer"))?;
    if index < 0 || index > MAX_OPERAND_INDEX as i128 {
        // upstream would raise an uncaught IndexError here (`OperandNumber.NAMES[index]`)
        // for index >= MAX_OPERAND_COUNT; we turn that into a clean error instead
        // of panicking, per the project's "no panics on untrusted input" rule.
        return Err(RuleError::invalid(format!(
            "operand index must be between 0 and {MAX_OPERAND_INDEX}"
        )));
    }
    let index = index as u8;

    let raw_value = d
        .get(key)
        .ok_or_else(|| RuleError::invalid(format!("missing value for {key}")))?;
    let sibling = sibling_description(d)?;
    let (value, description) = parse_description(raw_value, key, sibling)?;
    let n = expect_int(value, key)?;
    let feature = ctor(index, n)?;
    ensure_feature_valid_for_scopes(scopes, &feature)?;
    Ok(Node {
        stmt: Statement::Leaf(feature),
        description,
    })
}

/// the shared default dispatch for simple leaf keys: api, string, substring,
/// bytes, number, offset, mnemonic, "basic blocks", characteristic, export,
/// import, section, match, function-name, os, format, arch, class,
/// namespace, property (bare, no access).
fn build_default_leaf(
    key: &str,
    d: &serde_yaml::Mapping,
    scopes: Scopes,
) -> Result<Node, RuleError> {
    let raw_value = d
        .get(key)
        .ok_or_else(|| RuleError::invalid(format!("missing value for {key}")))?;
    let sibling = sibling_description(d)?;
    let (value, mut description) = parse_description(raw_value, key, sibling)?;

    let feature = if key == "api" {
        let s = expect_string(value, key)?;
        Feature::Api(trim_dll_part(&s))
    } else if key == "string" {
        let s = expect_string(value, key)?;
        string_factory(&s)?
    } else {
        feature_from_named_value(key, value, &mut description)?
    };

    ensure_feature_valid_for_scopes(scopes, &feature)?;
    Ok(Node {
        stmt: Statement::Leaf(feature),
        description,
    })
}

/// port of `parse_feature` dispatch + construction, for the keys that don't
/// need bespoke handling above (api/string are special-cased by the caller).
fn feature_from_named_value(
    key: &str,
    value: RawScalarLike,
    description: &mut Option<String>,
) -> Result<Feature, RuleError> {
    let _ = description;
    match key {
        "api" => Ok(Feature::Api(expect_string(value, key)?)),
        "substring" => Ok(Feature::String(StringFeature::Substring(expect_string(
            value, key,
        )?))),
        "bytes" => Ok(Feature::Bytes(expect_bytes(value, key)?)),
        "number" => Ok(Feature::Number(crate::features::NumberValue::Int(
            expect_int(value, key)?,
        ))),
        "offset" => {
            let n = expect_int(value, key)?;
            Ok(Feature::Offset(i64::try_from(n).map_err(|_| {
                RuleError::invalid(format!("offset value out of range: {n}"))
            })?))
        }
        "mnemonic" => Ok(Feature::Mnemonic(expect_string(value, key)?)),
        "characteristic" => Ok(Feature::Characteristic(expect_string(value, key)?)),
        "export" => Ok(Feature::Export(expect_string(value, key)?)),
        "import" => Ok(Feature::Import(expect_string(value, key)?)),
        "section" => Ok(Feature::Section(expect_string(value, key)?)),
        "match" => Ok(Feature::MatchedRule(expect_string(value, key)?)),
        "function-name" => Ok(Feature::FunctionName(expect_string(value, key)?)),
        "os" => Ok(Feature::Os(expect_string(value, key)?)),
        "format" => Ok(Feature::Format(expect_string(value, key)?)),
        "arch" => Ok(Feature::Arch(expect_string(value, key)?)),
        "class" => Ok(Feature::Class(expect_string(value, key)?)),
        "namespace" => Ok(Feature::Namespace(expect_string(value, key)?)),
        "property" => Ok(Feature::Property {
            name: expect_string(value, key)?,
            access: None,
        }),
        other => Err(RuleError::invalid(format!("unexpected statement: {other}"))),
    }
}

type RawScalarLike = RawScalar;

/// port of the `count(...)` branch: `count(<term>[(<arg>)]): <spec>`
fn build_count(
    key: &str,
    count_value: &Value,
    scopes: Scopes,
    popped_description: Option<String>,
) -> Result<Node, RuleError> {
    // pop_statement_description_entry only fires for sequence values, and
    // `count(...)`'s value is always the min/max spec (a scalar), so
    // popped_description is always None here; keep the parameter anyway to
    // make that invariant explicit at call sites.
    debug_assert!(popped_description.is_none());

    let inner = key
        .strip_prefix("count(")
        .and_then(|s| s.strip_suffix(')'))
        .ok_or_else(|| RuleError::invalid(format!("unexpected statement: {key}")))?;

    let (term, arg) = match inner.find('(') {
        Some(idx) => {
            let (t, rest) = inner.split_at(idx);
            let rest = &rest[1..];
            let arg = rest
                .strip_suffix(')')
                .ok_or_else(|| RuleError::invalid(format!("unexpected statement: {key}")))?;
            (t, Some(arg))
        }
        None => (inner, None),
    };

    let (feature, description) = match arg {
        None => {
            if term == "basic blocks" {
                (Feature::BasicBlock, None)
            } else {
                return Err(RuleError::invalid(format!(
                    "count({term}) requires an argument"
                )));
            }
        }
        Some(raw_arg) => {
            if term == "string" {
                (string_factory(raw_arg)?, None)
            } else {
                let arg_value = Value::String(raw_arg.to_string());
                let (mut value, description) = parse_description(&arg_value, term, None)?;
                if term == "api" {
                    if let RawScalar::Str(s) = &value {
                        value = RawScalar::Str(trim_dll_part(s));
                    }
                }
                let mut desc_opt = description;
                let feature = feature_from_named_value(term, value, &mut desc_opt)?;
                (feature, desc_opt)
            }
        }
    };
    ensure_feature_valid_for_scopes(scopes, &feature)?;

    let (min, max) = parse_count_spec(count_value)?;
    Ok(Node {
        stmt: Statement::Range {
            feature,
            min: min.unwrap_or(0),
            max,
        },
        description,
    })
}

fn parse_count_spec(value: &Value) -> Result<(Option<u32>, Option<u32>), RuleError> {
    match value {
        Value::Number(n) => {
            let count = n
                .as_u64()
                .or_else(|| n.as_i64().filter(|v| *v >= 0).map(|v| v as u64))
                .ok_or_else(|| RuleError::invalid(format!("unexpected range: {n}")))?;
            let count = u32::try_from(count)
                .map_err(|_| RuleError::invalid(format!("count out of range: {count}")))?;
            Ok((Some(count), Some(count)))
        }
        Value::String(s) => {
            if let Some(prefix) = s.strip_suffix(" or more") {
                Ok((Some(parse_u32(prefix.trim())?), None))
            } else if let Some(prefix) = s.strip_suffix(" or fewer") {
                Ok((None, Some(parse_u32(prefix.trim())?)))
            } else if s.starts_with('(') {
                parse_range(s)
            } else {
                Err(RuleError::invalid(format!("unexpected range: {s}")))
            }
        }
        other => Err(RuleError::invalid(format!("unexpected range: {other:?}"))),
    }
}

/// port of `parse_range`: "(min, max)" with either side optionally blank.
fn parse_range(s: &str) -> Result<(Option<u32>, Option<u32>), RuleError> {
    if !s.starts_with('(') || !s.ends_with(')') {
        return Err(RuleError::invalid(format!("invalid range: {s}")));
    }
    let inner = &s[1..s.len() - 1];
    let (min_spec, max_spec) = match inner.split_once(',') {
        Some((a, b)) => (a.trim(), b.trim()),
        None => (inner.trim(), ""),
    };

    let min = if min_spec.is_empty() {
        None
    } else {
        let v = parse_int(min_spec)?;
        if v < 0 {
            return Err(RuleError::invalid("range min less than zero"));
        }
        Some(
            u32::try_from(v)
                .map_err(|_| RuleError::invalid(format!("range min out of range: {v}")))?,
        )
    };
    let max = if max_spec.is_empty() {
        None
    } else {
        let v = parse_int(max_spec)?;
        if v < 0 {
            return Err(RuleError::invalid("range max less than zero"));
        }
        Some(
            u32::try_from(v)
                .map_err(|_| RuleError::invalid(format!("range max out of range: {v}")))?,
        )
    };

    if let (Some(mn), Some(mx)) = (min, max) {
        if mx < mn {
            return Err(RuleError::invalid("range max less than min"));
        }
    }
    Ok((min, max))
}

fn parse_u32(s: &str) -> Result<u32, RuleError> {
    let v = parse_int(s)?;
    u32::try_from(v).map_err(|_| RuleError::invalid(format!("value out of range: {v}")))
}

/// port of `parse_int`: hex if `0x`-prefixed, else decimal. Note this does
/// *not* special-case a leading `-` before `0x` (matching upstream, which
/// has the same gap) -- in practice this is never hit because a `-0x..`
/// scalar is already resolved to a native YAML integer before reaching this
/// function (verified empirically against both PyYAML and serde_yaml).
fn parse_int(s: &str) -> Result<i128, RuleError> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        i128::from_str_radix(hex, 16)
            .map_err(|e| RuleError::invalid(format!("invalid hex integer: {s} ({e})")))
    } else {
        s.parse::<i128>()
            .map_err(|e| RuleError::invalid(format!("invalid integer: {s} ({e})")))
    }
}

/// port of `parse_bytes`
fn parse_bytes(s: &str) -> Result<Vec<u8>, RuleError> {
    let cleaned = s.replace(' ', "");
    let bytes = crate::features::hex_decode(&cleaned).map_err(|_| {
        RuleError::invalid(format!(
            "unexpected bytes value: must be a valid hex sequence: \"{s}\""
        ))
    })?;
    if bytes.len() > MAX_BYTES_FEATURE_SIZE {
        return Err(RuleError::invalid(format!("unexpected bytes value: byte sequences must be no larger than {MAX_BYTES_FEATURE_SIZE} bytes")));
    }
    Ok(bytes)
}

/// port of `trim_dll_part`
fn trim_dll_part(api: &str) -> String {
    if api.contains(".#") {
        return api.to_string();
    }
    if api.matches('.').count() == 1 && !api.contains("::") {
        if let Some((_, rest)) = api.split_once('.') {
            return rest.to_string();
        }
    }
    api.to_string()
}

/// port of `StringFactory`: dispatches to `Regex` when the value looks like
/// `/pattern/` or `/pattern/i`, else a plain `String`.
fn string_factory(value: &str) -> Result<Feature, RuleError> {
    if value.starts_with('/') && (value.ends_with('/') || value.ends_with("/i")) && value.len() > 1
    {
        let re = CompiledRegex::compile(value).map_err(RuleError::invalid)?;
        Ok(Feature::String(StringFeature::Regex(re)))
    } else {
        Ok(Feature::String(StringFeature::Plain(value.to_string())))
    }
}

/// port of `pop_statement_description_entry`
fn pop_statement_description_entry(children: &mut Vec<Value>) -> Result<Option<String>, RuleError> {
    let description_key = Value::String("description".to_string());
    let mut found_idx: Option<usize> = None;
    let mut count = 0;
    for (i, c) in children.iter().enumerate() {
        if let Value::Mapping(m) = c {
            if m.len() == 1 && m.contains_key(&description_key) {
                count += 1;
                if found_idx.is_none() {
                    found_idx = Some(i);
                }
            }
        }
    }
    if count > 1 {
        return Err(RuleError::invalid(
            "statements can only have one description",
        ));
    }
    let Some(idx) = found_idx else {
        return Ok(None);
    };
    let removed = children.remove(idx);
    if let Value::Mapping(m) = removed {
        match m.get(&description_key) {
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(other) => Err(RuleError::invalid(format!(
                "description must be a string, got: {other:?}"
            ))),
            None => Ok(None),
        }
    } else {
        Ok(None)
    }
}

/// port of `unique`: order-preserving de-duplication of a compound
/// statement's children, keyed on `capa.features.common.Feature.__eq__`
/// (`(name, value)`, deliberately excluding `description` -- see
/// `Feature.__hash__`/`__eq__`, `capa/features/common.py`). Only leaf
/// *feature* children can ever be duplicates of one another this way: a
/// compound `Statement` subclass (`And`/`Or`/`Not`/`Some`/`Range`) never
/// overrides `__eq__`/`__hash__` upstream, so two structurally-identical
/// nested blocks are always "different objects" and both survive --
/// deliberately *not* using `Node`'s derived (structural, description-
/// inclusive) `PartialEq` here, which would get both cases backwards.
fn unique_nodes(nodes: Vec<Node>) -> Vec<Node> {
    let mut seen: Vec<Feature> = Vec::with_capacity(nodes.len());
    let mut out = Vec::with_capacity(nodes.len());
    for n in nodes {
        if let Statement::Leaf(f) = &n.stmt {
            if seen.iter().any(|sf| sf == f) {
                continue;
            }
            seen.push(f.clone());
        }
        out.push(n);
    }
    out
}

fn as_feature_mapping(v: &Value) -> Result<serde_yaml::Mapping, RuleError> {
    match v {
        Value::Mapping(m) => Ok(m.clone()),
        other => Err(RuleError::invalid(format!(
            "expected a feature/statement mapping, got: {other:?}"
        ))),
    }
}

fn sibling_description(d: &serde_yaml::Mapping) -> Result<Option<String>, RuleError> {
    match d.get("description") {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(other) => Err(RuleError::invalid(format!(
            "description must be a string, got: {other:?}"
        ))),
    }
}

fn value_as_plain_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn value_to_scalar(v: &Value) -> Result<RawScalar, RuleError> {
    match v {
        Value::String(s) => Ok(RawScalar::Str(s.clone())),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(RawScalar::Int(i as i128))
            } else if let Some(u) = n.as_u64() {
                Ok(RawScalar::Int(u as i128))
            } else {
                Err(RuleError::invalid(format!(
                    "unsupported numeric value: {n}"
                )))
            }
        }
        other => Err(RuleError::invalid(format!(
            "unexpected value type: {other:?}"
        ))),
    }
}

fn is_numeric_value_type(value_type: &str) -> bool {
    value_type == "number"
        || value_type == "offset"
        || value_type.starts_with("number/")
        || value_type.starts_with("offset/")
        || (value_type.starts_with("operand[")
            && (value_type.ends_with("].number") || value_type.ends_with("].offset")))
}

/// port of `parse_description`
fn parse_description(
    raw: &Value,
    value_type: &str,
    sibling_description: Option<String>,
) -> Result<(RawScalar, Option<String>), RuleError> {
    if value_type == "string" {
        return match raw {
            Value::String(s) => Ok((RawScalar::Str(s.clone()), sibling_description)),
            other => Err(RuleError::invalid(format!(
                "ambiguous string value {other:?}, must be defined as explicit string"
            ))),
        };
    }

    match raw {
        Value::String(s) => {
            let (value_str, description) = if let Some(idx) = s.find(DESCRIPTION_SEPARATOR) {
                if sibling_description.is_some() {
                    return Err(RuleError::invalid(format!(
                        "unexpected value: \"{s}\", only one description allowed (inline description with `{DESCRIPTION_SEPARATOR}`)"
                    )));
                }
                let value_part = s[..idx].to_string();
                let desc_part = s[idx + DESCRIPTION_SEPARATOR.len()..].to_string();
                if desc_part.is_empty() {
                    return Err(RuleError::invalid(format!(
                        "unexpected value: \"{s}\", description cannot be empty"
                    )));
                }
                (value_part, Some(desc_part))
            } else {
                (s.clone(), sibling_description)
            };

            if value_type == "bytes" {
                Ok((RawScalar::Bytes(parse_bytes(&value_str)?), description))
            } else if is_numeric_value_type(value_type) {
                let n = parse_int(value_str.trim()).map_err(|_| {
                    RuleError::invalid(format!(
                        "unexpected value: \"{value_str}\", must begin with numerical value"
                    ))
                })?;
                Ok((RawScalar::Int(n), description))
            } else {
                Ok((RawScalar::Str(value_str), description))
            }
        }
        other => Ok((value_to_scalar(other)?, sibling_description)),
    }
}

fn expect_string(v: RawScalar, field: &str) -> Result<String, RuleError> {
    match v {
        RawScalar::Str(s) => Ok(s),
        other => Err(RuleError::invalid(format!(
            "expected a string value for `{field}`, got: {other:?}"
        ))),
    }
}

fn expect_int(v: RawScalar, field: &str) -> Result<i128, RuleError> {
    match v {
        RawScalar::Int(n) => Ok(n),
        other => Err(RuleError::invalid(format!(
            "expected a numeric value for `{field}`, got: {other:?}"
        ))),
    }
}

fn expect_bytes(v: RawScalar, field: &str) -> Result<Vec<u8>, RuleError> {
    match v {
        RawScalar::Bytes(b) => Ok(b),
        other => Err(RuleError::invalid(format!(
            "expected a bytes value for `{field}`, got: {other:?}"
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::rules::{Rule, RuleError, Statement};

    /// wraps one `features:` list item in a minimal, otherwise-valid rule.
    fn parse_body(feature_yaml: &str) -> Result<Statement, RuleError> {
        let doc = format!(
            "rule:\n  meta:\n    name: test rule\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - {feature_yaml}\n"
        );
        Rule::from_yaml(&doc).map(|r| r.body.stmt)
    }

    #[test]
    fn number_hex_and_decimal() {
        assert!(matches!(
            parse_body("number: 0x10"),
            Ok(Statement::Leaf(crate::features::Feature::Number(
                crate::features::NumberValue::Int(16)
            )))
        ));
        assert!(matches!(
            parse_body("number: 16"),
            Ok(Statement::Leaf(crate::features::Feature::Number(
                crate::features::NumberValue::Int(16)
            )))
        ));
    }

    #[test]
    fn offset_negative_hex_via_native_yaml_int() {
        // "-0x30" is resolved to a native YAML integer before parsing ever
        // sees a string, exactly like PyYAML (verified empirically).
        assert!(matches!(
            parse_body("offset: -0x30"),
            Ok(Statement::Leaf(crate::features::Feature::Offset(-48)))
        ));
    }

    #[test]
    fn number_inline_description() {
        match parse_body("number: 0x10 = the flag").unwrap() {
            Statement::Leaf(crate::features::Feature::Number(
                crate::features::NumberValue::Int(16),
            )) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn inline_and_sibling_description_conflict_is_an_error() {
        let doc = "rule:\n  meta:\n    name: t\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - number: 0x10 = foo\n      description: bar\n";
        assert!(Rule::from_yaml(doc).is_err());
    }

    #[test]
    fn bytes_hex_and_cap() {
        assert!(parse_body("bytes: 01 02 03").is_ok());
        assert!(parse_body("bytes: zz").is_err(), "non-hex bytes must error");
        let too_long = "00 ".repeat(0x101);
        assert!(
            parse_body(&format!("bytes: {too_long}")).is_err(),
            "bytes over MAX_BYTES_FEATURE_SIZE must error"
        );
    }

    #[test]
    fn string_ambiguous_value_errors() {
        assert!(
            parse_body("string: 123").is_err(),
            "a bare numeric-looking `string:` value is ambiguous"
        );
    }

    #[test]
    fn string_regex_dispatch() {
        match parse_body("string: /foo.*bar/i").unwrap() {
            Statement::Leaf(crate::features::Feature::String(
                crate::features::StringFeature::Regex(re),
            )) => {
                assert!(re.is_match("FOO 123 bar"));
            }
            other => panic!("expected a regex feature, got {other:?}"),
        }
    }

    #[test]
    fn operand_index_out_of_range_errors() {
        assert!(parse_body("operand[0].number: 1").is_ok());
        assert!(parse_body("operand[4].number: 1").is_ok());
        assert!(
            parse_body("operand[5].number: 1").is_err(),
            "index 5 exceeds MAX_OPERAND_INDEX"
        );
    }

    #[test]
    fn count_range_forms() {
        assert!(matches!(
            parse_body("count(mnemonic(mov)): 2"),
            Ok(Statement::Range {
                min: 2,
                max: Some(2),
                ..
            })
        ));
        assert!(matches!(
            parse_body("count(mnemonic(mov)): 2 or more"),
            Ok(Statement::Range {
                min: 2,
                max: None,
                ..
            })
        ));
        assert!(matches!(
            parse_body("count(mnemonic(mov)): 2 or fewer"),
            Ok(Statement::Range {
                min: 0,
                max: Some(2),
                ..
            })
        ));
        assert!(matches!(
            parse_body("count(mnemonic(mov)): (1, 4)"),
            Ok(Statement::Range {
                min: 1,
                max: Some(4),
                ..
            })
        ));
        assert!(
            parse_body("count(mnemonic(mov)): (4, 1)").is_err(),
            "max less than min must error"
        );
    }

    #[test]
    fn count_basic_blocks_no_arg() {
        assert!(matches!(
            parse_body("count(basic blocks): (1, 5)"),
            Ok(Statement::Range {
                feature: crate::features::Feature::BasicBlock,
                ..
            })
        ));
    }

    #[test]
    fn os_format_arch_validity() {
        assert!(parse_body("os: windows").is_ok());
        assert!(parse_body("os: not-a-real-os").is_err());
        assert!(parse_body("format: pe").is_ok());
        assert!(parse_body("format: not-a-real-format").is_err());
        assert!(parse_body("arch: i386").is_ok());
        assert!(parse_body("arch: not-a-real-arch").is_err());
    }

    #[test]
    fn too_many_statements_errors() {
        let doc = "rule:\n  meta:\n    name: t\n    authors: [t]\n    scopes:\n      static: function\n      dynamic: unsupported\n  features:\n    - number: 1\n      description: d\n      extra: bogus\n";
        assert!(Rule::from_yaml(doc).is_err());
    }

    #[test]
    fn api_trims_dll_prefix() {
        match parse_body("api: kernel32.CreateFileA").unwrap() {
            Statement::Leaf(crate::features::Feature::Api(name)) => assert_eq!(name, "CreateFileA"),
            other => panic!("unexpected: {other:?}"),
        }
        // ordinal imports keep the dll part
        match parse_body("api: ws2_32.#1").unwrap() {
            Statement::Leaf(crate::features::Feature::Api(name)) => assert_eq!(name, "ws2_32.#1"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn duplicate_feature_values_are_deduped_regardless_of_description() {
        // port of `unique()` (capa/rules/__init__.py): two leaf features
        // with the *same value* but different descriptions are the same
        // node per `Feature.__eq__` ((name, value), no description), so
        // only the first survives -- e.g. real capa-rules' "create UDP
        // socket" declares `number: 2 = AF_INET` and `number: 2 =
        // SOCK_DGRAM` side by side; verified against real `capa -j` output
        // (difftest) that only one survives.
        let and = parse_body(
            "and:\n      - number: 2 = AF_INET\n      - number: 2 = SOCK_DGRAM\n      - number: 17 = IPPROTO_UDP\n",
        )
        .unwrap();
        let Statement::And(children) = and else {
            panic!("expected and")
        };
        assert_eq!(
            children.len(),
            2,
            "expected the duplicate `number: 2` to be deduped: {children:?}"
        );
    }

    #[test]
    fn structurally_identical_compound_children_are_never_deduped() {
        // the inverse case: `unique()` only special-cases `Feature`
        // equality; `Statement` subclasses (and/or/not/some/range) never
        // override `__eq__`, so two structurally-identical nested blocks
        // are distinct objects and both survive.
        let or = parse_body(
            "or:\n      - and:\n        - api: CreateFileA\n      - and:\n        - api: CreateFileA\n",
        )
        .unwrap();
        let Statement::Or(children) = or else {
            panic!("expected or")
        };
        assert_eq!(
            children.len(),
            2,
            "structurally-identical `and:` siblings must both survive"
        );
    }
}
