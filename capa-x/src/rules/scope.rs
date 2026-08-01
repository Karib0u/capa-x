//! Scopes, ported from `capa/rules/__init__.py`: `Scope`, `Scopes`,
//! `STATIC_SCOPES`, `DYNAMIC_SCOPES`, `STATIC_SCOPE_ORDER`,
//! `DYNAMIC_SCOPE_ORDER`, `is_subscope_compatible`, `SUPPORTED_FEATURES`,
//! `ensure_feature_valid_for_scopes`.

use std::collections::HashSet;
use std::sync::OnceLock;

use crate::features::Feature;
use crate::rules::error::RuleError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    File,
    Process,
    Thread,
    SpanOfCalls,
    Call,
    Function,
    BasicBlock,
    Instruction,
    /// used only to specify supported features per scope; never a rule's own
    /// static/dynamic scope value in practice, but is technically a legal
    /// `STATIC_SCOPES` member per upstream, so it's supported here too.
    Global,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::File => "file",
            Scope::Process => "process",
            Scope::Thread => "thread",
            Scope::SpanOfCalls => "span of calls",
            Scope::Call => "call",
            Scope::Function => "function",
            Scope::BasicBlock => "basic block",
            Scope::Instruction => "instruction",
            Scope::Global => "global",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        Some(match s {
            "file" => Scope::File,
            "process" => Scope::Process,
            "thread" => Scope::Thread,
            "span of calls" => Scope::SpanOfCalls,
            "call" => Scope::Call,
            "function" => Scope::Function,
            "basic block" => Scope::BasicBlock,
            "instruction" => Scope::Instruction,
            "global" => Scope::Global,
            _ => return None,
        })
    }
}

pub const STATIC_SCOPES: [Scope; 5] = [
    Scope::File,
    Scope::Global,
    Scope::Function,
    Scope::BasicBlock,
    Scope::Instruction,
];

pub const DYNAMIC_SCOPES: [Scope; 6] = [
    Scope::File,
    Scope::Global,
    Scope::Process,
    Scope::Thread,
    Scope::SpanOfCalls,
    Scope::Call,
];

pub const STATIC_SCOPE_ORDER: [Scope; 4] = [
    Scope::File,
    Scope::Function,
    Scope::BasicBlock,
    Scope::Instruction,
];

pub const DYNAMIC_SCOPE_ORDER: [Scope; 5] = [
    Scope::File,
    Scope::Process,
    Scope::Thread,
    Scope::SpanOfCalls,
    Scope::Call,
];

/// capa/rules/__init__.py: Scopes dataclass (static/dynamic scope pair)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Scopes {
    pub static_: Option<Scope>,
    pub dynamic: Option<Scope>,
}

impl Scopes {
    pub fn contains(&self, scope: Scope) -> bool {
        self.static_ == Some(scope) || self.dynamic == Some(scope)
    }

    /// port of `Scopes.from_dict`
    pub fn from_dict(map: &serde_yaml::Mapping) -> Result<Scopes, RuleError> {
        let keys: Vec<&str> = map.keys().filter_map(|k| k.as_str()).collect();

        if !keys.contains(&"static") {
            return Err(RuleError::invalid("static scope must be provided"));
        }
        if !keys.contains(&"dynamic") {
            return Err(RuleError::invalid("dynamic scope must be provided"));
        }

        let mut sorted_keys = keys.clone();
        sorted_keys.sort_unstable();
        if sorted_keys != ["dynamic", "static"] {
            return Err(RuleError::invalid(
                "scope flavors can be either static or dynamic",
            ));
        }

        let static_value = yaml_scalar_str(map, "static")?;
        let dynamic_value = yaml_scalar_str(map, "dynamic")?;

        let static_raw = if static_value == "unsupported" {
            None
        } else {
            Some(static_value)
        };
        let dynamic_raw = if dynamic_value == "unsupported" {
            None
        } else {
            Some(dynamic_value)
        };

        if static_raw.is_none() && dynamic_raw.is_none() {
            return Err(RuleError::invalid(
                "invalid scopes value. At least one scope must be specified",
            ));
        }

        let static_scope = match static_raw {
            None => None,
            Some(s) => {
                let scope = Scope::parse(&s);
                if !matches!(scope, Some(sc) if STATIC_SCOPES.contains(&sc)) {
                    return Err(RuleError::invalid(format!(
                        "{s} is not a valid static scope"
                    )));
                }
                scope
            }
        };
        let dynamic_scope = match dynamic_raw {
            None => None,
            Some(s) => {
                let scope = Scope::parse(&s);
                if !matches!(scope, Some(sc) if DYNAMIC_SCOPES.contains(&sc)) {
                    return Err(RuleError::invalid(format!(
                        "{s} is not a valid dynamic scope"
                    )));
                }
                scope
            }
        };

        Ok(Scopes {
            static_: static_scope,
            dynamic: dynamic_scope,
        })
    }
}

fn yaml_scalar_str(map: &serde_yaml::Mapping, key: &str) -> Result<String, RuleError> {
    let value = map
        .get(serde_yaml::Value::String(key.to_string()))
        .ok_or_else(|| RuleError::invalid(format!("{key} scope must be provided")))?;
    match value {
        serde_yaml::Value::String(s) => Ok(s.clone()),
        other => Err(RuleError::invalid(format!(
            "{key} scope must be a string, got: {other:?}"
        ))),
    }
}

/// port of `is_subscope_compatible`
pub fn is_subscope_compatible(scope: Option<Scope>, subscope: Scope) -> bool {
    let Some(scope) = scope else {
        return false;
    };

    if let Some(pos) = STATIC_SCOPE_ORDER.iter().position(|s| *s == subscope) {
        return STATIC_SCOPE_ORDER
            .iter()
            .position(|s| *s == scope)
            .is_some_and(|p| pos >= p);
    }
    if let Some(pos) = DYNAMIC_SCOPE_ORDER.iter().position(|s| *s == subscope) {
        return DYNAMIC_SCOPE_ORDER
            .iter()
            .position(|s| *s == scope)
            .is_some_and(|p| pos >= p);
    }
    false
}

/// A coarse "kind" of feature, ignoring its value, used only for scope
/// legality checks. `Characteristic` is deliberately excluded: its legality
/// depends on the specific characteristic string, checked separately (see
/// `characteristic_allowed`). Likewise `Com` has no entry: upstream's
/// `translate_com_feature` never scope-checks COM features either.
///
/// String/Substring/Regex collapse into one `StringFamily` kind because in
/// Python `Substring` and `Regex` both subclass `String`, so wherever
/// `SUPPORTED_FEATURES` lists bare `String`, `isinstance()` accepts all three
/// interchangeably (verified: no scope lists Substring/Regex without also
/// listing String, or vice versa lists them expecting String to be excluded).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeatureKind {
    MatchedRule,
    Export,
    Import,
    Section,
    FunctionName,
    StringFamily,
    Bytes,
    Api,
    Number,
    Offset,
    Mnemonic,
    OperandNumber,
    OperandOffset,
    Class,
    Namespace,
    Property,
    Os,
    Arch,
    Format,
    BasicBlock,
}

fn feature_kind(feature: &Feature) -> Option<FeatureKind> {
    use Feature::*;
    Some(match feature {
        Api(_) => FeatureKind::Api,
        String(_) => FeatureKind::StringFamily,
        Bytes(_) => FeatureKind::Bytes,
        Number(_) => FeatureKind::Number,
        Offset(_) => FeatureKind::Offset,
        OperandNumber(..) => FeatureKind::OperandNumber,
        OperandOffset(..) => FeatureKind::OperandOffset,
        Mnemonic(_) => FeatureKind::Mnemonic,
        Characteristic(_) => return None,
        Section(_) => FeatureKind::Section,
        Import(_) => FeatureKind::Import,
        Export(_) => FeatureKind::Export,
        FunctionName(_) => FeatureKind::FunctionName,
        Class(_) => FeatureKind::Class,
        Namespace(_) => FeatureKind::Namespace,
        Property { .. } => FeatureKind::Property,
        Os(_) => FeatureKind::Os,
        Arch(_) => FeatureKind::Arch,
        Format(_) => FeatureKind::Format,
        Com(..) => return None,
        MatchedRule(_) => FeatureKind::MatchedRule,
        BasicBlock => FeatureKind::BasicBlock,
    })
}

#[derive(Debug, Clone, Default)]
struct ScopeFeatures {
    kinds: HashSet<FeatureKind>,
    characteristics: HashSet<&'static str>,
}

/// port of `SUPPORTED_FEATURES`, built once and cached. See `capa/rules/__init__.py`
/// lines ~187-278 for the exact base sets and the `.update()` propagation order,
/// which this function reproduces step for step.
fn supported_features() -> &'static std::collections::HashMap<Scope, ScopeFeatures> {
    static TABLE: OnceLock<std::collections::HashMap<Scope, ScopeFeatures>> = OnceLock::new();
    TABLE.get_or_init(|| {
        use FeatureKind::*;
        let mut table: std::collections::HashMap<Scope, ScopeFeatures> =
            std::collections::HashMap::new();

        table.insert(
            Scope::Global,
            ScopeFeatures {
                kinds: [Os, Arch, Format].into_iter().collect(),
                characteristics: HashSet::new(),
            },
        );

        table.insert(
            Scope::File,
            ScopeFeatures {
                kinds: [
                    MatchedRule,
                    Export,
                    Import,
                    Section,
                    FunctionName,
                    StringFamily,
                    Class,
                    Namespace,
                ]
                .into_iter()
                .collect(),
                characteristics: ["embedded pe", "mixed mode", "forwarded export"]
                    .into_iter()
                    .collect(),
            },
        );

        table.insert(
            Scope::Process,
            ScopeFeatures {
                kinds: [MatchedRule].into_iter().collect(),
                characteristics: HashSet::new(),
            },
        );
        table.insert(Scope::Thread, ScopeFeatures::default());
        table.insert(Scope::SpanOfCalls, ScopeFeatures::default());
        table.insert(
            Scope::Call,
            ScopeFeatures {
                kinds: [MatchedRule, StringFamily, Api, Number]
                    .into_iter()
                    .collect(),
                characteristics: HashSet::new(),
            },
        );

        table.insert(
            Scope::Function,
            ScopeFeatures {
                kinds: [MatchedRule, BasicBlock].into_iter().collect(),
                characteristics: ["calls from", "calls to", "loop", "recursive call"]
                    .into_iter()
                    .collect(),
            },
        );
        table.insert(
            Scope::BasicBlock,
            ScopeFeatures {
                kinds: [MatchedRule].into_iter().collect(),
                characteristics: ["tight loop", "stack string"].into_iter().collect(),
            },
        );
        table.insert(
            Scope::Instruction,
            ScopeFeatures {
                kinds: [
                    MatchedRule,
                    Api,
                    Property,
                    Number,
                    StringFamily,
                    Bytes,
                    Offset,
                    Mnemonic,
                    OperandNumber,
                    OperandOffset,
                    Class,
                    Namespace,
                ]
                .into_iter()
                .collect(),
                characteristics: [
                    "nzxor",
                    "peb access",
                    "fs access",
                    "gs access",
                    "indirect call",
                    "call $+5",
                    "cross section flow",
                    "unmanaged call",
                ]
                .into_iter()
                .collect(),
            },
        );

        // global scope features are available in all other scopes
        let global = table[&Scope::Global].clone();
        for scope in [
            Scope::Instruction,
            Scope::BasicBlock,
            Scope::Function,
            Scope::File,
            Scope::Process,
            Scope::Thread,
            Scope::SpanOfCalls,
            Scope::Call,
        ] {
            if let Some(entry) = table.get_mut(&scope) {
                entry.kinds.extend(global.kinds.iter().copied());
                entry
                    .characteristics
                    .extend(global.characteristics.iter().copied());
            }
        }

        // all call scope features are also span-of-calls features
        let call = table[&Scope::Call].clone();
        merge_into(&mut table, Scope::SpanOfCalls, &call);

        // all span-of-calls scope features (and therefore, call features) are also thread features
        let span_of_calls = table[&Scope::SpanOfCalls].clone();
        merge_into(&mut table, Scope::Thread, &span_of_calls);

        // all thread scope features are also process features
        let thread = table[&Scope::Thread].clone();
        merge_into(&mut table, Scope::Process, &thread);

        // all instruction scope features are also basic block features
        let instruction = table[&Scope::Instruction].clone();
        merge_into(&mut table, Scope::BasicBlock, &instruction);

        // all basic block scope features are also function scope features
        let basic_block = table[&Scope::BasicBlock].clone();
        merge_into(&mut table, Scope::Function, &basic_block);

        table
    })
}

fn merge_into(
    table: &mut std::collections::HashMap<Scope, ScopeFeatures>,
    target: Scope,
    src: &ScopeFeatures,
) {
    if let Some(entry) = table.get_mut(&target) {
        entry.kinds.extend(src.kinds.iter().copied());
        entry
            .characteristics
            .extend(src.characteristics.iter().copied());
    }
}

/// port of `ensure_feature_valid_for_scopes`
pub fn ensure_feature_valid_for_scopes(scopes: Scopes, feature: &Feature) -> Result<(), RuleError> {
    // upstream never scope-checks COM features (`translate_com_feature` builds
    // an `Or` statement directly, bypassing `ensure_feature_valid_for_scopes`).
    if matches!(feature, Feature::Com(..)) {
        return Ok(());
    }

    let table = supported_features();
    let mut kinds: HashSet<FeatureKind> = HashSet::new();
    let mut characteristics: HashSet<&'static str> = HashSet::new();
    for scope in [scopes.static_, scopes.dynamic].into_iter().flatten() {
        if let Some(sf) = table.get(&scope) {
            kinds.extend(sf.kinds.iter().copied());
            characteristics.extend(sf.characteristics.iter().copied());
        }
    }

    if let Feature::Characteristic(value) = feature {
        if !characteristics.contains(value.as_str()) {
            return Err(RuleError::invalid(format!(
                "feature {feature} not supported for scopes {scopes:?}"
            )));
        }
        return Ok(());
    }

    let Some(kind) = feature_kind(feature) else {
        return Ok(());
    };
    if !kinds.contains(&kind) {
        return Err(RuleError::invalid(format!(
            "feature {feature} not supported for scopes {scopes:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::features::StringFeature;

    fn ok(scopes: Scopes, feature: Feature) {
        assert!(
            ensure_feature_valid_for_scopes(scopes, &feature).is_ok(),
            "expected {feature} to be legal for {scopes:?}"
        );
    }

    fn illegal(scopes: Scopes, feature: Feature) {
        assert!(
            ensure_feature_valid_for_scopes(scopes, &feature).is_err(),
            "expected {feature} to be illegal for {scopes:?}"
        );
    }

    fn s_static(scope: Scope) -> Scopes {
        Scopes {
            static_: Some(scope),
            dynamic: None,
        }
    }
    fn s_dynamic(scope: Scope) -> Scopes {
        Scopes {
            static_: None,
            dynamic: Some(scope),
        }
    }

    // one test per SUPPORTED_FEATURES row (capa/rules/__init__.py ~187-278)

    #[test]
    fn file_scope_row() {
        ok(s_static(Scope::File), Feature::MatchedRule("x".into()));
        ok(s_static(Scope::File), Feature::Export("x".into()));
        ok(s_static(Scope::File), Feature::Import("x".into()));
        ok(s_static(Scope::File), Feature::Section("x".into()));
        ok(s_static(Scope::File), Feature::FunctionName("x".into()));
        ok(
            s_static(Scope::File),
            Feature::Characteristic("embedded pe".into()),
        );
        ok(
            s_static(Scope::File),
            Feature::Characteristic("mixed mode".into()),
        );
        ok(
            s_static(Scope::File),
            Feature::Characteristic("forwarded export".into()),
        );
        ok(
            s_static(Scope::File),
            Feature::String(StringFeature::Plain("x".into())),
        );
        ok(
            s_static(Scope::File),
            Feature::String(StringFeature::Substring("x".into())),
        ); // Substring <: String
        ok(s_static(Scope::File), Feature::Class("x".into()));
        ok(s_static(Scope::File), Feature::Namespace("x".into()));
        // not in this scope's set
        illegal(s_static(Scope::File), Feature::Api("x".into()));
        illegal(s_static(Scope::File), Feature::Bytes(vec![1]));
        illegal(
            s_static(Scope::File),
            Feature::Characteristic("nzxor".into()),
        );
        illegal(s_static(Scope::File), Feature::BasicBlock);
    }

    #[test]
    fn process_scope_row() {
        ok(s_dynamic(Scope::Process), Feature::MatchedRule("x".into()));
        // inherited transitively via thread <- span of calls <- call
        ok(s_dynamic(Scope::Process), Feature::Api("x".into()));
        ok(
            s_dynamic(Scope::Process),
            Feature::Number(crate::features::NumberValue::Int(1)),
        );
        illegal(s_dynamic(Scope::Process), Feature::Bytes(vec![1]));
    }

    #[test]
    fn thread_scope_row() {
        // base set is empty; everything present comes from span-of-calls/call inheritance
        ok(s_dynamic(Scope::Thread), Feature::MatchedRule("x".into()));
        ok(s_dynamic(Scope::Thread), Feature::Api("x".into()));
        illegal(s_dynamic(Scope::Thread), Feature::Bytes(vec![1]));
    }

    #[test]
    fn span_of_calls_scope_row() {
        // base set is empty; inherits call's set
        ok(s_dynamic(Scope::SpanOfCalls), Feature::Api("x".into()));
        ok(
            s_dynamic(Scope::SpanOfCalls),
            Feature::Number(crate::features::NumberValue::Int(1)),
        );
        ok(
            s_dynamic(Scope::SpanOfCalls),
            Feature::String(StringFeature::Plain("x".into())),
        );
        illegal(s_dynamic(Scope::SpanOfCalls), Feature::Offset(1));
    }

    #[test]
    fn call_scope_row() {
        ok(s_dynamic(Scope::Call), Feature::MatchedRule("x".into()));
        ok(
            s_dynamic(Scope::Call),
            Feature::String(StringFeature::Plain("x".into())),
        );
        ok(
            s_dynamic(Scope::Call),
            Feature::String(StringFeature::Substring("x".into())),
        );
        ok(s_dynamic(Scope::Call), Feature::Api("x".into()));
        ok(
            s_dynamic(Scope::Call),
            Feature::Number(crate::features::NumberValue::Int(1)),
        );
        illegal(s_dynamic(Scope::Call), Feature::Offset(1));
        illegal(s_dynamic(Scope::Call), Feature::Bytes(vec![1]));
    }

    #[test]
    fn function_scope_row() {
        ok(s_static(Scope::Function), Feature::MatchedRule("x".into()));
        ok(s_static(Scope::Function), Feature::BasicBlock);
        ok(
            s_static(Scope::Function),
            Feature::Characteristic("calls from".into()),
        );
        ok(
            s_static(Scope::Function),
            Feature::Characteristic("calls to".into()),
        );
        ok(
            s_static(Scope::Function),
            Feature::Characteristic("loop".into()),
        );
        ok(
            s_static(Scope::Function),
            Feature::Characteristic("recursive call".into()),
        );
        // inherited from basic block / instruction
        ok(
            s_static(Scope::Function),
            Feature::Characteristic("tight loop".into()),
        );
        ok(
            s_static(Scope::Function),
            Feature::Characteristic("nzxor".into()),
        );
        ok(s_static(Scope::Function), Feature::Bytes(vec![1]));
        ok(s_static(Scope::Function), Feature::Mnemonic("mov".into()));
        illegal(s_static(Scope::Function), Feature::Export("x".into()));
    }

    #[test]
    fn basic_block_scope_row() {
        ok(
            s_static(Scope::BasicBlock),
            Feature::MatchedRule("x".into()),
        );
        ok(
            s_static(Scope::BasicBlock),
            Feature::Characteristic("tight loop".into()),
        );
        ok(
            s_static(Scope::BasicBlock),
            Feature::Characteristic("stack string".into()),
        );
        // inherited from instruction
        ok(s_static(Scope::BasicBlock), Feature::Bytes(vec![1]));
        ok(
            s_static(Scope::BasicBlock),
            Feature::Characteristic("nzxor".into()),
        );
        // NOT inherited from function (basic block can't contain basic blocks)
        illegal(s_static(Scope::BasicBlock), Feature::BasicBlock);
        illegal(
            s_static(Scope::BasicBlock),
            Feature::Characteristic("loop".into()),
        );
        illegal(s_static(Scope::BasicBlock), Feature::Export("x".into()));
    }

    #[test]
    fn instruction_scope_row() {
        ok(
            s_static(Scope::Instruction),
            Feature::MatchedRule("x".into()),
        );
        ok(s_static(Scope::Instruction), Feature::Api("x".into()));
        ok(
            s_static(Scope::Instruction),
            Feature::Property {
                name: "x".into(),
                access: None,
            },
        );
        ok(
            s_static(Scope::Instruction),
            Feature::Number(crate::features::NumberValue::Int(1)),
        );
        ok(
            s_static(Scope::Instruction),
            Feature::String(StringFeature::Plain("x".into())),
        );
        ok(s_static(Scope::Instruction), Feature::Bytes(vec![1]));
        ok(s_static(Scope::Instruction), Feature::Offset(1));
        ok(
            s_static(Scope::Instruction),
            Feature::Mnemonic("mov".into()),
        );
        ok(
            s_static(Scope::Instruction),
            Feature::OperandNumber(0, crate::features::NumberValue::Int(1)),
        );
        ok(s_static(Scope::Instruction), Feature::OperandOffset(0, 1));
        ok(s_static(Scope::Instruction), Feature::Class("x".into()));
        ok(s_static(Scope::Instruction), Feature::Namespace("x".into()));
        for c in [
            "nzxor",
            "peb access",
            "fs access",
            "gs access",
            "indirect call",
            "call $+5",
            "cross section flow",
            "unmanaged call",
        ] {
            ok(
                s_static(Scope::Instruction),
                Feature::Characteristic(c.into()),
            );
        }
        illegal(s_static(Scope::Instruction), Feature::BasicBlock);
        illegal(
            s_static(Scope::Instruction),
            Feature::Characteristic("tight loop".into()),
        );
        illegal(s_static(Scope::Instruction), Feature::Export("x".into()));
    }

    #[test]
    fn global_features_available_everywhere() {
        for scopes in [
            s_static(Scope::File),
            s_static(Scope::Function),
            s_static(Scope::BasicBlock),
            s_static(Scope::Instruction),
            s_dynamic(Scope::Process),
            s_dynamic(Scope::Thread),
            s_dynamic(Scope::SpanOfCalls),
            s_dynamic(Scope::Call),
        ] {
            ok(scopes, Feature::Os("windows".into()));
            ok(scopes, Feature::Arch("i386".into()));
            ok(scopes, Feature::Format("pe".into()));
        }
    }

    #[test]
    fn com_features_are_never_scope_checked() {
        // matches upstream: `translate_com_feature` never calls
        // `ensure_feature_valid_for_scopes`.
        ok(
            s_static(Scope::File),
            Feature::Com(crate::features::ComKind::Class, "x".into()),
        );
        ok(
            s_dynamic(Scope::Process),
            Feature::Com(crate::features::ComKind::Interface, "x".into()),
        );
    }

    #[test]
    fn is_subscope_compatible_orders() {
        assert!(is_subscope_compatible(Some(Scope::File), Scope::Function));
        assert!(is_subscope_compatible(
            Some(Scope::Function),
            Scope::BasicBlock
        ));
        assert!(is_subscope_compatible(
            Some(Scope::Function),
            Scope::Instruction
        ));
        assert!(!is_subscope_compatible(
            Some(Scope::Instruction),
            Scope::Function
        ));
        assert!(!is_subscope_compatible(None, Scope::Function));

        assert!(is_subscope_compatible(Some(Scope::Process), Scope::Thread));
        assert!(is_subscope_compatible(
            Some(Scope::Thread),
            Scope::SpanOfCalls
        ));
        assert!(is_subscope_compatible(Some(Scope::Process), Scope::Call));
        assert!(!is_subscope_compatible(Some(Scope::Call), Scope::Process));
    }

    #[test]
    fn scopes_from_dict_rejects_legacy_and_unknown_shapes() {
        let mk = |yaml: &str| -> Result<Scopes, RuleError> {
            let v: serde_yaml::Value = serde_yaml::from_str(yaml).expect("test yaml is valid");
            let serde_yaml::Value::Mapping(m) = v else {
                panic!("test yaml must be a mapping")
            };
            Scopes::from_dict(&m)
        };

        assert!(mk("static: function\ndynamic: unsupported\n").is_ok());
        assert!(mk("static: unsupported\ndynamic: call\n").is_ok());
        assert!(
            mk("static: unsupported\ndynamic: unsupported\n").is_err(),
            "at least one scope must be specified"
        );
        assert!(
            mk("static: function\n").is_err(),
            "dynamic key must be provided"
        );
        assert!(
            mk("static: function\ndynamic: call\nextra: oops\n").is_err(),
            "exactly {{static, dynamic}} keys"
        );
        assert!(
            mk("static: bogus\ndynamic: unsupported\n").is_err(),
            "unknown static scope name"
        );
        assert!(
            mk("static: global\ndynamic: unsupported\n").is_ok(),
            "global is technically a valid static scope"
        );
    }
}
