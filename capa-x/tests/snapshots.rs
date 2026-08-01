//! Snapshot tests for a handful of deliberately gnarly
//! rules, covering: regex + `/i` flag, `com/class`/`com/interface`,
//! `operand[N].number`/`.offset`, counts with ranges (`(min,max)`, "N or
//! more", "N or fewer"), span-of-calls (dynamic scope), nested subscopes,
//! `= description` inline syntax, a `lib` rule, `bytes:`, `substring:`, the
//! bare `N or more:` statement form, and `count(section(...))`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use capa_x::rules::Rule;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capa-x has a parent directory")
        .to_path_buf()
}

fn parse(rel_path: &str) -> Rule {
    let path = workspace_root().join(rel_path);
    Rule::from_yaml_file(&path).unwrap_or_else(|e| panic!("failed to parse {rel_path}: {e}"))
}

macro_rules! snapshot_rule {
    ($test_name:ident, $rel_path:expr) => {
        #[test]
        fn $test_name() {
            let rule = parse($rel_path);
            insta::assert_debug_snapshot!(
                stringify!($test_name),
                (
                    &rule.name,
                    &rule.namespace,
                    &rule.scopes,
                    &rule.is_lib,
                    &rule.body
                )
            );
        }
    };
}

// com/class, com/interface, nested `basic block:` subscopes, `offset: ... =`
// inline description, `optional:`, `call:` subscope with a statement-level
// description.
snapshot_rule!(
    rule_wmi_com_and_nested_subscopes,
    "rules/host-interaction/wmi/connect-to-wmi-namespace-via-wbemlocator.yml"
);

// dynamic-only rule using the `span of calls` scope.
snapshot_rule!(rule_span_of_calls, "rules/communication/send-data.yml");

// `lib: true` rule with a nested `basic block:` subscope.
snapshot_rule!(rule_lib_flag, "rules/lib/allocate-memory.yml");

// `operand[0].number`, and the `instruction:` subscope shorthand where >1
// child implies a top-level `and:`.
snapshot_rule!(
    rule_operand_and_instruction_shorthand,
    "rules/nursery/execute-syscall.yml"
);

// `count(...)` with `(min, max)` ranges, "N or more", `count(mnemonic(...))`,
// `count(characteristic(...))`, and a `match:` dependency.
snapshot_rule!(
    rule_count_ranges_and_match_dep,
    "rules/data-manipulation/encryption/rc4/encrypt-data-using-rc4-prga.yml"
);

// regex feature with the `/i` case-insensitive flag.
snapshot_rule!(
    rule_regex_case_insensitive,
    "rules/anti-analysis/reference-analysis-tools-strings.yml"
);

// `substring:` feature.
snapshot_rule!(rule_substring, "rules/collection/get-steam-token.yml");

// `bytes:` feature.
snapshot_rule!(
    rule_bytes,
    "rules/load-code/execute-vbscript-javascript-or-jscript-in-memory.yml"
);

// bare `N or more:` statement (not `count(...)`).
snapshot_rule!(
    rule_n_or_more_statement,
    "rules/collection/credit-card/parse-credit-card-information.yml"
);

// `count(section(...))`.
snapshot_rule!(
    rule_count_section,
    "rules/anti-analysis/packer/themida/packed-with-themida.yml"
);

// negative hex `offset:` values.
snapshot_rule!(
    rule_negative_hex_offset,
    "rules/data-manipulation/hashing/md5/hash-data-with-md5.yml"
);

// `count(mnemonic(...))` with "N or more".
snapshot_rule!(
    rule_count_mnemonic,
    "rules/anti-analysis/anti-debugging/debugger-detection/check-for-hardware-breakpoints.yml"
);
