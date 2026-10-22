//! Function ID matching: a port of `FidProgramSeeker` scoring and the safe
//! subset of `ApplyFidEntriesCommand` / `MatchNameAnalysis` naming.
use super::hash::Quad;
use super::pack::{
    Pack, Record, Relation, FLAG_AUTO_FAIL, FLAG_AUTO_PASS, FLAG_FORCE_RELATION,
    FLAG_FORCE_SPECIFIC,
};

/// `FidService.SCORE_THRESHOLD`.
const SCORE_THRESHOLD: f32 = 14.6;
/// `FidService.MEDIUM_HASH_CODE_UNIT_LENGTH`.
const MEDIUM_LENGTH: u16 = 24;
/// `FidProgramSeeker.MAX_NUM_PARENTS_FOR_SCORE`.
const MAX_PARENTS: usize = 500;

/// A function with the hashes of its callees (children) and callers (parents),
/// each unique by full hash.
pub struct Family<'a> {
    pub quad: Quad,
    pub children: &'a [Quad],
    pub parents: &'a [Quad],
}

fn score(pack: &Pack<'_>, family: &Family<'_>, record: &Record) -> Option<f32> {
    if record.flags & FLAG_AUTO_FAIL != 0 {
        return None;
    }
    let mut code_units = record.code_units;
    let mut specific = 0_i32;
    let specific_match = record.specific_hash == family.quad.specific_hash as u32;
    if specific_match {
        specific = i32::from(record.specific_additional);
    }
    if record.flags & FLAG_FORCE_SPECIFIC != 0 && !specific_match {
        return None;
    }
    if record.flags & FLAG_AUTO_PASS != 0 && code_units < MEDIUM_LENGTH {
        code_units = MEDIUM_LENGTH;
    }
    let mut children = 0_i32;
    for child in family.children {
        if pack.has_relation(Relation::Superior, record, child.full_hash) {
            children += i32::from(child.code_units);
        }
    }
    if record.flags & FLAG_FORCE_RELATION != 0 && children == 0 {
        return None;
    }
    let mut parents = 0_i32;
    if family.parents.len() < MAX_PARENTS {
        for parent in family.parents {
            if pack.has_relation(Relation::Inferior, record, parent.full_hash) {
                parents += i32::from(parent.code_units);
            }
        }
    }
    // Java accumulates `functionScore += 0.67 * specific` in double, stored in a float.
    let function_score = (f64::from(code_units) + 0.67 * f64::from(specific)) as f32;
    let total = function_score + children as f32 + parents as f32;
    // The threshold test sums in the same order as Java.
    if function_score + (children as f32) + (parents as f32) < SCORE_THRESHOLD {
        return None;
    }
    Some(total)
}

/// A C identifier the decompiler can print. An x86-32 `__stdcall` or `__fastcall` name
/// carries its argument size (`name@8`); the printer turns the `@` into `_`, as Ghidra does.
fn identifier(name: &str) -> Option<String> {
    let first = name.bytes().next()?;
    let base = match name.rsplit_once('@') {
        Some((base, size)) if !size.is_empty() && size.bytes().all(|b| b.is_ascii_digit()) => base,
        _ => name,
    };
    (!first.is_ascii_digit()
        && !base.is_empty()
        && base.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    .then(|| name.to_owned())
}

/// Strip the C++ decoration of simple MSVC names (`?name@@...`, `?name@Class@@...`),
/// and name the global allocation operators, which Ghidra prints as `operator_new` and
/// `operator_delete`. Returns `None` for other operators, constructors, templates and
/// compiler-generated names, which need a real demangler.
fn plain_name(raw: &str) -> Option<String> {
    let Some(rest) = raw.strip_prefix('?') else {
        return identifier(raw);
    };
    if rest.starts_with("?2@") {
        return Some("operator_new".into());
    }
    if rest.starts_with("?3@") {
        return Some("operator_delete".into());
    }
    identifier(rest.get(..rest.find('@')?)?)
}

/// The name to give a function whose Function ID match is ambiguous. Ghidra labels every
/// candidate `FID_conflict:<name>` and the decompiler shows one of them; which one depends on
/// its database order, so this picks the least decorated name (fewest leading underscores, then
/// shortest). On the four ambiguous matches checked against Ghidra it agrees three times.
pub fn conflict_name(candidates: &[String]) -> Option<String> {
    candidates
        .iter()
        .filter_map(|name| plain_name(name))
        .min_by_key(|name| {
            (
                name.bytes().take_while(|&b| b == b'_').count(),
                name.len(),
                name.clone(),
            )
        })
        .map(|name| format!("FID_conflict:{name}"))
}

/// Candidates that reach the score threshold, best first (stable, like Java's sort).
pub fn scored_candidates(pack: &Pack<'_>, family: &Family<'_>) -> Vec<(f32, Record)> {
    let mut scored: Vec<(f32, Record)> = pack
        .candidates(family.quad.full_hash)
        .into_iter()
        .filter_map(|record| score(pack, family, &record).map(|s| (s, record)))
        .collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored
}

/// Every name of the best-scoring candidates, sorted: what Ghidra labels `FID_conflict:`
/// when there is more than one.
pub fn match_candidates(pack: &Pack<'_>, family: &Family<'_>) -> Vec<String> {
    let scored = scored_candidates(pack, family);
    let Some(best) = scored.first().map(|first| first.0) else {
        return Vec::new();
    };
    let mut names: Vec<String> = Vec::new();
    for (value, record) in &scored {
        if *value < best {
            break;
        }
        let Ok(name) = pack.name(record.name) else {
            return Vec::new();
        };
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names.sort();
    names
}

/// The name Ghidra's FID analysis would apply, when it is unambiguous.
pub fn match_name(pack: &Pack<'_>, family: &Family<'_>) -> Option<String> {
    let names = match_candidates(pack, family);
    if names.is_empty() {
        return None;
    }
    let stripped: std::collections::BTreeSet<&str> =
        names.iter().map(|n| n.trim_start_matches('_')).collect();
    let chosen = if names.len() == 1 || stripped.len() == 1 {
        names.first()?.clone()
    } else {
        let simple: std::collections::BTreeSet<Option<String>> =
            names.iter().map(|n| plain_name(n)).collect();
        match simple.iter().next() {
            Some(Some(only)) if simple.len() == 1 => only.clone(),
            _ => return None,
        }
    };
    plain_name(&chosen)
}

#[cfg(test)]
mod tests {
    use super::*;

    static PACK: &[u8] = include_bytes!("../../sigs/fid-x64.pack");

    fn quad(code_units: i16, full: u64, additional: i8, specific: u64) -> Quad {
        Quad {
            code_units,
            full_hash: full,
            specific_additional: additional,
            specific_hash: specific,
        }
    }

    /// Hashes Ghidra 12.1.4 computed for these leaf functions in its own analysis
    /// and named from the same databases.
    #[test]
    fn names_leaf_runtime_functions_like_ghidra() -> Result<(), crate::fid::pack::PackError> {
        let pack = Pack::parse(PACK)?;
        let strlen = quad(56, 0xdcc7_b814_702d_fa6d, 25, 0x6a9c_0b2f_06df_67b2);
        let family = Family {
            quad: strlen,
            children: &[],
            parents: &[],
        };
        assert_eq!(match_name(&pack, &family).as_deref(), Some("strlen"));
        let memcpy = quad(192, 0xa676_d735_c16d_2d70, 127, 0x49b5_5c22_0ed5_e136);
        let family = Family {
            quad: memcpy,
            children: &[],
            parents: &[],
        };
        assert_eq!(match_name(&pack, &family).as_deref(), Some("memcpy"));
        Ok(())
    }

    #[test]
    fn unknown_hash_has_no_name() -> Result<(), crate::fid::pack::PackError> {
        let pack = Pack::parse(PACK)?;
        let family = Family {
            quad: quad(50, 1, 0, 2),
            children: &[],
            parents: &[],
        };
        assert_eq!(match_name(&pack, &family), None);
        Ok(())
    }

    #[test]
    fn short_functions_need_relations_to_reach_the_threshold(
    ) -> Result<(), crate::fid::pack::PackError> {
        let pack = Pack::parse(PACK)?;
        // Every candidate of a short hash must be rejected without relation evidence.
        let mut checked = 0;
        for index in (0..pack.record_count()).step_by(997) {
            let Some(record) = pack.candidates_at(index) else {
                continue;
            };
            if record.code_units >= 12 || record.flags & FLAG_AUTO_PASS != 0 {
                continue;
            }
            let family = Family {
                quad: Quad {
                    code_units: 4,
                    full_hash: pack.full_hash_of(index),
                    specific_additional: 0,
                    specific_hash: u64::MAX,
                },
                children: &[],
                parents: &[],
            };
            checked += 1;
            assert!(scored_candidates(&pack, &family)
                .iter()
                .all(|(s, _)| *s >= SCORE_THRESHOLD));
        }
        assert!(checked > 10);
        Ok(())
    }

    #[test]
    fn simple_msvc_names_are_stripped_and_complex_ones_refused() {
        assert_eq!(plain_name("memset").as_deref(), Some("memset"));
        assert_eq!(
            plain_name("?common_exit@@YAXHW4@Z").as_deref(),
            Some("common_exit")
        );
        assert_eq!(plain_name("?name@Class@@QEAAXXZ").as_deref(), Some("name"));
        assert_eq!(plain_name("??0_LocaleUpdate@@QEAA@XZ"), None);
        assert_eq!(plain_name("??$parse@D@@YAXXZ"), None);
        assert_eq!(plain_name("`vector deleting destructor'"), None);
        assert_eq!(plain_name("9lives"), None);
    }
}
