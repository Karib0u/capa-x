//! Port of `vivisect/analysis/ms/msvcfunc.py` (pinned vivisect 1.3.2), plus
//! just enough of `vivisect/analysis/ms/msvc.py` and
//! `vivisect/vamp/msvc/__init__.py` to reach it.
//!
//! MSVC's `/GS` stack-cookie check has a fixed shape, so vivisect
//! byte-signature-matches it (`msvc.py`, a *function* analysis module) and
//! names the function `security_check_cookie_<va>`. `msvcfunc.py` then reads
//! the cookie's address out of that function's first instruction and, for
//! every `mov` that references the cookie, turns the *containing code block*
//! into a function of its own.
//!
//! That split is why capa still extracts features from a `/GS`-protected
//! function whose enclosing function FLIRT recognised as library code: the
//! cookie-restoring tail becomes a separate, unnamed function. Without it,
//! `terminate process` and `link function at runtime on Windows` go missing
//! on samples where the only call site sits in such a tail.
//!
//! No emulation is involved -- this is a byte signature, one operand read,
//! and a data-xref walk.

use std::collections::BTreeSet;

use iced_x86::Mnemonic;

use super::image::LoadedImage;

/// The `security_check_cookie` rows of `vivisect/vamp/msvc/__init__.py`'s
/// `sigs` table, as `(bytes, mask)`. envi's `bytesig` compares
/// `candidate[i] & mask[i] == bytes[i]`, so a `0x00` mask byte is a
/// wildcard (`envi/bytesig.py:getSignature`). Only the cookie rows are
/// needed here; the rest of that table names functions this port has no
/// consumer for.
const SECURITY_CHECK_COOKIE_SIGNATURES: [(&[u8], &[u8]); 5] = [
    // 32-bit, VS 2005 / 2008 / 2010 / 2012 / 2013
    (
        &[0x3b, 0x0d, 0, 0, 0, 0, 0x75, 0x02, 0xf3, 0xc3, 0xe9],
        &[0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff],
    ),
    // 32-bit, VS 2015 / 2017 (bnd prefixes)
    (
        &[
            0x3b, 0x0d, 0, 0, 0, 0, 0xf2, 0x75, 0x02, 0xf2, 0xc3, 0xf2, 0xe9,
        ],
        &[
            0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
    ),
    // 64-bit, VS 2005 / 2008 / 2010 / 2012 / 2013
    (
        &[
            0x48, 0x3b, 0x0d, 0, 0, 0, 0, 0x75, 0x11, 0x48, 0xc1, 0xc1, 0x10, 0x66, 0xf7, 0xc1,
            0xff, 0xff, 0x75, 0x02, 0xf3, 0xc3, 0x48, 0xc1, 0xc9, 0x10, 0xe9,
        ],
        &[
            0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
    ),
    // 64-bit, VS 2015
    (
        &[
            0x48, 0x3b, 0x0d, 0, 0, 0, 0, 0xf2, 0x75, 0x11, 0x48, 0xc1, 0xc1, 0x10, 0x66, 0xf7,
            0xc1, 0xff, 0xff, 0xf2, 0x75, 0x02, 0xf2, 0xc3, 0x48, 0xc1, 0xc9, 0x10, 0xe9,
        ],
        &[
            0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
    ),
    // 64-bit, VS 2019
    (
        &[
            0x48, 0x3b, 0x0d, 0, 0, 0, 0, 0xf2, 0x75, 0x12, 0x48, 0xc1, 0xc1, 0x10, 0x66, 0xf7,
            0xc1, 0xff, 0xff, 0xf2, 0x75, 0x02, 0xf2, 0xc3, 0x48, 0xc1, 0xc9, 0x10, 0xe9,
        ],
        &[
            0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
    ),
];

const LONGEST_SIGNATURE: usize = 29;

/// `msvc.py:analyzeFunction`'s `vs.getSignature(bytes, offset)` restricted to
/// the `security_check_cookie` rows: does a `/GS` cookie check start exactly
/// at `address`?
pub fn is_security_check_cookie(image: &LoadedImage, address: u64) -> bool {
    let Some(candidate) = image.bytes_at(address, LONGEST_SIGNATURE) else {
        return false;
    };
    SECURITY_CHECK_COOKIE_SIGNATURES
        .iter()
        .any(|(signature, mask)| {
            candidate.len() >= signature.len()
                && candidate
                    .iter()
                    .zip(signature.iter())
                    .zip(mask.iter())
                    .all(|((&actual, &expected), &mask)| actual & mask == expected)
        })
}

/// `msvcfunc.py`'s inner condition: the referencing instruction must be a
/// `mov`. Kept next to the rest of the port so the upstream shape stays
/// visible at one place.
pub fn references_cookie(mnemonic: Mnemonic) -> bool {
    mnemonic == Mnemonic::Mov
}

/// Collect the block starts `msvcfunc.py` would turn into functions.
///
/// `cookies` are the addresses read out of each matched
/// `security_check_cookie`'s first instruction; `sources` yields the
/// instruction addresses that reference a given cookie; `block_start`
/// resolves `vw.getCodeBlock(fromva)[0]`, returning `None` where upstream's
/// `if not cb: continue` would fire. Upstream skips an address that is
/// already a function, which the caller does with its own `function_starts`.
pub fn new_function_starts<S, B, M>(
    cookies: &BTreeSet<u64>,
    sources: S,
    mnemonic_at: M,
    block_start: B,
) -> BTreeSet<u64>
where
    S: Fn(u64) -> Vec<u64>,
    M: Fn(u64) -> Option<Mnemonic>,
    B: Fn(u64) -> Option<u64>,
{
    let mut out = BTreeSet::new();
    for &cookie in cookies {
        for from in sources(cookie) {
            let Some(mnemonic) = mnemonic_at(from) else {
                continue;
            };
            if !references_cookie(mnemonic) {
                continue;
            }
            let Some(start) = block_start(from) else {
                continue;
            };
            out.insert(start);
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_function_starts_only_follows_mov_references() {
        let cookies = BTreeSet::from([0x9000]);
        let starts = new_function_starts(
            &cookies,
            |cookie| {
                assert_eq!(cookie, 0x9000);
                vec![0x1000, 0x2000]
            },
            |from| {
                Some(if from == 0x1000 {
                    Mnemonic::Mov
                } else {
                    Mnemonic::Cmp
                })
            },
            |from| Some(from & !0xff),
        );
        assert_eq!(starts, BTreeSet::from([0x1000]));
    }

    #[test]
    fn new_function_starts_skips_addresses_with_no_code_block() {
        let cookies = BTreeSet::from([0x9000]);
        let starts = new_function_starts(
            &cookies,
            |_| vec![0x1000],
            |_| Some(Mnemonic::Mov),
            |_| None,
        );
        assert!(starts.is_empty());
    }
}
