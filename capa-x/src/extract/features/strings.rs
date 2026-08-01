//! ASCII / UTF-16LE string extraction, ported from
//! `capa/features/extractors/strings.py` (v9.4.0, see PINNED.md). Originates
//! from FLOSS; capa vendors a minimal copy.
//!
//! Both extractors implement the same non-overlapping "maximal run of
//! qualifying bytes" semantics as Python's `re.finditer` over a
//! `{n,}`-quantified single-class pattern: a manual scan is used instead of
//! a regex engine since the character class turns out to be exactly
//! printable ASCII (0x20..=0x7e) plus tab (0x09) -- see `is_ascii_byte`.
//! Off-by-ones here cause silent rule diffs, not errors.

/// capa/features/extractors/strings.py: REPEATS
const REPEATS: [u8; 4] = [b'A', 0x00, 0xFE, 0xFF];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedString {
    pub s: String,
    /// byte offset into the buffer this string was found at
    pub offset: usize,
}

/// the `ASCII_BYTE` character class: printable ASCII (space through `~`)
/// plus tab. capa/features/extractors/strings.py's `ASCII_BYTE` is built
/// from an explicit enumeration of punctuation/digits/letters that, taken
/// together, is exactly this contiguous range plus `\t`.
fn is_ascii_byte(b: u8) -> bool {
    b == b'\t' || (0x20..=0x7e).contains(&b)
}

/// port of `buf_filled_with`: is every byte in `buf` equal to `character`?
/// The empty buffer contains no bytes, therefore always returns false.
fn buf_filled_with(buf: &[u8], character: u8) -> bool {
    if buf.is_empty() {
        return false;
    }
    buf.iter().all(|&b| b == character)
}

/// port of `extract_ascii_strings` (default `n = 4`).
pub fn extract_ascii_strings(buf: &[u8], n: usize) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    if buf.is_empty() || n < 1 {
        return out;
    }
    if REPEATS.contains(&buf[0]) && buf_filled_with(buf, buf[0]) {
        return out;
    }

    let mut i = 0usize;
    while i < buf.len() {
        if is_ascii_byte(buf[i]) {
            let start = i;
            while i < buf.len() && is_ascii_byte(buf[i]) {
                i += 1;
            }
            if i - start >= n {
                // every byte in [start, i) is ASCII by construction, so
                // this can't fail.
                let s: String = buf[start..i].iter().map(|&b| b as char).collect();
                out.push(ExtractedString { s, offset: start });
            }
        } else {
            i += 1;
        }
    }
    out
}

/// port of `extract_unicode_strings` (default `n = 4`): naive UTF-16LE, one
/// `(ascii_byte, 0x00)` pair per character, matches allowed to start at any
/// byte offset (not just even ones) -- a match can immediately follow a
/// shorter-than-`n` run that started one byte earlier.
pub fn extract_unicode_strings(buf: &[u8], n: usize) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    if buf.is_empty() || n < 1 {
        return out;
    }
    if REPEATS.contains(&buf[0]) && buf_filled_with(buf, buf[0]) {
        return out;
    }

    let mut i = 0usize;
    while i + 1 < buf.len() {
        // count consecutive valid (ascii, 0x00) pairs starting at i.
        let mut j = i;
        let mut pairs = 0usize;
        while j + 1 < buf.len() && is_ascii_byte(buf[j]) && buf[j + 1] == 0 {
            pairs += 1;
            j += 2;
        }
        if pairs >= n {
            // `str.decode("utf-16")` on a run of (ascii, 0x00) pairs is
            // just the ascii bytes widened to UTF-16 code units; every code
            // unit here is <=0x7e, so this can't produce a decode error the
            // way Python's `contextlib.suppress(UnicodeDecodeError)` guards
            // against (that guard exists for lone surrogates, which can't
            // occur when every high byte is 0).
            let s: String = buf[i..j]
                .chunks_exact(2)
                .map(|pair| pair[0] as char)
                .collect();
            out.push(ExtractedString { s, offset: i });
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// Approximates vivisect's `detectString`/`detectUnicode` at a specific
/// address, used by the data-xref instruction features (`viv/insn.py`'s
/// `read_string`/`derefs`). Vivisect internals are deliberately not ported
/// here; this reuses the file-scope string scanner at an address instead.
///
/// An earlier version of this function called the scanner with no minimum
/// length (`n = 1`), reasoning that vivisect's real `detectString`/
/// `detectUnicode` require no minimum either. That reasoning was wrong: the
/// pinned vivisect source (`vivisect/__init__.py`, `.venv`) shows both
/// require their null terminator to land only after a handful of qualifying
/// bytes (ASCII: `count >= 4`; UTF-16LE: `count > 8`, i.e. 5+ code units) --
/// anything shorter is rejected outright, not merely "short." With `n = 1`,
/// a single ASCII byte immediately followed by `0x00` (extremely common:
/// it's the second byte of *any* UTF-16LE character) always "matches" as a
/// one-character ASCII string and wins ASCII-first priority below, silently
/// shadowing a real, much longer UTF-16LE string one byte later -- e.g. the
/// UTF-16LE run `"SCardControl\0"` was never found this way, because its
/// own first byte plus the trailing `\0` of whatever preceded it always
/// forms a spurious length-1 ASCII "match" ending exactly where the real
/// string begins.
///
/// [`string_at`] now ports both loops directly. Two pieces are still left
/// out, and neither can change an answer here:
///
/// - the location-database lookahead (`if count > 0: loc =
///   self.getLocation(va+count)`), which reuses an *already recorded*
///   `LOC_STRING`/`LOC_UNI`; capa-x has no such database, and the byte
///   scan below is what fills it upstream in the first place.
/// - the pascal/delphi length-prefix branch (`c == 0 and (count == dlen or
///   count == plen)`), which is reachable only for `count < 4` -- the
///   preceding `count >= 4` branch already returns for anything longer, and
///   a run shorter than 4 is below `MIN_STRING_LEN` regardless.
const MIN_STRING_LEN: usize = 4;
/// `detectUnicode`'s own minimum: `if c0 == 0: if count > 8: return count`,
/// counting *bytes*, so five UTF-16LE code units.
const MIN_UNICODE_BYTES: usize = 9;

/// vivisect's own character class, which is *not* capa's `ASCII_BYTE`:
/// `detectString` and `detectUnicode` both stop at the first byte whose
/// `chr(c)` is outside Python's `string.printable`
/// (`vivisect/__init__.py:1062` and `:1118`). That set is printable ASCII
/// plus all of Python's whitespace -- so `\n`, `\r`, `\x0b` and `\x0c` are
/// *inside* a vivisect-detected string, where [`is_ascii_byte`] ends one.
/// Using the narrower class here truncated `" HTTP/1.1\r\nHost: "` at the
/// `\r` and cost every rule that matches on the tail.
fn is_viv_printable_byte(b: u8) -> bool {
    is_ascii_byte(b) || matches!(b, b'\n' | 0x0b | 0x0c | b'\r')
}

/// `detectString`: a run of printable bytes **terminated by a `0x00` inside
/// the buffer**. A run that ends at any other byte, or that reaches the end
/// of the buffer, is `-1` -- not a string. That terminator requirement is
/// what keeps the AES s-box (`63 7c 77 7b f2 ...` -- four printable bytes
/// then `0xf2`) out of `isProbablyString`, and so keeps its `bytes` feature.
fn detect_string(buf: &[u8]) -> Option<String> {
    let len = buf
        .iter()
        .take_while(|&&b| is_viv_printable_byte(b))
        .count();
    if len < MIN_STRING_LEN || buf.get(len) != Some(&0) {
        return None;
    }
    Some(buf[..len].iter().map(|&b| b as char).collect())
}

/// `detectUnicode`: "simple" UTF-16LE -- every code unit's high byte must
/// equal the *first* one's (`charset = bytes[offset + 1]`, virtually always
/// `0`), the low bytes must be printable, and a `0x00` low byte terminates.
fn detect_unicode(buf: &[u8]) -> Option<String> {
    let charset = *buf.get(1)?;
    let mut count = 0usize;
    loop {
        let &low = buf.get(count)?;
        // upstream reads `c1` before testing `c0`, so a terminator with no
        // room for its high byte is a reject, not a match.
        let &high = buf.get(count.saturating_add(1))?;
        if low == 0 {
            if count < MIN_UNICODE_BYTES {
                return None;
            }
            return buf
                .chunks_exact(2)
                .take(count / 2)
                .map(|unit| char::from_u32(u32::from(u16::from_le_bytes([unit[0], unit[1]]))))
                .collect();
        }
        if !is_viv_printable_byte(low) || high != charset {
            return None;
        }
        count = count.saturating_add(2);
    }
}

pub fn string_at(buf: &[u8]) -> Option<String> {
    detect_string(buf).or_else(|| detect_unicode(buf))
}

/// port of the `vw.isProbablyString(p) or vw.isProbablyUnicode(p)` check in
/// `derefs`: does *some* qualifying string start exactly at the start of
/// `buf`?
pub fn is_probably_string(buf: &[u8]) -> bool {
    string_at(buf).is_some()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ascii_min_length_boundary() {
        // `\n` (0x0a) is *not* in the ASCII_BYTE class (only `\t` among
        // control characters is), so it splits runs here; plain space
        // would not (space is itself a class member; that's covered by
        // `unicode_odd_offset_match`'s sibling test data, indirectly).
        let buf = b"ab\nabcd\nabc";
        // "ab" (2) and "abc" (3) are below the n=4 threshold; "abcd" (4) is not.
        let found = extract_ascii_strings(buf, 4);
        assert_eq!(
            found,
            vec![ExtractedString {
                s: "abcd".to_string(),
                offset: 3
            }]
        );
    }

    #[test]
    fn ascii_run_at_buffer_edges() {
        let buf = b"abcd";
        let found = extract_ascii_strings(buf, 4);
        assert_eq!(
            found,
            vec![ExtractedString {
                s: "abcd".to_string(),
                offset: 0
            }]
        );
    }

    #[test]
    fn ascii_skips_buffer_filled_with_repeat_byte() {
        let buf = vec![b'A'; 100];
        assert!(extract_ascii_strings(&buf, 4).is_empty());

        let buf = vec![0x00u8; 100];
        assert!(extract_ascii_strings(&buf, 4).is_empty());
        assert!(extract_unicode_strings(&buf, 4).is_empty());
    }

    #[test]
    fn unicode_basic() {
        let mut buf = Vec::new();
        for b in b"abcd" {
            buf.push(*b);
            buf.push(0);
        }
        let found = extract_unicode_strings(&buf, 4);
        assert_eq!(
            found,
            vec![ExtractedString {
                s: "abcd".to_string(),
                offset: 0
            }]
        );
    }

    #[test]
    fn unicode_odd_offset_match() {
        // byte 0 (0x01, outside the ASCII_BYTE class) can't start any pair
        // at all, so the scan advances a single byte to position 1 -- an
        // *odd* offset -- where a full "abcd" run begins. This exercises
        // the "no forced 2-byte alignment" pitfall: a match need not start
        // on an even byte offset.
        let mut buf = vec![0x01u8];
        for b in b"abcd" {
            buf.push(*b);
            buf.push(0);
        }
        let found = extract_unicode_strings(&buf, 4);
        assert_eq!(
            found,
            vec![ExtractedString {
                s: "abcd".to_string(),
                offset: 1
            }]
        );
    }

    #[test]
    fn unicode_below_min_length_is_skipped() {
        let mut buf = Vec::new();
        for b in b"abc" {
            buf.push(*b);
            buf.push(0);
        }
        assert!(extract_unicode_strings(&buf, 4).is_empty());
    }

    #[test]
    fn empty_buffer_yields_nothing() {
        assert!(extract_ascii_strings(&[], 4).is_empty());
        assert!(extract_unicode_strings(&[], 4).is_empty());
    }

    #[test]
    fn string_at_rejects_a_short_ascii_run_below_the_minimum_length() {
        // a 1-character ASCII run no longer counts -- it must not shadow a
        // real string starting one byte later (see `string_at`'s doc
        // comment: this used to be the exact bug that hid UTF-16LE strings
        // like "SCardControl" behind a spurious single-byte ASCII match).
        assert_eq!(string_at(b"a\x00\x00\x00"), None);
    }

    #[test]
    fn string_at_finds_a_plain_ascii_run() {
        assert_eq!(string_at(b"AAAA\x00BBBB\x00"), Some("AAAA".to_string()));
    }

    #[test]
    fn string_at_finds_a_unicode_string_hidden_behind_a_too_short_ascii_prefix() {
        // the byte at offset 0 plus the following 0x00 looks like a
        // 1-character ASCII string, but that's below MIN_STRING_LEN, so
        // this must fall through to the UTF-16LE scan and find the real
        // "SCardControl" string starting at the same offset.
        let mut buf = b"S\x00C\x00a\x00r\x00d\x00C\x00o\x00n\x00t\x00r\x00o\x00l\x00".to_vec();
        buf.extend_from_slice(&[0, 0]);
        assert_eq!(string_at(&buf), Some("SCardControl".to_string()));
    }

    #[test]
    fn string_at_returns_none_when_nothing_starts_at_zero() {
        assert_eq!(string_at(&[0x00, 0x00, 0x00]), None);
        assert!(!is_probably_string(&[0x00, 0x00, 0x00]));
    }

    #[test]
    fn is_probably_string_needs_a_terminator_inside_the_buffer() {
        assert!(is_probably_string(b"hello\x00"));
        // `detectString` returns -1 when the run reaches the end of the
        // buffer without a `0x00` -- it never guesses.
        assert!(!is_probably_string(b"hello"));
    }

    #[test]
    fn is_probably_string_rejects_a_run_ending_at_a_non_printable_byte() {
        // the AES s-box: `c|w{` is four printable bytes, but `0xf2` ends the
        // run instead of a terminator, so this stays a `bytes` feature.
        assert!(!is_probably_string(&[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5
        ]));
    }

    #[test]
    fn string_at_spans_the_whitespace_ascii_byte_rejects() {
        // vivisect's `detectString` accepts everything in Python's
        // `string.printable`, which includes `\r`, `\n`, `\x0b` and `\x0c`.
        // Real case (`af13e7583ed1b27c4ae219e344a37e2b.exe_`, 0x405005):
        // truncating at the `\r` drops the `Host:` the rule matches on.
        assert_eq!(
            string_at(b" HTTP/1.1\r\nHost: \x00"),
            Some(" HTTP/1.1\r\nHost: ".to_string())
        );
        assert_eq!(
            string_at(b"a\x0bb\x0cc\x00"),
            Some("a\x0bb\x0cc".to_string())
        );
        // capa's own file-scope `ASCII_BYTE` class is unchanged by this: it
        // still ends a string at `\r`.
        assert_eq!(
            extract_ascii_strings(b" HTTP/1.1\r\nHost: \x00", 4)
                .first()
                .map(|found| found.s.clone()),
            Some(" HTTP/1.1".to_string())
        );
    }

    #[test]
    fn string_at_finds_utf16_with_whitespace_bytes() {
        assert_eq!(
            string_at(b"a\x00b\x00\r\x00c\x00d\x00\x00\x00"),
            Some("ab\rcd".to_string())
        );
    }
}
