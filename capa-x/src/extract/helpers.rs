//! Port of `capa/features/extractors/helpers.py` (v9.4.0, see PINNED.md):
//! symbol-name variant generation for imports/APIs, forwarded-export name
//! reformatting, and the embedded-PE carving scan.

/// capa/features/extractors/helpers.py: `is_aw_function`. Import/export
/// names are always ASCII in practice (validated at decode time by the
/// callers in `pe.rs`), so a byte-length/byte-indexing check here is
/// equivalent to Python's character-based one.
pub fn is_aw_function(symbol: &str) -> bool {
    let bytes = symbol.as_bytes();
    if bytes.len() < 2 {
        return false;
    }
    matches!(bytes[bytes.len() - 1], b'A' | b'W')
}

/// capa/features/extractors/helpers.py: `is_ordinal`
pub fn is_ordinal(symbol: &str) -> bool {
    symbol.starts_with('#')
}

/// port of `generate_symbols`: for a given dll and symbol name, generate
/// variants. Order matters -- this feeds directly into `FeatureSet`
/// insertion order, so it's preserved exactly as Python yields it.
pub fn generate_symbols(dll: &str, symbol: &str, include_dll: bool) -> Vec<String> {
    let mut dll = dll.to_lowercase();
    if let Some(stripped) = dll.strip_suffix(".dll") {
        dll = stripped.to_string();
    }
    if let Some(stripped) = dll.strip_suffix(".drv") {
        dll = stripped.to_string();
    }
    if let Some(stripped) = dll.strip_suffix(".so") {
        dll = stripped.to_string();
    }

    let mut out = Vec::new();
    let ordinal = is_ordinal(symbol);

    if include_dll || ordinal {
        out.push(format!("{dll}.{symbol}"));
    }

    if !ordinal {
        out.push(symbol.to_string());

        if is_aw_function(symbol) {
            let trimmed = &symbol[..symbol.len() - 1];
            if include_dll {
                out.push(format!("{dll}.{trimmed}"));
            }
            out.push(trimmed.to_string());
        }
    }

    out
}

/// port of `reformat_forwarded_export_name`: a forwarded export has a DLL
/// name/path and symbol name; the former is lowercased, the latter kept
/// verbatim. Uses the *last* `.` as separator (the DLL name can be a full
/// path with embedded periods). Python's `str.rpartition` returns `("",
/// "", s)` when the separator isn't found at all -- i.e. the whole name
/// becomes the "symbol" with an empty (lowercased-to-empty) "dll" -- so
/// that quirk is preserved rather than treating the whole string as a dll.
pub fn reformat_forwarded_export_name(forwarded_name: &str) -> String {
    let (dll, symbol) = match forwarded_name.rfind('.') {
        Some(idx) => (&forwarded_name[..idx], &forwarded_name[idx + 1..]),
        None => ("", forwarded_name),
    };
    format!("{}.{symbol}", dll.to_lowercase())
}

/// capa/features/extractors/helpers.py: `all_zeros`. Used by
/// `extract_insn_bytes_features` to skip an all-zero dereferenced buffer.
pub fn all_zeros(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// `PE/carve.py`'s `MAX_OFFSET_PE_AFTER_MZ`: an `e_lfanew` further than this
/// from the `MZ` disqualifies the candidate, however well the `PE` magic
/// happens to match at the far end.
const MAX_OFFSET_PE_AFTER_MZ: usize = 0x200;

/// Port of `carve_pe`. Derive the only possible single-byte XOR key from
/// each candidate's first byte, avoiding 256 separate scans of the file.
/// Results retain the reference's LIFO order: descending key, then ascending
/// offset within a key (`capa/features/extractors/helpers.py::carve_pe`).
pub fn carve_pe(buf: &[u8], offset: usize) -> Vec<(usize, u8)> {
    let Some(tail) = buf.get(offset..) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (relative, pair) in tail.windows(2).enumerate() {
        let [first, second] = pair else {
            continue;
        };
        let key = first ^ b'M';
        if second ^ key != b'Z' {
            continue;
        }
        // `relative` is within the slice starting at `offset`.
        let off = offset + relative;
        let Some(e_lfanew) = off.checked_add(0x3c) else {
            continue;
        };
        let Some(raw) = buf.get(e_lfanew..).and_then(|tail| tail.get(..4)) else {
            continue;
        };
        let [a, b, c, d] = raw else {
            continue;
        };
        let newoff = u32::from_le_bytes([a ^ key, b ^ key, c ^ key, d ^ key]) as usize;
        if newoff > MAX_OFFSET_PE_AFTER_MZ {
            continue;
        }
        let Some(peoff) = off.checked_add(newoff) else {
            continue;
        };
        if buf.get(peoff..).and_then(|tail| tail.get(..2)) == Some(&[b'P' ^ key, b'E' ^ key]) {
            out.push((off, key));
        }
    }
    out.sort_unstable_by_key(|&(off, key)| (std::cmp::Reverse(key), off));
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_symbols_plain_name() {
        let out = generate_symbols("KERNEL32.dll", "CreateFileA", true);
        assert_eq!(
            out,
            vec![
                "kernel32.CreateFileA".to_string(),
                "CreateFileA".to_string(),
                "kernel32.CreateFile".to_string(),
                "CreateFile".to_string(),
            ]
        );
    }

    #[test]
    fn generate_symbols_no_include_dll() {
        let out = generate_symbols("kernel32.dll", "CreateFileA", false);
        assert_eq!(
            out,
            vec!["CreateFileA".to_string(), "CreateFile".to_string()]
        );
    }

    #[test]
    fn generate_symbols_ordinal() {
        let out = generate_symbols("ws2_32.dll", "#1", true);
        assert_eq!(out, vec!["ws2_32.#1".to_string()]);
    }

    #[test]
    fn generate_symbols_ordinal_no_dll_still_yields_dll_form() {
        // ordinal-form symbols always include the dll, regardless of
        // include_dll -- there's no bare-name variant for an ordinal.
        let out = generate_symbols("ws2_32.dll", "#1", false);
        assert_eq!(out, vec!["ws2_32.#1".to_string()]);
    }

    #[test]
    fn generate_symbols_strips_known_extensions() {
        assert_eq!(
            generate_symbols("foo.drv", "Bar", true),
            vec!["foo.Bar".to_string(), "Bar".to_string()]
        );
        assert_eq!(
            generate_symbols("libfoo.so", "Bar", true),
            vec!["libfoo.Bar".to_string(), "Bar".to_string()]
        );
    }

    #[test]
    fn reformat_forwarded_export_name_uses_last_dot() {
        assert_eq!(
            reformat_forwarded_export_name("NTDLL.RtlAllocateHeap"),
            "ntdll.RtlAllocateHeap"
        );
        assert_eq!(
            reformat_forwarded_export_name("some.path.with.dots.Func"),
            "some.path.with.dots.Func"
                .rsplit_once('.')
                .map(|(d, s)| format!("{}.{s}", d.to_lowercase()))
                .expect("has a dot")
        );
    }

    #[test]
    fn reformat_forwarded_export_name_no_dot() {
        assert_eq!(reformat_forwarded_export_name("NoDotHere"), ".NoDotHere");
    }

    #[test]
    fn carve_pe_finds_plain_embedded_mz_pe() {
        // a minimal embedded "PE": MZ header with e_lfanew (at +0x3c)
        // pointing at a PE signature, embedded at offset 5 in a carrier
        // buffer, unobfuscated (xor key 0).
        let mut buf = vec![0u8; 5];
        let mut embedded = vec![0u8; 0x40];
        embedded[0] = b'M';
        embedded[1] = b'Z';
        // e_lfanew: PE signature sits right after this 0x40-byte header.
        embedded[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        embedded.extend_from_slice(b"PE");
        buf.extend_from_slice(&embedded);

        let found = carve_pe(&buf, 1);
        assert_eq!(found, vec![(5, 0)]);
    }

    #[test]
    fn carve_pe_empty_on_no_match() {
        assert!(carve_pe(b"no embedded pe here", 1).is_empty());
    }

    #[test]
    fn carve_pe_preserves_xor_key_and_offset_order() {
        let mut buf = Vec::new();
        let mut expected = Vec::new();
        for key in 0..=255u8 {
            for _ in 0..2 {
                let offset = buf.len();
                let mut header = vec![0; 0x42];
                header[..2].copy_from_slice(b"MZ");
                header[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
                header[0x40..].copy_from_slice(b"PE");
                buf.extend(header.into_iter().map(|byte| byte ^ key));
                expected.push((offset, key));
            }
        }
        expected.sort_unstable_by_key(|&(off, key)| (std::cmp::Reverse(key), off));
        assert_eq!(carve_pe(&buf, 0), expected);
        for start in [1, 0x42, buf.len() - 1, buf.len(), usize::MAX] {
            let expected: Vec<_> = expected
                .iter()
                .copied()
                .filter(|&(off, _)| off >= start)
                .collect();
            assert_eq!(carve_pe(&buf, start), expected);
        }
    }

    #[test]
    fn carve_pe_checks_header_bounds_and_continues_after_invalid_candidates() {
        for key in [0, 1, 0x80, 0xff] {
            let mut buf = vec![key; 0x300];
            // Invalid header followed by a valid one for the same XOR key.
            for (off, pe_offset) in [(0, 0x201u32), (0x80, 0x200)] {
                buf[off..off + 2].copy_from_slice(&[b'M' ^ key, b'Z' ^ key]);
                for (dst, byte) in buf[off + 0x3c..off + 0x40]
                    .iter_mut()
                    .zip(pe_offset.to_le_bytes())
                {
                    *dst = byte ^ key;
                }
                let pe = off + pe_offset as usize;
                buf[pe..pe + 2].copy_from_slice(&[b'P' ^ key, b'E' ^ key]);
            }
            assert_eq!(carve_pe(&buf, 0), vec![(0x80, key)]);
            for end in [0, 1, 2, 0x3f, 0x40, 0x281] {
                assert!(carve_pe(&buf[..end], 0).is_empty());
            }
        }
    }

    #[test]
    fn all_zeros_detects_all_zero_and_non_zero_buffers() {
        assert!(all_zeros(&[0, 0, 0]));
        assert!(all_zeros(&[]));
        assert!(!all_zeros(&[0, 0, 1]));
    }
}
