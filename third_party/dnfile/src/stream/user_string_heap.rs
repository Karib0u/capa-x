use crate::{Result, error::Error};

#[derive(Debug, Clone, serde::Serialize)]
pub struct UserStringHeap<'a> {
    #[serde(skip_serializing)]
    data: &'a [u8],
}

impl<'a> UserStringHeap<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Returns a copy of the user-string bytes (UTF-16 LE) at `index`.
    pub fn get(&self, index: usize) -> Result<Vec<u8>> {
        Ok(self.get_ref(index)?.to_vec())
    }

    /// Returns a borrowed slice of the user-string bytes at `index` — zero-copy.
    pub fn get_ref(&self, index: usize) -> Result<&'a [u8]> {
        if index >= self.data.len() {
            return Err(Error::UserStringHeapReadOutOfBound(index, self.data.len()));
        }

        let (data_length, length_size) = crate::utils::read_compressed_usize(
            self.data
                .get(index..)
                .ok_or(Error::UserStringHeapReadOutOfBound(index, self.data.len()))?,
        )?;

        let end_index = index
            .checked_add(length_size)
            .and_then(|i| i.checked_add(data_length));
        match end_index {
            Some(end) if end <= self.data.len() => Ok(&self.data[index + length_size..end]),
            _ => Err(Error::UserStringHeapReadOutOfBound(index, self.data.len())),
        }
    }

    /// Decode the #US heap entry at `index` as a Rust `String`.
    ///
    /// 0.5.1 (parity with upstream `malwarefrank/dnfile` PR #93):
    /// uses `String::from_utf16_lossy` instead of the strict
    /// `String::from_utf16`. Some .NET malware deliberately stores
    /// invalid UTF-16 in `#US` heap entries — unpaired high/low
    /// surrogates, terminator-byte oddities — as a poor-man's
    /// anti-analysis trick: strict decoders bail with
    /// `FromUtf16Error`, the calling tool drops the string from
    /// its feature set, and rules looking for that string don't
    /// fire. The lossy decoder replaces invalid surrogates with
    /// U+FFFD (`�`) and yields the rest of the string verbatim,
    /// which matches what upstream Python dnfile + capa do (with
    /// `errors='surrogatepass'` / `errors='replace'`) so capa
    /// rules see the same string content across both
    /// implementations.
    ///
    /// If you need a strict-or-fail decode for a specific use
    /// case, walk `get_ref(index)` yourself and call
    /// `String::from_utf16` directly — the raw bytes are still
    /// borrowed zero-copy.
    pub fn get_us(&self, index: usize) -> Result<String> {
        let data = self.get_ref(index)?;
        let utf16: Vec<u16> = data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&utf16))
    }
}

impl<'a> crate::DnPe<'a> {
    pub fn new_user_string_heap(
        &self,
        _metadata_rva: &u32,
        _stream_offset: &u32,
        _stream_size: &usize,
        _stream_name: &str,
        stream_data: &'a [u8],
    ) -> Result<super::Stream<'a>> {
        Ok(super::Stream::UserStringHeap(UserStringHeap::new(
            stream_data,
        )))
    }
}
