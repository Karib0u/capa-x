use crate::{Result, error::Error};
use std::borrow::Cow;

#[derive(Debug, Clone, serde::Serialize)]
pub struct StringHeap<'a> {
    #[serde(skip_serializing)]
    data: &'a [u8],
}

impl<'a> StringHeap<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Returns the null-terminated string at `index`, lossily decoded as UTF-8.
    pub fn get(&self, index: usize) -> Result<String> {
        Ok(self.get_cow(index)?.into_owned())
    }

    /// Zero-allocation variant: returns a `Cow<'_, str>` borrowing the heap
    /// when the bytes are valid UTF-8.
    pub fn get_cow(&self, index: usize) -> Result<Cow<'a, str>> {
        Ok(String::from_utf8_lossy(self.get_bytes(index)?))
    }

    /// Returns the raw bytes (without the trailing NUL) at `index`.
    pub fn get_bytes(&self, index: usize) -> Result<&'a [u8]> {
        if index >= self.data.len() {
            return Err(Error::StringHeapReadOutOfBound(index, self.data.len()));
        }
        let tail = &self.data[index..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        Ok(&tail[..end])
    }
}

impl<'a> crate::DnPe<'a> {
    pub fn new_string_heap(
        &self,
        _metadata_rva: &u32,
        _stream_offset: &u32,
        _stream_size: &usize,
        _stream_name: &str,
        stream_data: &'a [u8],
    ) -> Result<super::Stream<'a>> {
        Ok(super::Stream::StringHeap(StringHeap::new(stream_data)))
    }
}
