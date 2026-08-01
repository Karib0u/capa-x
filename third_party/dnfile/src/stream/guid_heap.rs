use crate::{Result, error::Error};

#[derive(Debug, Clone, serde::Serialize)]
pub struct GuidHeap<'a> {
    #[serde(skip_serializing)]
    data: &'a [u8],
}

impl<'a> GuidHeap<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn get(&self, index: usize) -> Result<uuid::Uuid> {
        const SIZE: usize = 16;
        if index < 1 {
            return Ok(uuid::Uuid::default());
        }
        // ECMA-335 GUID heap indices are 1-based. All arithmetic is checked
        // to avoid wraparound on attacker-supplied indices that would
        // otherwise bypass the upper-bound check.
        let offset = index
            .checked_sub(1)
            .and_then(|i| i.checked_mul(SIZE))
            .ok_or(Error::GuidHeapReadOutOfBound(index, self.data.len()))?;
        let end = offset
            .checked_add(SIZE)
            .ok_or(Error::GuidHeapReadOutOfBound(index, self.data.len()))?;
        if end > self.data.len() {
            return Err(Error::GuidHeapReadOutOfBound(index, self.data.len()));
        }
        Ok(uuid::Uuid::from_slice(&self.data[offset..end])?)
    }
}

impl<'a> crate::DnPe<'a> {
    pub fn new_guid_heap(
        &self,
        _metadata_rva: &u32,
        _stream_offset: &u32,
        _stream_size: &usize,
        _stream_name: &str,
        stream_data: &'a [u8],
    ) -> Result<super::Stream<'a>> {
        Ok(super::Stream::GuidHeap(GuidHeap::new(stream_data)))
    }
}
