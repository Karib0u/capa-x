use crate::{Result, error::Error};

pub fn read_usize(data: &[u8]) -> Result<usize> {
    match data.len() {
        1 => Ok(data[0] as usize),
        2 => Ok(u16::from_le_bytes(data[..].try_into()?) as usize),
        4 => Ok(u32::from_le_bytes(data[..].try_into()?) as usize),
        8 => Ok(u64::from_le_bytes(data[..].try_into()?) as usize),
        _ => Err(Error::CantReadUsizeFromBytesLen(data.len())),
    }
}

pub fn read_compressed_usize(data: &[u8]) -> Result<(usize, usize)> {
    let b0 = *data.first().ok_or(Error::ReadCompressedUsize)?;
    if b0 & 0x80 == 0 {
        Ok((b0 as usize, 1))
    } else if b0 & 0x40 == 0 {
        let b1 = *data.get(1).ok_or(Error::ReadCompressedUsize)?;
        let value = ((b0 as usize & 0x7F) << 8) | b1 as usize;
        Ok((value, 2))
    } else if b0 & 0x20 == 0 {
        let b1 = *data.get(1).ok_or(Error::ReadCompressedUsize)?;
        let b2 = *data.get(2).ok_or(Error::ReadCompressedUsize)?;
        let b3 = *data.get(3).ok_or(Error::ReadCompressedUsize)?;
        let value = ((b0 as usize & 0x3F) << 24)
            | ((b1 as usize) << 16)
            | ((b2 as usize) << 8)
            | b3 as usize;
        Ok((value, 4))
    } else {
        Err(Error::ReadCompressedUsize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_usize_1_byte() {
        assert_eq!(read_usize(&[0xAB]).unwrap(), 0xAB);
    }

    #[test]
    fn read_usize_2_bytes_little_endian() {
        assert_eq!(read_usize(&[0x34, 0x12]).unwrap(), 0x1234);
    }

    #[test]
    fn read_usize_4_bytes_little_endian() {
        assert_eq!(read_usize(&[0x78, 0x56, 0x34, 0x12]).unwrap(), 0x1234_5678);
    }

    #[test]
    fn read_usize_8_bytes_little_endian() {
        assert_eq!(
            read_usize(&[0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]).unwrap(),
            0x0123_4567_89AB_CDEF
        );
    }

    #[test]
    fn read_usize_rejects_odd_lengths() {
        assert!(read_usize(&[0x12, 0x34, 0x56]).is_err());
    }

    // ECMA-335 II.23.2 compressed-integer encoding tests:
    #[test]
    fn read_compressed_usize_one_byte_form() {
        // Values 0..=0x7F encoded in a single byte.
        assert_eq!(read_compressed_usize(&[0x00]).unwrap(), (0x00, 1));
        assert_eq!(read_compressed_usize(&[0x03]).unwrap(), (0x03, 1));
        assert_eq!(read_compressed_usize(&[0x7F]).unwrap(), (0x7F, 1));
    }

    #[test]
    fn read_compressed_usize_two_byte_form() {
        // Values 0x80..=0x3FFF encoded in two bytes with prefix 10.
        // 0x80 -> bytes (0x80, 0x80).
        assert_eq!(read_compressed_usize(&[0x80, 0x80]).unwrap(), (0x80, 2));
        // 0x2E57 -> bytes (0xAE, 0x57)
        assert_eq!(read_compressed_usize(&[0xAE, 0x57]).unwrap(), (0x2E57, 2));
        // Maximum 2-byte value: 0x3FFF
        assert_eq!(read_compressed_usize(&[0xBF, 0xFF]).unwrap(), (0x3FFF, 2));
    }

    #[test]
    fn read_compressed_usize_four_byte_form() {
        // Values 0x4000..=0x1FFF_FFFF encoded in four bytes with prefix 110.
        assert_eq!(
            read_compressed_usize(&[0xC0, 0x00, 0x40, 0x00]).unwrap(),
            (0x4000, 4)
        );
        // Maximum 4-byte value: 0x1FFF_FFFF
        assert_eq!(
            read_compressed_usize(&[0xDF, 0xFF, 0xFF, 0xFF]).unwrap(),
            (0x1FFF_FFFF, 4)
        );
    }

    #[test]
    fn read_compressed_usize_rejects_invalid_prefix() {
        // 0xE0 has the 111 prefix which is not valid for unsigned compressed ints.
        assert!(read_compressed_usize(&[0xE0, 0x00, 0x00, 0x00]).is_err());
    }
}
