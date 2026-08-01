//! Typed signature-blob decoders for `#Blob` heap entries
//! (dnfile-rs 0.5.1).
//!
//! Two decoders here, covering the most common `#Blob` payloads
//! encountered in malware-triage workflows:
//!
//! ### `CustomAttribute` (ECMA-335 II.23.3)
//!
//! Decodes a `CustomAttribute` blob into typed `Value`s. Layout:
//!
//! ```text
//!   prolog  : u16        = 0x0001 (sentinel)
//!   fixed[] : FixedArg
//!   numNamed: u16
//!   named[] : NamedArg
//! ```
//!
//! Each `FixedArg` is a value whose `ElementType` is determined by
//! the constructor's signature (passed in via
//! `CustomAttribute::decode_with_types`). For callers that don't
//! have the constructor signature, the simpler
//! `CustomAttribute::decode_raw_named` decoder skips the fixed
//! args entirely and walks the named-arg section (which carries
//! self-describing element types).
//!
//! ### `MarshalSpec` (ECMA-335 II.23.4)
//!
//! Decodes a `FieldMarshal.NativeType` blob — the marshalling
//! descriptor pinned via the `MarshalAs(UnmanagedType.X)` attribute
//! on a parameter or field. Covers the simple cases (single
//! `NATIVE_TYPE_*` byte, length-prefixed arrays/strings, custom
//! marshaller class+cookie) which match what `DllImport`
//! signatures use almost universally.
//!
//! ## Scope (deferred to a future release)
//!
//! Full ECMA-335 II.23.2 signature-blob decoding (MethodDefSig /
//! MethodRefSig / FieldSig / PropertySig / LocalVarSig / TypeSpec
//! / MethodSpec / StandAloneMethodSig and the recursive `TypeSig`
//! grammar with its ~25 variants) is intentionally NOT in 0.5.1.
//! That's a thousand-LOC subsystem in its own right; this module
//! covers the two narrow surfaces that ship the most user value
//! (CustomAttribute → maps to `[Obfuscation]`, `[DllImport]`,
//! `[Guid]`, `[AssemblyVersion]`, etc.; MarshalSpec → describes
//! the unmanaged binding side of every P/Invoke).

use crate::{Result, error::Error};

// ---------------------------------------------------------------
// ElementType — ECMA-335 II.23.1.16. Only the variants we actually
// decode are spelled out; everything else stays as a u8.
// ---------------------------------------------------------------

/// ECMA-335 II.23.1.16 element-type byte tags. We only enumerate
/// the variants the typed CustomAttribute / MarshalSpec decoders
/// produce; unknown tags surface as `Value::Raw(u8, …)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[repr(u8)]
pub enum ElementType {
    End = 0x00,
    Void = 0x01,
    Boolean = 0x02,
    Char = 0x03,
    I1 = 0x04,
    U1 = 0x05,
    I2 = 0x06,
    U2 = 0x07,
    I4 = 0x08,
    U4 = 0x09,
    I8 = 0x0a,
    U8 = 0x0b,
    R4 = 0x0c,
    R8 = 0x0d,
    String = 0x0e,
    /// `SZARRAY` — single-dimension array with lower bound 0.
    SzArray = 0x1d,
    /// CustomAttribute-only pseudo-tag for `System.Type`.
    Type = 0x50,
    /// CustomAttribute-only pseudo-tag for boxed value
    /// (`object` field/parameter).
    Boxed = 0x51,
    /// CustomAttribute named-arg: field reference.
    Field = 0x53,
    /// CustomAttribute named-arg: property reference.
    Property = 0x54,
    /// CustomAttribute-only pseudo-tag for a boxed enum value.
    Enum = 0x55,
}

impl ElementType {
    /// Parse a raw byte. Returns None for unknown tags; the
    /// caller can then fall back to `Value::Raw`.
    #[must_use]
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x00 => Self::End,
            0x01 => Self::Void,
            0x02 => Self::Boolean,
            0x03 => Self::Char,
            0x04 => Self::I1,
            0x05 => Self::U1,
            0x06 => Self::I2,
            0x07 => Self::U2,
            0x08 => Self::I4,
            0x09 => Self::U4,
            0x0a => Self::I8,
            0x0b => Self::U8,
            0x0c => Self::R4,
            0x0d => Self::R8,
            0x0e => Self::String,
            0x1d => Self::SzArray,
            0x50 => Self::Type,
            0x51 => Self::Boxed,
            0x53 => Self::Field,
            0x54 => Self::Property,
            0x55 => Self::Enum,
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------
// CustomAttribute — ECMA-335 II.23.3
// ---------------------------------------------------------------

/// Decoded `CustomAttribute` value (fixed arg or named-arg
/// payload).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum Value {
    Boolean(bool),
    Char(u16),
    I1(i8),
    U1(u8),
    I2(i16),
    U2(u16),
    I4(i32),
    U4(u32),
    I8(i64),
    U8(u64),
    R4(f32),
    R8(f64),
    /// `SerString` — length-prefixed UTF-8. `None` is the
    /// "null string" sentinel (compressed-length byte 0xFF).
    String(Option<String>),
    /// `SerType` — `System.Type` reference. Same encoding as
    /// `SerString` (length-prefixed UTF-8 assembly-qualified
    /// type name).
    Type(Option<String>),
    /// `SZARRAY` of the given element type. `None` is the
    /// "null array" sentinel (length field 0xFFFF_FFFF).
    Array(Option<Vec<Value>>),
    /// Element-type byte that we recognised but didn't fully
    /// decode (e.g. nested generics). Carries the remaining
    /// blob bytes so the caller can fall back to a custom
    /// parser.
    Raw(u8, Vec<u8>),
}

/// One named-arg entry from a CustomAttribute blob.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct NamedArg {
    /// `Field` or `Property`.
    pub kind: ElementType,
    /// Field/property element type.
    pub elem_type: u8,
    /// For SZARRAY / Enum named args this is the inner element
    /// type byte; `None` otherwise.
    pub inner_elem_type: Option<u8>,
    /// Member name.
    pub name: String,
    /// Decoded value.
    pub value: Value,
}

/// Decoded CustomAttribute blob.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CustomAttribute {
    /// Positional args (constructor parameters).
    pub fixed: Vec<Value>,
    /// Field/property assignments inside `[Attr(field = value)]`.
    pub named: Vec<NamedArg>,
}

impl CustomAttribute {
    /// Decode with a known constructor parameter list. `ctor_types`
    /// is the sequence of `ElementType` bytes for each fixed arg
    /// (extracted from the ctor's `MethodDefSig` — caller's
    /// responsibility). Unknown / unsupported element types in
    /// `ctor_types` cause the corresponding fixed slot to be
    /// recorded as `Value::Raw(byte, remaining_bytes)` and parsing
    /// stops at that slot.
    pub fn decode_with_types(blob: &[u8], ctor_types: &[u8]) -> Result<Self> {
        let mut r = Reader::new(blob);
        // Prolog must be 0x0001.
        let prolog = r.read_u16_le()?;
        if prolog != 0x0001 {
            return Err(Error::FormatError(format!(
                "CustomAttribute: bad prolog 0x{prolog:04x}"
            )));
        }
        let mut fixed = Vec::with_capacity(ctor_types.len());
        for &ty in ctor_types {
            fixed.push(r.read_value(ty)?);
        }
        let num_named = r.read_u16_le()?;
        let mut named = Vec::with_capacity(num_named as usize);
        for _ in 0..num_named {
            named.push(r.read_named_arg()?);
        }
        Ok(Self { fixed, named })
    }

    /// Decode just the named-args section, skipping the fixed
    /// args. Useful when the caller doesn't have access to the
    /// constructor's signature — named args are self-describing
    /// (they carry their element type inline), fixed args aren't.
    /// `fixed_blob_len` tells the reader how many bytes the fixed
    /// section consumes (caller computes from ctor info or passes
    /// `0` to assume there are no fixed args).
    pub fn decode_raw_named(blob: &[u8], fixed_blob_len: usize) -> Result<Vec<NamedArg>> {
        let mut r = Reader::new(blob);
        let prolog = r.read_u16_le()?;
        if prolog != 0x0001 {
            return Err(Error::FormatError(format!(
                "CustomAttribute: bad prolog 0x{prolog:04x}"
            )));
        }
        r.skip(fixed_blob_len)?;
        let num_named = r.read_u16_le()?;
        let mut named = Vec::with_capacity(num_named as usize);
        for _ in 0..num_named {
            named.push(r.read_named_arg()?);
        }
        Ok(named)
    }
}

// ---------------------------------------------------------------
// MarshalSpec — ECMA-335 II.23.4
// ---------------------------------------------------------------

/// Decoded `FieldMarshal.NativeType` blob.
///
/// The full taxonomy is large (~50 `NATIVE_TYPE_*` constants), but
/// most blobs are a single byte. We surface the common shapes
/// distinctly and bucket the rest into [`MarshalSpec::Simple`] so
/// callers can still see what tag was set.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum MarshalSpec {
    /// Single-byte tag: `NATIVE_TYPE_*` constant.
    Simple(u8),
    /// `NATIVE_TYPE_ARRAY` (0x2a). Optional element type tag,
    /// optional `ParamNum` (for size-controlled-by-parameter),
    /// optional `NumElem` (compile-time size), optional
    /// `ParamNumMultiplier` (size = ParamNum × this).
    Array {
        elem_type: Option<u8>,
        param_num: Option<u32>,
        num_elem: Option<u32>,
        param_num_multiplier: Option<u32>,
    },
    /// `NATIVE_TYPE_FIXEDSYSSTRING` (0x17) — fixed-length string
    /// inline in a struct.
    FixedSysString { size: u32 },
    /// `NATIVE_TYPE_FIXEDARRAY` (0x1e) — fixed-length array
    /// inline in a struct.
    FixedArray { size: u32, elem_type: Option<u8> },
    /// `NATIVE_TYPE_CUSTOMMARSHALER` (0x2c) — custom marshaller
    /// class + cookie.
    CustomMarshaler {
        guid: String,
        unmanaged_type: String,
        managed_type: String,
        cookie: String,
    },
}

/// Common `NATIVE_TYPE_*` byte tags. Exposed as constants rather
/// than a full enum because the long tail is long and most code
/// only cares about a handful.
pub mod native_type {
    pub const VOID: u8 = 0x01;
    pub const BOOLEAN: u8 = 0x02;
    pub const I1: u8 = 0x03;
    pub const U1: u8 = 0x04;
    pub const I2: u8 = 0x05;
    pub const U2: u8 = 0x06;
    pub const I4: u8 = 0x07;
    pub const U4: u8 = 0x08;
    pub const I8: u8 = 0x09;
    pub const U8: u8 = 0x0a;
    pub const R4: u8 = 0x0b;
    pub const R8: u8 = 0x0c;
    pub const LPSTR: u8 = 0x14;
    pub const LPWSTR: u8 = 0x15;
    pub const LPTSTR: u8 = 0x16;
    pub const FIXEDSYSSTRING: u8 = 0x17;
    pub const IUNKNOWN: u8 = 0x19;
    pub const IDISPATCH: u8 = 0x1a;
    pub const STRUCT: u8 = 0x1b;
    pub const INTF: u8 = 0x1c;
    pub const SAFEARRAY: u8 = 0x1d;
    pub const FIXEDARRAY: u8 = 0x1e;
    pub const INT: u8 = 0x1f;
    pub const UINT: u8 = 0x20;
    pub const BYVALSTR: u8 = 0x22;
    pub const ANSIBSTR: u8 = 0x23;
    pub const TBSTR: u8 = 0x24;
    pub const VARIANTBOOL: u8 = 0x25;
    pub const FUNC: u8 = 0x26;
    pub const ASANY: u8 = 0x28;
    pub const ARRAY: u8 = 0x2a;
    pub const LPSTRUCT: u8 = 0x2b;
    pub const CUSTOMMARSHALER: u8 = 0x2c;
    pub const ERROR: u8 = 0x2d;
}

impl MarshalSpec {
    /// Decode a `FieldMarshal.NativeType` blob.
    pub fn decode(blob: &[u8]) -> Result<Self> {
        let mut r = Reader::new(blob);
        let tag = r.read_u8()?;
        match tag {
            native_type::ARRAY => {
                // Optional trailing fields, all using compressed-uint
                // encoding for the lengths/indices. The spec marks
                // each as optional — absence is signalled by the
                // input simply running out.
                let elem_type = if r.has_more() {
                    Some(r.read_u8()?)
                } else {
                    None
                };
                let param_num = if r.has_more() {
                    Some(r.read_compressed_uint()? as u32)
                } else {
                    None
                };
                let num_elem = if r.has_more() {
                    Some(r.read_compressed_uint()? as u32)
                } else {
                    None
                };
                let param_num_multiplier = if r.has_more() {
                    Some(r.read_compressed_uint()? as u32)
                } else {
                    None
                };
                Ok(Self::Array {
                    elem_type,
                    param_num,
                    num_elem,
                    param_num_multiplier,
                })
            }
            native_type::FIXEDSYSSTRING => Ok(Self::FixedSysString {
                size: r.read_compressed_uint()? as u32,
            }),
            native_type::FIXEDARRAY => {
                let size = r.read_compressed_uint()? as u32;
                let elem_type = if r.has_more() {
                    Some(r.read_u8()?)
                } else {
                    None
                };
                Ok(Self::FixedArray { size, elem_type })
            }
            native_type::CUSTOMMARSHALER => {
                // Four length-prefixed UTF-8 strings: GUID,
                // UnmanagedType (always empty), ManagedType,
                // Cookie. The GUID and UnmanagedType slots are
                // deprecated but still present in the wire format.
                Ok(Self::CustomMarshaler {
                    guid: r.read_ser_string_required()?,
                    unmanaged_type: r.read_ser_string_required()?,
                    managed_type: r.read_ser_string_required()?,
                    cookie: r.read_ser_string_required()?,
                })
            }
            other => Ok(Self::Simple(other)),
        }
    }
}

// ---------------------------------------------------------------
// Low-level reader — bounds-checked, no panics.
// ---------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    fn has_more(&self) -> bool {
        self.pos < self.data.len()
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::NotEnoughData(self.data.len(), n))?;
        if end > self.data.len() {
            return Err(Error::NotEnoughData(self.data.len(), end));
        }
        self.pos = end;
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or(Error::NotEnoughData(self.data.len(), self.pos + 1))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_u16_le(&mut self) -> Result<u16> {
        let end = self.pos + 2;
        if end > self.data.len() {
            return Err(Error::NotEnoughData(self.data.len(), end));
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos = end;
        Ok(v)
    }

    fn read_u32_le(&mut self) -> Result<u32> {
        let end = self.pos + 4;
        if end > self.data.len() {
            return Err(Error::NotEnoughData(self.data.len(), end));
        }
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos = end;
        Ok(v)
    }

    fn read_i8(&mut self) -> Result<i8> {
        Ok(self.read_u8()? as i8)
    }

    fn read_i16_le(&mut self) -> Result<i16> {
        Ok(self.read_u16_le()? as i16)
    }

    fn read_i32_le(&mut self) -> Result<i32> {
        Ok(self.read_u32_le()? as i32)
    }

    fn read_u64_le(&mut self) -> Result<u64> {
        let end = self.pos + 8;
        if end > self.data.len() {
            return Err(Error::NotEnoughData(self.data.len(), end));
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[self.pos..end]);
        self.pos = end;
        Ok(u64::from_le_bytes(buf))
    }

    fn read_i64_le(&mut self) -> Result<i64> {
        Ok(self.read_u64_le()? as i64)
    }

    fn read_f32_le(&mut self) -> Result<f32> {
        let bits = self.read_u32_le()?;
        Ok(f32::from_bits(bits))
    }

    fn read_f64_le(&mut self) -> Result<f64> {
        let bits = self.read_u64_le()?;
        Ok(f64::from_bits(bits))
    }

    fn read_compressed_uint(&mut self) -> Result<usize> {
        let (v, len) = crate::utils::read_compressed_usize(self.remaining())?;
        self.pos += len;
        Ok(v)
    }

    /// ECMA-335 II.23.3 `SerString` — `null | empty | (len, utf8[len])`.
    /// `len` is compressed-uint; sentinel byte 0xFF means null.
    fn read_ser_string(&mut self) -> Result<Option<String>> {
        // Peek the first byte for the null sentinel.
        let first = *self
            .data
            .get(self.pos)
            .ok_or(Error::NotEnoughData(self.data.len(), self.pos + 1))?;
        if first == 0xff {
            self.pos += 1;
            return Ok(None);
        }
        let len = self.read_compressed_uint()?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or(Error::NotEnoughData(self.data.len(), self.pos + len))?;
        if end > self.data.len() {
            return Err(Error::NotEnoughData(self.data.len(), end));
        }
        let s = std::str::from_utf8(&self.data[self.pos..end])
            .map_err(|e| Error::FormatError(format!("SerString utf8: {e}")))?
            .to_string();
        self.pos = end;
        Ok(Some(s))
    }

    /// `SerString` that promotes a leading `0xFF` (null sentinel)
    /// to an empty string — used by MarshalSpec strings which
    /// are always non-null in practice.
    fn read_ser_string_required(&mut self) -> Result<String> {
        Ok(self.read_ser_string()?.unwrap_or_default())
    }

    fn read_value(&mut self, ty: u8) -> Result<Value> {
        match ElementType::from_u8(ty) {
            Some(ElementType::Boolean) => Ok(Value::Boolean(self.read_u8()? != 0)),
            Some(ElementType::Char) => Ok(Value::Char(self.read_u16_le()?)),
            Some(ElementType::I1) => Ok(Value::I1(self.read_i8()?)),
            Some(ElementType::U1) => Ok(Value::U1(self.read_u8()?)),
            Some(ElementType::I2) => Ok(Value::I2(self.read_i16_le()?)),
            Some(ElementType::U2) => Ok(Value::U2(self.read_u16_le()?)),
            Some(ElementType::I4) => Ok(Value::I4(self.read_i32_le()?)),
            Some(ElementType::U4) => Ok(Value::U4(self.read_u32_le()?)),
            Some(ElementType::I8) => Ok(Value::I8(self.read_i64_le()?)),
            Some(ElementType::U8) => Ok(Value::U8(self.read_u64_le()?)),
            Some(ElementType::R4) => Ok(Value::R4(self.read_f32_le()?)),
            Some(ElementType::R8) => Ok(Value::R8(self.read_f64_le()?)),
            Some(ElementType::String) => Ok(Value::String(self.read_ser_string()?)),
            Some(ElementType::Type) => Ok(Value::Type(self.read_ser_string()?)),
            Some(ElementType::SzArray) => {
                // u32 length, then `length` element values.
                // Sentinel 0xFFFF_FFFF = null array.
                let len = self.read_u32_le()?;
                if len == 0xffff_ffff {
                    return Ok(Value::Array(None));
                }
                // The element type byte for fixed-arg SZARRAY is
                // NOT inline — the caller already knows it from the
                // ctor signature. But since `read_value` is generic
                // over `ty` and we only got `SzArray` here, we
                // can't recover the element type. Fall back to
                // returning the raw remaining bytes; this is a
                // limitation of the "fixed-arg without inner type"
                // shape. Real consumers will reach here through
                // `decode_raw_named` (named-arg SZARRAY) which
                // carries the inner type inline.
                Ok(Value::Raw(
                    ElementType::SzArray as u8,
                    self.remaining().to_vec(),
                ))
            }
            _ => Ok(Value::Raw(ty, self.remaining().to_vec())),
        }
    }

    /// Named-arg layout: `FieldOrProp(1) ElemType(1) [ArrayInner(1)]
    /// Name(SerString) Value`. For SZARRAY / Enum named args,
    /// an extra type byte follows.
    fn read_named_arg(&mut self) -> Result<NamedArg> {
        let kind_byte = self.read_u8()?;
        let kind = ElementType::from_u8(kind_byte).ok_or_else(|| {
            Error::FormatError(format!(
                "CustomAttribute named: bad field-or-prop byte 0x{kind_byte:02x}"
            ))
        })?;
        if !matches!(kind, ElementType::Field | ElementType::Property) {
            return Err(Error::FormatError(format!(
                "CustomAttribute named: expected Field/Property, got {kind:?}"
            )));
        }
        let elem_type = self.read_u8()?;
        let inner_elem_type = match ElementType::from_u8(elem_type) {
            // SZARRAY carries the inner element type as the next byte.
            Some(ElementType::SzArray) => Some(self.read_u8()?),
            // Enum: next is a SerString naming the enum type (we
            // skip it here; it's not needed for value decoding —
            // the underlying primitive type isn't actually in the
            // wire format, the spec says enum named args use the
            // declared underlying type. We default to I4.).
            Some(ElementType::Enum) => {
                let _enum_type_name = self.read_ser_string()?;
                None
            }
            _ => None,
        };
        let name = self.read_ser_string()?.unwrap_or_default();
        let value_ty = match inner_elem_type {
            Some(inner) if elem_type == ElementType::SzArray as u8 => {
                // SZARRAY of `inner` — handle inline because the
                // inner type isn't passed through `read_value`'s
                // tag dispatch.
                let len = self.read_u32_le()?;
                if len == 0xffff_ffff {
                    Value::Array(None)
                } else {
                    let mut items = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        items.push(self.read_value(inner)?);
                    }
                    Value::Array(Some(items))
                }
            }
            _ if elem_type == ElementType::Enum as u8 => {
                // Default underlying type = I4; real consumers
                // would resolve the enum to its underlying type
                // via the TypeDef table.
                self.read_value(ElementType::I4 as u8)?
            }
            _ => self.read_value(elem_type)?,
        };
        Ok(NamedArg {
            kind,
            elem_type,
            inner_elem_type,
            name,
            value: value_ty,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal: empty CustomAttribute (no fixed args, no named).
    /// `prolog(0x0001) + numNamed(0x0000)`.
    #[test]
    fn custom_attribute_empty() {
        let blob = [0x01, 0x00, 0x00, 0x00];
        let ca = CustomAttribute::decode_with_types(&blob, &[]).unwrap();
        assert!(ca.fixed.is_empty());
        assert!(ca.named.is_empty());
    }

    /// One fixed I4 arg with value 0x12345678.
    #[test]
    fn custom_attribute_fixed_i4() {
        let blob = [
            0x01, 0x00, // prolog
            0x78, 0x56, 0x34, 0x12, // i4
            0x00, 0x00, // numNamed
        ];
        let ca = CustomAttribute::decode_with_types(&blob, &[ElementType::I4 as u8]).unwrap();
        assert_eq!(ca.fixed, vec![Value::I4(0x1234_5678)]);
    }

    /// One fixed SerString "hi".
    #[test]
    fn custom_attribute_fixed_string() {
        let blob = [
            0x01, 0x00, // prolog
            0x02, b'h', b'i', // len + utf8
            0x00, 0x00, // numNamed
        ];
        let ca = CustomAttribute::decode_with_types(&blob, &[ElementType::String as u8]).unwrap();
        assert_eq!(ca.fixed, vec![Value::String(Some("hi".to_string()))]);
    }

    /// Named property `Foo = true`.
    #[test]
    fn custom_attribute_named_bool() {
        let blob = [
            0x01,
            0x00, // prolog
            0x01,
            0x00, // numNamed = 1
            ElementType::Property as u8,
            ElementType::Boolean as u8,
            0x03,
            b'F',
            b'o',
            b'o', // name
            0x01, // bool = true
        ];
        let ca = CustomAttribute::decode_with_types(&blob, &[]).unwrap();
        assert_eq!(ca.named.len(), 1);
        assert_eq!(ca.named[0].name, "Foo");
        assert_eq!(ca.named[0].value, Value::Boolean(true));
    }

    /// MarshalSpec — single-byte LPWSTR.
    #[test]
    fn marshal_spec_simple_lpwstr() {
        let ms = MarshalSpec::decode(&[native_type::LPWSTR]).unwrap();
        assert_eq!(ms, MarshalSpec::Simple(native_type::LPWSTR));
    }

    /// MarshalSpec — array with element type + param num.
    #[test]
    fn marshal_spec_array_with_param_num() {
        let blob = [native_type::ARRAY, native_type::I4, 0x02];
        let ms = MarshalSpec::decode(&blob).unwrap();
        assert!(matches!(
            ms,
            MarshalSpec::Array {
                elem_type: Some(native_type::I4),
                param_num: Some(2),
                num_elem: None,
                param_num_multiplier: None,
            }
        ));
    }

    /// MarshalSpec — FixedSysString size=64.
    #[test]
    fn marshal_spec_fixed_sys_string() {
        let blob = [native_type::FIXEDSYSSTRING, 0x40];
        let ms = MarshalSpec::decode(&blob).unwrap();
        assert!(matches!(ms, MarshalSpec::FixedSysString { size: 64 }));
    }
}
