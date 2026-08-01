#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("PE parse error: {0}")]
    ParseError(#[from] goblin::error::Error),
    #[error("unsupported binary format: {0}")]
    UnsupportedBinaryFormat(&'static str),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("{0}")]
    UnresolvedRvaError(u32),
    #[error("{0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("{0}")]
    Utf16Error(#[from] std::string::FromUtf16Error),
    #[error("undefined stream")]
    UndefinedStream,
    #[error("undefined meta data table index (0..63) {0}")]
    UndefinedMetaDataTableIndex(u32),
    #[error("undefined meta data table name {0}")]
    UndefinedMetaDataTableName(&'static str),
    #[error("data not enough {0} required {1}")]
    NotEnoughData(usize, usize),
    #[error("row index out of bound {0} {1}")]
    RowIndexOutOfBound(usize, usize),
    #[error("{0}")]
    CantReadUsizeFromBytesLen(usize),
    #[error("{0}")]
    CodedIndexWithUndefinedTable(String),
    #[error("{0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("{0}")]
    RefToUndefinedHeap(&'static str),
    #[error("try to read string from non string heap")]
    TryReadStringFromNotStringHeap,
    #[error("try to read blob from non blob heap")]
    TryReadBlobFromNotBlobHeap,
    #[error("try to read guid from non guid heap")]
    TryReadGuidFromNotGuidHeap,
    #[error("read compressed usize error")]
    ReadCompressedUsize,
    #[error("{0} {1}")]
    StringHeapReadOutOfBound(usize, usize),
    #[error("{0} {1}")]
    BlobHeapReadOutOfBound(usize, usize),
    #[error("{0} {1}")]
    GuidHeapReadOutOfBound(usize, usize),
    #[error("{0} {1}")]
    UserStringHeapReadOutOfBound(usize, usize),
    #[error("{0}")]
    FormatError(String),
    #[error("{0}")]
    ParseGuidError(#[from] uuid::Error),
    #[error("undefined operand type")]
    UndefinedOperandType(crate::lang::cil::enums::OperandType),
    #[error("decompile error")]
    DecompileError,
    #[error("{0}")]
    ConversionError(&'static str),
    #[error("{0}")]
    MethodBodyFormatError(String),
    #[error("operand not have value")]
    OperandHasNoValue,
    #[error("incorrect cast to {0} in file {1} at line {2}")]
    IncorrectCastTo(&'static str, &'static str, u32),
    #[error("incorrect table requested {0} in file {1} at line {2}")]
    IncorrectTableRequested(&'static str, &'static str, u32),
    #[error("not implemented")]
    NotImplementedError,
}
