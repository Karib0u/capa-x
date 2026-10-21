//! Ghidra Function ID (FID) hashing and lookup for x86-64.
//!
//! The hash is a faithful port of `MessageDigestFidHasher` and the FNV-1a 64
//! digest from Ghidra 12.1.4 (`Ghidra/Features/FunctionID`). Ghidra derives the
//! per-instruction mask and operand objects from its Sleigh x86-64 language;
//! `x86` re-derives them with iced-x86 and is validated against Ghidra's own
//! output with `scripts/decompiler_fid/` (see `sigs/FID.md`).
pub mod hash;
pub mod matcher;
pub mod names;
pub mod pack;
pub mod x86;
