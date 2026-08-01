//! Address taxonomy, ported from `capa/features/address.py`.
//!
//! Each address kind is kept structurally distinct (e.g. `Absolute(0x1000)`
//! and `Relative(0x1000)` are never equal). Upstream's `AbsoluteVirtualAddress`
//! / `RelativeVirtualAddress` / `FileOffsetAddress` all subclass `int` without
//! overriding `__eq__`/`__hash__`, so in Python those three actually *do*
//! compare equal and hash identically when their numeric value matches. In
//! practice a single feature set is only ever populated with one address
//! flavor at a time (a static extractor never mixes absolute and relative
//! addresses for the same sample), so this divergence is not expected to be
//! observable in real corpora; keeping the kinds distinct here is safer than
//! replicating the accidental collision.
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Address {
    /// an absolute memory address
    Absolute(u64),
    /// a memory address relative to a base address
    Relative(u64),
    /// an address relative to the start of a file
    File(u64),
    /// a .NET token
    DnToken(u32),
    /// an offset into an object specified by a .NET token
    DnTokenOffset { token: u32, offset: u32 },
    /// an address of a process in a dynamic execution trace
    Process { ppid: u32, pid: u32 },
    /// addresses a thread in a dynamic execution trace
    Thread { ppid: u32, pid: u32, tid: u32 },
    /// addresses a call in a dynamic execution trace
    Call {
        ppid: u32,
        pid: u32,
        tid: u32,
        id: u64,
    },
    /// capa/features/address.py: NO_ADDRESS -- the address of a feature that
    /// isn't found at any particular location (e.g. a global os/arch/format
    /// feature).
    NoAddress,
}

impl Address {
    /// Cross-kind order (the leading discriminant) is a plain derived
    /// discriminant order -- Python's `_NoAddress.__lt__`/`__gt__` sorts it
    /// last among mixed types, a rendering-only quirk we don't need to
    /// match exactly, since a single collection is never a mix of kinds in
    /// practice.
    ///
    /// Within a kind, the field order below *does* matter and must match
    /// Python's `__lt__` on the corresponding `capa/features/address.py`
    /// class: `capabilities/{static,dynamic}.py`'s drivers visit functions/
    /// basic blocks/instructions/processes/threads/calls in
    /// `sorted(dict.keys())` order (see `features/extractors/null.py`), and
    /// that visitation order determines which feature is inserted first into
    /// a shared scope's `FeatureSet` -- which in turn decides the result of
    /// `Bytes`/`Substring`/`Regex`'s short-circuiting scan (see `engine.rs`).
    /// Notably `DynamicCallAddress.__lt__` compares `(thread, id)`, i.e.
    /// `(ppid, pid, tid)` *then* `id` -- not `id` first.
    fn sort_key(&self) -> impl Ord {
        match *self {
            Address::Absolute(v) => (0u8, v, 0u32, 0u32, 0u32, 0u64),
            Address::Relative(v) => (1u8, v, 0, 0, 0, 0),
            Address::File(v) => (2u8, v, 0, 0, 0, 0),
            Address::DnToken(v) => (3u8, v as u64, 0, 0, 0, 0),
            Address::DnTokenOffset { token, offset } => (4u8, 0u64, token, offset, 0, 0),
            Address::Process { ppid, pid } => (5u8, 0u64, ppid, pid, 0, 0),
            Address::Thread { ppid, pid, tid } => (6u8, 0u64, ppid, pid, tid, 0),
            Address::Call { ppid, pid, tid, id } => (7u8, 0u64, ppid, pid, tid, id),
            Address::NoAddress => (8u8, 0, 0, 0, 0, 0),
        }
    }
}

impl Address {
    /// Python truthiness of the corresponding `capa.features.address.Address`
    /// object: `AbsoluteVirtualAddress`/`RelativeVirtualAddress`/
    /// `FileOffsetAddress`/`DNTokenAddress` subclass `int` and don't override
    /// `__bool__`, so they're falsy exactly when their value is `0`. Every
    /// other kind (including `NoAddress`/`_NoAddress`) has no `__bool__`/
    /// `__len__` override either, so plain-object default truthiness (always
    /// `True`) applies.
    ///
    /// Used by `capabilities/static.rs`'s `find_file_capabilities` port,
    /// which special-cases `if va:` when folding `extract_file_features()`
    /// into the file scope's `FeatureSet` -- a file feature at literal
    /// address/offset/token `0` is recorded with an *empty* location set
    /// rather than `{0}` (capa/capabilities/common.py).
    pub fn is_truthy(&self) -> bool {
        match self {
            Address::Absolute(v) | Address::Relative(v) | Address::File(v) => *v != 0,
            Address::DnToken(v) => *v != 0,
            Address::DnTokenOffset { .. }
            | Address::Process { .. }
            | Address::Thread { .. }
            | Address::Call { .. }
            | Address::NoAddress => true,
        }
    }

    /// a stable, difftest-friendly string using the same `type` tag names as
    /// the freeze wire format's `AddressType` (`capa/features/freeze/
    /// __init__.py`), so `scripts/difftest.py` can derive an identical key
    /// straight from `capa -j`'s per-match address JSON (`{"type": ...,
    /// "value": ...}`, produced by `frz.Address.from_capa`) without needing
    /// to know anything else about our internal representation.
    pub fn canonical_key(&self) -> String {
        match self {
            Address::Absolute(v) => format!("absolute:{v}"),
            Address::Relative(v) => format!("relative:{v}"),
            Address::File(v) => format!("file:{v}"),
            Address::DnToken(v) => format!("dn token:{v}"),
            Address::DnTokenOffset { token, offset } => format!("dn token offset:{token},{offset}"),
            Address::Process { ppid, pid } => format!("process:{ppid},{pid}"),
            Address::Thread { ppid, pid, tid } => format!("thread:{ppid},{pid},{tid}"),
            Address::Call { ppid, pid, tid, id } => format!("call:{ppid},{pid},{tid},{id}"),
            Address::NoAddress => "no address".to_string(),
        }
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Absolute(v) => write!(f, "absolute(0x{v:x})"),
            Address::Relative(v) => write!(f, "relative(0x{v:x})"),
            Address::File(v) => write!(f, "file(0x{v:x})"),
            Address::DnToken(v) => write!(f, "token(0x{v:x})"),
            Address::DnTokenOffset { token, offset } => {
                write!(f, "token(0x{token:x})+(0x{offset:x})")
            }
            Address::Process { ppid, pid } => {
                if *ppid > 0 {
                    write!(f, "process(ppid: {ppid}, pid: {pid})")
                } else {
                    write!(f, "process(pid: {pid})")
                }
            }
            Address::Thread { ppid, pid, tid } => {
                write!(
                    f,
                    "{}, thread(tid: {tid})",
                    Address::Process {
                        ppid: *ppid,
                        pid: *pid
                    }
                )
            }
            Address::Call { ppid, pid, tid, id } => {
                write!(
                    f,
                    "{}, call(id: {id})",
                    Address::Thread {
                        ppid: *ppid,
                        pid: *pid,
                        tid: *tid
                    }
                )
            }
            Address::NoAddress => write!(f, "no address"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn distinct_kinds_are_not_equal_even_with_same_value() {
        assert_ne!(Address::Absolute(0x1000), Address::Relative(0x1000));
        assert_ne!(Address::Absolute(0x1000), Address::File(0x1000));
    }

    #[test]
    fn call_address_orders_by_thread_then_id() {
        // matches DynamicCallAddress.__lt__: (thread, id), i.e. (ppid, pid,
        // tid) before id -- a call with a lower id in a later thread must
        // still sort after an earlier thread's higher-id call.
        let a = Address::Call {
            ppid: 0,
            pid: 1,
            tid: 0,
            id: 99,
        };
        let b = Address::Call {
            ppid: 0,
            pid: 2,
            tid: 0,
            id: 0,
        };
        assert!(a < b);
    }

    #[test]
    fn is_truthy_matches_python_object_truthiness() {
        assert!(!Address::Absolute(0).is_truthy());
        assert!(Address::Absolute(1).is_truthy());
        assert!(!Address::File(0).is_truthy());
        assert!(!Address::DnToken(0).is_truthy());
        assert!(Address::NoAddress.is_truthy());
        assert!(Address::Process { ppid: 0, pid: 0 }.is_truthy());
    }

    #[test]
    fn ordering_is_total_and_stable() {
        let mut addrs = vec![
            Address::NoAddress,
            Address::File(1),
            Address::Absolute(2),
            Address::Absolute(1),
        ];
        addrs.sort();
        assert_eq!(
            addrs,
            vec![
                Address::Absolute(1),
                Address::Absolute(2),
                Address::File(1),
                Address::NoAddress,
            ]
        );
    }
}
