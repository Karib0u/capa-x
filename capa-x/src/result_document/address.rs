//! JSON-facing address model, ported from `capa/features/freeze/__init__.py`:
//! `AddressType` / `Address`. This is the *output* counterpart to
//! `freeze::RawAddress` (which only reads this shape); the result document
//! (`capa/render/result_document.py`) reuses the freeze module's `Address`
//! type verbatim for every address it embeds, dumped without `by_alias`
//! (attribute names, which happen to equal the wire `type` tag strings here)
//! and with `exclude_none=True` (so `NO_ADDRESS`'s `value: None` is omitted
//! entirely rather than written as `null`).

use serde::{Deserialize, Serialize};

use crate::address::Address;

/// mirrors `frz.Address`: `{"type": ..., "value": ...}`, `value` omitted
/// when absent (only `NO_ADDRESS` has no value).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RdAddress {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<AddressValue>,
}

/// `Union[int, tuple[int, ...], None]` -- an absolute/relative/file/dn-token
/// address's bare integer, or a dn-token-offset/process/thread/call
/// address's tuple of integers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AddressValue {
    Int(u64),
    Tuple(Vec<u64>),
}

impl From<&Address> for RdAddress {
    fn from(addr: &Address) -> RdAddress {
        match *addr {
            Address::Absolute(v) => RdAddress {
                kind: "absolute".to_string(),
                value: Some(AddressValue::Int(v)),
            },
            Address::Relative(v) => RdAddress {
                kind: "relative".to_string(),
                value: Some(AddressValue::Int(v)),
            },
            Address::File(v) => RdAddress {
                kind: "file".to_string(),
                value: Some(AddressValue::Int(v)),
            },
            Address::DnToken(v) => RdAddress {
                kind: "dn token".to_string(),
                value: Some(AddressValue::Int(v as u64)),
            },
            Address::DnTokenOffset { token, offset } => RdAddress {
                kind: "dn token offset".to_string(),
                value: Some(AddressValue::Tuple(vec![token as u64, offset as u64])),
            },
            Address::Process { ppid, pid } => RdAddress {
                kind: "process".to_string(),
                value: Some(AddressValue::Tuple(vec![ppid as u64, pid as u64])),
            },
            Address::Thread { ppid, pid, tid } => RdAddress {
                kind: "thread".to_string(),
                value: Some(AddressValue::Tuple(vec![
                    ppid as u64,
                    pid as u64,
                    tid as u64,
                ])),
            },
            Address::Call { ppid, pid, tid, id } => RdAddress {
                kind: "call".to_string(),
                value: Some(AddressValue::Tuple(vec![
                    ppid as u64,
                    pid as u64,
                    tid as u64,
                    id,
                ])),
            },
            Address::NoAddress => RdAddress {
                kind: "no address".to_string(),
                value: None,
            },
        }
    }
}

impl From<Address> for RdAddress {
    fn from(addr: Address) -> RdAddress {
        RdAddress::from(&addr)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn no_address_omits_value_key() {
        let json = serde_json::to_string(&RdAddress::from(Address::NoAddress)).unwrap();
        assert_eq!(json, r#"{"type":"no address"}"#);
    }

    #[test]
    fn absolute_address_shape() {
        let json = serde_json::to_string(&RdAddress::from(Address::Absolute(0x401000))).unwrap();
        assert_eq!(json, r#"{"type":"absolute","value":4198400}"#);
    }

    #[test]
    fn call_address_is_a_four_tuple() {
        let addr = Address::Call {
            ppid: 1,
            pid: 2,
            tid: 3,
            id: 99,
        };
        let json = serde_json::to_string(&RdAddress::from(addr)).unwrap();
        assert_eq!(json, r#"{"type":"call","value":[1,2,3,99]}"#);
    }

    #[test]
    fn round_trips_through_deserialize() {
        for addr in [
            Address::Absolute(1),
            Address::Relative(2),
            Address::File(3),
            Address::DnToken(4),
            Address::DnTokenOffset {
                token: 5,
                offset: 6,
            },
            Address::Process { ppid: 7, pid: 8 },
            Address::Thread {
                ppid: 7,
                pid: 8,
                tid: 9,
            },
            Address::Call {
                ppid: 7,
                pid: 8,
                tid: 9,
                id: 10,
            },
            Address::NoAddress,
        ] {
            let rd = RdAddress::from(addr);
            let json = serde_json::to_string(&rd).unwrap();
            let back: RdAddress = serde_json::from_str(&json).unwrap();
            assert_eq!(rd, back);
        }
    }
}
