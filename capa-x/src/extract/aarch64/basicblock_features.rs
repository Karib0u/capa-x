//! AArch64 basic-block-scope feature extraction, ported
//! from `capa/features/extractors/binexport2/basicblock.py` (v9.4.0, see
//! PINNED.md) -- the BinExport2/Ghidra ARM backend, *not* the x86 vivisect
//! `basicblock_features.rs` port: the "tight loop" test differs between the
//! two upstream backends (see below), so the two are not shared even though
//! both run against this crate's own `recovery::BasicBlock`.

use crate::address::Address;
use crate::features::Feature;

use super::recovery::BasicBlock;

/// capa/features/extractors/binexport2/basicblock.py: `extract_features` /
/// `BASIC_BLOCK_HANDLERS`. Also yields the `BasicBlock` feature itself, same
/// as the x86 port.
pub fn extract_features(block: &BasicBlock) -> Vec<(Address, Feature)> {
    let mut out = vec![(Address::Absolute(block.addr), Feature::BasicBlock)];
    out.extend(extract_bb_tight_loop(block));
    out
}

/// port of `extract_bb_tight_loop`: does *any* successor edge of this block
/// -- of any kind -- target the block itself? Unlike the x86 port (which
/// checks whether the block's *last instruction* is specifically a
/// conditional branch back to its own start, matching vivisect's
/// `BR_COND`-only semantics), upstream's BinExport2 version has no
/// instruction-kind test at all: it only asks whether `basic_block_index` is
/// its own edge source among the edges that target it
/// (`extract_bb_tight_loop` in the Python source). A block composed of
/// straight-line code that unconditionally falls through or branches back to
/// its own start therefore counts here, where it would not for x86.
fn extract_bb_tight_loop(block: &BasicBlock) -> Vec<(Address, Feature)> {
    if block.succs.iter().any(|edge| edge.target == block.addr) {
        vec![(
            Address::Absolute(block.addr),
            Feature::Characteristic("tight loop".to_string()),
        )]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::extract::recovery::{Edge, EdgeKind};

    fn block(addr: u64, succs: Vec<Edge>) -> BasicBlock {
        BasicBlock {
            addr,
            insns: Vec::new(),
            succs,
        }
    }

    #[test]
    fn extract_features_always_includes_basic_block_feature() {
        let b = block(0x1000, Vec::new());
        assert_eq!(
            extract_features(&b)[0],
            (Address::Absolute(0x1000), Feature::BasicBlock)
        );
    }

    #[test]
    fn tight_loop_detected_for_any_self_edge_kind() {
        for kind in [EdgeKind::Branch, EdgeKind::Fallthrough, EdgeKind::JumpTable] {
            let b = block(
                0x1000,
                vec![Edge {
                    target: 0x1000,
                    kind,
                }],
            );
            assert_eq!(
                extract_bb_tight_loop(&b),
                vec![(
                    Address::Absolute(0x1000),
                    Feature::Characteristic("tight loop".to_string())
                )],
                "kind {kind:?} should count as a tight loop"
            );
        }
    }

    #[test]
    fn tight_loop_not_detected_without_a_self_edge() {
        let b = block(
            0x1000,
            vec![Edge {
                target: 0x1010,
                kind: EdgeKind::Branch,
            }],
        );
        assert!(extract_bb_tight_loop(&b).is_empty());
    }

    #[test]
    fn tight_loop_ignores_a_tail_call_edge_to_a_different_function() {
        let b = block(
            0x1000,
            vec![Edge {
                target: 0x9000,
                kind: EdgeKind::TailCall,
            }],
        );
        assert!(extract_bb_tight_loop(&b).is_empty());
    }
}
