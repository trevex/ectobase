//! Convert the retired 64-slot neighbor-NAT tables into the `NAT_OWNERS{,6}` tries on an upgrade.
//!
//! A node upgrading across NAT return scaling Increment 1 still has `NEIGHBOR_NAT{,6}` and their
//! count arrays pinned from the build that declared them. Nothing binds them any more and
//! [`crate::loader::load_ebpf`] unpins them, so without this the edge's already-announced remote
//! NAT blocks would go unrelayed until its mesh agent reconnected and replayed them. Read them
//! before the loader runs, install the blocks after adopt, and let the loader's sweep do the
//! unpinning — which makes the migration one-shot: the next upgrade finds nothing.
//!
//! Every failure here degrades to a log. A node that cannot read its old table still has to come
//! up; the blocks it lost come back on the agent's next replay, which is exactly the behaviour
//! this module improves on.

use std::collections::HashMap;

use flowplane_common::{NeighborNat6Entry, NeighborNatEntry};

/// The retired `NEIGHBOR_NAT` value, byte for byte as the build that pinned it wrote it. The live
/// [`NeighborNatEntry`] is a plain record now (no `repr(C)`, no `Pod`) and is free to change
/// shape, so this is the only copy of that ABI left: frozen, and pinned by a layout test.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) struct LegacyNeighborNat {
    pub underlay: [u8; 16],
    pub nat_ip: [u8; 4],
    pub vni: u32,
    pub port_min: u16,
    pub port_max: u16,
    /// 1 = slot in use.
    pub enabled: u8,
    pub _pad: [u8; 3],
}

/// The retired `NEIGHBOR_NAT6` value. IPv6 sibling of [`LegacyNeighborNat`].
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) struct LegacyNeighborNat6 {
    pub underlay: [u8; 16],
    pub nat_ip6: [u8; 16],
    pub vni: u32,
    pub port_min: u16,
    pub port_max: u16,
    pub enabled: u8,
    pub _pad: [u8; 3],
}

// SAFETY: both are `#[repr(C)]` fixed-size POD types whose padding is an explicit `_pad` field, so
// their raw bytes are the map value ABI the retired build wrote.
unsafe impl aya::Pod for LegacyNeighborNat {}
unsafe impl aya::Pod for LegacyNeighborNat6 {}

/// The live blocks in a slot table. The old control plane rewrote slots `0..count` on every change
/// and never cleared the ones above, so a slot at or above `count` is a withdrawn block's corpse —
/// reading it back would re-announce a block to a node that no longer owns it. A hole below the
/// count is a write the old process never finished; skip it and keep walking.
fn blocks4(count: u32, slots: &HashMap<u32, LegacyNeighborNat>) -> Vec<NeighborNatEntry> {
    (0..count)
        .filter_map(|i| slots.get(&i))
        .filter(|e| e.enabled != 0)
        .map(|e| NeighborNatEntry {
            underlay: e.underlay,
            nat_ip: e.nat_ip,
            vni: e.vni,
            port_min: e.port_min,
            port_max: e.port_max,
        })
        .collect()
}

/// IPv6 sibling of [`blocks4`].
fn blocks6(count: u32, slots: &HashMap<u32, LegacyNeighborNat6>) -> Vec<NeighborNat6Entry> {
    (0..count)
        .filter_map(|i| slots.get(&i))
        .filter(|e| e.enabled != 0)
        .map(|e| NeighborNat6Entry {
            underlay: e.underlay,
            nat_ip6: e.nat_ip6,
            vni: e.vni,
            port_min: e.port_min,
            port_max: e.port_max,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::mem::{align_of, offset_of, size_of};

    fn legacy4(nat_ip: [u8; 4], port_min: u16, port_max: u16) -> LegacyNeighborNat {
        LegacyNeighborNat {
            underlay: [7; 16],
            nat_ip,
            vni: 9,
            port_min,
            port_max,
            enabled: 1,
            _pad: [0; 3],
        }
    }

    /// The bytes on bpffs were written by a build that is gone; this struct is the only copy of
    /// that ABI left, so its shape is frozen. Size alone does not pin field order.
    #[test]
    fn the_legacy_v4_layout_is_frozen() {
        assert_eq!(size_of::<LegacyNeighborNat>(), 32);
        assert_eq!(align_of::<LegacyNeighborNat>(), 4);
        assert_eq!(offset_of!(LegacyNeighborNat, underlay), 0);
        assert_eq!(offset_of!(LegacyNeighborNat, nat_ip), 16);
        assert_eq!(offset_of!(LegacyNeighborNat, vni), 20);
        assert_eq!(offset_of!(LegacyNeighborNat, port_min), 24);
        assert_eq!(offset_of!(LegacyNeighborNat, port_max), 26);
        assert_eq!(offset_of!(LegacyNeighborNat, enabled), 28);
    }

    #[test]
    fn the_legacy_v6_layout_is_frozen() {
        assert_eq!(size_of::<LegacyNeighborNat6>(), 44);
        assert_eq!(align_of::<LegacyNeighborNat6>(), 4);
        assert_eq!(offset_of!(LegacyNeighborNat6, underlay), 0);
        assert_eq!(offset_of!(LegacyNeighborNat6, nat_ip6), 16);
        assert_eq!(offset_of!(LegacyNeighborNat6, vni), 32);
        assert_eq!(offset_of!(LegacyNeighborNat6, port_min), 36);
        assert_eq!(offset_of!(LegacyNeighborNat6, port_max), 38);
        assert_eq!(offset_of!(LegacyNeighborNat6, enabled), 40);
    }

    #[test]
    fn a_block_carries_every_field_across() {
        let slots = HashMap::from([(0, legacy4([203, 0, 113, 5], 1024, 2048))]);
        assert_eq!(
            blocks4(1, &slots),
            vec![flowplane_common::NeighborNatEntry {
                underlay: [7; 16],
                nat_ip: [203, 0, 113, 5],
                vni: 9,
                port_min: 1024,
                port_max: 2048,
            }]
        );
    }

    /// The old reprogram rewrote slots 0..count and never cleared the ones above, so a slot at or
    /// above the count is a withdrawn block's corpse. Reading it back would re-announce a block to
    /// a node that no longer owns it.
    #[test]
    fn a_slot_above_the_count_is_a_withdrawn_blocks_corpse() {
        let slots = HashMap::from([
            (0, legacy4([203, 0, 113, 5], 1024, 2048)),
            (1, legacy4([203, 0, 113, 6], 1024, 2048)),
        ]);
        let got = blocks4(1, &slots);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].nat_ip, [203, 0, 113, 5]);
    }

    #[test]
    fn a_disabled_slot_is_skipped() {
        let mut dead = legacy4([203, 0, 113, 6], 1024, 2048);
        dead.enabled = 0;
        let slots = HashMap::from([(0, legacy4([203, 0, 113, 5], 1024, 2048)), (1, dead)]);
        let got = blocks4(2, &slots);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].nat_ip, [203, 0, 113, 5]);
    }

    /// A hole below the count (a write the old process never finished) skips that slot rather than
    /// stopping the walk: the slots above it are live blocks.
    #[test]
    fn a_hole_below_the_count_does_not_end_the_walk() {
        let slots = HashMap::from([(1, legacy4([203, 0, 113, 6], 1024, 2048))]);
        let got = blocks4(2, &slots);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].nat_ip, [203, 0, 113, 6]);
    }

    #[test]
    fn a_v6_block_carries_every_field_across() {
        let slots = HashMap::from([(
            0,
            LegacyNeighborNat6 {
                underlay: [7; 16],
                nat_ip6: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5],
                vni: 9,
                port_min: 1024,
                port_max: 2048,
                enabled: 1,
                _pad: [0; 3],
            },
        )]);
        assert_eq!(
            blocks6(1, &slots),
            vec![flowplane_common::NeighborNat6Entry {
                underlay: [7; 16],
                nat_ip6: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5],
                vni: 9,
                port_min: 1024,
                port_max: 2048,
            }]
        );
    }

    #[test]
    fn a_v6_slot_above_the_count_is_a_withdrawn_blocks_corpse() {
        let one = LegacyNeighborNat6 {
            underlay: [7; 16],
            nat_ip6: [1; 16],
            vni: 9,
            port_min: 1024,
            port_max: 2048,
            enabled: 1,
            _pad: [0; 3],
        };
        let mut two = one;
        two.nat_ip6 = [2; 16];
        let slots = HashMap::from([(0, one), (1, two)]);
        let got = blocks6(1, &slots);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].nat_ip6, [1; 16]);
    }
}
