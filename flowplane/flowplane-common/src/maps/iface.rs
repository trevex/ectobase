//! Interface / port / underlay map key & value types (the `INTERFACES`, `INTERFACES6`,
//! `PORT_META`, `UNDERLAY`, and `IFACE_META` restart-journal maps).

/// Key for the `interfaces` map: an overlay (VNI, IPv4) tuple.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct IfaceKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
}

/// Key for the `interfaces6` map: an overlay (VNI, IPv6) tuple. The v6 sibling of [`IfaceKey`];
/// shares the same [`IfaceValue`]. Used by the node-VTEP local-delivery demux.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct IfaceKey6 {
    pub vni: u32,
    pub ipv6: [u8; 16],
}

/// Value for the `interfaces` map: how to reach/deliver to an overlay IP.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct IfaceValue {
    /// Host-side tap ifindex for local delivery (0 if remote).
    pub tap_ifindex: u32,
    /// 1 = interface is local to this hypervisor, 0 = remote.
    pub is_local: u32,
    /// Underlay IPv6 endpoint of the owning hypervisor (tunnel dst for remote).
    pub underlay_ipv6: [u8; 16],
    /// Guest MAC (inner eth dst for local delivery).
    pub guest_mac: [u8; 6],
    /// 1 = the local delivery device has a netns peer (veth/netkit) → local delivery may use
    /// `bpf_redirect_peer` (inject at the peer's ingress in the pod netns, same softirq). 0 = a
    /// peerless device (root-netns tap) → must use plain `bpf_redirect`. Set at attach from the
    /// DeviceType. Occupies one byte within the struct's existing size, so `size_of::<IfaceValue>()`
    /// is unchanged.
    pub peer_capable: u8,
    pub _pad: [u8; 1],
}

/// Ingress delivery entry: an interface's underlay IPv6 -> its VNI + local tap + guest MAC.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct UnderlayValue {
    pub vni: u32,
    pub tap_ifindex: u32,
    pub guest_mac: [u8; 6],
    pub _pad: [u8; 2],
}

/// Sentinel `UnderlayValue::tap_ifindex` marking a WAN-edge local-deliver underlay: `uplink_rx`
/// decaps the inner IPv4 and XDP_PASSes it to the local kernel (VyOS routes/masquerades to the real
/// WAN) instead of redirecting to a guest tap. A real ifindex is never `u32::MAX`; `tap_ifindex==0`
/// already means an LB-anycast VNF, so this needs a distinct value.
pub const UNDERLAY_LOCAL_DELIVER: u32 = u32::MAX;

/// Per-port metadata, keyed by the guest tap's host-side ifindex.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct PortMeta {
    pub vni: u32,
    pub guest_ipv4: [u8; 4],
    pub gateway_ipv4: [u8; 4],
    pub guest_mac: [u8; 6],
    /// 1 = L3 pod edge (netkit): IP from byte 0, no L2 responders, synthetic-eth push/pop at the
    /// edge; 0 = L2 (veth/tap/vf).
    pub l3: u8,
    /// 1 = this port is an SR-IOV VF/SF representor eligible for hardware flow-offload (the offload
    /// manager installs tc-flower rules for its established E/W flows). Written at attach.
    pub offloaded: u8,
    pub underlay_ipv6: [u8; 16],
    pub gateway_ipv6: [u8; 16],
    /// Guest overlay IPv6 address (all-zero when the guest is IPv4-only). Used by NAT64 to
    /// reconstruct the IPv6 destination of the reply packet.
    pub guest_ipv6: [u8; 16],
}

impl IfaceKey {
    pub fn new(vni: u32, ipv4: [u8; 4]) -> Self {
        Self { vni, ipv4 }
    }
}

impl IfaceKey6 {
    pub fn new(vni: u32, ipv6: [u8; 16]) -> Self {
        Self { vni, ipv6 }
    }
}

/// Max bytes of an `interface_id` persisted in the `IFACE_META` restart journal. An interface_id is
/// a k8s UID plus a short interface name (~60 bytes in practice); attach rejects longer ids.
pub const IFACE_ID_MAX: usize = 64;
/// Max bytes of a device (kernel netdev) name in the journal — Linux IFNAMSIZ (16) covers it.
pub const IFACE_DEV_MAX: usize = 16;

/// Key of the `IFACE_META` restart journal: the full `interface_id`, zero-padded to a fixed width so
/// the whole id survives a restart (a hash would lose it — we need the id back verbatim to rebuild
/// `by_id`/`links`). Written by userspace only; the datapath never reads this map.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IfaceMetaKey {
    pub id: [u8; IFACE_ID_MAX],
}

/// Value of the `IFACE_META` restart journal: everything the control plane needs to rebuild its
/// in-memory bookkeeping and re-attach the guest program after an flowplane restart. `id_len`/`device_len`
/// give the used prefix of the padded `IfaceMetaKey.id` / `device`. `tap_ifindex` is the ifindex at
/// attach time; the rebuild re-derives the live ifindex from `device` (the veth persists) and treats
/// this as a cross-check. `l3` records how the guest program was attached, so adopt re-points the pinned
/// link with the matching mechanism (netkit → `bpf(BPF_LINK_UPDATE)`, veth/tcx → `readopt_tc_link`).
/// Field order is chosen so the struct has no implicit padding (`_pad` makes the tail explicit).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IfaceMetaVal {
    pub vni: u32,
    pub tap_ifindex: u32,
    pub ipv4: [u8; 4],
    pub id_len: u16,
    pub device_len: u16,
    pub ipv6: [u8; 16],
    pub underlay: [u8; 16],
    pub device: [u8; IFACE_DEV_MAX],
    /// 1 = the guest program is attached to a netkit L3 primary via `BPF_NETKIT_PEER` (adopt must
    /// re-point it with `bpf(BPF_LINK_UPDATE)`); 0 = tcx/clsact on a veth (adopt uses `readopt_tc_link`).
    pub l3: u8,
    pub _pad: [u8; 3],
}

impl IfaceMetaKey {
    /// Pad `id` into the fixed-width key. Returns `None` if `id` exceeds [`IFACE_ID_MAX`] (attach
    /// rejects such ids rather than silently truncating — a truncated key could alias another id).
    pub fn from_id(id: &[u8]) -> Option<Self> {
        if id.len() > IFACE_ID_MAX {
            return None;
        }
        let mut k = [0u8; IFACE_ID_MAX];
        k[..id.len()].copy_from_slice(id);
        Some(Self { id: k })
    }
}

// SAFETY: all `#[repr(C)]` fixed-size POD types with no padding beyond explicit `_pad` fields, so
// their raw bytes are a valid map key/value ABI shared with the eBPF datapath.
#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for IfaceKey {}
    unsafe impl aya::Pod for IfaceKey6 {}
    unsafe impl aya::Pod for IfaceValue {}
    unsafe impl aya::Pod for IfaceMetaKey {}
    unsafe impl aya::Pod for IfaceMetaVal {}
    unsafe impl aya::Pod for UnderlayValue {}
    unsafe impl aya::Pod for PortMeta {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn iface_key_is_word_packed() {
        // POD layout must be stable for sharing with eBPF: 4 (vni) + 4 (ipv4).
        assert_eq!(size_of::<IfaceKey>(), 8);
        // Natural 4-byte alignment (so an Array/Hash of them is densely packed).
        assert_eq!(align_of::<IfaceKey>(), 4);
        let k = IfaceKey::new(100, [10, 0, 0, 5]);
        assert_eq!(k.vni, 100);
        assert_eq!(k.ipv4, [10, 0, 0, 5]);
    }

    #[test]
    fn iface_key6_layout() {
        // POD layout must be stable for sharing with eBPF: 4 (vni) + 16 (ipv6) = 20, align 4.
        assert_eq!(offset_of!(IfaceKey6, vni), 0);
        assert_eq!(offset_of!(IfaceKey6, ipv6), 4);
        assert_eq!(size_of::<IfaceKey6>(), 4 + 16);
        assert_eq!(align_of::<IfaceKey6>(), 4);
        let k = IfaceKey6::new(100, [0x20; 16]);
        assert_eq!(k.vni, 100);
        assert_eq!(k.ipv6, [0x20; 16]);
    }

    #[test]
    fn port_meta_and_iface_layout() {
        // 4 (vni) + 4 (guest_ipv4) + 4 (gateway_ipv4) + 6 (guest_mac) + 1 (l3) + 1 (offloaded)
        // + 16 (underlay_ipv6) + 16 (gateway_ipv6) + 16 (guest_ipv6) = 68.
        assert_eq!(size_of::<PortMeta>(), 68);
        assert_eq!(size_of::<IfaceValue>(), 32);
        assert_eq!(align_of::<PortMeta>(), 4);
        assert_eq!(size_of::<UnderlayValue>(), 16);
    }
}
