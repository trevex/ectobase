//! Load-balancer / DSR / VIP map key & value types (the `VIPS`, `NAT_IPS6`, `LB`, `MAGLEV`,
//! `DSR` / `DSR6` maps and the Geneve DSR TLV payload).

/// Key for the `vips` map: (VNI, IPv4). Value is the mapped IPv4 (the 1:1 counterpart).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct VipKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
}

/// Key for the `NAT_IPS6` marker map: (VNI, IPv6) — marks a public NAT66 source IP the local node
/// owns. v6 sibling of [`VipKey`].
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct VipKey6 {
    pub vni: u32,
    pub ipv6: [u8; 16],
}

/// LB service key: (vni, balanced IPv4, L4 port, proto). proto: 6=TCP, 17=UDP, 1=ICMP.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct LbKey {
    pub vni: u32,
    pub ipv4: [u8; 4],
    pub port: u16,
    pub proto: u8,
    pub _pad: u8,
}

/// LB value: the Maglev table id + its size (number of slots).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct LbValue {
    pub table_id: u32,
    pub size: u32,
}

/// Maglev slot key: (table_id, slot). Value in the map is the backend IPv4 (`[u8;4]`).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct MaglevKey {
    pub table_id: u32,
    pub slot: u32,
}

/// Maglev slot value: a fully self-describing LB backend. `node_vtep == Local.underlay_ipv6` decides
/// local-vs-remote delivery (no `is_local:0` INTERFACES rows needed); on a local hit the datapath
/// resolves the delivery tap via `INTERFACES[(vni, overlay_ip4)]` / `INTERFACES6[(vni, overlay_ip6)]`.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct LbBackend {
    /// Backend node underlay /128 (the tunnel dst for a remote backend).
    pub node_vtep: [u8; 16],
    /// Backend guest overlay IP: a v4 address left-justified in the first 4 bytes when `is_v6 == 0`,
    /// or the full 16-byte v6 address when `is_v6 == 1`.
    pub overlay_ip: [u8; 16],
    /// Backend delivery VNI (the tenant VNI the guest lives in).
    pub vni: u32,
    /// Overlay family selector: 0 → look up `INTERFACES` with `overlay_ip[0..4]`; 1 → `INTERFACES6`.
    pub is_v6: u8,
    pub _pad: [u8; 3],
}

/// The DSR identity an edge dispatches to a backend: the VIP (+ service port + family) the backend
/// must reverse-SNAT the guest reply source to. Payload of the Geneve DSR TLV (see flowplane-core::dsr).
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct DsrOpt {
    /// 0 = VIP is IPv4 (first 4 bytes of `vip`); 1 = IPv6 (full 16 bytes).
    pub family: u8,
    pub _pad: u8,
    /// Service L4 port (host order in the struct; encode/decode handle network order).
    pub port: u16,
    /// The VIP, v4 left-justified in 16 bytes when `family == 0`.
    pub vip: [u8; 16],
}

/// DSR reverse-SNAT state: the VIP a backend must rewrite a guest reply's source address to,
/// stored in the dedicated `DSR`/`DSR6` LRU maps keyed by the reply 5-tuple (`CtKey`/`CtKey6` —
/// `invert_key`/`invert_key6` of the forwarded flow's key). Deliberately compact (24 bytes) so it
/// does not inflate `CtEntry` or the conntrack hot paths; `last_seen` is informational only — the
/// LRU map itself handles eviction.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct DsrVip {
    /// The VIP, v4 left-justified in 16 bytes for a v4 flow (mirrors `DsrOpt::vip`/`LbBackend::overlay_ip`).
    pub vip: [u8; 16],
    /// Informational: kernel-monotonic ns timestamp of the most recent note. Not read by the
    /// reverse-SNAT rewrite; the LRU map's own eviction handles lifecycle.
    pub last_seen: u64,
}

// SAFETY: all `#[repr(C)]` fixed-size POD types with no padding beyond explicit `_pad` fields, so
// their raw bytes are a valid map key/value ABI shared with the eBPF datapath.
#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for VipKey {}
    unsafe impl aya::Pod for VipKey6 {}
    unsafe impl aya::Pod for LbKey {}
    unsafe impl aya::Pod for LbValue {}
    unsafe impl aya::Pod for MaglevKey {}
    unsafe impl aya::Pod for LbBackend {}
    unsafe impl aya::Pod for DsrOpt {}
    unsafe impl aya::Pod for DsrVip {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn lb_keys_have_no_implicit_padding() {
        // LbKey: vni(4) ipv4(4) port(2) proto(1) _pad(1) = 12.
        assert_eq!(offset_of!(LbKey, vni), 0);
        assert_eq!(offset_of!(LbKey, ipv4), 4);
        assert_eq!(offset_of!(LbKey, port), 8);
        assert_eq!(offset_of!(LbKey, proto), 10);
        assert_eq!(offset_of!(LbKey, _pad), 11);
        assert_eq!(size_of::<LbKey>(), 4 + 4 + 2 + 1 + 1);
        // The padding-free word-packed keys.
        assert_eq!(size_of::<VipKey>(), 4 + 4);
        assert_eq!(size_of::<MaglevKey>(), 4 + 4);
        assert_eq!(align_of::<LbKey>(), 4, "LbKey must stay 4-byte aligned");
    }

    #[test]
    fn vip_key_layout() {
        assert_eq!(size_of::<VipKey>(), 8);
        assert_eq!(size_of::<VipKey6>(), 20); // 4 + 16
    }

    #[test]
    fn lb_layouts() {
        assert_eq!(size_of::<LbKey>(), 12);
        assert_eq!(size_of::<LbValue>(), 8);
        assert_eq!(size_of::<MaglevKey>(), 8);
    }

    #[test]
    fn lb_backend_layout() {
        // node_vtep(16) + overlay_ip(16) + vni(4) + is_v6(1) + _pad(3) = 40, u32-aligned.
        // MAGLEV is a RUNTIME map re-created on load — no wire/journal ABI concern; the only
        // coupling is the eBPF reader + the control-plane writer, changed together.
        assert_eq!(size_of::<LbBackend>(), 40);
        assert_eq!(align_of::<LbBackend>(), 4);
    }

    #[test]
    fn dsr_opt_layout() {
        // family(1) + _pad(1) + port(2) + vip(16) = 20, the Geneve DSR TLV payload size
        // (24-byte buffer = 4-byte option header + this 20-byte payload).
        assert_eq!(offset_of!(DsrOpt, family), 0);
        assert_eq!(offset_of!(DsrOpt, port), 2);
        assert_eq!(offset_of!(DsrOpt, vip), 4);
        assert_eq!(size_of::<DsrOpt>(), 20);
        assert_eq!(align_of::<DsrOpt>(), 2);
    }

    #[test]
    fn dsr_vip_layout() {
        // 16 (vip) + 8 (last_seen) = 24, u64-aligned. RUNTIME LRU map value (DSR/DSR6) — no
        // wire/journal ABI concern, same coupling rule as `ct_entry_layout`.
        assert_eq!(size_of::<DsrVip>(), 24);
        assert_eq!(align_of::<DsrVip>(), 8);
    }
}
