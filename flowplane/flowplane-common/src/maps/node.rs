//! Node-global datapath map types & constants: the per-hypervisor `LOCAL` / `CONFIG` entries, the
//! debug `INSPECT` map, per-interface QoS `MeterState`, the Geneve overlay overhead constant, and
//! the tail-call program-array indices.

/// Geneve overlay wire overhead the kernel's `collect_md` device adds on top of the inner frame the
/// eBPF programs see: outer IPv6 (40) + outer UDP (8) + Geneve header (8) = 56. The outer Ethernet
/// (14) is link framing on the fabric NIC, not part of the L3/L4 overhead a guest's own MTU needs to
/// account for. The datapath does not write outer bytes (the kernel builds them from a `TunnelEncap`
/// decision — see `flowplane_core::encap`), so `pkt.len()` on the egress Encap arm and the ingress
/// uplink path is the INNER length only; anywhere that needs to reflect real wire bytes (rate
/// metering, the advertised guest MTU) adds this constant back in.
pub const GENEVE_OVERHEAD: usize = 56;

/// Per-interface QoS state. Three lanes:
/// - Egress total (EDT SHAPING): `total_bps` = shaped rate (bytes/s, 0 = unlimited);
///   `total_last_ns` = the EDT schedule cursor (`t_last`, ns). `total_burst`/`total_tokens` are
///   UNUSED on the EDT path (no token bucket) and kept 0 for layout stability.
/// - Egress public (token-bucket POLICING of external/NATed egress): `public_*`.
/// - Ingress (token-bucket POLICING of traffic delivered to the guest): `ingress_*`.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct MeterState {
    pub total_bps: u64,
    pub total_burst: u64,
    pub total_tokens: u64,
    pub total_last_ns: u64,
    pub public_bps: u64,
    pub public_burst: u64,
    pub public_tokens: u64,
    pub public_last_ns: u64,
    pub ingress_bps: u64,
    pub ingress_burst: u64,
    pub ingress_tokens: u64,
    pub ingress_last_ns: u64,
}

/// This hypervisor's uplink + underlay gateway, written once into LOCAL[0] by the control plane.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Local {
    pub uplink_ifindex: u32,
    pub uplink_mac: [u8; 6],
    /// Underlay next-hop (gateway/ToR router) MAC — outer eth dst for ALL encapped traffic.
    pub gateway_mac: [u8; 6],
    pub underlay_ipv6: [u8; 16],
}

/// Debug-only type for the `INSPECT` map: records the first 32 bytes of the first packet an
/// XDP program sees, plus the total length and a per-packet counter.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct InspectEntry {
    pub len: u32,
    pub seen: u32,
    pub bytes: [u8; 32],
}

/// Tail-call indices into the `GUEST_PROGS_TC` program array (egress datapath split).
/// `GUEST_PROG_DHCP` dispatches the DHCP responder; `GUEST_PROG_IPV6` the NAT64 egress path;
/// `GUEST_PROG_V6_FWD` the IPv6 overlay egress (firewall + conntrack + route6 + encap), split out
/// because the v6 firewall/conntrack structures overflow tc_guest_tx's 512B combined BPF stack.
/// `GUEST_PROG_IPV4` stays reserved for a future v4 split.
pub const GUEST_PROG_DHCP: u32 = 0;
pub const GUEST_PROG_IPV4: u32 = 1;
pub const GUEST_PROG_IPV6: u32 = 2;
pub const GUEST_PROG_V6_FWD: u32 = 3;

/// Tail-call index into the `UPLINK_PROGS` **tc** program array (ingress datapath split; these
/// programs are tc/tcx on the geneve device).
/// `UPLINK_PROG_V6` dispatches the inner-IPv6 ingress path (`xdp_uplink_v6`), split out of
/// `uplink_rx` because the v6 firewall/conntrack structures overflow the combined BPF stack. tc
/// programs can only tail-call other tc programs of the SAME attach type, so this lives in its own
/// array (not the guest-egress-side `GUEST_PROGS_TC`).
pub const UPLINK_PROG_V6: u32 = 0;

/// Single-entry `CONFIG` map: per-hypervisor datapath parameters for the PoC's
/// CONFIG-driven single-peer overlay (one guest + one peer hypervisor). The XDP programs
/// read entry 0; the control plane populates it. MACs/ifindexes are filled at e2e time.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Config {
    /// Overlay VNI this hypervisor's guest belongs to.
    pub vni: u32,
    /// ifindex of the underlay-facing uplink (encap redirect target).
    pub uplink_ifindex: u32,
    /// ifindex of the guest-facing tap/veth (decap redirect target).
    pub guest_ifindex: u32,
    pub _pad: u32,
    /// This hypervisor's underlay IPv6 (outer src on encap).
    pub local_underlay_ipv6: [u8; 16],
    /// The peer hypervisor's underlay IPv6 (outer dst on encap).
    pub peer_underlay_ipv6: [u8; 16],
    /// Uplink source MAC (outer eth src on encap).
    pub local_mac: [u8; 6],
    /// Peer uplink MAC (outer eth dst on encap).
    pub peer_mac: [u8; 6],
    /// Guest MAC (inner eth dst on decap delivery).
    pub guest_mac: [u8; 6],
    pub _pad2: [u8; 2],
}

// SAFETY: all `#[repr(C)]` fixed-size POD types with no padding beyond explicit `_pad` fields, so
// their raw bytes are a valid map key/value ABI shared with the eBPF datapath.
#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for Local {}
    unsafe impl aya::Pod for InspectEntry {}
    unsafe impl aya::Pod for MeterState {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn local_has_stable_layout() {
        // 4 (uplink_ifindex) + 6 (uplink_mac) + 6 (gateway_mac) + 16 (underlay_ipv6) = 32.
        assert_eq!(size_of::<Local>(), 32);
    }

    #[test]
    fn config_has_stable_layout() {
        // 4*4 (u32s) + 16 + 16 (underlays) + 6+6+6+2 (macs+pad) = 16 + 32 + 20 = 68.
        assert_eq!(size_of::<Config>(), 68);
        assert_eq!(align_of::<Config>(), 4);
    }

    #[test]
    fn meter_state_layout() {
        // 12 fields * 8 bytes each = 96 bytes.
        assert_eq!(size_of::<MeterState>(), 96);
        assert_eq!(align_of::<MeterState>(), 8);
    }
}
