//! Overlay-egress decision under Geneve `collect_md`.
//!
//! P2 replaces the hand-rolled IP-in-IPv6 outer-header byte writer with a **decision**: the
//! datapath resolves which tunnel key (VNI + remote underlay) a packet should carry and hands that
//! off; the kernel's `collect_md` Geneve device builds the real outer Eth/IPv6/UDP/Geneve header
//! from it (via `bpf_skb_set_tunnel_key` — wired up in a later eBPF-facing task) and transmits.
//! Nothing in `flowplane-core` (or the native sim) writes outer bytes anymore.

use flowplane_common::RouteValue;

// Single-sourced in `flowplane_common::proto`; re-exported so `flowplane_core::encap::{ETH_LEN, ..}`
// keeps resolving for the many offset-math call sites (decap, inner-frame parsing) that still need
// them — only the OUTER-HEADER byte writer this module used to own has gone away.
pub use flowplane_common::proto::{ETH_LEN, IPV6_LEN};

/// The overlay-egress decision: stamp this Geneve tunnel key and hand the packet to the geneve
/// device. Replaces the old byte-written outer Eth+IPv6 header — the kernel builds the wire bytes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TunnelEncap {
    pub vni: u32,
    pub remote: [u8; 16],
    /// When present, the encap carries a DSR Geneve TLV with this VIP identity (edge -> backend).
    /// `None` for every non-DSR encap (plain overlay egress, reforward).
    pub dsr_vip: Option<flowplane_common::DsrOpt>,
}

/// Build the tunnel-key decision for a matched overlay route. Single-sourced so every route-driven
/// encap site (guest egress v4/v6, NAT64 egress) emits the identical `{vni, remote}` pair.
#[inline(always)]
pub fn tunnel_encap(route: &RouteValue) -> TunnelEncap {
    TunnelEncap {
        vni: route.nexthop_vni,
        remote: route.nexthop_ipv6,
        dsr_vip: None,
    }
}

/// Re-forward decision for an LB remote backend (East-West DSR): re-target the SAME `vni` at a
/// different backend underlay, WITHOUT decap — the inner (still fully encapped) frame is left
/// completely untouched; only the tunnel key changes. Faithful port of the old byte-rewriting
/// `encap::reforward` (which rewrote the outer Ethernet + IPv6 src/dst in place); the kernel geneve
/// device now owns that rewrite via `bpf_skb_set_tunnel_key`, so this can no longer fail a bounds
/// check the way the byte writer could.
#[inline(always)]
pub fn reforward(vni: u32, backend: &[u8; 16]) -> TunnelEncap {
    TunnelEncap {
        vni,
        remote: *backend,
        dsr_vip: None,
    }
}
