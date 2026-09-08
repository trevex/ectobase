//! NAT64 ingress reply orchestrator ([`process_uplink_nat64_ingress`]): the v4→v6 expansion tail
//! reached from `uplink::process_uplink_rx`'s CT_F_NAT64 branch. Split out of the datapath god-file
//! per review P1.2; behavior-preserving.

use crate::conntrack::ct_apply;
use crate::decap::GW_MAC;
use crate::encap::ETH_LEN;
use crate::nat64::{nat64_ingress_parse, nat64_ingress_write};
use crate::pkt::{Action, Pkt};

/// Inputs for [`process_uplink_nat64_ingress`]. `rev` is the reverse `CT_F_NAT64` conntrack entry the
/// caller already resolved (restores the guest IPv4 dst + orig L4 port); this fn takes no `Maps`.
pub struct UplinkNat64IngressIn<'a> {
    pub tap_ifindex: u32,
    pub guest_mac: [u8; 6],
    pub guest_ipv6: [u8; 16],
    pub rev: &'a flowplane_common::CtEntry,
}

/// Host NAT64 ingress reply path, in place on `pkt`. Mirrors the eBPF ingress `nat64_ingress`:
/// reverse `ct_apply` → `nat64_ingress_parse` (Pass on miss) → `grow_head(20)` → `nat64_ingress_write`.
///
/// Post-decap, `pkt` arrives as `[InnerEth(14)][InnerIPv4(20)][L4]` (34+L4 bytes) — the kernel
/// already stripped the outer Eth/IPv6/UDP/Geneve header. NAT64 v4→v6 EXPANDS the inner header
/// (IPv4 20 → IPv6 40), so this is a **+20 GROW** to `[Eth(14)][IPv6(40)][L4]` (54+L4 bytes) — the
/// mirror image of `nat64_egress`'s v6→v4 shrink, reversed.
///
/// `#[inline(never)]`: ingress-only, same BPF-stack-relief reasoning as `uplink::process_uplink`.
#[inline(never)]
pub fn process_uplink_nat64_ingress<P: Pkt>(pkt: &mut P, in_: &UplinkNat64IngressIn) -> Action {
    let inner_off = ETH_LEN;
    let orig_sport = in_.rev.xlate_port;

    // 1. Reverse conntrack apply: restore the guest IPv4 dst + orig L4 port (+ checksums).
    ct_apply(pkt, inner_off, in_.rev);

    // 2. Parse (IHL/proto/TTL/addrs/checksum + reconstructed 64:ff9b:: IPv6 src).
    let xlate =
        match nat64_ingress_parse(&*pkt, inner_off, in_.guest_ipv6, in_.guest_mac, orig_sport) {
            Some(x) => x,
            None => return Action::Pass,
        };

    // 3. Resize: grow 20 bytes at the front (models adjust_room(+20, BPF_ADJ_ROOM_MAC) /
    // bpf_xdp_adjust_head(-20)) — v4(20)→v6(40) inner header expansion.
    if !pkt.grow_head(20) {
        return Action::Drop;
    }

    // 4. Write: guest Ethernet + inner IPv6 header + L4 translation.
    if !nat64_ingress_write(pkt, ETH_LEN, GW_MAC, &xlate) {
        return Action::Drop;
    }

    Action::Redirect(in_.tap_ifindex)
}
