//! tc (clsact ingress) glue for the guest edge. Mirrors the XDP guest_tx/guest_dhcp split but uses
//! skb primitives (pull_data/change_tail) and tc return codes, and replies to the guest by
//! redirecting back out the tap. The heavy logic lives in the shared pure core (flowplane_common::dhcp).

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_redirect, bpf_skb_change_tail},
    macros::classifier,
    programs::TcContext,
};

use crate::coreimpl::{GlobalMaps, RawPkt};
use crate::dhcp::learn_mac;
use crate::dhcp::tc_dhcpv6_respond;
use crate::maps::{GUEST_PROGS_TC, PORT_META};
use flowplane_common::dhcp::{looks_like_dhcpv4, looks_like_dhcpv6};
use flowplane_core::dhcp::{parse as dhcp4_parse, write as dhcp4_write, MIN_DHCP_LEN, REPLY_LEN};

// skb->tstamp delivery-time kind: monotonic delivery time honored by the fq qdisc (EDT model).
const BPF_SKB_TSTAMP_DELIVERY_MONO: u32 = 1;

// `aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT}` are already `i32` (the verdict type a
// `#[classifier]` returns), so they're used directly below.

/// clsact-ingress on a guest tap: host receives = guest egress. ARP + IPv6 ND are answered
/// in place (redirect back to guest); DHCP is tail-called. Everything else → TC_ACT_OK passthrough.
#[classifier]
pub fn tc_guest_tx(ctx: TcContext) -> i32 {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    // Hold PortMeta by REFERENCE (not a ~70-byte by-value copy): frees the stack the per-packet
    // bpf_fib_lookup scratch needs to stay under the 512B BPF combined-stack limit on the v4 encap
    // path. Every use below is a field read or `&`-borrow, so a reference suffices.
    let meta = match unsafe { PORT_META.get(&ifindex) } {
        Some(m) => m,
        None => return TC_ACT_OK,
    };
    // Bounds-checked ethertype read (classification only).
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + 14 > data_end {
        return TC_ACT_OK;
    }
    let ethertype = u16::from_be(unsafe {
        core::ptr::read_unaligned((data as *const u8).add(12) as *const u16)
    });

    // ARP request for the gateway → reply in place, redirect back to the guest.
    if ethertype == flowplane_core::arp_nd::ETH_P_ARP {
        if ctx
            .pull_data((flowplane_common::arp_nd::ETH_LEN + flowplane_core::arp_nd::ARP_LEN) as u32)
            .is_ok()
            && flowplane_core::arp_nd::arp_reply(
                &mut crate::coreimpl::RawPkt::new(ctx.data(), ctx.data_end()),
                meta.gateway_ipv4,
                // Advertise the gateway at the shared virtual router MAC (GW_MAC) — the SAME src MAC
                // the datapath puts on every frame it delivers to a guest (uplink/local/nat64/dhcp).
                // A distinct router MAC (not the guest's own) is the correct L2 gateway model and is
                // agnostic to the guest-edge L2 topology (veth / tap / mirred / bridge all work).
                crate::arp_nd::GW_MAC,
            )
        {
            return unsafe { bpf_redirect(ifindex, 0) as i32 };
        }
        return TC_ACT_OK;
    }

    // IPv6 → may be an ND Neighbor Solicitation for the gateway.
    if ethertype == flowplane_common::arp_nd::ETH_P_IPV6 {
        // NAT64 egress (mirrors XDP v6_guest_tx order: nat64 first). The full translate+SNAT+encap
        // path can't run inline here — tc_guest_tx's own stack frame plus tc_nat64_egress's blow
        // the BPF 512-byte combined-call stack budget. So we cheaply peek the inner IPv6 dst and, if
        // it's in 64:ff9b::/96, TAIL-CALL the dedicated tc_guest_nat64 program (fresh stack budget),
        // exactly like DHCP. Non-NAT64 IPv6 falls through to ND / overlay forwarding below.
        const V6_HDR: usize = flowplane_common::arp_nd::ETH_LEN + crate::parse::IPV6_LEN;
        if ctx.pull_data(V6_HDR as u32).is_ok()
            && ctx.data() + V6_HDR <= ctx.data_end()
            && unsafe {
                flowplane_core::nat64::is_nat64_addr(&core::ptr::read_unaligned(
                    (ctx.data() as *const u8).add(flowplane_common::arp_nd::ETH_LEN + 24)
                        as *const [u8; 16],
                ))
            }
        {
            let _ = unsafe { GUEST_PROGS_TC.tail_call(&ctx, flowplane_common::GUEST_PROG_IPV6) };
            // tail_call only returns on failure (e.g. slot empty) → fall through to passthrough.
            return TC_ACT_OK;
        }
        const ND_FRAME: usize =
            flowplane_common::arp_nd::ETH_LEN + flowplane_common::arp_nd::IPV6_LEN + 32;
        if ctx.pull_data(ND_FRAME as u32).is_ok()
            && flowplane_core::arp_nd::nd_reply(
                &mut crate::coreimpl::RawPkt::new(ctx.data(), ctx.data_end()),
                meta.gateway_ipv6,
                crate::arp_nd::GW_MAC, // gateway at the shared router MAC (see arp_reply above)
            )
        {
            return unsafe { bpf_redirect(ifindex, 0) as i32 };
        }
        // IPv6 Router Solicitation (ICMPv6 type 133) → reply with a Managed RA carrying the default
        // gateway + the MTU option, so a self-configuring guest/VM gets a v6 default route + link MTU
        // (DHCPv6 cannot carry MTU). The ND pull above made ETH+IPv6+ICMP-type present; peek the type
        // cheaply, then GROW the skb to the (larger) RA size before writing the reply in place.
        const RS_TYPE: u8 = flowplane_core::arp_nd::ND_RS;
        let is_rs = ctx.data() + flowplane_common::arp_nd::ETH_LEN + crate::parse::IPV6_LEN + 1
            <= ctx.data_end()
            && unsafe {
                let p = ctx.data() as *const u8;
                *p.add(flowplane_common::arp_nd::ETH_LEN + 6)
                    == flowplane_core::arp_nd::IPPROTO_ICMPV6
                    && *p.add(flowplane_common::arp_nd::ETH_LEN + crate::parse::IPV6_LEN) == RS_TYPE
            };
        if is_rs {
            // Read only the MTU field (not the whole DhcpConfig) to keep this off the heavy stack.
            // Default = the standard 1500 link MTU minus the Geneve overlay overhead the kernel adds
            // on transmit (`flowplane_common::GENEVE_OVERHEAD`), same default as the DHCPv4 responder.
            let mtu = crate::maps::DHCP_CONFIG
                .get(0)
                .map(|c| c.mtu)
                .unwrap_or((1500 - flowplane_common::GENEVE_OVERHEAD) as u16)
                as u32;
            if unsafe { bpf_skb_change_tail(ctx.skb.skb, flowplane_core::arp_nd::RA_LEN as u32, 0) }
                == 0
                && ctx.pull_data(flowplane_core::arp_nd::RA_LEN as u32).is_ok()
                && flowplane_core::arp_nd::ra_reply(
                    &mut crate::coreimpl::RawPkt::new(ctx.data(), ctx.data_end()),
                    meta.gateway_ipv6,
                    crate::arp_nd::GW_MAC, // router advertised at the shared router MAC
                    mtu,
                )
            {
                return unsafe { bpf_redirect(ifindex, 0) as i32 };
            }
            return TC_ACT_OK;
        }

        // DHCPv6 (UDP dst 547) → tail-call the dedicated responder.
        if looks_like_dhcpv6(ctx.data(), ctx.data_end()) {
            let _ = unsafe { GUEST_PROGS_TC.tail_call(&ctx, flowplane_common::GUEST_PROG_DHCP) };
            return TC_ACT_OK;
        }

        // Not ND → IPv6 inner overlay egress: TAIL-CALL the dedicated tc_guest_egress_v6 program.
        // The firewall + conntrack + route6 + encap path can't run inline here — tc_guest_tx's own
        // 448B frame plus the v6 fw/ct structures (FwRule6 80B, CtKey6 44B, CtEntry 24B) blow the
        // BPF 512B combined-call stack budget. A tail-call gives it a fresh stack (like tc_guest_nat64).
        let _ = ctx.pull_data((flowplane_common::arp_nd::ETH_LEN + crate::parse::IPV6_LEN) as u32);
        let _ = unsafe { GUEST_PROGS_TC.tail_call(&ctx, flowplane_common::GUEST_PROG_V6_FWD) };
        // tail_call only returns on failure (slot empty) → passthrough.
        return TC_ACT_OK;
    }

    // DHCPv4 → tail-call the dedicated responder.
    if looks_like_dhcpv4(ctx.data(), ctx.data_end()) {
        let _ = unsafe { GUEST_PROGS_TC.tail_call(&ctx, flowplane_common::GUEST_PROG_DHCP) };
        return TC_ACT_OK;
    }

    // IPv4 → run the shared in-place egress pipeline and execute the verdict with tc primitives:
    // PASS/DROP, deliver to a local guest tap (redirect), or encapsulate into the overlay and
    // redirect out the uplink.
    if ethertype == 0x0800 {
        // Make the inner IPv4 header range writable for the in-place pipeline (NAT/VIP).
        let _ = ctx.pull_data((flowplane_common::arp_nd::ETH_LEN + 40) as u32);
        // Re-establish a clean lower bound for the verifier after pull_data invalidated the
        // pkt-range facts: the inner IPv4 base header (ETH_LEN + 20) must be present. This mirrors
        // the XDP guest_tx guard before forward_decision_v4 and keeps the in-place reads in-bounds.
        if ctx.data() + flowplane_common::arp_nd::ETH_LEN + 20 > ctx.data_end() {
            return TC_ACT_OK;
        }
        match crate::egress::forward_decision_v4(ctx.data(), ctx.data_end(), ifindex, meta) {
            crate::egress::EgressVerdict::Pass => return TC_ACT_OK,
            crate::egress::EgressVerdict::Drop => return TC_ACT_SHOT,
            crate::egress::EgressVerdict::Local {
                tap_ifindex,
                guest_mac,
            } => {
                if ctx.data() + flowplane_common::arp_nd::ETH_LEN <= ctx.data_end() {
                    let q = ctx.data() as *mut u8;
                    unsafe {
                        // dst = local guest MAC, src = gateway MAC; ethertype stays IPv4.
                        let g = guest_mac;
                        let gw = crate::arp_nd::GW_MAC;
                        let mut i = 0;
                        while i < 6 {
                            *q.add(i) = g[i];
                            *q.add(6 + i) = gw[i];
                            i += 1;
                        }
                    }
                    // Guest-egress same-node local delivery stays plain bpf_redirect: bpf_redirect_peer
                    // from the netkit PEER (pod-egress) hook does not deliver through the peer's
                    // ingress mirred to the VM tap (proven live). Peer-redirect is uplink-only (see
                    // ingress::execute).
                    return unsafe { bpf_redirect(tap_ifindex, 0) as i32 };
                }
                return TC_ACT_OK;
            }
            crate::egress::EgressVerdict::Encap(tunnel) => {
                // No byte write: the kernel's `collect_md` Geneve device builds the outer
                // Eth/IPv6/UDP/Geneve header itself from the tunnel-key metadata dst stamped below.
                // EDT egress shaping: stamp the wire-length-derived departure time so the uplink's fq
                // qdisc paces this flow. `ctx.len()` is skb->len BEFORE the geneve device's own
                // encapsulation grows it further — this under-counts the eventual wire overhead (a
                // follow-up task can account for it; see `flowplane_core::datapath` encap-arm notes).
                // No shaping configured => no stamp (send immediately).
                if let Some(ts) = crate::meter::edt_stamp(ifindex, ctx.len() as u64) {
                    unsafe {
                        aya_ebpf::helpers::gen::bpf_skb_set_tstamp(
                            ctx.skb.skb as *mut _,
                            ts,
                            BPF_SKB_TSTAMP_DELIVERY_MONO,
                        );
                    }
                }
                if !crate::tunnel::set_tunnel_key(ctx.skb.skb, &tunnel) {
                    return TC_ACT_SHOT;
                }
                return crate::tunnel::redirect();
            }
        }
    }
    TC_ACT_OK
}

/// tc NAT64 egress responder (tail-call target, slot GUEST_PROG_IPV6). Reached from `tc_guest_tx`
/// when the inner IPv6 dst is in 64:ff9b::/96. Running as its own program gives the heavy
/// translate+SNAT+encap path a fresh BPF stack budget (it doesn't fit on top of tc_guest_tx's
/// frame). On any fall-through/parse miss, pass the packet to the stack.
#[classifier]
pub fn tc_guest_nat64(ctx: TcContext) -> i32 {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    // Read only the two fields tc_nat64_egress needs — copying the whole ~70-byte PortMeta onto
    // this entry's frame would add to the tail-called call chain's combined BPF stack budget.
    let (vni, guest_ipv4) = match unsafe { PORT_META.get(&ifindex) } {
        Some(m) => (m.vni, m.guest_ipv4),
        None => return TC_ACT_OK,
    };
    match crate::nat64::tc_nat64_egress(&ctx, vni, guest_ipv4) {
        Ok(Some(act)) => act,
        Ok(None) => TC_ACT_OK,
        Err(_) => TC_ACT_SHOT,
    }
}

/// tc IPv6 overlay egress (tail-call target, slot GUEST_PROG_V6_FWD). Reached from `tc_guest_tx` for
/// a non-ND / non-NAT64 / non-DHCPv6 inner-IPv6 guest packet. Running as its own program gives the
/// egress firewall + conntrack + route6 + encap path a FRESH BPF stack budget (it overflows
/// tc_guest_tx's 512B combined frame). Mirrors `tc_guest_nat64`. Falls through to passthrough on miss.
#[classifier]
pub fn tc_guest_egress_v6(ctx: TcContext) -> i32 {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    // Hold PORT_META by reference — copying the whole ~70-byte PortMeta onto this frame would eat
    // into the budget the fw/ct call chain needs. `forward_decision_v6` takes `&PortMeta`.
    let meta = match unsafe { PORT_META.get(&ifindex) } {
        Some(m) => m,
        None => return TC_ACT_OK,
    };
    if ctx.data() + flowplane_common::arp_nd::ETH_LEN + crate::parse::IPV6_LEN > ctx.data_end() {
        return TC_ACT_OK;
    }
    // The tail-call gave this program a fresh 512B stack budget. `forward_decision_v6` is a thin
    // #[inline(always)] dispatcher that calls the two heavy stages — firewall/conntrack
    // (egress_fw_ct_v6) and route6+deliver (route_decision_v6) — as SEQUENTIAL #[inline(never)]
    // subprograms, so their frames never coexist. The Encap-arm tunnel-key stamp is likewise split
    // out (encap_v6_egress), kept out-of-line for the same reason it always was, even though it no
    // longer carries heavy locals.
    match crate::egress::forward_decision_v6(ctx.data(), ctx.data_end(), ifindex, meta) {
        crate::egress::EgressVerdict::Pass => TC_ACT_OK,
        crate::egress::EgressVerdict::Drop => TC_ACT_SHOT,
        crate::egress::EgressVerdict::Local {
            tap_ifindex,
            guest_mac,
        } => {
            if ctx.data() + flowplane_common::arp_nd::ETH_LEN <= ctx.data_end() {
                let q = ctx.data() as *mut u8;
                unsafe {
                    let g = guest_mac;
                    let gw = crate::arp_nd::GW_MAC;
                    let mut i = 0;
                    while i < 6 {
                        *q.add(i) = g[i];
                        *q.add(6 + i) = gw[i];
                        i += 1;
                    }
                    core::ptr::write_unaligned(q.add(12) as *mut u16, 0x86DDu16.to_be());
                }
                // Guest-egress same-node local delivery stays plain bpf_redirect (peer-redirect is
                // uplink-only — see the v4 arm + ingress::execute).
                return unsafe { bpf_redirect(tap_ifindex, 0) as i32 };
            }
            TC_ACT_OK
        }
        crate::egress::EgressVerdict::Encap(tunnel) => encap_v6_egress(&ctx, ifindex, &tunnel),
    }
}

/// Stamp the Geneve tunnel key + EDT-stamp + redirect for an inner-v6 overlay egress packet.
/// Out-of-line (`#[inline(never)]`) so this stays its own BPF stack frame, sequential to (never
/// coexisting with) `tc_guest_egress_v6`'s frame — that frame is held live across the
/// `egress_fw_ct_v6` subprogram call, and the two must stay under the 512B combined stack limit.
/// `ctx` is passed by reference (only skb helpers are called on it — no packet pointer is
/// cast/stored across the boundary).
#[inline(never)]
fn encap_v6_egress(
    ctx: &TcContext,
    ifindex: u32,
    tunnel: &flowplane_core::encap::TunnelEncap,
) -> i32 {
    // No byte write: see the v4 arm's comment in `tc_guest_tx`.
    if let Some(ts) = crate::meter::edt_stamp(ifindex, ctx.len() as u64) {
        unsafe {
            aya_ebpf::helpers::gen::bpf_skb_set_tstamp(
                ctx.skb.skb as *mut _,
                ts,
                BPF_SKB_TSTAMP_DELIVERY_MONO,
            );
        }
    }
    if !crate::tunnel::set_tunnel_key(ctx.skb.skb, tunnel) {
        return TC_ACT_SHOT;
    }
    crate::tunnel::redirect()
}

/// tc DHCP responder: build the OFFER/ACK into the (resized) skb and redirect it back to the guest.
#[classifier]
pub fn tc_guest_dhcp(ctx: TcContext) -> i32 {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let meta = match unsafe { PORT_META.get(&ifindex) } {
        Some(m) => *m,
        None => return TC_ACT_OK,
    };
    // DHCPv4 and DHCPv6 share this tail-call slot; dispatch on the ethertype/port. DHCPv6 builds the
    // ADVERTISE/REPLY into the skb and redirects it back out the tap toward the guest.
    if looks_like_dhcpv6(ctx.data(), ctx.data_end()) {
        if tc_dhcpv6_respond(&ctx, &meta) {
            return unsafe { bpf_redirect(ifindex, 0) as i32 };
        }
        return TC_ACT_OK;
    }
    // Make the request head writable/linear so the parse works on direct packet access. A DISCOVER
    // is typically SHORTER than REPLY_LEN (e.g. ~286B vs 428B), so pulling REPLY_LEN here fails
    // (bpf_skb_pull_data cannot pull past skb->len) and we'd bail before ever growing the skb.
    // Pull only the fixed DHCP header (MIN_DHCP_LEN), which every valid request carries; the skb is
    // grown to REPLY_LEN and re-pulled below, before the reply is written.
    if ctx.pull_data(MIN_DHCP_LEN as u32).is_err() {
        return TC_ACT_OK;
    }
    let req = match dhcp4_parse(&RawPkt::new(ctx.data(), ctx.data_end())) {
        Some(r) => r,
        None => return TC_ACT_OK,
    };
    learn_mac(ifindex, &meta, req.client_mac);
    // Resize the skb to REPLY_LEN, then re-establish writability (change_tail invalidates bounds).
    let cur = (ctx.data_end() - ctx.data()) as u32;
    if cur != REPLY_LEN as u32
        && unsafe { bpf_skb_change_tail(ctx.skb.skb, REPLY_LEN as u32, 0) } != 0
    {
        return TC_ACT_OK;
    }
    if ctx.pull_data(REPLY_LEN as u32).is_err() {
        return TC_ACT_OK;
    }
    let ok = dhcp4_write(
        &mut RawPkt::new(ctx.data(), ctx.data_end()),
        &req,
        meta.guest_ipv4,
        meta.gateway_ipv4,
        crate::arp_nd::GW_MAC,
        &GlobalMaps,
        ifindex,
    );
    if !ok {
        return TC_ACT_SHOT;
    }
    // Reply to the guest: redirect back out the tap we arrived on (egress = toward guest).
    // In tc, bpf_redirect returns TC_ACT_REDIRECT, which is the correct return value.
    unsafe { bpf_redirect(ifindex, 0) as i32 }
}
