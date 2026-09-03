use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    helpers::bpf_redirect,
    programs::TcContext,
};
use flowplane_core::err::DpErr;
use flowplane_core::maps::Maps as _;

use crate::arp_nd::GW_MAC;
use crate::coreimpl::GlobalMaps;
use crate::maps::UNDERLAY;
use crate::parse::{write6, ETH_LEN, ETH_P_IPV6, IPV6_LEN};
use crate::tunnel::{get_tunnel_key, redirect as tunnel_redirect, set_tunnel_key};

/// Stateless ingress firewall for the inner-v6 LB-local delivery path (no conntrack: DSR keeps the
/// inner dst = VIP). Returns `true` if the packet must be dropped. Out-of-line (`#[inline(never)]`)
/// so its firewall stack frame is freed before returning into the caller — keeps `v6_uplink_rx`
/// under the 512B combined BPF stack limit.
///
/// Takes `data`/`data_end` as SCALARS and reconstructs the packet window inside via `RawPkt` — no
/// `TcContext`/pkt pointer crosses the bpf-to-bpf boundary (passing one and then deriving `pkt_end`
/// in the callee trips the verifier's "R_ pointer arithmetic on pkt_end prohibited"). Mirrors the
/// egress `egress_fw_ct_v6` shape.
#[inline(never)]
fn ingress_fw_lb_v6(data: usize, data_end: usize, tap_ifindex: u32) -> bool {
    flowplane_core::firewall::fw_eval_dir6(
        &crate::coreimpl::RawPkt::new(data, data_end),
        &crate::coreimpl::GlobalMaps,
        ETH_LEN + IPV6_LEN,
        tap_ifindex,
        flowplane_common::FW_DIR_INGRESS,
    ) == flowplane_common::FW_ACTION_DROP
}

/// Stateful firewall + conntrack for the inner-v6 normal (non-LB) ingress delivery path, applied
/// pre-decap (inner v6 header at ETH_LEN + IPV6_LEN — see the module-level `// TODO(4c)` note: this
/// offset predates the outer-header removal and is stale until Task 5's offset sweep, same as the
/// rest of this file's internal math). Returns `true` if the packet must be dropped (deny-by-default
/// on a new flow). Out-of-line (`#[inline(never)]`) so its CtKey6/CtEntry stack frame stays off the
/// combined `v6_uplink_rx` BPF stack (512B limit).
///
/// Takes `data`/`data_end` as SCALARS and reconstructs the packet window inside via `RawPkt` — see
/// [`ingress_fw_lb_v6`] for why.
#[inline(never)]
fn ingress_fw_ct_v6(data: usize, data_end: usize, tap_ifindex: u32, vni: u32) -> bool {
    if let Some(key) = crate::conntrack::ct_key6(data, data_end, ETH_LEN + IPV6_LEN, vni) {
        match unsafe { crate::maps::CONNTRACK6.get(&key) } {
            Some(e) => {
                let mut e = *e;
                crate::conntrack::ct_touch6(data, data_end, ETH_LEN + IPV6_LEN, &key, &mut e);
            }
            None => {
                if flowplane_core::firewall::fw_eval_dir6(
                    &crate::coreimpl::RawPkt::new(data, data_end),
                    &crate::coreimpl::GlobalMaps,
                    ETH_LEN + IPV6_LEN,
                    tap_ifindex,
                    flowplane_common::FW_DIR_INGRESS,
                ) == flowplane_common::FW_ACTION_DROP
                {
                    return true;
                }
                flowplane_core::conntrack::ct_create_default6(
                    &crate::coreimpl::RawPkt::new(data, data_end),
                    &mut crate::coreimpl::GlobalMaps,
                    ETH_LEN + IPV6_LEN,
                    vni,
                    crate::conntrack::now(),
                );
            }
        }
    }
    false
}

/// Write the inner Ethernet header (dst=guest MAC, src=GW_MAC, ethertype=IPv6) in place and
/// redirect to the tap. NO resize: the kernel already decapped the outer Eth/IPv6/UDP/Geneve header
/// before this tcx program ran, so the frame at offset 0 IS already the guest's own inner Ethernet
/// header (preserved verbatim through the tunnel) — unlike the pre-4b XDP path, which had to
/// `adjust_head` off a hand-rolled outer prefix to reach it.
///
/// Takes `data`/`data_end` as SCALARS (not `&TcContext`) for the same reason [`ingress_fw_lb_v6`]
/// does: passing the context reference across this `#[inline(never)]` bpf-to-bpf boundary and then
/// re-deriving `data()`/`data_end()` inside trips the verifier's "R2 pointer arithmetic on pkt_end
/// prohibited" (confirmed empirically — see the P2 Task 4b report). `bpf_redirect` needs no ctx.
#[inline(never)]
fn decap_deliver_v6(
    data: usize,
    data_end: usize,
    guest_mac: [u8; 6],
    tap_ifindex: u32,
) -> Result<i32, DpErr> {
    if data + ETH_LEN > data_end {
        return Err(DpErr::Bounds);
    }
    let q = data as *mut u8;
    unsafe {
        write6(q, &guest_mac);
        write6(q.add(6), &GW_MAC);
        core::ptr::write_unaligned(q.add(12) as *mut u16, ETH_P_IPV6.to_be());
    }
    Ok(unsafe { bpf_redirect(tap_ifindex, 0) } as i32)
}

/// tcx ingress for an inner-IPv6 frame, tail-called from `uplink_rx` when the decapped inner
/// ethertype is IPv6. VNI comes from `get_tunnel_key` (the kernel's `collect_md` decap stamped it as
/// the skb's tunnel-key metadata — NOT from an outer address, which no longer exists by the time
/// this program runs).
///
/// // TODO(4c): this is still HAND-INLINED (no `flowplane_core::datapath` v6-ingress orchestrator
/// exists yet — that is Task 4c's job, which will also give it sim coverage). This function keeps
/// the pre-4b LB dispatch + firewall/conntrack shape, minimally adapted: `get_tunnel_key` replaces
/// the `UNDERLAY[outer_dst]` VNI source, the manual `adjust_head` outer-decap is REMOVED (kernel
/// already decapped), and the non-LB delivery target is now mechanism #1 (`ROUTES6(vni, inner_dst)
/// -> UNDERLAY`) instead of the old outer_dst-as-delivery-target VTEP scheme. Two features from the
/// pre-4b path are DROPPED here (not ported — matching what 4a's v4 core orchestrator already
/// dropped for the same reason, see `flowplane_core::datapath::process_uplink`): the ICMPv6-echo-to-
/// VIP intercept (needed the outer_dst-as-our-own-identity scheme to detect "packet addressed to the
/// LB VNF itself") and the mechanism-#4 WAN-edge-sentinel/genuine-miss-drop upgrade (a ROUTES6 miss
/// here still falls through to TC_ACT_OK, the pre-4b behavior — NOT the stricter fail-closed default
/// mechanism #1/v4 now has). Both are real, disclosed gaps for Task 4c to close.
pub fn v6_uplink_rx(ctx: &TcContext) -> Result<i32, DpErr> {
    let vni = match get_tunnel_key(ctx.skb.skb) {
        Some((vni, _remote)) => vni,
        None => return Ok(TC_ACT_OK),
    };
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + ETH_LEN + IPV6_LEN + 40 > data_end {
        return Ok(TC_ACT_OK);
    }
    // IPv6 LB: if the inner IPv6 dst is an LB VIP, Maglev-select a backend.
    // - Remote backend: re-stamp the tunnel key toward the backend + redirect to the geneve device
    //   (no decap, no byte write — mirrors the v4 LB-remote-backend reforward).
    // - Local backend: decap and deliver to the backend VM's tap (not the LB VNF tap).
    let lb_backend = crate::lb::lb_select_forward_v6(ctx, ETH_LEN + IPV6_LEN, vni);
    if let Some(bul) = lb_backend {
        match unsafe { UNDERLAY.get(&bul) } {
            Some(bu) => {
                let guest_mac = bu.guest_mac;
                let tap_ifindex = bu.tap_ifindex;
                if ingress_fw_lb_v6(ctx.data(), ctx.data_end(), bu.tap_ifindex) {
                    return Ok(TC_ACT_SHOT);
                }
                return decap_deliver_v6(ctx.data(), ctx.data_end(), guest_mac, tap_ifindex);
            }
            None => {
                if !set_tunnel_key(ctx.skb.skb, &flowplane_core::encap::reforward(vni, &bul)) {
                    return Ok(TC_ACT_SHOT);
                }
                return Ok(tunnel_redirect());
            }
        }
    }
    // Mechanism #1 (v6, hand-inlined pending 4c): ROUTES6(vni, inner_dst) -> nexthop_ipv6 ->
    // UNDERLAY(nexthop_ipv6). A miss passes through to the kernel (pre-4b behavior — see the
    // TODO(4c) above re: the not-yet-adopted mechanism #4 fail-closed default).
    let inner_dst = unsafe {
        core::ptr::read_unaligned(
            (data as *const u8).add(ETH_LEN + IPV6_LEN + 24) as *const [u8; 16]
        )
    };
    let u = match GlobalMaps
        .route6_get(vni, &inner_dst)
        .and_then(|route| GlobalMaps.underlay_get(&route.nexthop_ipv6))
    {
        Some(u) => u,
        None => return Ok(TC_ACT_OK),
    };
    if ingress_fw_ct_v6(ctx.data(), ctx.data_end(), u.tap_ifindex, vni) {
        return Ok(TC_ACT_SHOT);
    }
    decap_deliver_v6(ctx.data(), ctx.data_end(), u.guest_mac, u.tap_ifindex)
}
