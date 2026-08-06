use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_redirect, bpf_xdp_adjust_head},
    programs::XdpContext,
};
use flowplane_common::{Local, RouteValue};
use flowplane_core::encap::{write_outer_v6, EncapParams, IPV6_LEN};
use flowplane_core::err::DpErr;

use crate::coreimpl::CtxPkt;

/// Resolve the real egress ifindex + L2 nexthop (dst MAC) + our src MAC for an outer packet destined
/// to `dst6`, via the kernel FIB + neighbour table (`bpf_fib_lookup`). Returns `(dmac, smac, ifindex)`
/// on success, `None` on any FIB miss / unresolved neighbour so the caller keeps its configured
/// fallback (`Local.gateway_mac` / `uplink_mac` / `uplink_ifindex`).
///
/// Why: the startup-resolved single gateway MAC is wrong on a multi-router uplink — on a dual-homed
/// fabric node the node's OWN link-local can appear as a stale "router" neighbour, so a fixed
/// `grep -m1 router` MAC can point the encap frame at the node itself (the switch then drops it as
/// PACKET_OTHERHOST). A per-packet FIB lookup returns the correct nexthop MAC from the kernel neigh
/// table AND lets egress follow whichever ToR the FIB selects (per-flow ECMP across both uplinks).
///
/// `ctx` is the raw program context (`*mut __sk_buff` for tc, `*mut xdp_md` for XDP). The ~64-byte
/// `bpf_fib_lookup` params ride in the `FIB_SCRATCH` per-CPU array (NOT the stack) — the `tc_guest_tx`
/// v4 chain is already near the 512-byte BPF combined-stack limit — and callers hold `PortMeta` by
/// reference. `#[inline(never)]` keeps this glue out of the caller's frame.
#[inline(never)]
pub fn fib_nexthop(
    ctx: *mut core::ffi::c_void,
    dst6: &[u8; 16],
) -> Option<([u8; 6], [u8; 6], u32)> {
    const AF_INET6: u8 = 10;
    const BPF_FIB_LOOKUP_DIRECT: u32 = 1;
    const BPF_FIB_LOOKUP_OUTPUT: u32 = 2;
    const BPF_FIB_LKUP_RET_SUCCESS: i64 = 0;
    let p = crate::maps::FIB_SCRATCH.get_ptr_mut(0)?;
    unsafe {
        core::ptr::write_bytes(
            p as *mut u8,
            0,
            core::mem::size_of::<aya_ebpf::bindings::bpf_fib_lookup>(),
        );
        (*p).family = AF_INET6;
        // ipv6_dst (anon union #4) = the outer destination, in network byte order (its raw bytes).
        core::ptr::copy_nonoverlapping(
            dst6.as_ptr(),
            core::ptr::addr_of_mut!((*p).__bindgen_anon_4) as *mut u8,
            16,
        );
        let ret = aya_ebpf::helpers::gen::bpf_fib_lookup(
            ctx,
            p,
            core::mem::size_of::<aya_ebpf::bindings::bpf_fib_lookup>() as i32,
            BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT,
        );
        if ret == BPF_FIB_LKUP_RET_SUCCESS {
            Some(((*p).dmac, (*p).smac, (*p).ifindex))
        } else {
            None
        }
    }
}

/// Override an `EncapParams`' L2 nexthop + egress ifindex with a per-packet FIB result, falling back
/// to the configured `Local` values on a FIB miss. Central so the tc and XDP encap paths share it.
#[inline(always)]
pub fn fib_override(ctx: *mut core::ffi::c_void, e: &mut EncapParams) {
    if let Some((dmac, smac, ifindex)) = fib_nexthop(ctx, &e.nexthop_ipv6) {
        e.gateway_mac = dmac;
        e.uplink_mac = smac;
        e.uplink_ifindex = ifindex;
    }
}

/// Grow headroom and write the outer Eth+IPv6 for an encap toward `route.nexthop_ipv6`. Returns
/// `true` on success.
/// `inner_proto` = IPv6 next-header byte (IPPROTO_IPIP for an IPv4 inner, IPPROTO_IPV6 for IPv6).
#[inline(always)]
fn write_encap_outer(
    ctx: &XdpContext,
    local: &Local,
    src_underlay: &[u8; 16],
    route: &RouteValue,
    inner_proto: u8,
) -> bool {
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(IPV6_LEN as i32)) } != 0 {
        return false;
    }
    let e = EncapParams {
        gateway_mac: local.gateway_mac,
        uplink_mac: local.uplink_mac,
        uplink_ifindex: local.uplink_ifindex,
        src_underlay: *src_underlay,
        nexthop_ipv6: route.nexthop_ipv6,
        inner_proto,
        // N-S return re-encap (edge wan_rx). Flow-label ECMP for this path is a follow-up; the
        // inner 5-tuple is available in the wan_rx handler and would be threaded here.
        flow_label: 0,
    };
    write_outer_v6(&mut CtxPkt { ctx }, &e)
}

/// Like [`encap_and_redirect`] but redirects via the `UPLINK_DEV` devmap (slot 0 == uplink ifindex)
/// instead of a plain `bpf_redirect`. On containerlab veth uplinks a plain XDP_REDIRECT is silently
/// dropped unless the peer port has an XDP program (veth `ndo_xdp_xmit` peer requirement); the devmap
/// path avoids that. Used ONLY by the edge `wan_rx` branches (which have no tail calls). Production
/// real NICs are unaffected either way.
#[inline(always)]
pub fn encap_and_redirect_via_devmap(
    ctx: &XdpContext,
    local: &Local,
    src_underlay: &[u8; 16],
    route: &RouteValue,
    inner_proto: u8,
) -> Result<u32, DpErr> {
    if write_encap_outer(ctx, local, src_underlay, route, inner_proto) {
        Ok(crate::maps::UPLINK_DEV
            .redirect(0, 0)
            .unwrap_or(xdp_action::XDP_ABORTED))
    } else {
        Err(DpErr::Bounds)
    }
}

/// Re-forward an already-encapped packet to a new backend underlay (LB remote backend): rewrite
/// the outer Ethernet (dst=gateway_mac, src=uplink_mac) + outer IPv6 (src=lb_underlay,
/// dst=backend) and redirect out the uplink WITHOUT decap. Returns the XDP action.
#[inline(always)]
pub fn reforward(
    ctx: &XdpContext,
    local: &Local,
    lb_underlay: &[u8; 16],
    backend: &[u8; 16],
) -> u32 {
    match flowplane_core::encap::reforward(
        &mut crate::coreimpl::CtxPkt { ctx },
        local,
        lb_underlay,
        backend,
    ) {
        flowplane_core::pkt::Action::Redirect(ifindex) => {
            (unsafe { bpf_redirect(ifindex, 0) }) as u32
        }
        _ => xdp_action::XDP_DROP,
    }
}
