#![no_std]
#![no_main]

mod arp_nd;
mod conntrack;
mod coreimpl;
mod csum;
mod dbg;
mod dhcp;
mod egress;
mod ingress;
mod inspect;
mod lb;
mod maps;
mod meter;
mod nat;
mod nat64;
mod parse;
mod tc;
mod tunnel;
mod v6;
mod vip;
mod xdp_encap;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

/// Trivial pass program used as a redirect-target enabler: XDP redirect *into* a veth only
/// works if the veth's peer has an XDP program attached. Attach this on those receiving ends.
#[xdp]
pub fn xdp_pass(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

// `frags`: declare multi-buffer support (BPF_F_XDP_HAS_FRAGS) so native XDP can attach at jumbo MTU
// (a single-buffer program is capped at ~1 page). Safe here because the datapath only touches
// front headers (all access is const-offset within the guaranteed linear head) and uses incremental
// delta checksums — it never reads the payload, which is what would live in the frags. See
// docs/dataplane/kernel-xdp-tc.md. wan_rx is marked the same for the same reason.
#[xdp(frags)]
pub fn uplink_rx(ctx: XdpContext) -> u32 {
    dbg::dlog!(&ctx, "uplink_rx: ingress_ifindex={}", unsafe {
        (*ctx.ctx).ingress_ifindex
    });
    match ingress::try_uplink_rx(&ctx) {
        Ok(act) => act,
        Err(_) => xdp_action::XDP_PASS,
    }
}

/// Inner-IPv6 ingress tail-call target: `uplink_rx` tail-calls this (via `UPLINK_PROGS`) for an
/// encapped frame whose inner is IPv6 (outer next-header 41). The tail-call RESETS the BPF stack,
/// giving the v6 firewall + conntrack path a fresh 512B budget — inline in `uplink_rx` its
/// CtKey6/CtEntry/FwRule6 frames overflowed the combined stack on top of uplink_rx's own 408B.
/// Loaded by the daemon but NOT attached to an interface (it is only ever reached via tail-call).
/// `#[xdp(frags)]` matches `uplink_rx` (the frags flag must be consistent across a tail call).
#[xdp(frags)]
pub fn xdp_uplink_v6(ctx: XdpContext) -> u32 {
    match v6::v6_uplink_rx(&ctx) {
        Ok(act) => act,
        Err(_) => xdp_action::XDP_PASS,
    }
}

/// WAN-edge return path: attached to the WAN uplink by `serve --role edge`. Encaps internet
/// return traffic destined to a `nat_ip` back toward the owning hypervisor over the fabric.
#[xdp(frags)]
pub fn wan_rx(ctx: XdpContext) -> u32 {
    dbg::dlog!(&ctx, "wan_rx: ingress_ifindex={}", unsafe {
        (*ctx.ctx).ingress_ifindex
    });
    match ingress::try_wan_rx(&ctx) {
        Ok(act) => act,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[xdp]
pub fn xdp_inspect(ctx: XdpContext) -> u32 {
    inspect::try_inspect(&ctx)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
