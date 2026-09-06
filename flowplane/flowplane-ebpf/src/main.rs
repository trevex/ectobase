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
mod maps;
mod meter;
mod nat;
mod nat64;
mod parse;
mod tc;
mod tunnel;
mod v6;
mod vip;

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};

/// B7c: tcx ingress "pre-program" on the geneve `collect_md` device, attached BEFORE `uplink_rx` on
/// the SAME hook (see `flowplane::control::Control::bring_up`'s `LinkOrder::first()` attach). Its only
/// job is the DSR reverse-VIP map note — split out of `uplink_rx` into its OWN fresh 512B BPF stack,
/// since neither inlining nor out-of-lining it on `uplink_rx`'s own call graph verifies (see
/// `ingress::try_uplink_dsr_note`'s doc comment for the full story). ALWAYS returns `TC_ACT_UNSPEC`
/// (== `TCX_NEXT` under the kernel's tcx multi-prog dispatcher) so `uplink_rx` always runs next.
#[classifier]
pub fn uplink_dsr_note(ctx: TcContext) -> i32 {
    ingress::try_uplink_dsr_note(&ctx)
}

/// tcx ingress on the geneve `collect_md` device (Task 3's device — see `flowplane_device::geneve`).
/// The kernel decaps the outer Eth/IPv6/UDP/Geneve header before this runs; VNI comes from
/// `get_tunnel_key`, not an outer address (see `ingress.rs`'s module doc for the full design).
#[classifier]
pub fn uplink_rx(ctx: TcContext) -> i32 {
    dbg::dlog!(&ctx, "uplink_rx: ingress_ifindex={}", unsafe {
        (*ctx.skb.skb).ingress_ifindex
    });
    match ingress::try_uplink_rx(&ctx) {
        Ok(act) => act,
        Err(_) => TC_ACT_OK,
    }
}

/// Inner-IPv6 ingress tail-call target: `uplink_rx` tail-calls this (via `UPLINK_PROGS`) for a
/// decapped frame whose inner ethertype is IPv6. The tail-call RESETS the BPF stack, giving the v6
/// firewall + conntrack path a fresh 512B budget — inline in `uplink_rx` its CtKey6/CtEntry/FwRule6
/// frames overflowed the combined stack on top of uplink_rx's own frame. Loaded by the daemon but
/// NOT attached to an interface (it is only ever reached via tail-call). Still named `xdp_uplink_v6`
/// (unchanged, to minimize the loader/control-plane diff) even though it is now a tc program.
#[classifier]
pub fn xdp_uplink_v6(ctx: TcContext) -> i32 {
    match v6::v6_uplink_rx(&ctx) {
        Ok(act) => act,
        Err(_) => TC_ACT_OK,
    }
}

/// WAN-edge return path: attached to the WAN uplink by `serve --role edge`. Encaps internet
/// return traffic destined to a `nat_ip` back toward the owning hypervisor over the fabric.
#[classifier]
pub fn wan_rx(ctx: TcContext) -> i32 {
    dbg::dlog!(&ctx, "wan_rx: ingress_ifindex={}", unsafe {
        (*ctx.skb.skb).ingress_ifindex
    });
    match ingress::try_wan_rx(&ctx) {
        Ok(act) => act,
        Err(_) => TC_ACT_OK,
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
