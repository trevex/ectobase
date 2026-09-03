use aya_ebpf::programs::TcContext;

/// If the inner IPv6 dst (last 4 bytes) matches an LB service, Maglev-select a backend and return
/// its underlay /128. Used for IPv6-in-IPv6 uplink relay (`v6.rs`, still hand-inlined pending the
/// Task 4c v6 core orchestrator). `ip_off` points to the inner IPv6 header.
#[inline(always)]
pub fn lb_select_forward_v6(ctx: &TcContext, ip_off: usize, vni: u32) -> Option<[u8; 16]> {
    flowplane_core::lb::lb_select_forward_v6(
        &crate::coreimpl::TcPkt { ctx },
        &crate::coreimpl::GlobalMaps,
        ip_off,
        vni,
    )
}
