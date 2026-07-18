//! Per-interface egress rate metering / EDT shaping. The token-bucket and EDT logic lives in
//! `flowplane_core::meter` (the SAME code the native SimNode + unit tests run); these wrappers only
//! supply the eBPF `GlobalMaps` seam over the `METER` map + the `bpf_ktime_get_ns()` timestamp.

use aya_ebpf::helpers::bpf_ktime_get_ns;

/// EDT egress: compute+advance the departure schedule for `ifindex` sending `wire_len` bytes.
/// Returns `Some(tstamp_ns)` when shaping is configured (caller sets `skb->tstamp`), else `None`.
/// `#[inline(never)]`: the 96-byte `MeterState` local must live in this subprogram's own 512-byte
/// BPF stack frame, not the entry program's (see Task 1's meter_pass fix).
#[inline(never)]
pub fn edt_stamp(ifindex: u32, wire_len: u64) -> Option<u64> {
    let now = unsafe { bpf_ktime_get_ns() };
    flowplane_core::meter::edt_egress(&mut crate::coreimpl::GlobalMaps, ifindex, wire_len, now)
}

/// Police the external-egress (public) lane. `true` = pass, `false` = drop. `#[inline(never)]` for
/// the same BPF-stack reason as `edt_stamp`.
#[inline(never)]
pub fn public_pass(ifindex: u32, len: u64, is_external: bool) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    flowplane_core::meter::public_pass(
        &mut crate::coreimpl::GlobalMaps,
        ifindex,
        len,
        is_external,
        now,
    )
}

/// Police the ingress lane (keyed by dest tap ifindex). `true` = pass, `false` = drop.
/// `#[inline(never)]` for the same BPF-stack reason as `edt_stamp`.
#[inline(never)]
pub fn ingress_pass(ifindex: u32, len: u64) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    flowplane_core::meter::ingress_pass(&mut crate::coreimpl::GlobalMaps, ifindex, len, now)
}
