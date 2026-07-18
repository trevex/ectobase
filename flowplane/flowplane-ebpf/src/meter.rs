//! Per-interface egress rate metering. The token-bucket logic lives in `flowplane_core::meter`
//! (the SAME code the native SimNode + unit tests run); this wrapper only supplies the eBPF
//! `GlobalMaps` seam over the `METER` map + the `bpf_ktime_get_ns()` timestamp.

use aya_ebpf::helpers::bpf_ktime_get_ns;

/// Token-bucket rate check for `ifindex` sending a `len`-byte frame. Gates `total` always, `public`
/// when `is_external`. true = pass, false = drop. No METER entry => unlimited (pass). Delegates to
/// the shared `flowplane_core::meter::meter_pass` over the eBPF `GlobalMaps` (METER map accessor),
/// stamping `now` from the kernel monotonic clock.
///
/// `#[inline(never)]`: the 96-byte `MeterState` local must NOT be inlined into the callers
/// (`guest_tx`, `tc_guest_tx`) whose combined inline budgets are already near the 512-byte BPF
/// stack limit. Outlining gives this function its own fresh 512-byte BPF stack frame.
#[inline(never)]
pub fn meter_pass(ifindex: u32, len: u64, is_external: bool) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    flowplane_core::meter::meter_pass(
        &mut crate::coreimpl::GlobalMaps,
        ifindex,
        len,
        is_external,
        now,
    )
}
