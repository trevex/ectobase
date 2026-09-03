//! Per-interface egress rate metering / EDT shaping. The token-bucket + EDT MATH lives in
//! `flowplane_core::meter::{take, edt_departure}` (the SAME pure fns the native SimNode + unit tests
//! run — the real seam). These eBPF wrappers supply the map glue AROUND that math.
//!
//! Map glue is POINTER-BASED (`METER.get_ptr_mut` + in-place field updates), NOT a by-value
//! `MeterState` copy. This is REQUIRED, not an optimization: `MeterState` is 96 bytes, and the entry
//! programs that call these wrappers (`uplink_rx`, `tc_guest_tx`) already use ~450 bytes of BPF
//! stack. A by-value copy — inlined into the caller OR held in a `#[inline(never)]` callee frame —
//! pushes the combined bpf-to-bpf call chain over the 512-byte verifier limit ("combined stack size
//! of 2 calls is 560. Too large"). Reading only the lane scalars through the map pointer keeps each
//! callee frame to a few u64s. (The map-driven `flowplane_core::meter::{edt_egress,public_pass,
//! ingress_pass}` wrappers copy `MeterState` by value — fine in the sim's userspace, fatal in eBPF —
//! so the sim uses those while eBPF calls the scalar `take`/`edt_departure` seam here.)

use aya_ebpf::helpers::bpf_ktime_get_ns;
use flowplane_core::meter::{edt_departure, take};

use crate::maps::METER;

/// EDT egress: advance the departure schedule for `ifindex` sending `wire_len` bytes, in place on the
/// `total` lane. Returns `Some(tstamp_ns)` when shaping is configured (`total_bps != 0`), else `None`
/// (caller sends immediately). `#[inline(never)]` keeps this tiny frame off the entry program's.
#[inline(never)]
pub fn edt_stamp(ifindex: u32, wire_len: u64) -> Option<u64> {
    let ptr = METER.get_ptr_mut(&ifindex)?;
    unsafe {
        if (*ptr).total_bps == 0 {
            return None;
        }
        let now = bpf_ktime_get_ns();
        let (tstamp, t_last) = edt_departure((*ptr).total_bps, wire_len, (*ptr).total_last_ns, now);
        (*ptr).total_last_ns = t_last;
        Some(tstamp)
    }
}

/// Police the external-egress (public) lane in place. `true` = pass, `false` = drop. Only gates when
/// `is_external`; no entry or `public_bps == 0` => pass.
#[inline(never)]
pub fn public_pass(ifindex: u32, len: u64, is_external: bool) -> bool {
    if !is_external {
        return true;
    }
    let ptr = match METER.get_ptr_mut(&ifindex) {
        Some(p) => p,
        None => return true,
    };
    unsafe {
        if (*ptr).public_bps == 0 {
            return true;
        }
        let now = bpf_ktime_get_ns();
        let (pass, tok) = take(
            (*ptr).public_bps,
            (*ptr).public_burst,
            (*ptr).public_tokens,
            (*ptr).public_last_ns,
            now,
            len,
        );
        (*ptr).public_tokens = tok;
        (*ptr).public_last_ns = now;
        pass
    }
}

// The pointer-based ingress-lane policer that used to live here (mirroring `edt_stamp`/
// `public_pass` above) was dropped in P2 Task 4b: `uplink_rx` now delegates ingress-lane metering
// to `flowplane_core::meter::ingress_pass` (the by-value `MeterState` wrapper) via
// `flowplane_core::datapath::process_uplink`, instead of hand-inlining the map access here. See
// this module's header comment for why the by-value wrapper is normally avoided in eBPF (stack
// pressure) — this is a known, disclosed risk for the verifier checkpoint, not an oversight.
