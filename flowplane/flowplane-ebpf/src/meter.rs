use aya_ebpf::helpers::bpf_ktime_get_ns;
use flowplane_common::MeterState;

use crate::maps::METER;

#[inline(always)]
fn take(bps: u64, burst: u64, tokens: u64, last_ns: u64, now: u64, len: u64) -> (bool, u64) {
    if bps == 0 {
        return (true, tokens);
    }
    let elapsed = now.saturating_sub(last_ns);
    // Avoid 128-bit ops (bpf-linker rejects __multi3/__udivti3).
    // Cap elapsed at 1 second to keep refill within u64 range (bps bytes/s max).
    let elapsed_capped = if elapsed > 1_000_000_000 {
        1_000_000_000u64
    } else {
        elapsed
    };
    let refill = elapsed_capped / 1_000_000_000 * bps
        + (elapsed_capped % 1_000_000_000) * bps / 1_000_000_000;
    let mut t = tokens.saturating_add(refill);
    if t > burst {
        t = burst;
    }
    if t >= len {
        (true, t - len)
    } else {
        (false, t)
    }
}

/// Token-bucket rate check for `ifindex` sending a `len`-byte frame. Gates `total` always, `public`
/// when `is_external`. true = pass, false = drop. No METER entry => unlimited (pass).
#[inline(always)]
pub fn meter_pass(ifindex: u32, len: u64, is_external: bool) -> bool {
    let mut m: MeterState = match unsafe { METER.get(&ifindex) } {
        Some(m) => *m,
        None => return true,
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let (pass_t, tok_t) = take(
        m.total_bps,
        m.total_burst,
        m.total_tokens,
        m.total_last_ns,
        now,
        len,
    );
    m.total_tokens = tok_t;
    m.total_last_ns = now;
    let mut pass = pass_t;
    if is_external {
        let (pass_p, tok_p) = take(
            m.public_bps,
            m.public_burst,
            m.public_tokens,
            m.public_last_ns,
            now,
            len,
        );
        m.public_tokens = tok_p;
        m.public_last_ns = now;
        pass = pass && pass_p;
    }
    let _ = METER.insert(&ifindex, &m, 0);
    pass
}
