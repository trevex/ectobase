//! Per-interface egress rate metering (token bucket), ported over the `Maps` trait so the SAME
//! token-bucket logic runs in eBPF and natively. Faithful port of the eBPF `meter::{take, meter_pass}`.
//!
//! Metering does NOT mutate packet bytes — `meter_pass` reads/refills/writes the `METER` map entry
//! for an interface and returns a pass/drop verdict. There are two buckets per interface: `total`
//! (gates ALL egress) and `public` (gates south-north / external egress, checked only when
//! `is_external`). No METER entry for the interface => unlimited (pass).
//!
//! Time impurity: the eBPF `meter_pass` stamps `last_ns` from `bpf_ktime_get_ns()`. As with
//! conntrack, `now: u64` is a parameter — the eBPF wrapper passes `now()`, the sim passes a
//! controlled clock. `take()` itself is pure.

use crate::maps::Maps;
use flowplane_common::MeterState;

/// Token-bucket step for one bucket: refill from `bps` over `now - last_ns`, clamp to `burst`, then
/// try to spend `len` tokens. Returns `(pass, new_tokens)`. `bps == 0` => unlimited (pass, tokens
/// unchanged). Pure — verbatim port of the eBPF `meter::take` (same saturating math, same 1 s
/// elapsed cap to keep the refill within u64, same burst clamp, same `tokens >= len` boundary).
#[inline(always)]
pub fn take(bps: u64, burst: u64, tokens: u64, last_ns: u64, now: u64, len: u64) -> (bool, u64) {
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
/// when `is_external`. `true` = pass, `false` = drop. No METER entry => unlimited (pass).
///
/// Faithful port of the eBPF `meter::meter_pass`: reads `METER[ifindex]`, refills+spends the total
/// bucket (and the public bucket when external) via [`take`], stamps `*_last_ns = now`, and writes
/// the updated state back. `now` is the current monotonic time (ns); the eBPF wrapper passes
/// `now()`, the sim passes a controlled clock.
#[inline(always)]
pub fn meter_pass<M: Maps>(
    maps: &mut M,
    ifindex: u32,
    len: u64,
    is_external: bool,
    now: u64,
) -> bool {
    let mut m: MeterState = match maps.meter_get(ifindex) {
        Some(m) => m,
        None => return true,
    };
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
    maps.meter_update(ifindex, m);
    pass
}

#[cfg(test)]
mod tests {
    use super::take;

    const SEC: u64 = 1_000_000_000;

    #[test]
    fn bps_zero_is_unlimited_pass_tokens_unchanged() {
        // bps == 0 => always pass, tokens returned verbatim (no refill, no spend).
        assert_eq!(take(0, 100, 0, 0, 12345, 9000), (true, 0));
        assert_eq!(take(0, 100, 42, 500, 12345, 9000), (true, 42));
    }

    #[test]
    fn token_depletion_then_drop() {
        // burst=1500, start full, no time elapsed (now==last_ns => no refill). Spend 1000 twice:
        // 1500 -> pass, 500 left -> next 1000 exceeds 500 -> drop, tokens unchanged.
        let (p1, t1) = take(1_000_000, 1500, 1500, 0, 0, 1000);
        assert_eq!((p1, t1), (true, 500));
        let (p2, t2) = take(1_000_000, 1500, t1, 0, 0, 1000);
        assert_eq!((p2, t2), (false, 500));
    }

    #[test]
    fn refill_after_elapsed() {
        // bps=1000 B/s, burst=2000. Start at 0 tokens, last_ns=0. After 1 s, refill=1000.
        // Spend 800 => pass, 200 left.
        let (p, t) = take(1000, 2000, 0, 0, SEC, 800);
        assert_eq!((p, t), (true, 200));
    }

    #[test]
    fn refill_fractional_second() {
        // bps=1000 B/s. Half a second elapsed => refill = 500.
        let (p, t) = take(1000, 2000, 0, 0, SEC / 2, 400);
        assert_eq!((p, t), (true, 100));
    }

    #[test]
    fn elapsed_capped_at_one_second() {
        // 10 s elapsed but the refill is capped at 1 s worth (bps=1000 => +1000, not +10000).
        // Start at 0, burst huge so the clamp isn't what limits us. refill=1000 => spend 900 pass.
        let (p, t) = take(1000, 1_000_000, 0, 0, 10 * SEC, 900);
        assert_eq!((p, t), (true, 100));
        // And 900+900 in the same 1s-worth would be 1800 > 1000 refill => second spend of 1000 drops.
        let (p2, t2) = take(1000, 1_000_000, 0, 0, 10 * SEC, 1000);
        assert_eq!((p2, t2), (true, 0));
        let (p3, _t3) = take(1000, 1_000_000, 0, 0, 10 * SEC, 1001);
        assert_eq!(p3, false);
    }

    #[test]
    fn burst_clamp() {
        // bps=1_000_000, burst=1500. After 10 s the raw refill would be huge, but the bucket is
        // clamped to burst=1500. Spend 1500 => pass, 0 left; a further 1 would drop.
        let (p, t) = take(1_000_000, 1500, 0, 0, 10 * SEC, 1500);
        assert_eq!((p, t), (true, 0));
        let (p2, t2) = take(1_000_000, 1500, 100, 0, 10 * SEC, 1500);
        // 100 + huge refill clamped to 1500; spend 1500 => 0 left.
        assert_eq!((p2, t2), (true, 0));
    }

    #[test]
    fn exact_boundary_tokens_equal_len() {
        // tokens == len (no refill) => pass with exactly 0 left (>= boundary is inclusive).
        let (p, t) = take(1_000_000, 5000, 1000, 0, 0, 1000);
        assert_eq!((p, t), (true, 0));
    }
}
