//! Per-interface rate metering — token-bucket policing and EDT shaping — ported over the `Maps`
//! trait so the SAME logic runs in eBPF and natively.
//!
//! `MeterState` has three lanes per interface:
//! - **`total`** — EDT shaping of ALL egress ([`edt_egress`]); the old token-bucket `meter_pass`
//!   was removed once eBPF and sim both migrated to EDT.
//! - **`public`** — token-bucket POLICING of south-north / external egress ([`public_pass`],
//!   checked only when `is_external`).
//! - **`ingress`** — token-bucket POLICING of traffic delivered to the guest tap ([`ingress_pass`]).
//!
//! No METER entry for the interface => unlimited (pass / send immediately).
//!
//! Time impurity: `now: u64` is always a parameter — the eBPF wrappers pass `bpf_ktime_get_ns()`,
//! the sim passes a controlled clock. `take()` and `edt_departure()` are fully pure.

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

/// Earliest-departure-time step for one packet on a shaped lane. Returns
/// `(tstamp_ns, new_t_last)`. The packet may leave no earlier than `max(t_last, now)`; the schedule
/// cursor then advances by the packet's airtime (`wire_len * 1e9 / rate_bps`). `rate_bps == 0` =>
/// unlimited: send at `now`, cursor = `now`. Pure — no 128-bit ops (wire_len is bounded by the MTU,
/// so `wire_len * 1e9` stays within u64). This is the shaping analog of `take` (which polices).
#[inline(always)]
pub fn edt_departure(rate_bps: u64, wire_len: u64, t_last: u64, now: u64) -> (u64, u64) {
    if rate_bps == 0 {
        return (now, now);
    }
    let delay = wire_len.saturating_mul(1_000_000_000) / rate_bps;
    let t_sched = if t_last > now { t_last } else { now };
    (t_sched, t_sched.saturating_add(delay))
}

/// Map-driven EDT egress step for `ifindex` sending `wire_len` bytes. Reads `METER[ifindex]`,
/// advances the schedule cursor (`total_last_ns`) via [`edt_departure`] on the egress rate
/// (`total_bps`), writes it back, and returns the packet's departure timestamp (ns). `None` = no
/// egress shaping configured (no entry, or `total_bps == 0`) — caller sends immediately. The eBPF
/// wrapper passes `bpf_ktime_get_ns()`; the sim passes a controlled clock.
#[inline(always)]
pub fn edt_egress<M: Maps>(maps: &mut M, ifindex: u32, wire_len: u64, now: u64) -> Option<u64> {
    let mut m: MeterState = maps.meter_get(ifindex)?;
    if m.total_bps == 0 {
        return None;
    }
    let (tstamp, t_last) = edt_departure(m.total_bps, wire_len, m.total_last_ns, now);
    m.total_last_ns = t_last;
    maps.meter_update(ifindex, m);
    Some(tstamp)
}

/// Token-bucket POLICE of the external-egress (public) lane. Only gates when `is_external`. `true` =
/// pass, `false` = drop. No entry, or `public_bps == 0` => pass. Faithful reuse of [`take`].
#[inline(always)]
pub fn public_pass<M: Maps>(
    maps: &mut M,
    ifindex: u32,
    len: u64,
    is_external: bool,
    now: u64,
) -> bool {
    if !is_external {
        return true;
    }
    let mut m: MeterState = match maps.meter_get(ifindex) {
        Some(m) => m,
        None => return true,
    };
    if m.public_bps == 0 {
        return true;
    }
    let (pass, tok) = take(
        m.public_bps,
        m.public_burst,
        m.public_tokens,
        m.public_last_ns,
        now,
        len,
    );
    m.public_tokens = tok;
    m.public_last_ns = now;
    maps.meter_update(ifindex, m);
    pass
}

/// Token-bucket POLICE of the ingress lane (traffic delivered to the guest), keyed by the
/// destination tap `ifindex`. `true` = pass, `false` = drop. No entry, or `ingress_bps == 0` =>
/// pass. Faithful reuse of [`take`].
#[inline(always)]
pub fn ingress_pass<M: Maps>(maps: &mut M, ifindex: u32, len: u64, now: u64) -> bool {
    let mut m: MeterState = match maps.meter_get(ifindex) {
        Some(m) => m,
        None => return true,
    };
    if m.ingress_bps == 0 {
        return true;
    }
    let (pass, tok) = take(
        m.ingress_bps,
        m.ingress_burst,
        m.ingress_tokens,
        m.ingress_last_ns,
        now,
        len,
    );
    m.ingress_tokens = tok;
    m.ingress_last_ns = now;
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

    #[test]
    fn edt_unlimited_sends_now() {
        // rate 0 => send immediately, cursor tracks now.
        assert_eq!(super::edt_departure(0, 1500, 0, 12345), (12345, 12345));
    }

    #[test]
    fn edt_idle_departs_now_and_reserves_airtime() {
        // 1_000_000 B/s, 1500B => delay = 1500 * 1e9 / 1e6 = 1_500_000 ns.
        // Idle (t_last=0 < now): departs at now, cursor advances to now + delay.
        let (ts, t_last) = super::edt_departure(1_000_000, 1500, 0, 10_000_000);
        assert_eq!(ts, 10_000_000);
        assert_eq!(t_last, 11_500_000);
    }

    #[test]
    fn edt_backlogged_queues_after_cursor() {
        // Cursor ahead of now (backlog): packet departs at the cursor, not now.
        let (ts, t_last) = super::edt_departure(1_000_000, 1500, 20_000_000, 10_000_000);
        assert_eq!(ts, 20_000_000);
        assert_eq!(t_last, 21_500_000);
    }
}
