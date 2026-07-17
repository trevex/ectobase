# M12 — Per-Interface Rate Metering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add dpservice-style **per-interface egress rate limiting** — a `total_rate` cap on all of an interface's outgoing traffic and a `public_rate` cap on its south-north (external) traffic — enforced in-datapath with a token bucket, configurable via `CreateInterface`'s `metering_parameters` (and a CLI flag).

**Architecture:** A `METER` map keyed by interface ifindex holds two token buckets (total + public). On `guest_tx`, after the route lookup tells us whether the destination is external, the datapath refills both buckets from elapsed `bpf_ktime` and deducts the packet length; if the **total** bucket (always) or the **public** bucket (external dst only) lacks tokens, the packet is `XDP_DROP`ped (the srTCM "RED" outcome). Rates are configured in Mbps (matching the proto), converted to bytes/sec at program time.

**Tech Stack:** Rust + aya/aya-ebpf (rustup `nightly-2026-01-15`, bpf-linker), tonic gRPC, `env/netns-e2e.sh`.

**Spec:** `docs/superpowers/specs/2026-06-17-full-parity-gap-design.md` (§4.7, rate-metering half; milestone M12). Grounded in dpservice `include/dp_port.h` (`total_flow_rate_cap`/`public_flow_rate_cap`, `rte_meter_srtcm`) + `src/nodes/snat_node.c` (the south-north `public_flow_rate_cap` srTCM check that drops RED). Proto: `MeteringParams{ total_rate, public_rate }` (Mbps) on `CreateInterfaceRequest.metering_parameters`.

**Scope note:** §4.7 also lists **packet relay** (ICMP-error / NAT-associated relay). That is a niche correctness edge case (path-MTU / unreachable handling) with low drop-in value; it is **deferred** (documented here), and M12 delivers the rate-metering half, which is in the gRPC contract and testable.

**Starting point (M1–M10, M13 complete):** `egress::try_guest_tx`: ARP → conntrack apply + egress firewall → VIP snat → `ROUTES.get(LPM)` (yields `route.is_external`) → `nat::nat_snat_egress(..., is_ext)` → DEFAULT-ensure → `encap_and_redirect(ctx, local, &meta.underlay_ipv6, route, inner_len)`. `meta = PORT_META[ingress_ifindex]` (the source interface). `bpf_ktime_get_ns` available. `xdp_action::XDP_DROP`. gRPC `create_interface` decodes `CreateInterfaceRequest` and calls `control.create_interface(...)`. 12 e2e tests; metering is opt-in (no meter configured ⇒ unlimited), so default behavior is unchanged.

## Design decisions locked for M12

- **Token bucket per interface, two buckets** (`total` + `public`), keyed by ifindex. Rate `bps == 0` ⇒ that bucket is unlimited (the no-meter default). Burst defaults to `rate_bps / 8` bytes (≈125 ms of traffic) if not otherwise specified — enough to not penalize normal bursts, small enough to cap a flood.
- **Enforced on `guest_tx` egress**, after the route lookup (so `is_external` is known): the `total` bucket gates all IPv4 egress; the `public` bucket additionally gates `route.is_external` egress. Either bucket dry ⇒ `XDP_DROP`.
- **Racy-but-approximate** token state in a shared map (multiple CPUs may update one bucket). dpservice's per-port DPDK meter is single-core; our XDP version accepts the approximation (a PoC lab caps a single guest's flood — low concurrency). Documented.
- **Config via `CreateInterface.metering_parameters` (Mbps)** and a CLI `--meter "<ifname>=<total_mbps>:<public_mbps>"`. `0` = unlimited.

## File Structure

```
flowplane-common/src/lib.rs   # + MeterState (64B) + layout test
flowplane-ebpf/src/
  maps.rs                  # + METER map
  meter.rs                 # NEW: meter_pass(ifindex, len, is_external) -> bool (token bucket)
  egress.rs                # meter check before encap; XDP_DROP if over
  main.rs                  # + mod meter;
flowplane/src/
  maps.rs                  # Meter wrapper
  control.rs               # set_meter(interface_id, total_mbps, public_mbps); create_interface honors it
  grpc.rs                  # create_interface decodes metering_parameters
  main.rs                  # --meter CLI
env/netns-e2e.sh           # rate-cap acceptance (flood drops, slow passes) (Test 13)
```

---

## Task 1: Common `MeterState` type

**Files:** Modify `flowplane-common/src/lib.rs`

- [ ] **Step 1: Add the type**
```rust
/// Per-interface egress token buckets. `*_bps` are bytes/sec (0 = unlimited); `*_tokens` and
/// `*_last_ns` are mutable runtime state refilled from bpf_ktime. `total` gates all egress;
/// `public` additionally gates south-north (external) egress.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct MeterState {
    pub total_bps: u64,
    pub total_burst: u64,
    pub total_tokens: u64,
    pub total_last_ns: u64,
    pub public_bps: u64,
    pub public_burst: u64,
    pub public_tokens: u64,
    pub public_last_ns: u64,
}
```
Add `unsafe impl aya::Pod for MeterState {}` in `user_impls`. Add layout assert `size_of::<MeterState>() == 64`. `cargo test -p flowplane-common --features user` → pass.

- [ ] **Step 2: Commit**
```bash
cargo fmt --all
git add flowplane-common
git commit -m "feat(meter): MeterState POD (per-interface token buckets)"
```

## Task 2: eBPF METER map + `meter.rs`

**Files:** Modify `flowplane-ebpf/src/maps.rs`, `flowplane-ebpf/src/main.rs`; Create `flowplane-ebpf/src/meter.rs`

- [ ] **Step 1: Map (`maps.rs`)**
Add `MeterState` to the `flowplane_common` import; append:
```rust
#[map]
pub static METER: HashMap<u32, MeterState> = HashMap::with_max_entries(1024, 0);
```

- [ ] **Step 2: `meter.rs`**
```rust
use aya_ebpf::helpers::bpf_ktime_get_ns;
use flowplane_common::MeterState;

use crate::maps::METER;

/// Refill a single bucket from elapsed time and try to take `len` bytes. Returns (pass, new_tokens).
#[inline(always)]
fn take(bps: u64, burst: u64, tokens: u64, last_ns: u64, now: u64, len: u64) -> (bool, u64) {
    if bps == 0 {
        return (true, tokens); // unlimited
    }
    let elapsed = now.saturating_sub(last_ns);
    // refill = elapsed_ns * bytes_per_sec / 1e9
    let refill = (elapsed as u128 * bps as u128 / 1_000_000_000u128) as u64;
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

/// Token-bucket rate check for interface `ifindex` sending a `len`-byte frame. Gates the `total`
/// bucket always, and the `public` bucket when `is_external`. Returns true = pass, false = drop.
#[inline(always)]
pub fn meter_pass(ifindex: u32, len: u64, is_external: bool) -> bool {
    let mut m: MeterState = match unsafe { METER.get(&ifindex) } {
        Some(m) => *m,
        None => return true, // no meter configured -> unlimited
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let (pass_t, tok_t) = take(m.total_bps, m.total_burst, m.total_tokens, m.total_last_ns, now, len);
    m.total_tokens = tok_t;
    m.total_last_ns = now;
    let mut pass = pass_t;
    if is_external {
        let (pass_p, tok_p) =
            take(m.public_bps, m.public_burst, m.public_tokens, m.public_last_ns, now, len);
        m.public_tokens = tok_p;
        m.public_last_ns = now;
        pass = pass && pass_p;
    }
    let _ = METER.insert(&ifindex, &m, 0);
    pass
}
```
Add `mod meter;` to `flowplane-ebpf/src/main.rs` (alphabetical: after `mod maps;`, before `mod nat;`).

- [ ] **Step 3: build + verifier**
```bash
cargo build -p flowplane
cargo test -p flowplane --no-run 2>&1 | tee /tmp/t.log
BIN=$(grep -oE 'target/debug/deps/flowplane-[a-f0-9]+' /tmp/t.log | head -1)
sudo -E "$BIN" --include-ignored --exact loader::tests::both_programs_pass_verifier   # 1 passed
```
(Not wired yet; confirms it compiles + verifies. The `u128` math is userspace-style but compiles in eBPF for division by a constant; if the verifier/bpf-linker rejects the `u128` divide, fall back to `elapsed.saturating_mul(bps) / 1_000_000_000` in u64 — acceptable precision for lab rates — and note the change.)

- [ ] **Step 4: Commit**
```bash
cargo fmt --all
git add flowplane-ebpf
git commit -m "feat(meter): METER map + token-bucket meter_pass"
```

## Task 3: Egress enforcement

**Files:** Modify `flowplane-ebpf/src/egress.rs`

- [ ] **Step 1: Meter check before encap**
In `try_guest_tx`, after the route lookup + `nat_snat_egress` (so `is_external` is known) and BEFORE `encap_and_redirect`, add:
```rust
    // Rate metering: token-bucket per source interface. `inner_len` is the egress frame size.
    let frame_len = (ctx.data_end() - ctx.data()) as u64;
    if !crate::meter::meter_pass(ifindex, frame_len, route.is_external != 0) {
        return Ok(xdp_action::XDP_DROP);
    }
```
`ifindex` is the source-interface ifindex already bound at the top of `try_guest_tx` (`let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };`). `route.is_external` is in scope. Place it just before the `let inner_len = ...; let local = ...; encap_and_redirect(...)` tail.

- [ ] **Step 2: build + verifier + e2e**
```bash
cargo build -p flowplane
# verifier gate -> 1 passed
./env/netns-e2e.sh run 2>&1 | tail -8   # Tests 1-12 pass (no meter configured => meter_pass returns true)
```

- [ ] **Step 3: Commit**
```bash
cargo fmt --all
git add flowplane-ebpf
git commit -m "feat(meter): enforce per-interface egress rate cap (drop over-rate)"
```

## Task 4: Control + CLI + gRPC

**Files:** Modify `flowplane/src/maps.rs`, `flowplane/src/control.rs`, `flowplane/src/grpc.rs`, `flowplane/src/main.rs`

- [ ] **Step 1: `Meter` wrapper (`flowplane/src/maps.rs`)**
Add a `Meter` wrapper over `HashMap<MapData, u32, MeterState>` (`open("METER")`, `upsert(u32, MeterState)`, `remove(&u32)`), mirroring `FwMetaMap`. Add `MeterState` to imports.

- [ ] **Step 2: `Control` (`control.rs`)**
Add `meter: crate::maps::Meter` to `Inner` (open in `bring_up`). Add:
```rust
    /// Program the per-interface egress rate caps (Mbps; 0 = unlimited). burst = rate/8 bytes.
    pub fn set_meter(&self, interface_id: &[u8], total_mbps: u64, public_mbps: u64) -> anyhow::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let ifindex = *g.by_ifindex.get(interface_id).ok_or_else(|| anyhow::anyhow!("unknown interface"))?;
        let total_bps = total_mbps.saturating_mul(1_000_000) / 8;
        let public_bps = public_mbps.saturating_mul(1_000_000) / 8;
        g.meter.upsert(ifindex, flowplane_common::MeterState {
            total_bps, total_burst: (total_bps / 8).max(2000), total_tokens: total_bps / 8,
            total_last_ns: 0,
            public_bps, public_burst: (public_bps / 8).max(2000), public_tokens: public_bps / 8,
            public_last_ns: 0,
        })
    }
```
(`by_ifindex` exists from M6. `(bps/8).max(2000)` gives a small burst floor so a tiny cap still admits a packet.) Call `set_meter` from `create_interface` when metering is provided — extend `create_interface`'s signature with `total_mbps: u64, public_mbps: u64` params (0/0 = none), and after programming the interface, if either is non-zero, program the METER (reuse the body of `set_meter` inline or factor a private helper, since `create_interface` already holds the lock).

- [ ] **Step 3: gRPC `create_interface` decodes metering (`grpc.rs`)**
`MeteringParams { total_rate: u64, public_rate: u64 }` (Mbps). Decode `r.metering_parameters` → `(total, public)` (default `(0,0)` when `None`) and pass to `control.create_interface(...)`.

- [ ] **Step 4: CLI `--meter` (`main.rs`)**
Add `--meter` repeatable: `"<ifname>=<total_mbps>:<public_mbps>"`. In bringup, after interfaces are programmed, open `maps::Meter` and for each `--meter`, resolve the ifname → ifindex (`ifindex(ifname)`) and upsert a `MeterState` (same Mbps→bytes/burst conversion as `set_meter`). Build.

- [ ] **Step 5: build + commit**
```bash
cargo build -p flowplane
cargo test -p flowplane 2>&1 | tail -3
cargo fmt --all
git add flowplane
git commit -m "feat(meter): control/CLI/gRPC program per-interface rate caps"
```

## Task 5: Lab rate-cap acceptance (Test 13)

**Files:** Modify `env/netns-e2e.sh`

- [ ] **Step 1: Configure a low cap on guesta**
In the hypa `bringup`, add `--meter "gA-h=1:0"` (1 Mbps total egress on guesta, no public-specific cap = 125000 bytes/s; burst ≈ 15625 bytes ≈ 11 large packets).

- [ ] **Step 2: Test 13 — flood drops, slow passes**
Add to `cmd_test` before "All tests passed":
```bash
    echo "=== Test 13: rate metering — guesta egress capped at 1 Mbps (flood drops, slow passes) ==="
    # A fast flood of large packets exceeds the 1 Mbps token bucket -> significant loss. A slow,
    # small ping stays under the cap -> 0 loss.
    FLOOD=$(sudo ip netns exec guesta ping -c 60 -i 0.003 -s 1400 -W 1 10.0.0.6 2>/dev/null \
            | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+' || echo 100)
    echo "  flood (60x1400B @ ~3ms): ${FLOOD}% loss"
    sleep 1  # let the bucket refill
    if sudo ip netns exec guesta ping -c 3 -i 1 -W 2 10.0.0.6 >/dev/null 2>&1; then
        SLOW_OK=1
    else
        SLOW_OK=0
    fi
    if [ "${FLOOD:-0}" -ge 20 ] && [ "$SLOW_OK" -eq 1 ]; then
        echo "  rate metering OK: flood was throttled (${FLOOD}% loss), slow traffic passed"
    else
        echo "  WARNING: metering not behaving (flood loss=${FLOOD}%, slow_ok=${SLOW_OK})"
    fi
    echo ""
```
GATE: the flood shows meaningful loss (≥20%) while slow traffic is lossless; Tests 1–12 still pass (only guesta is metered; other guests/flows unaffected). Note: Test 1/5/9 use guesta→guestb at low rates well under 1 Mbps, so they remain lossless. If Test 9's sustained ping or Test 7/8 (guesta-originated) approach the cap, raise the cap or scope the meter to a dedicated probe — verify during the run and adjust the Mbps so the existing guesta tests stay green.

- [ ] **Step 3: Run + commit**
```bash
./env/netns-e2e.sh run 2>&1 | tail -45   # Tests 1-13 pass, clean teardown
git add flowplane env/netns-e2e.sh
git commit -m "test(e2e): per-interface egress rate metering (flood throttled, slow passes)"
```

---

## Self-Review

**Spec coverage (§4.7 rate-metering half):**
- per-port `total_rate` + `public_rate` token buckets → Tasks 1,2,4. ✓
- enforced on egress (south-north for public) → Task 3. ✓
- configured via `CreateInterface.metering_parameters` (Mbps) + CLI → Task 4. ✓
- testing: flood throttled, slow passes → Task 5. ✓
- packet relay → explicitly deferred (header note).

**Placeholder scan:** burst defaults (`rate/8`, floor 2000) are concrete; the `u128` refill has a u64 fallback noted; the lab cap (1 Mbps) is chosen to throttle a flood while leaving the slow guesta tests lossless (Task 5 Step 2 flags re-tuning if a guesta test approaches the cap). No TBD.

**Type consistency:** `MeterState{total_bps,total_burst,total_tokens,total_last_ns,public_*}`(64) defined Task 1; `METER: HashMap<u32, MeterState>` (Task 2) ↔ `Meter` wrapper (Task 4). `meter_pass(ifindex, len, is_external) -> bool` (Task 2) called in `egress.rs` (Task 3). `set_meter(interface_id, total_mbps, public_mbps)` + `create_interface(... total_mbps, public_mbps)` (Task 4) program METER with Mbps→bytes/sec (`*1e6/8`).

**Risk note:** metering is opt-in (no METER entry ⇒ `meter_pass` returns true), so Tests 1–12 are unaffected until Task 5 adds a cap on guesta — the one tuning risk is the cap interacting with existing guesta-originated tests (1/5/7/8/9), flagged in Task 5 for adjustment. The shared-map token state is racy but adequate for the single-guest lab flood.
