# QoS: EDT shaping & policing

!!! warning "Status: Partial"
    Policing (drop) and the EDT stamping/wiring are implemented and validated in the lab. True FQ
    pacing (loss-free shaping) can only be measured on real fabric/VMs — nested netns + veth do
    not provide real FQ, so the clab run validates policing and "tstamp is set", not the pacing.

Per-interface QoS gives each guest three independent traffic-control lanes: EDT-shaped total
egress, policed external egress, and policed ingress. The central capability is true shaping:
pacing traffic to a rate with no packet loss, using the kernel's Earliest-Departure-Time model
(EDT + the FQ qdisc), the same design Cilium's Bandwidth Manager adopted after moving off TBF
policing.

## The unified tcx guest edge

Shaping requires the guest egress path to traverse an egress qdisc, which is only possible on the
tc/skb path: an XDP `bpf_redirect`/devmap transmit uses `ndo_xdp_xmit`, which bypasses the qdisc
entirely, making shaping structurally impossible on an XDP fast path. That is why the guest edge was
unified on a single tc datapath (`tc_guest_tx`) for both container veth/netkit and VM tap — one guest
program, one attach path. The rest of the forwarding path has since followed: `uplink_rx`, `wan_rx`,
and `uplink_dsr_note` are tcx classifiers as well (see
[Datapath programs](../architecture/dataplane/programs.md)), so every program in the path works on an
skb and the departure timestamp it stamps survives to the transmit path.

The qdisc side is explicit: the loader puts an `fq` root qdisc on each physical uplink
(`ensure_fq_qdisc`, called for the primary uplink, every `--extra-uplink`, and the edge's WAN
uplink), so overlay egress leaving via that NIC is paced against the stamp.

tcx works cleanly under vhost-net: guest→host traverses `netif_receive_skb` → tcx ingress, and
host→guest traverses the tap qdisc → tcx egress.

## Shape vs police

Shaping and policing differ in both mechanism and over-rate behaviour:

| | Shape | Police |
|---|---|---|
| Mechanism | EDT: stamp a departure time, FQ delays the packet | Token bucket: drop when the bucket is empty |
| Over-rate behaviour | delay (no loss), smoothed to the rate | drop |
| Where | egress total lane | external-egress (public) lane, ingress lane |

Shaping paces without loss and is the right model for a bandwidth cap; policing drops and is used
where a hard sub-cap or an inbound cap is wanted.

## The three lanes

All lanes are keyed by interface ifindex and live in one QoS map entry per interface
(`MeterState`). No entry for an ifindex ⇒ all lanes unlimited (pass / send immediately).

| Lane | Direction | Mechanism | Where |
|---|---|---|---|
| Egress total | VM → out | EDT shaping (smoothed) | stamp in `tc_guest_tx`, pace at uplink FQ |
| Egress public | VM → external | token-bucket police | `tc_guest_tx`, on `is_external` |
| Ingress | out → VM | token-bucket police | `uplink_rx`, after resolving the dest tap |

### Egress shaping with EDT

In `tc_guest_tx`, once the forward decision resolves the source VM's egress rate, a pure-core
function computes the packet's departure time and the datapath stamps it on the skb via
`bpf_skb_set_tstamp(skb, tstamp, BPF_SKB_TSTAMP_DELIVERY_MONO)`. The stamp goes on before the encap
decision is executed — a tunnel-key stamp (`bpf_skb_set_tunnel_key`) plus a `bpf_redirect` to the
kernel geneve `collect_md` device, neither of which touches `tstamp` — so the encapped frame reaches
the uplink's FQ still carrying its departure time, and FQ holds it until then.

The scheduling math lives in `flowplane-core/src/meter.rs` as `edt_departure` — the shaping analog
of the policing `take`, sharing the same verifier-friendly discipline (saturating math, no 128-bit
ops, clock passed in as a parameter so eBPF passes `bpf_ktime_get_ns()` and the sim passes a
controlled clock):

```rust
/// The packet may leave no earlier than max(t_last, now); the schedule cursor then advances by
/// the packet's airtime (wire_len * 1e9 / rate_bps). rate_bps == 0 => unlimited.
pub fn edt_departure(rate_bps: u64, wire_len: u64, t_last: u64, now: u64) -> (u64, u64) {
    if rate_bps == 0 {
        return (now, now);
    }
    let delay = wire_len.saturating_mul(1_000_000_000) / rate_bps;
    let t_sched = if t_last > now { t_last } else { now };
    (t_sched, t_sched.saturating_add(delay))
}
```

`edt_egress` reads `METER[ifindex]`, advances the schedule cursor (`total_last_ns`) via
`edt_departure` on the egress rate, writes it back, and returns the departure timestamp — `None`
means no shaping is configured (no entry, or rate 0) and the caller sends immediately.

FQ hashes the encapped uplink traffic by the outer (per-dest-node) header, so per-flow fairness
degrades to per-dest-node buckets — but EDT pacing honours `tstamp` regardless of the flow bucket,
which is what shaping needs.

### External-egress and ingress policing

Both reuse the token bucket `take` unchanged:

- `public_pass` runs in `tc_guest_tx` on `is_external` only — an additional drop cap on external
  egress, layered on top of the EDT total shaping.
- `ingress_pass` runs in `uplink_rx` once the (already-decapped) frame's delivery target resolves to
  a local tap, keyed by that tap. Policing needs no qdisc — it is a drop decision taken inside the
  program — so it is hook-agnostic; ingress is policed only.

```rust
pub fn take(bps: u64, burst: u64, tokens: u64, last_ns: u64, now: u64, len: u64) -> (bool, u64) {
    if bps == 0 { return (true, tokens); }           // unlimited
    let elapsed = now.saturating_sub(last_ns);
    let elapsed_capped = elapsed.min(1_000_000_000);  // cap refill to 1s worth, keep within u64
    let refill = elapsed_capped / 1_000_000_000 * bps
        + (elapsed_capped % 1_000_000_000) * bps / 1_000_000_000;
    let mut t = tokens.saturating_add(refill);
    if t > burst { t = burst; }
    if t >= len { (true, t - len) } else { (false, t) }
}
```

### Same-node delivery is never shaped

Same-node VM→VM (the `Deliver::Local` fast path) redirects tap→tap directly, bypassing the uplink
FQ, so it is not egress-shaped. Cross-node egress (encap → uplink) and all external egress
are shaped.

## The `InterfaceQoS` API

QoS is expressed per interface (`api/net/v1alpha1`, `NetworkInterfaceSpec.QoS`); nil means unlimited.
The agent lowers it into the one dataplane QoS map entry via `DataplaneNode/ConfigureQoS`:

```go
type InterfaceQoS struct {
    Egress  *EgressQoS `json:"egress,omitempty"`  // EDT-shaped at the uplink fq qdisc
    Ingress *RateLimit `json:"ingress,omitempty"` // token-bucket policed
}
type EgressQoS struct {
    RateMbps   uint32 `json:"rateMbps,omitempty"`   // EDT-shaped total egress; 0 = unlimited
    BurstKB    uint32 `json:"burstKB,omitempty"`    // optional; EDT ignores it in v1
    PublicMbps uint32 `json:"publicMbps,omitempty"` // external sub-cap (policed); 0 = unlimited
}
type RateLimit struct {
    RateMbps uint32 `json:"rateMbps,omitempty"`
    BurstKB  uint32 `json:"burstKB,omitempty"`
}
```

`EgressQoS.RateMbps` → the EDT total lane, `EgressQoS.PublicMbps` → the public police lane,
`Ingress.RateMbps` → the ingress police lane.

Like the firewall, NAT, and load-balancer policy, QoS rides the compiled path rather than the
raw `NetworkInterface`: the compiler flattens `NetworkInterfaceSpec.QoS` into
`CompiledNIC.spec.qos` (a `CompiledQoS{egressMbps, publicMbps, ingressMbps}` — burst is not
programmed), the broker syncs the `CompiledNIC` to the workload's pool, and the node agent programs
QoS from the `CompiledNIC` — selecting it, like all the agent's policy, by the NIC's interface being
locally attached (matched by the unique `(VNI, overlay IP)` key), not by a declared node. So QoS
follows the workload across pools and reschedules, and the agent reads no raw `NetworkInterface` at
all. The agent's QoS reconciler diffs the desired caps against what it has applied and idempotently
clears a lane to unlimited when the spec drops it or the NIC is deleted. The uplink loader ensures an
`fq` root qdisc (`tc qdisc replace dev <if> root fq`) so the EDT stamps actually pace. On a real
multi-queue NIC an `mq` root with per-queue `fq` leaves would be preferable; that is not implemented
yet, and `root fq` is correct for the single-queue/veth case and a safe default elsewhere.

## Validating shaping

A containerlab run cannot validate precise pacing. Nested netns + veth means no real FQ pacing
(the same reason Cilium disables its Bandwidth Manager in Kind). So in clab, the egress/ingress
policing and the "tstamp is set" wiring validate; true FQ shaping validates only on real
fabric/VMs. The EDT computation is covered by `flowplane-core/src/meter.rs` unit tests plus an
in-process sim departure-spacing test over a controlled clock, but a claim that shaping paces
requires a real-hardware measurement.

Kernel floor: tcx links need ≥ 6.6; `bpf_skb_set_tstamp` delivery-mono needs a recent kernel.
QoS is L4-agnostic — there is no L7 / DSCP / priority QoS, and no ingress shaping (ingress is policed
only).
