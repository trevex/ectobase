# DPDK functional QoS / meter — design

Date: 2026-07-24
Status: designed, approved (rate policy decided)

## Problem

On the DPDK dataplane, `ConfigureQoS` is accepted by the gRPC `DataplaneNode`
service but **not enforced**. The rate cap never reaches the datapath, so all
three meter lanes run unlimited.

Root cause: the meter (`flowplane_common::MeterState`) lives entirely in the
per-lcore FLOW half (`nfkit::PerLcoreFlowMaps`), and `nfkit::SharedConfigMaps`
has **no meter table** (Task 4 deliberately excluded it — the token
buckets/EDT cursors are mutated per-packet and belong per-lcore). So
`DpdkMapWriter::meter_upsert` has no config-map target: it only bumps the config
generation. The per-lcore meters are therefore never seeded with a rate, and
`take`/`edt_departure` see `*_bps == 0` → every lane passes/paces unlimited.

`MeterState` has three lanes, each split into config and per-packet state:

| lane      | config (rate)            | per-packet state           | core fn         |
|-----------|--------------------------|----------------------------|-----------------|
| `total`   | `total_bps`, `total_burst`     | `total_tokens`, `total_last_ns`     | `edt_egress` (EDT shape) |
| `public`  | `public_bps`, `public_burst`   | `public_tokens`, `public_last_ns`   | `public_pass` (police external egress) |
| `ingress` | `ingress_bps`, `ingress_burst` | `ingress_tokens`, `ingress_last_ns` | `ingress_pass` (police delivery) |

The meter only **drops or stamps EDT timestamps** — it never rewrites packet
bytes. It is therefore outside the DPDK==sim==eBPF byte-parity contract, so the
DPDK aggregate-rate semantics are a free design choice (eBPF/sim keep their
single shared `MeterState` map, unchanged).

## Decision: full rate per lcore

With RSS spreading an interface's flows across N worker lcores, each lcore
enforces the **full** configured rate independently (no `bps/N` division, no
shared bucket).

- **Pro:** simplest; matches the shared-nothing per-lcore datapath (M8); zero
  cross-core coordination on the per-packet hot path; a single flow (RSS-pinned
  to one lcore) gets exactly its configured cap.
- **Accepted limitation:** an interface whose flows span N lcores can pass up to
  ~N× the configured rate in aggregate. Documented in the `meter_upsert` doc +
  here; precise aggregate shaping (`bps/N`, or a shared atomic bucket) is a
  future refinement, explicitly out of scope.

Rejected alternatives: **divided rate (`bps/N`)** — bounds aggregate but caps a
lone flow at `cap/N` and needs lcore-count awareness at config time; **shared
atomic bucket** — accurate but adds a per-packet cross-lcore atomic on a hot
cacheline, cutting against the shared-nothing design.

## Architecture

The design **splits `MeterState` at the storage layer** — config in shared
memory, token state per-lcore — and composes them on read. The core meter
functions (`take`, `edt_departure`, `edt_egress`, `public_pass`, `ingress_pass`)
and the `MeterState` struct are **untouched**. Only the DPDK `Maps` plumbing
changes.

### 1. `MeterConfig` (flowplane-common)

New POD struct holding the six config `u64`s (the rate half of `MeterState`):

```rust
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct MeterConfig {
    pub total_bps: u64,
    pub total_burst: u64,
    pub public_bps: u64,
    pub public_burst: u64,
    pub ingress_bps: u64,
    pub ingress_burst: u64,
}
```

Placed in `flowplane-common` so both `nfkit` (table value) and the DPDK writer
reference one definition. Const-assert padding-free (the shared-table key/value
discipline). This lane is DPDK-only; eBPF/sim never see it.

### 2. Shared meter-config table (`nfkit::SharedConfigMaps`)

Add one RcuHash table (the 16th config table): `ifindex (u32) → MeterConfig`.
The key is wrapped with a unique non-zero first-byte tag (the ALL-ZERO-KEY =
`rte_hash` double-free / `EMPTY_SLOT==0` rule that every SharedConfigMaps key
already follows), padding-free (const-asserted). Single-writer `&self` interior
mutability + LF+RCU, identical to the other 15 config tables. Setters:
`meter_config_insert(ifindex, MeterConfig) -> bool`, `meter_config_remove(&ifindex) -> bool`,
and a lock-free reader `meter_config_get(ifindex) -> Option<MeterConfig>`.

### 3. `DpdkMapWriter::meter_upsert` / `meter_remove` (flowplane-dpdk)

`meter_upsert(ifindex, state: MeterState)` extracts the six config fields into a
`MeterConfig` and writes it to the shared table (was: only bump generation).
`meter_remove(ifindex)` removes the shared entry. Both keep the generation bump
for consistency with the other writers, but it is **no longer load-bearing** for
the meter — config is read fresh from the shared table on every packet.

The `MapWriter` trait signature (`meter_upsert(ifindex, MeterState)`) is
UNCHANGED — the eBPF `AyaWriter` still writes the full `MeterState` to its single
shared METER map exactly as today. Only the DPDK impl's body changes.

### 4. `ComposedMaps::meter_get` — compose on read

This is where "full rate per lcore" is realized: every lcore reads the **same**
shared `MeterConfig`, overlaying its own per-lcore token state.

```rust
fn meter_get(&self, ifindex: u32) -> Option<MeterState> {
    // No shared config → no meter configured → unlimited (today's behavior).
    let cfg = self.cfg.meter_config_get(ifindex)?;
    let m = match self.flow.meter_get(ifindex) {
        // Established: keep this lcore's own tokens/last_ns, overlay the shared rate.
        Some(state) => MeterState {
            total_bps: cfg.total_bps, total_burst: cfg.total_burst,
            total_tokens: state.total_tokens, total_last_ns: state.total_last_ns,
            public_bps: cfg.public_bps, public_burst: cfg.public_burst,
            public_tokens: state.public_tokens, public_last_ns: state.public_last_ns,
            ingress_bps: cfg.ingress_bps, ingress_burst: cfg.ingress_burst,
            ingress_tokens: state.ingress_tokens, ingress_last_ns: state.ingress_last_ns,
        },
        // First sight on this lcore: start each lane with a FULL bucket.
        None => MeterState {
            total_bps: cfg.total_bps, total_burst: cfg.total_burst,
            total_tokens: cfg.total_burst, total_last_ns: 0,
            public_bps: cfg.public_bps, public_burst: cfg.public_burst,
            public_tokens: cfg.public_burst, public_last_ns: 0,
            ingress_bps: cfg.ingress_bps, ingress_burst: cfg.ingress_burst,
            ingress_tokens: cfg.ingress_burst, ingress_last_ns: 0,
        },
    };
    Some(m)
}
```

`ComposedMaps::meter_update` is **unchanged**: it persists the returned
`MeterState` to the per-lcore table. The `bps`/`burst` it happens to store are
ignored on the next read (re-overlaid from shared), so only `tokens`/`last_ns`
are load-bearing per-lcore.

**Config-change self-correction:** because config is re-read every packet, a
lowered rate is picked up immediately — `take`/`edt_departure` clamp the
per-lcore `tokens` to the new (smaller) `burst` on the next packet. No explicit
per-lcore invalidation is required; the generation bump is not needed here.

## Data flow

```
ConfigureQoS(ifindex, rate) ──▶ ControlCore ──▶ DpdkMapWriter::meter_upsert
                                                   │ extract 6 config fields
                                                   ▼
                                    SharedConfigMaps.meter_config[ifindex] = MeterConfig   (single writer, RCU)
                                                   │
   per-packet, on each lcore:                      │ lock-free read
   process_guest_tx / uplink ──▶ meter fn ──▶ ComposedMaps::meter_get(ifindex)
                                                   │  overlay shared cfg + per-lcore tokens
                                                   ▼
                                       take()/edt_departure()  ──▶ pass/drop | EDT tstamp
                                                   │
                                       ComposedMaps::meter_update  ──▶ per-lcore tokens/last_ns
```

## Testing (all in `nfkit`, `--no-huge`, EAL inits once)

1. **Config plumbing (unit):** `SharedConfigMaps` meter-config insert / get /
   remove round-trip; key tag is non-zero + padding-free (const-assert).
2. **Functional policing:** program an `ingress_bps` (or `public_bps`) cap over
   `ComposedMaps`, drive the datapath, send a burst exceeding the bucket, assert
   the first `burst`-worth pass and subsequent packets **drop** — proving
   enforcement (previously *all* passed).
3. **Fresh bucket + config change:** first packet on an lcore starts with a full
   bucket (`tokens == burst`); after lowering the cap, the next packet clamps to
   the new burst (self-correction, no stale over-admission).
4. **EDT lane:** with `total_bps` set, the egress-encap path now returns a
   non-`None` EDT departure timestamp (was `None` = unshaped).

The existing `nfkit/tests/generation_invalidation.rs` already proves the
shared-config + per-lcore compose pattern end-to-end over `ComposedMaps`; the
meter tests reuse that harness shape (program shared config, run datapath over a
`ComposedMaps`, assert datapath behavior).

## Scope boundaries (YAGNI)

- No `bps/N` division, no shared atomic bucket, no lcore-count awareness.
- No change to `flowplane-core` meter code, `MeterState`, eBPF, or sim.
- No new gRPC surface — `ConfigureQoS` already maps to `meter_upsert`.
- No `MapWriter` trait change — the eBPF `AyaWriter` path is untouched.
- Aggregate over-admission across N lcores is an accepted, documented limitation.
