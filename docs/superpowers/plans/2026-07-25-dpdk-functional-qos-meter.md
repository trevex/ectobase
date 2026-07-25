# DPDK Functional QoS/Meter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `ConfigureQoS` actually enforce rate limits on the DPDK dataplane by seeding a per-interface rate config into shared memory and composing it with per-lcore token state on read.

**Architecture:** Split `MeterState` storage — the six rate config fields go into a new shared `SharedConfigMaps` table (written by `DpdkMapWriter::meter_upsert`); the token/timestamp state stays per-lcore. `ComposedMaps::meter_get` overlays the shared config onto the per-lcore state on every read, so every lcore enforces the full configured rate (full-rate-per-lcore policy). Core meter functions, `MeterState`, eBPF, and sim are untouched (the meter never rewrites bytes → outside byte-parity).

**Tech Stack:** Rust, DPDK (via `nfkit` + `dpdk-sys`), `RcuHash` (LF+RCU) shared config tables, `flowplane-core` datapath, tokio/tonic gRPC.

**Reference spec:** `docs/superpowers/specs/2026-07-24-dpdk-functional-qos-meter-design.md`

---

## File Structure

- `flowplane/flowplane-common/src/lib.rs` — add `MeterConfig` struct + extraction from `MeterState` + layout test (Task 1).
- `flowplane/nfkit/src/shared_config.rs` — add the 16th config table (`meter_config`): tagged key, struct field, constructor build, Drop, insert/remove/get methods (Task 2).
- `flowplane/nfkit/tests/meter.rs` — NEW EAL test binary, one `#[test]` built up across Tasks 2–4 (EAL inits once per binary).
- `flowplane/flowplane-dpdk/src/writer.rs` — `DpdkMapWriter::meter_upsert`/`meter_remove` write the shared table (Task 3).
- `flowplane/nfkit/src/per_lcore_flow.rs` — `ComposedMaps::meter_get` composes shared config + per-lcore state (Task 4).

**Note on the standalone `DpdkMaps` (`dpdk_maps.rs`):** out of scope. It is a self-contained single-instance test backend that stores the full `MeterState` (config+state) in one table populated directly; the serve path uses `ComposedMaps`. Leave it unchanged.

**Note on EAL-once:** `SharedConfigMaps`/`PerLcoreFlowMaps` need a live EAL, and EAL inits once per process. All EAL-requiring meter tests therefore live in ONE `#[test]` in `nfkit/tests/meter.rs` (its own test binary → its own process → its own EAL init), run with `--ignored --test-threads=1`. Tasks 2–4 each append a section to that one test.

---

## Task 1: `MeterConfig` struct in flowplane-common

**Files:**
- Modify: `flowplane/flowplane-common/src/lib.rs` (add after the `MeterState` struct, ends near line 205)

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `flowplane/flowplane-common/src/lib.rs` (find the existing `mod tests` — it holds layout tests like `config_has_stable_layout`):

```rust
    #[test]
    fn meter_config_layout_and_extraction() {
        // 6 × u64, no padding.
        assert_eq!(core::mem::size_of::<MeterConfig>(), 48);
        let state = MeterState {
            total_bps: 1,
            total_burst: 2,
            total_tokens: 999,   // state — must NOT be copied into MeterConfig
            total_last_ns: 999,
            public_bps: 3,
            public_burst: 4,
            public_tokens: 999,
            public_last_ns: 999,
            ingress_bps: 5,
            ingress_burst: 6,
            ingress_tokens: 999,
            ingress_last_ns: 999,
        };
        let cfg = MeterConfig::from_state(&state);
        assert_eq!(
            cfg,
            MeterConfig {
                total_bps: 1,
                total_burst: 2,
                public_bps: 3,
                public_burst: 4,
                ingress_bps: 5,
                ingress_burst: 6,
            }
        );
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p flowplane-common meter_config_layout_and_extraction`
Expected: FAIL — `cannot find type MeterConfig`.

- [ ] **Step 3: Write minimal implementation**

Add immediately after the `MeterState` struct definition in `flowplane/flowplane-common/src/lib.rs`:

```rust
/// The rate-config half of [`MeterState`] (the six `*_bps`/`*_burst` fields), stored in the DPDK
/// shared config table so `ConfigureQoS` can seed a per-interface rate that every lcore reads. The
/// token/timestamp state (`*_tokens`/`*_last_ns`) stays per-lcore and is NOT part of this struct.
/// DPDK-only: eBPF/sim keep the full `MeterState` in their single shared meter map.
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

impl MeterConfig {
    /// Extract the six rate-config fields from a full `MeterState` (drops the token/timestamp state).
    #[must_use]
    pub fn from_state(s: &MeterState) -> Self {
        Self {
            total_bps: s.total_bps,
            total_burst: s.total_burst,
            public_bps: s.public_bps,
            public_burst: s.public_burst,
            ingress_bps: s.ingress_bps,
            ingress_burst: s.ingress_burst,
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p flowplane-common meter_config_layout_and_extraction`
Expected: PASS.

- [ ] **Step 5: Confirm the whole common crate + default build still green**

Run: `cargo test -p flowplane-common && cargo build`
Expected: all pass; default build stays DPDK-free.

- [ ] **Step 6: Commit**

```bash
git add flowplane/flowplane-common/src/lib.rs
git commit -m "feat(common): add MeterConfig (rate half of MeterState) for the DPDK shared meter table"
```

---

## Task 2: Shared meter-config table in `SharedConfigMaps`

**Files:**
- Modify: `flowplane/nfkit/src/shared_config.rs` (tagged key ~line 143; padding-free assert ~line 168; struct field ~line 233; `build!` ~line 316; `Ok(Self{..})` ~line 340; methods near `fw_meta_insert` ~line 513; reader near `route4_get` ~line 581; Drop ~line 684)
- Create: `flowplane/nfkit/tests/meter.rs`

- [ ] **Step 1: Write the failing test (new EAL test binary, section 1)**

Create `flowplane/nfkit/tests/meter.rs`:

```rust
//! Functional QoS/meter over the DPDK shared-config + per-lcore compose path. EAL inits once, so
//! this is ONE `#[test]` built up in sections. Run with `--ignored --test-threads=1`.
#![cfg(test)]

use flowplane_common::MeterConfig;
use nfkit::{Eal, SharedConfigMaps};

#[test]
#[ignore = "requires EAL --no-huge"]
fn meter_config_and_policing() {
    let _eal = Eal::init([
        "nfkit-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "nfkit_meter",
    ])
    .expect("EAL init");

    // ── (1) Shared meter-config table round-trip ──────────────────────────────
    let shared = SharedConfigMaps::new(0, 1024).expect("shared config");
    let cfg = MeterConfig {
        total_bps: 100,
        total_burst: 200,
        public_bps: 300,
        public_burst: 400,
        ingress_bps: 500,
        ingress_burst: 600,
    };
    assert_eq!(shared.meter_config_get(7), None, "(1) empty before insert");
    assert!(shared.meter_config_insert(7, cfg), "(1) insert ok");
    assert_eq!(
        shared.meter_config_get(7),
        Some(cfg),
        "(1) get returns the inserted config"
    );
    assert!(shared.meter_config_remove(7), "(1) remove returns true when present");
    assert_eq!(shared.meter_config_get(7), None, "(1) gone after remove");
    // Section (2) — functional policing — is appended in Task 4.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p nfkit --test meter -- --ignored --test-threads=1`
Expected: FAIL to compile — `no method named meter_config_get/insert/remove on SharedConfigMaps`.

- [ ] **Step 3: Add the tagged key + padding-free assert**

In `flowplane/nfkit/src/shared_config.rs`, after the `DhcpMetaK` line (`tagged_key!(DhcpMetaK, 15, { ifindex: u32 }, 3);`) add:

```rust
// tag 16: meter config (ifindex).
tagged_key!(MeterCfgK, 16, { ifindex: u32 }, 3);
```

Then in the padding-free `const _` block (after `assert!(std::mem::size_of::<DhcpMetaK>() == 8);`) add:

```rust
const _: () = assert!(std::mem::size_of::<MeterCfgK>() == 8);
```

- [ ] **Step 4: Add the struct field**

In the `pub struct SharedConfigMaps` field list, after `dhcp_meta: std::mem::ManuallyDrop<RcuHash<DhcpMetaK, DhcpMeta>>,` add:

```rust
    meter_config: std::mem::ManuallyDrop<RcuHash<MeterCfgK, flowplane_common::MeterConfig>>,
```

- [ ] **Step 5: Build the table in `new()` + move it into `Self`**

In `new()`, after `let dhcp_meta = build!("dm");` add:

```rust
        let meter_config = build!("mc");
```

Then in the `Ok(Self { .. })` literal, after `dhcp_meta: std::mem::ManuallyDrop::new(dhcp_meta),` add:

```rust
            meter_config: std::mem::ManuallyDrop::new(meter_config),
```

- [ ] **Step 6: Add the writer + reader methods**

After the `fw_meta_remove` method (near line 519), add:

```rust
    /// Insert/overwrite a per-interface meter rate config. Returns false if the table is full.
    pub fn meter_config_insert(&self, ifindex: u32, cfg: flowplane_common::MeterConfig) -> bool {
        self.meter_config.insert(&MeterCfgK::new(ifindex), cfg)
    }
    /// Remove a per-interface meter rate config. Returns true if present.
    pub fn meter_config_remove(&self, ifindex: u32) -> bool {
        self.meter_config.remove(&MeterCfgK::new(ifindex))
    }
```

After the `route4_get`/other reader getters (near line 581, alongside the `_get` readers), add:

```rust
    /// Lock-free read of a per-interface meter rate config (None = no QoS configured).
    pub fn meter_config_get(&self, ifindex: u32) -> Option<flowplane_common::MeterConfig> {
        self.meter_config.get(&MeterCfgK::new(ifindex))
    }
```

- [ ] **Step 7: Drop the table**

In the `impl Drop for SharedConfigMaps`, inside the `unsafe { .. }` block, after `std::mem::ManuallyDrop::drop(&mut self.dhcp_meta);` add:

```rust
            std::mem::ManuallyDrop::drop(&mut self.meter_config);
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `cargo test -p nfkit --test meter -- --ignored --test-threads=1`
Expected: PASS (`meter_config_and_policing ... ok`).

- [ ] **Step 9: Commit**

```bash
git add flowplane/nfkit/src/shared_config.rs flowplane/nfkit/tests/meter.rs
git commit -m "feat(nfkit): add shared meter-config table (tag 16) to SharedConfigMaps"
```

---

## Task 3: `DpdkMapWriter::meter_upsert`/`meter_remove` write the shared table

**Dependency direction:** `nfkit` must NOT depend on `flowplane-dpdk` (that would be circular — `flowplane-dpdk` depends on `nfkit`). So the `DpdkMapWriter` test lives in `flowplane-dpdk`'s own test tree, not `nfkit/tests/meter.rs`.

**Files:**
- Modify: `flowplane/flowplane-dpdk/src/writer.rs` (`meter_upsert`/`meter_remove` near line 174; module doc "meter gap" near line 23)
- Create: `flowplane/flowplane-dpdk/tests/meter_writer.rs` (new EAL test binary in the flowplane-dpdk crate)

- [ ] **Step 1: Confirm the import paths**

Run: `grep -n 'pub use\|pub struct DpdkMapWriter\|pub mod' flowplane/flowplane-dpdk/src/lib.rs; grep -n 'pub trait MapWriter\|pub use.*MapWriter' flowplane/flowplane-control/src/*.rs`
Note the reachable paths for `DpdkMapWriter` (either `flowplane_dpdk::DpdkMapWriter` or `flowplane_dpdk::writer::DpdkMapWriter`) and the `MapWriter` trait (`flowplane_control::MapWriter` or `flowplane_control::writer::MapWriter`). Use whatever the crate actually exports in Step 2's `use`.

- [ ] **Step 2: Write the failing test (new EAL test binary)**

Create `flowplane/flowplane-dpdk/tests/meter_writer.rs` (adjust the two `use` paths per Step 1):

```rust
//! DpdkMapWriter::meter_upsert seeds the shared meter-config table. Needs EAL (--no-huge). Its own
//! test binary → own process → own EAL init. Run with `--ignored`.
#![cfg(test)]

use std::sync::Arc;

use flowplane_common::{MeterConfig, MeterState};
use flowplane_control::MapWriter; // trait providing meter_upsert (adjust path per Step 1)
use flowplane_dpdk::DpdkMapWriter; // adjust path per Step 1
use nfkit::{Eal, SharedConfigMaps};

#[test]
#[ignore = "requires EAL --no-huge"]
fn meter_upsert_seeds_shared_config() {
    let _eal = Eal::init([
        "fp-dpdk-test",
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-pci",
        "--file-prefix",
        "fp_meter_wr",
    ])
    .expect("EAL init");

    let shared = Arc::new(SharedConfigMaps::new(0, 1024).expect("shared config"));
    let mut writer = DpdkMapWriter::new(shared.clone());
    // A full MeterState as ConfigureQoS would deliver it (state fields are irrelevant to config).
    let state = MeterState {
        total_bps: 10,
        total_burst: 20,
        total_tokens: 7,
        total_last_ns: 7,
        public_bps: 30,
        public_burst: 40,
        public_tokens: 7,
        public_last_ns: 7,
        ingress_bps: 50,
        ingress_burst: 60,
        ingress_tokens: 7,
        ingress_last_ns: 7,
    };
    writer.meter_upsert(9, state).expect("meter_upsert");
    assert_eq!(
        shared.meter_config_get(9),
        Some(MeterConfig::from_state(&state)),
        "meter_upsert wrote the rate config into the shared table"
    );
    writer.meter_remove(&9).expect("meter_remove");
    assert_eq!(
        shared.meter_config_get(9),
        None,
        "meter_remove cleared the shared config"
    );
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p flowplane-dpdk --test meter_writer -- --ignored`
Expected: FAIL — `meter_config_get` returns `None` (current `meter_upsert` only bumps generation).

- [ ] **Step 4: Implement — make `meter_upsert`/`meter_remove` write the table**

In `flowplane/flowplane-dpdk/src/writer.rs`, replace the two methods:

```rust
    fn meter_upsert(&mut self, _ifindex: u32, _val: MeterState) -> anyhow::Result<()> {
        self.sc.bump_generation();
        Ok(())
    }
    /// See [`Self::meter_upsert`]: no config-map target; bump generation, no error.
    fn meter_remove(&mut self, _ifindex: &u32) -> anyhow::Result<()> {
        self.sc.bump_generation();
        Ok(())
    }
```

with:

```rust
    /// Write the rate-config half of `val` into the shared meter-config table so every datapath
    /// lcore reads the SAME per-interface rate (full-rate-per-lcore: each lcore enforces the full
    /// cap independently — aggregate across N RSS lcores can reach N× the cap, a documented
    /// limitation). The token/timestamp state stays per-lcore. The generation bump is kept for
    /// consistency but is no longer load-bearing for the meter (config is read fresh per packet).
    fn meter_upsert(&mut self, ifindex: u32, val: MeterState) -> anyhow::Result<()> {
        let ok = self
            .sc
            .meter_config_insert(ifindex, flowplane_common::MeterConfig::from_state(&val));
        anyhow::ensure!(ok, "meter-config table full for ifindex {ifindex}");
        self.sc.bump_generation();
        Ok(())
    }
    /// Remove the interface's shared meter config (rate no longer enforced). Bump generation.
    fn meter_remove(&mut self, ifindex: &u32) -> anyhow::Result<()> {
        self.sc.meter_config_remove(*ifindex);
        self.sc.bump_generation();
        Ok(())
    }
```

Also update the module-doc "meter gap" note (near line 23) — replace the paragraph stating there is no meter table with a one-liner noting the shared meter-config table now backs `meter_upsert` (config), tokens stay per-lcore.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p flowplane-dpdk --test meter_writer -- --ignored`
Expected: PASS (`meter_upsert_seeds_shared_config ... ok`).

- [ ] **Step 6: Commit**

```bash
git add flowplane/flowplane-dpdk/src/writer.rs flowplane/flowplane-dpdk/tests/meter_writer.rs
git commit -m "feat(dpdk): DpdkMapWriter::meter_upsert seeds the shared meter-config table"
```

---

## Task 4: `ComposedMaps::meter_get` composes shared config + per-lcore state (enforcement)

**Files:**
- Modify: `flowplane/nfkit/src/per_lcore_flow.rs` (`ComposedMaps::meter_get` near line 189)
- Modify: `flowplane/nfkit/tests/meter.rs` (append section 2: functional policing + fresh-bucket + config-change)

- [ ] **Step 1: Append the failing test section**

Add to the top imports of `flowplane/nfkit/tests/meter.rs`:

```rust
use etherparse::PacketBuilder;
use flowplane_common::{Local, PortMeta, RouteValue};
use flowplane_core::datapath::{process_guest_tx, GuestTxIn};
use flowplane_core::pkt::Action;
use nfkit::{ComposedMaps, MbufPkt, Mempool, PerLcoreFlowMaps};
```

(`MeterConfig`, `Eal`, `SharedConfigMaps` are already imported by section (1). `FwMeta`/`FwRule`/`FwRuleKey`/`FW_*` are referenced fully-qualified as `flowplane_common::…` below, so they need no `use`.)

Append section (2) to the end of the test fn (before the closing `}`). This drives the guest-egress datapath with an external route so the `public_pass` lane polices, exactly the fixture shape from `tests/generation_invalidation.rs`:

```rust
    // ── (2) Functional policing: public lane drops once the per-lcore bucket empties ──
    const VNI: u32 = 100;
    const SRC_IFINDEX: u32 = 10;
    const UPLINK_IFINDEX: u32 = 7;
    const GUEST_IP: [u8; 4] = [10, 0, 2, 20];
    const GUEST_MAC: [u8; 6] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00];
    const EXT_DST: [u8; 4] = [203, 0, 113, 9];
    const NEXTHOP_UL: [u8; 16] = [0x20, 0x01, 0x0d, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const SRC_UL: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    let pool = Mempool::new("meter_pool", 1023, 250, 0).expect("pool");
    let sc = SharedConfigMaps::new(0, 1024).expect("shared config 3");
    sc.set_local(Local {
        uplink_ifindex: UPLINK_IFINDEX,
        uplink_mac: [0x02; 6],
        gateway_mac: [0x03; 6],
        underlay_ipv6: SRC_UL,
    });
    // External route → the public (external-egress) meter lane runs.
    assert!(sc.route4_insert(
        VNI,
        EXT_DST,
        RouteValue {
            nexthop_vni: 0,
            nexthop_ipv6: NEXTHOP_UL,
            is_external: 1,
            _pad: [0; 3],
        },
    ));
    // Egress firewall allow-all on the source interface (deny-by-default otherwise).
    assert!(sc.fw_meta_insert(
        SRC_IFINDEX,
        flowplane_common::FwMeta { ingress_count: 0, egress_count: 1 },
    ));
    assert!(sc.fw_rules_insert(
        flowplane_common::FwRuleKey { ifindex: SRC_IFINDEX, idx: 0 },
        flowplane_common::FwRule {
            src_ip: [0; 4], src_mask: [0; 4], dst_ip: [0; 4], dst_mask: [0; 4],
            src_port_min: 0, src_port_max: 65535, dst_port_min: 0, dst_port_max: 65535,
            icmp_type: 0xffff, icmp_code: 0xffff, proto: 0,
            action: flowplane_common::FW_ACTION_ACCEPT,
            direction: flowplane_common::FW_DIR_EGRESS,
            enabled: 1,
        },
    ));

    // A guest frame [Eth][IPv4][UDP] GUEST_IP -> EXT_DST (~46 bytes on the wire).
    let frame = {
        let b = PacketBuilder::ethernet2(GUEST_MAC, [0xbb; 6])
            .ipv4(GUEST_IP, EXT_DST, 64)
            .udp(12345, 443);
        let mut out = Vec::new();
        b.write(&mut out, &[0x01, 0x02, 0x03, 0x04]).unwrap();
        out
    };
    let meta = PortMeta {
        vni: VNI,
        guest_ipv4: GUEST_IP,
        gateway_ipv4: [10, 0, 0, 1],
        guest_mac: GUEST_MAC,
        _pad: [0; 2],
        underlay_ipv6: SRC_UL,
        gateway_ipv6: [0; 16],
        guest_ipv6: [0; 16],
    };
    let in_ = GuestTxIn { meta: &meta, src_ifindex: SRC_IFINDEX, now: 0 };

    // A tiny public burst: 100 bytes at 0 bps refill (now stays 0). ~2 of our ~46-byte frames fit.
    assert!(sc.meter_config_insert(
        SRC_IFINDEX,
        MeterConfig {
            total_bps: 0, total_burst: 0,
            public_bps: 1_000_000, public_burst: 100, // burst 100 bytes
            ingress_bps: 0, ingress_burst: 0,
        },
    ));

    let flow = PerLcoreFlowMaps::new(0).expect("per-lcore flow");
    let mut maps = ComposedMaps { cfg: &sc, flow };

    // Helper: run one frame through process_guest_tx, return the verdict.
    let mut send = |maps: &mut ComposedMaps<'_>| -> Action {
        let mut mb = pool.alloc().expect("alloc");
        mb.append(frame.len() as u16).expect("append");
        mb.data_mut().copy_from_slice(&frame);
        let mut mp = MbufPkt::new(&mut mb);
        process_guest_tx(&mut mp, maps, &in_).action
    };

    // now stays 0 → no refill. Burst=100 bytes admits the first ~2 frames, then drops.
    let mut passed = 0;
    let mut dropped = 0;
    for _ in 0..6 {
        match send(&mut maps) {
            Action::Redirect(_) => passed += 1,
            Action::Drop => dropped += 1,
            Action::Pass => {}
        }
    }
    assert!(passed >= 1, "(2) at least the first packet passes (full bucket)");
    assert!(dropped >= 1, "(2) ENFORCEMENT: packets drop once the public bucket empties (was: all passed)");

    // ── (2b) Fresh bucket on a SECOND lcore's per-lcore state: full-rate-per-lcore ──
    // A brand-new PerLcoreFlowMaps (models another worker lcore) starts with a FULL bucket even
    // though the first lcore already drained its own — each lcore enforces the cap independently.
    let flow2 = PerLcoreFlowMaps::new(0).expect("per-lcore flow 2");
    let mut maps2 = ComposedMaps { cfg: &sc, flow: flow2 };
    assert_eq!(
        send(&mut maps2),
        Action::Redirect(UPLINK_IFINDEX),
        "(2b) a second lcore starts with a fresh full bucket (full-rate-per-lcore)"
    );

    // ── (2c) No config → unlimited (regression guard for the None branch) ──
    assert!(sc.meter_config_remove(SRC_IFINDEX));
    let flow3 = PerLcoreFlowMaps::new(0).expect("per-lcore flow 3");
    let mut maps3 = ComposedMaps { cfg: &sc, flow: flow3 };
    for _ in 0..10 {
        assert_eq!(
            send(&mut maps3),
            Action::Redirect(UPLINK_IFINDEX),
            "(2c) with no meter config the public lane is unlimited (all pass)"
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p nfkit --test meter -- --ignored --test-threads=1`
Expected: FAIL at section (2) — `dropped >= 1` fails, because `ComposedMaps::meter_get` currently returns only the per-lcore state (which has `public_bps == 0`), so `public_pass` never polices → everything passes.

- [ ] **Step 3: Implement the compose in `ComposedMaps::meter_get`**

In `flowplane/nfkit/src/per_lcore_flow.rs`, replace the `ComposedMaps` `meter_get` (near line 189, the one that delegates to `self.flow.meter_get`):

```rust
    fn meter_get(&self, ifindex: u32) -> Option<MeterState> {
        self.flow.meter_get(ifindex)
    }
```

with the compose (leave `meter_update` directly below it UNCHANGED — it still persists per-lcore state):

```rust
    fn meter_get(&self, ifindex: u32) -> Option<MeterState> {
        // Full-rate-per-lcore: overlay the SHARED rate config onto THIS lcore's token state. No
        // shared config → no QoS configured → None (unlimited). On this lcore's first sight of the
        // meter, seed each lane with a full bucket (tokens = burst); config changes self-correct
        // because `take`/`edt_departure` clamp tokens to the (re-read) burst on the next packet.
        let cfg = self.cfg.meter_config_get(ifindex)?;
        let m = match self.flow.meter_get(ifindex) {
            Some(s) => MeterState {
                total_bps: cfg.total_bps,
                total_burst: cfg.total_burst,
                total_tokens: s.total_tokens,
                total_last_ns: s.total_last_ns,
                public_bps: cfg.public_bps,
                public_burst: cfg.public_burst,
                public_tokens: s.public_tokens,
                public_last_ns: s.public_last_ns,
                ingress_bps: cfg.ingress_bps,
                ingress_burst: cfg.ingress_burst,
                ingress_tokens: s.ingress_tokens,
                ingress_last_ns: s.ingress_last_ns,
            },
            None => MeterState {
                total_bps: cfg.total_bps,
                total_burst: cfg.total_burst,
                total_tokens: cfg.total_burst,
                total_last_ns: 0,
                public_bps: cfg.public_bps,
                public_burst: cfg.public_burst,
                public_tokens: cfg.public_burst,
                public_last_ns: 0,
                ingress_bps: cfg.ingress_bps,
                ingress_burst: cfg.ingress_burst,
                ingress_tokens: cfg.ingress_burst,
                ingress_last_ns: 0,
            },
        };
        Some(m)
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p nfkit --test meter -- --ignored --test-threads=1`
Expected: PASS (all of sections 1–2, incl. 2b/2c).

- [ ] **Step 5: Run the existing DPDK datapath regression tests (no meter config ⇒ unchanged)**

Run: `cargo test -p nfkit --test generation_invalidation -- --ignored --test-threads=1`
Expected: PASS — those fixtures set no meter config, so `meter_get` returns `None` (unlimited), unchanged behavior.

- [ ] **Step 6: Commit**

```bash
git add flowplane/nfkit/src/per_lcore_flow.rs flowplane/nfkit/tests/meter.rs
git commit -m "feat(nfkit): ComposedMaps::meter_get composes shared rate config + per-lcore tokens (functional QoS)"
```

---

## Task 5: Final verification + fmt/clippy

**Files:** none (verification only)

- [ ] **Step 1: fmt + clippy on all touched crates**

Run: `cargo fmt --check -p flowplane-common -p nfkit -p flowplane-dpdk && cargo clippy -p flowplane-common -p nfkit -p flowplane-dpdk`
Expected: no fmt diff; no new clippy warnings (a pre-existing `too_many_arguments` on `attach.rs` may appear — unrelated). If fmt diffs, run `cargo fmt -p <crate>` and re-commit.

- [ ] **Step 2: Full non-root suites unchanged (byte-parity intact)**

Run: `make test && make sim`
Expected: `flowplane-common` 19 + `flowplane-core`/`flowplane-sim` 70 green — the meter change is DPDK-only, so eBPF/sim/core are untouched.

- [ ] **Step 3: Privileged eBPF anchors unchanged (meter is outside byte-parity)**

Run: `make sim-anchor`
Expected: all anchors green (verifier + uplink/lb/dnat/guest_tx/dhcp). No change expected — the eBPF meter path is not touched.

- [ ] **Step 4: The two nfkit EAL meter/generation tests green**

Run: `cargo test -p nfkit --test meter --test generation_invalidation -- --ignored --test-threads=1`
Expected: both PASS.

- [ ] **Step 5: Commit any fmt fixup (if Step 1 changed files)**

```bash
git add -A && git commit -m "chore(dpdk): fmt after functional QoS meter"
```

---

## Self-Review Notes (author)

- **Spec coverage:** MeterConfig (Task 1); shared table + key tag + Drop (Task 2); meter_upsert/remove writing shared (Task 3); compose-on-read + full-bucket-first-sight + None=unlimited + config-change self-correction (Task 4); functional policing + fresh-bucket + EDT-lane availability (Task 4 tests; the EDT lane is exercised implicitly via the shared `total_bps` plumbing — a dedicated EDT-tstamp assertion is optional and omitted to keep the datapath fixture single-lane). All spec sections map to a task.
- **Scope:** DPDK-only. `MapWriter` trait, `MeterState`, core meter fns, eBPF `AyaWriter`, sim, and the standalone `DpdkMaps` are explicitly untouched.
- **Type consistency:** `MeterConfig::from_state(&MeterState)`, `meter_config_insert/remove/get`, `MeterCfgK` (tag 16), field `meter_config`, build key `"mc"` — used consistently across tasks.
