# nfkit Milestone 11 — hitless DPDK dataplane upgrade: blue-green + externalized conntrack snapshot

**Date:** 2026-07-22
**Status:** Design — approved in brainstorming (model + scope), pending spec review → writing-plans.
**Parent:** `2026-07-20-flowplane-dpdk-nfkit-design.md`. **Builds on:** M8 (per-lcore `DpdkMaps`, unique-named rte_hash), M3 (`DpdkHash`, `process_uplink/guest_tx`), the Maglev LB already in `flowplane-core/lb.rs`. Branch `design/flowplane-dpdk`.
**Grounded in:** the verified deep-research memory `dpdk-inplace-upgrade-m11` (DPDK primary/secondary rejected for version upgrade; ct_sync / VPP-tag / Katran-Maglev prior art).

## 1. Goal & why

Give the DPDK backend a **hitless (sub-millisecond) upgrade** story. Research verdict: DPDK has no turnkey primitive, and its primary/secondary sharing is unusable for version upgrade (identical-version requirement; cross-binary function-pointer hazard the docs pin on `librte_hash`; primary clears shared memory). For a poll-mode forwarder **the process is the datapath**, so the viable model is **blue-green** (a new binary runs concurrently on split RSS lanes, traffic flips atomically, the old drains) made *sub-ms* by: (a) **consistent-hash LB** (already in the datapath) so LB flows need no state handoff, and (b) an **externalized conntrack/NAT snapshot** pre-loaded into the new instance so stateful NAT flows survive the flip. This milestone delivers the **design** for that orchestration plus the **reusable enabling primitive**: a per-lcore `DpdkMaps` conntrack/NAT snapshot serialize→restore round-trip, testable without a smartNIC.

## 2. Locked decisions

| Decision | Choice |
|---|---|
| Upgrade model | **Blue-green + connection draining**, atomic steering flip; **consistent-hash** (existing Maglev) for the LB path; **externalized conntrack** for stateful NAT flows |
| Sub-ms question | No simpler DPDK-native path beats this for stateful flows (process = datapath); the sub-ms property comes from the atomic flip + state pre-loaded. eBPF backend remains the "kernel-holds-traffic" zero-loss option where chosen. |
| This milestone's slice | **Conntrack + NAT snapshot serialize → restore round-trip** on per-lcore `DpdkMaps` (the primitive every stateful-handoff variant needs); full orchestration is design-only here |
| Enabling primitive | Add **`DpdkHash` iteration** (`rte_hash_iterate`) — currently absent; needed to walk CT/NAT for a snapshot |
| Snapshot format | A **versioned, self-describing** byte blob (magic + version + per-table `[count, (key,value)…]`) over the POD `CtKey/CtEntry/NatKey/NatValue` (already `#[repr(C)]`); host-endian, single-host handoff — NOT a cross-arch wire format |
| Testable w/o HW | Serialize/restore round-trip + established-flow continuity are `--no-huge`, deterministic. The atomic RSS/rte_flow flip + real two-instance drain need HW/privileged and are DESIGN-ONLY (noted, deferred) |

## 3. Components

```
flowplane/nfkit/src/dpdk_hash.rs    += iterate/for_each over rte_hash (rte_hash_iterate) — enabling primitive
flowplane/nfkit/src/snapshot.rs     new: serialize/restore a DpdkMaps CT+NAT snapshot (versioned blob)
flowplane/nfkit/src/lib.rs          re-export snapshot API
flowplane/nfkit/tests/dpdk_hash.rs  += iteration test (insert N, iterate → all N back)
flowplane/nfkit/tests/snapshot_roundtrip.rs   new: export CT+NAT from instance A → restore into fresh B → byte-identical; established-flow continuity (process_uplink over B hits the restored CT, no re-create)
docs/... (design doc content lives in this spec §5)
```

### 3.1 `DpdkHash` iteration (enabling primitive)

`rte_hash_iterate(h, &key, &data, &next)` walks live entries. Add a safe `for_each(&self, f: impl FnMut(&K, &V))` (or an `iter()` yielding `(K, V)` copies) that loops `rte_hash_iterate` until it returns `-ENOENT`. SAFETY: the returned `key`/`data` are borrowed pointers into the table valid until the next mutation; copy `K`/`V` out (they're `Copy` POD) before calling `f`. Test: insert N distinct entries, iterate, assert the set of `(K,V)` returned equals what was inserted.

### 3.2 `snapshot` module (the round-trip)

- `serialize_maps(&DpdkMaps) -> Vec<u8>` — writes a versioned blob: `MAGIC("NFKS")` + `u16 version` + for each snapshotted table (`conntrack`, `nat`, `nat_ips`) a `u32 count` then `count × (key_bytes, value_bytes)` via the POD structs. Uses §3.1 iteration.
- `restore_maps(&mut DpdkMaps, &[u8]) -> Result<RestoreStats, SnapshotError>` — validates magic/version, re-inserts every entry into a fresh `DpdkMaps`. Rejects a version/magic mismatch (an upgrade must refuse an incompatible snapshot rather than corrupt state).
- Scope: conntrack + NAT bindings (the flow state that must survive). Read-mostly config maps (routes/fw/underlay/lb/maglev) are re-derived from the control plane on the new instance — NOT snapshotted (they're not per-flow state). Document this boundary.
- `RestoreStats { conntrack, nat, nat_ips }` counts for assertions/telemetry.

### 3.3 Established-flow continuity test (the proof)

`snapshot_roundtrip.rs` (`--no-huge`): build instance A's `DpdkMaps`, run `process_uplink`/`process_guest_tx` over several flows so A creates conntrack (+ a NAT binding). `serialize_maps(&A)` → blob. Build a FRESH instance B (`DpdkMaps::new`, empty), `restore_maps(&mut B, &blob)`. Assert: (1) B's CT/NAT tables are byte-identical to A's (same keys+values, via iteration); (2) **continuity** — replaying an ESTABLISHED-flow packet through B takes the established path (CT hit, no new create / correct NAT translation), i.e. the flow "survived" the simulated binary swap. This is the sub-ms-handoff primitive proven without hardware.

## 4. Definition of Done

- `DpdkHash` iteration added + unit-tested; `snapshot` serialize/restore round-trip + established-flow continuity pass `--no-huge` (`cargo test -p nfkit`); all M3–M10 anchors green.
- Snapshot is versioned + rejects magic/version mismatch; scope (CT+NAT only, config re-derived) documented.
- `cargo test -p flowplane-sim` + `anchor_*` unchanged (M11 is nfkit-only; no `flowplane-core`/eBPF change — snapshot walks `DpdkMaps` via the new iteration).
- **Design doc** (§5) records the full blue-green orchestration + the deferred (HW/privileged) pieces + the shared-nothing tension resolution.
- Default host build untouched.

## 5. Design doc — full blue-green hitless upgrade orchestration (implementation deferred beyond the slice)

1. **Two instances, split RSS lanes.** New binary starts, EAL/PMD init + `DpdkMaps::new` (unique names — M8 already makes this safe) while the old keeps forwarding. New instance owns a disjoint RSS lane / queue set (or, on af_xdp, its own XSKs sharing the UMEM).
2. **State pre-load.** Old instance `serialize_maps` → new instance `restore_maps` (CT+NAT). Config maps re-derived from the control plane (routebus/CompiledNIC). For steady-state divergence during the window, a short **ct_sync-style delta stream** (research finding 5) tops up flows created during handoff — DESIGN NOTE, not in the slice.
3. **Atomic steering flip.** Move flows from old lanes to new: RSS redirection-table write / `rte_flow` rule swap (HW) or af_xdp XDP-prog redirect (µs-scale) → the sub-ms hiccup. Consistent-hash LB means flipped LB flows recompute the same backend with no state dependence.
4. **Drain + retire.** Old instance finishes in-flight flows (connection draining) then exits. Alternatively the "no-CT-handoff" variant: old keeps ITS flows to completion (new takes only new flows) — zero hiccup for existing flows, needs old/new discrimination (new instance reforwards unknown flows to old, like the distributed-LB reforward pattern).
5. **Control/forwarder split (optional, VPP-tag model, finding 6):** a long-lived forwarder + restartable control process makes CONTROL upgrades hitless independently; reconcile via tagged dataplane objects. Separate follow-up.
6. **Deferred/HW-gated:** rte_flow rule persistence across the flip on real mlx5 (`RTE_ETH_DEV_CAPA_FLOW_RULE_KEEP` — needs ConnectX to validate); the real two-instance af_xdp drain (privileged); the ct_sync delta stream. All noted as post-slice work.

## 6. Risks / open questions

- **rte_hash_iterate + concurrent mutation** — iteration borrows live pointers; the snapshot must run when the table is quiescent (the old instance is draining / paused for the export) or copy-out per step. For the slice (single-threaded export of a static table) this is safe; document the quiescence requirement for the live orchestration.
- **Snapshot compatibility across versions** — the whole point is an OLD binary's snapshot loaded by a NEW binary. If `CtKey/CtEntry/NatKey/NatValue` layouts change between versions, the blob is incompatible → the `version` field must gate it and `restore` must refuse+fall back (accept flow loss) rather than corrupt. Same-arch/same-host assumption (host-endian) is fine for local upgrade; document it.
- **Which tables are per-flow state** — snapshot conntrack + NAT bindings (`nat`, `nat_ips`) + verify whether `meter` (EDT schedule cursors) should be carried; routes/fw/lb/maglev/underlay are config, re-derived. Confirm the exact set against `DpdkMaps` fields + `ct_create_default`/`snat_egress` write sites.
- **The slice ≠ the whole upgrade** — this milestone proves the STATE-HANDOFF primitive, not the atomic flip or two-instance drain (those need HW/privileged). Be explicit in the DoD that continuity is proven for the state layer; the flip is design-only.
- **Value vs pure connection-draining** — if the accepted flow-loss budget turns out generous, the simpler no-CT-handoff draining variant may suffice and the snapshot becomes optional. The slice keeps the snapshot primitive available either way (also useful for debug/observability: dumping live CT).
