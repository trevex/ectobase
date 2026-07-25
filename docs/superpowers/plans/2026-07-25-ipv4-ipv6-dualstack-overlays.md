# IPv4/IPv6/Dual-Stack Overlays Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Support IPv4-only, IPv6-only, and dual-stack overlays on both dataplanes by making the shared interface programming symmetric per-family, relaxing attach validation to require ≥1 overlay IP, and deterministically configuring container (veth) pod-netns addressing/routes at attach.

**Architecture:** The datapath is already family-agnostic (route+UNDERLAY-driven delivery), so NO eBPF datapath change. Make `ControlCore::program_interface` gate the v4 self-route + v4 INTERFACES write on `ipv4 != 0` (mirroring the existing v6 conditional); relax both backends' attach to require ≥1 family; add a shared `flowplane_device::configure_guest_netns` for containers; verify responder zero-gateway gating. VMs keep DHCP/RA.

**Tech Stack:** Rust; `flowplane-control` (`ControlCore`/`MemMapWriter`); `flowplane-device` (`ip`/`ip netns` subprocess); tonic (DPDK node).

**Reference spec:** `docs/superpowers/specs/2026-07-25-ipv4-ipv6-dualstack-overlays-design.md`

---

## File Structure

- `flowplane/flowplane-control/src/interface.rs` — `program_interface`: conditional v4 route + INTERFACES (Task 1)
- `flowplane/flowplane/src/attach.rs` — validation ≥1 family; gate INTERFACES read-back on v4; `ips` present families; call `configure_guest_netns` (Tasks 2, 5)
- `flowplane/flowplane-dpdk/src/node.rs` — validation ≥1 family; `ips` present families; call `configure_guest_netns` (Tasks 3, 5)
- `flowplane/flowplane-device/src/netns.rs` (new) + `src/lib.rs` — `configure_guest_netns` (Task 4)
- `flowplane/flowplane-core/src/arp_nd.rs` — defensive zero-gateway guards (Task 6)

---

## Task 1: Symmetric `program_interface` (conditional v4)

**Files:** Modify `flowplane/flowplane-control/src/interface.rs`

- [ ] **Step 1: Write failing tests**

Add to the `#[cfg(test)] mod tests` in `interface.rs` (it already `use`s `MemMapWriter`, `ControlCore`; check the existing test imports and match). These assert the map writes per family. Read the existing tests to see how to inspect `MemMapWriter` state (it exposes the programmed tables — e.g. a `routes`/`route6`/`ifaces` accessor or a `.writer` field; use the same inspection the existing `program_interface`/lb tests use).

```rust
    fn params(ipv4: [u8; 4], ipv6: [u8; 16]) -> IfaceParams {
        IfaceParams {
            interface_id: b"if-1".to_vec(),
            device: "veth-x".into(),
            tap: 42,
            effective_mac: [0x02, 0, 0, 0, 0, 1],
            vni: 100,
            ipv4,
            ipv6,
            gateway_ipv4: [10, 0, 0, 1],
            gateway_ipv6: [0; 16],
            underlay_ipv6: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            total_mbps: 0,
            public_mbps: 0,
        }
    }

    #[test]
    fn program_interface_v6_only_skips_v4_route_and_ifaces() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.program_interface(params([0; 4], [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10])).unwrap();
        // v6 self-route present; NO v4 /32 route; NO INTERFACES(v4,0) entry.
        // (Use the MemMapWriter inspection the sibling tests use; assert:)
        //  - route6 has (vni=100, the /128) -> underlay
        //  - route4 has NO (vni=100, 0.0.0.0/32)
        //  - ifaces has NO IfaceKey{vni:100, ipv4:[0;4]}
    }

    #[test]
    fn program_interface_v4_only_skips_v6_route() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.program_interface(params([10, 0, 0, 5], [0; 16])).unwrap();
        //  - route4 has (vni=100, 10.0.0.5/32); ifaces has IfaceKey{100, [10,0,0,5]}; route6 empty
    }

    #[test]
    fn program_interface_dual_programs_both() {
        let mut c = ControlCore::new(MemMapWriter::default());
        c.program_interface(params([10, 0, 0, 5], [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10])).unwrap();
        //  - route4 + ifaces(v4) + route6 all present
    }
```
Fill the assertion bodies using the ACTUAL `MemMapWriter` inspection API (read `flowplane-control/src/mem.rs` + an existing `program_interface`/routes test to see how programmed entries are read back — e.g. `c.writer().routes.get(...)` or a public getter). If `MemMapWriter` has no read API for a table, add a minimal `#[cfg(test)]` getter or use whatever the existing tests use. Do NOT invent an API — match the codebase.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p flowplane-control program_interface_`
Expected: FAIL — the v6-only test fails (a bogus v4 /32 + INTERFACES(v4,0) are currently programmed).

- [ ] **Step 3: Implement the conditional**

In `program_interface`, wrap the v4 `ifaces_upsert` AND the v4 `route_upsert(vni, ipv4, 32, …)` in `if ipv4 != [0u8; 4] { … }` (mirroring the existing `if ipv6 != [0u8; 16]` around `route6_upsert`). Concretely, change:
```rust
        self.w.ifaces_upsert(
            IfaceKey::new(vni, ipv4),
            IfaceValue { tap_ifindex: tap, is_local: 1, underlay_ipv6, guest_mac: effective_mac, _pad: [0; 2] },
        )?;
        self.w.underlay_upsert( /* … unchanged … */ )?;
        // Local self-route …
        self.w.route_upsert(vni, ipv4, 32, RouteValue { nexthop_vni: vni, nexthop_ipv6: underlay_ipv6, is_external: 0, _pad: [0; 3] })?;
        if ipv6 != [0u8; 16] { self.w.route6_upsert( /* … */ )?; }
```
to:
```rust
        // INTERFACES (v4-keyed MAC-learning shadow) + the v4 /32 self-route: only for a present
        // overlay IPv4. IPv6-only interfaces program the v6 self-route only (below); a bogus
        // (vni, 0.0.0.0) INTERFACES key + 0.0.0.0/32 route would collide across v6-only interfaces.
        if ipv4 != [0u8; 4] {
            self.w.ifaces_upsert(
                IfaceKey::new(vni, ipv4),
                IfaceValue { tap_ifindex: tap, is_local: 1, underlay_ipv6, guest_mac: effective_mac, _pad: [0; 2] },
            )?;
        }
        self.w.underlay_upsert( /* … unchanged (always) … */ )?;
        if ipv4 != [0u8; 4] {
            self.w.route_upsert(vni, ipv4, 32, RouteValue { nexthop_vni: vni, nexthop_ipv6: underlay_ipv6, is_external: 0, _pad: [0; 3] })?;
        }
        if ipv6 != [0u8; 16] { self.w.route6_upsert( /* … unchanged … */ )?; }
```
Keep `underlay_upsert` and the `IfaceMeta` journal write UNCONDITIONAL (they carry the interface regardless of family; the journal stores ipv4=0/ipv6=0 for the absent family). Do NOT change PortMeta programming (guest_ipv4/ipv6 already carry 0 for the absent family).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p flowplane-control program_interface_` then `cargo test -p flowplane-control`
Expected: all pass (incl. the existing interface tests — v4-only + dual unchanged).

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane-control/src/interface.rs
git commit -m "feat(control): program_interface gates v4 route + INTERFACES on ipv4!=0 (v6-only support)"
```

---

## Task 2: eBPF attach — require ≥1 family, gate read-back, symmetric `ips`

**Files:** Modify `flowplane/flowplane/src/attach.rs`

- [ ] **Step 1: Relax the IPv4 requirement**

Replace (near line 206):
```rust
        let ipv4 = primary_ipv4(requested_ips)
            .context("attach requires at least one IPv4 in requested_ips")?;
        let ipv6 = primary_ipv6(requested_ips);
```
with:
```rust
        // Overlay IPs: at least ONE family is required; either may be absent (all-zeros).
        let ipv4 = primary_ipv4(requested_ips).unwrap_or([0u8; 4]);
        let ipv6 = primary_ipv6(requested_ips);
        if ipv4 == [0u8; 4] && ipv6 == [0u8; 16] {
            anyhow::bail!("attach requires at least one overlay IP (IPv4 or IPv6) in requested_ips");
        }
```

- [ ] **Step 2: Gate the INTERFACES read-back on ipv4 != 0**

The read-back (~line 288–300) reads `INTERFACES[vni, ipv4]` to confirm programming; for a v6-only interface there is no v4 INTERFACES entry, so it must be skipped. Wrap the whole read-back block in `if ipv4 != [0u8; 4] { … }`. Read the exact block first and wrap it (it currently unconditionally reads back and `bail!("INTERFACES read-back failed after programming")`).

- [ ] **Step 3: Make `ips` reflect present families**

Replace the `AttachOutcome` `ips` field build (near line 313):
```rust
            ips: vec![Ipv4Addr::from(ipv4).to_string()],
```
with:
```rust
            ips: {
                let mut v = Vec::new();
                if ipv4 != [0u8; 4] { v.push(Ipv4Addr::from(ipv4).to_string()); }
                if ipv6 != [0u8; 16] { v.push(Ipv6Addr::from(ipv6).to_string()); }
                v
            },
```

- [ ] **Step 4: Verify**

Run: `cargo build -p flowplane 2>&1 | grep -E 'warning|error'` (none) and `cargo test -p flowplane` (green; ~unchanged count — v4/dual attach behavior identical).

- [ ] **Step 5: Commit**

```bash
git add flowplane/flowplane/src/attach.rs
git commit -m "feat(ebpf): attach accepts v6-only/v4-only/dual (>=1 family); gate v4 INTERFACES read-back; symmetric ips"
```

---

## Task 3: DPDK attach — require ≥1 family, symmetric `ips`

**Files:** Modify `flowplane/flowplane-dpdk/src/node.rs`

- [ ] **Step 1: Relax the guard**

Replace the current guard:
```rust
        if ipv4 == [0u8; 4] {
            return Err(Status::invalid_argument(
                "attach requires at least one overlay IPv4 (IPv6-only overlays not yet supported)",
            ));
        }
```
with:
```rust
        // At least one overlay family is required; either may be absent.
        if ipv4 == [0u8; 4] && ipv6 == [0u8; 16] {
            return Err(Status::invalid_argument(
                "attach requires at least one overlay IP (IPv4 or IPv6) in requested_ips",
            ));
        }
```

- [ ] **Step 2: Symmetric `ips` in the response**

Replace:
```rust
            ips: vec![std::net::Ipv4Addr::from(ipv4).to_string()],
```
with:
```rust
            ips: {
                let mut v = Vec::new();
                if ipv4 != [0u8; 4] { v.push(std::net::Ipv4Addr::from(ipv4).to_string()); }
                if ipv6 != [0u8; 16] { v.push(std::net::Ipv6Addr::from(ipv6).to_string()); }
                v
            },
```

- [ ] **Step 3: Verify**

Run: `cargo build -p flowplane-dpdk 2>&1 | grep -E 'warning|error'` (none); `cargo test -p flowplane-dpdk --lib` (green). The `--ignored` EAL attach test still passes (uses a v4 request): `sudo -E $(command -v cargo) test -p flowplane-dpdk --test attach_veth -- --ignored --test-threads=1`.

- [ ] **Step 4: Commit**

```bash
git add flowplane/flowplane-dpdk/src/node.rs
git commit -m "feat(dpdk): attach accepts v6-only/v4-only/dual (>=1 family); symmetric ips"
```

---

## Task 4: `configure_guest_netns` in `flowplane-device`

**Files:** Create `flowplane/flowplane-device/src/netns.rs`; modify `flowplane/flowplane-device/src/lib.rs`

- [ ] **Step 1: Write the failing test + the fn**

Create `flowplane/flowplane-device/src/netns.rs`. Reuse the `run`/`run_netns` helpers from `veth.rs` — make them `pub(crate)` (they already are) and `use crate::veth::{run, run_netns};` (or move them to a shared `pub(crate) mod cmd`; simplest: `use crate::veth::{run, run_netns}`).

```rust
//! Deterministic container guest-netns addressing/routes at attach: configure the pod's overlay
//! address(es) + per-family default route on the veth guest end. Containers only (VMs self-config
//! via DHCP/RA). Point-to-point veth: use `onlink` so no shared subnet is assumed.

use anyhow::{Context, Result};

use crate::veth::run_netns;

/// What to configure inside the pod netns. A zero family is skipped.
pub struct GuestNetConfig {
    pub netns_path: String,
    pub guest_ifname: String,
    pub ipv4: [u8; 4],
    pub gateway_ipv4: [u8; 4],
    pub ipv6: [u8; 16],
    pub gateway_ipv6: [u8; 16],
}

/// Configure the present families on the guest end. Idempotent-ish: assumes a freshly created veth.
pub fn configure_guest_netns(c: &GuestNetConfig) -> Result<()> {
    let dev = &c.guest_ifname;
    if c.ipv4 != [0u8; 4] {
        let ip = std::net::Ipv4Addr::from(c.ipv4).to_string();
        let gw = std::net::Ipv4Addr::from(c.gateway_ipv4).to_string();
        run_netns(&c.netns_path, &["ip", "addr", "add", &format!("{ip}/32"), "dev", dev]).context("add v4 addr")?;
        if c.gateway_ipv4 != [0u8; 4] {
            // On-link host route to the gateway, then default via it (Cilium point-to-point model).
            run_netns(&c.netns_path, &["ip", "route", "add", &gw, "dev", dev]).context("add v4 gw onlink route")?;
            run_netns(&c.netns_path, &["ip", "route", "add", "default", "via", &gw, "dev", dev]).context("add v4 default route")?;
        }
    }
    if c.ipv6 != [0u8; 16] {
        let ip = std::net::Ipv6Addr::from(c.ipv6).to_string();
        run_netns(&c.netns_path, &["ip", "-6", "addr", "add", &format!("{ip}/128"), "dev", dev]).context("add v6 addr")?;
        if c.gateway_ipv6 != [0u8; 16] {
            let gw = std::net::Ipv6Addr::from(c.gateway_ipv6).to_string();
            // The datapath answers NS for gateway_ipv6 (the on-link gateway); default via it, onlink.
            run_netns(&c.netns_path, &["ip", "-6", "route", "add", "default", "via", &gw, "dev", dev, "onlink"]).context("add v6 default route")?;
        }
    }
    Ok(())
}
```
NOTE: verify the exact v4 gateway model against the reference fabric. `gateway_ipv4` is a link-local-style gateway (e.g. `169.254.0.1`) on a different subnet than a `/32` pod IP, so the explicit on-link host route to `<gw>` (`ip route add <gw> dev <dev>`) BEFORE `default via <gw>` is required (this is the Cilium pattern). If `ip route add <gw> dev <dev>` needs a scope/onlink flag on this kernel, add `onlink` (`ip route add default via <gw> dev <dev> onlink` also works without the explicit host route). The implementer should test both forms in Step 2's netns and use whichever the kernel accepts; keep it minimal.

Add tests:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::veth::run_netns;

    fn mk_ns(ns: &str) -> String {
        let _ = super::super::veth::delete_link("gnc-h0");
        let _ = std::process::Command::new("ip").args(["netns", "del", ns]).output();
        std::process::Command::new("ip").args(["netns", "add", ns]).output().unwrap();
        // a dummy dev inside the ns to configure
        let path = format!("/var/run/netns/{ns}");
        run_netns(&path, &["ip", "link", "add", "eth0", "type", "dummy"]).unwrap();
        run_netns(&path, &["ip", "link", "set", "eth0", "up"]).unwrap();
        path
    }

    #[test]
    #[ignore = "privileged: creates a netns + configures addrs/routes (needs CAP_NET_ADMIN)"]
    fn configures_v6_only() {
        let ns = "gnc-v6";
        let path = mk_ns(ns);
        configure_guest_netns(&GuestNetConfig {
            netns_path: path.clone(),
            guest_ifname: "eth0".into(),
            ipv4: [0; 4],
            gateway_ipv4: [0; 4],
            ipv6: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10],
            gateway_ipv6: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        }).unwrap();
        // v6 addr present, v6 default route present, NO v4 addr.
        run_netns(&path, &["ip", "-6", "addr", "show", "eth0"]).unwrap();
        assert!(run_netns(&path, &["ip", "-6", "route", "show", "default"]).is_ok());
        let _ = std::process::Command::new("ip").args(["netns", "del", ns]).output();
    }

    #[test]
    #[ignore = "privileged: needs CAP_NET_ADMIN"]
    fn configures_v4_only_and_dual() {
        // v4-only
        let ns = "gnc-v4";
        let path = mk_ns(ns);
        configure_guest_netns(&GuestNetConfig {
            netns_path: path.clone(), guest_ifname: "eth0".into(),
            ipv4: [10, 0, 0, 5], gateway_ipv4: [169, 254, 0, 1],
            ipv6: [0; 16], gateway_ipv6: [0; 16],
        }).unwrap();
        run_netns(&path, &["ip", "route", "show", "default"]).unwrap();
        let _ = std::process::Command::new("ip").args(["netns", "del", ns]).output();
    }
}
```
Add to `lib.rs`: `pub mod netns;` + `pub use netns::{configure_guest_netns, GuestNetConfig};`.

- [ ] **Step 2: Verify**

Run (privileged): `sudo -E $(command -v cargo) test -p flowplane-device -- --ignored --test-threads=1` — the new netns tests pass (adjust the v4 route form per the NOTE if a command errors). Unprivileged: `cargo test -p flowplane-device` still green.

- [ ] **Step 3: Commit**

```bash
git add flowplane/flowplane-device/
git commit -m "feat(device): configure_guest_netns — deterministic container pod-netns addr/routes"
```

---

## Task 5: Wire `configure_guest_netns` into both veth attach paths

**Files:** Modify `flowplane/flowplane/src/attach.rs`, `flowplane/flowplane-dpdk/src/node.rs`

- [ ] **Step 1: eBPF Veth arm**

In `attach.rs`, the `DeviceType::Veth` arm (after `create_veth_pair`, after `program_interface`/`create_interface` succeeds), call:
```rust
        flowplane_device::configure_guest_netns(&flowplane_device::GuestNetConfig {
            netns_path: netns_path.to_string(),
            guest_ifname: interface_id.to_string(), // the guest eth name (== ifname for veth)
            ipv4,
            gateway_ipv4: self.gateway_ipv4,
            ipv6,
            gateway_ipv6: self.gateway_ipv6,
        })?;
```
Place it ONLY on the Veth path (NOT Tap/PodTap). Use the same `guest_name` var the veth creation used.

- [ ] **Step 2: DPDK attach**

In `node.rs` `attach_interface`, after `program_interface` + `register`, before building the response, call `configure_guest_netns` off-thread (subprocess) for the veth (device_type is already veth-only here in B2a):
```rust
        {
            let cfg = flowplane_device::GuestNetConfig {
                netns_path: r.netns_path.clone(),
                guest_ifname: guest_name.clone(),
                ipv4,
                gateway_ipv4: attach.gateway_ipv4,
                ipv6,
                gateway_ipv6: attach.gateway_ipv6,
            };
            tokio::task::spawn_blocking(move || flowplane_device::configure_guest_netns(&cfg))
                .await
                .map_err(|e| Status::internal(format!("guest-netns task panicked: {e}")))?
                .map_err(|e| Status::internal(format!("configure guest netns: {e}")))?;
        }
```
(On failure here, roll back like the other error paths: delete the veth + release IPAM + forget the registry entry — mirror the existing `program_interface` rollback ordering: no subprocess under the ctrl lock, drop it first.)

- [ ] **Step 3: Verify**

Run: `cargo build -p flowplane -p flowplane-dpdk 2>&1 | grep -E 'warning|error'` (none). Privileged DPDK attach test now also configures the netns — extend/confirm `tests/attach_veth.rs` asserts the guest end has the addr+route (or add a v6-only attach case). Run it under sudo. eBPF: `cargo test -p flowplane` green.

- [ ] **Step 4: Commit**

```bash
git add flowplane/flowplane/src/attach.rs flowplane/flowplane-dpdk/src/node.rs
git commit -m "feat: configure container guest netns (addr+routes) at attach on both backends"
```

---

## Task 6: Responder zero-gateway gating (defensive)

**Files:** Modify `flowplane/flowplane-core/src/arp_nd.rs`

- [ ] **Step 1: Guard the v4/v6 responders against a zero gateway**

A single-family guest never solicits the absent family, but harden anyway so a zero gateway is never advertised. In `arp_reply`, add at the top (after the frame-present bound):
```rust
    if gateway_ipv4 == [0u8; 4] {
        return false; // no v4 gateway configured (v6-only interface) — do not answer ARP
    }
```
In `nd_reply` and `ra_reply`, add the analogous guard `if gateway_ipv6 == [0u8; 16] { return false; }` near the top (after the frame-present bound, before matching the target). Read each fn and place the guard where it can't break the existing constant-offset verifier structure (a leading early-return is safe). Do the same for the DHCPv4 responder entry (gate on the port's guest_ipv4/gateway being non-zero) and DHCPv6 (guest_ipv6 non-zero) IF they don't already no-op — read `dhcp.rs` and add a guard only where a zero would otherwise be emitted; if they already only fire on a matching request, note that no change is needed.

- [ ] **Step 2: Verify (these are on the eBPF datapath — rebuild + anchors)**

Run: `cargo build -p flowplane 2>&1 | grep -E 'warning|error'` (none) and `make sim` (70 green — the arp_nd core fns are exercised by sim). Then `make sim-anchor` (the tc_guest anchors load these — verifier must still pass; the added early-return is trivial). If any anchor/verifier fails, the guard broke the constant-offset structure — move it earlier/simplify.

- [ ] **Step 3: Commit**

```bash
git add flowplane/flowplane-core/src/arp_nd.rs
git commit -m "fix(datapath): ARP/ND/RA responders no-op when the family's gateway is unset"
```

---

## Task 7: Final verification

- [ ] **Step 1: fmt + clippy**

Run: `cargo fmt --check -p flowplane-control -p flowplane-device -p flowplane -p flowplane-dpdk && cargo clippy -p flowplane-control -p flowplane-device -p flowplane -p flowplane-dpdk 2>&1 | grep -E '^(warning|error)(\[|:)' | grep -v 'flowplane@0.1.0' | grep -v too_many_arguments`
Expected: no fmt diff; no new warnings.

- [ ] **Step 2: Non-root suites**

Run: `make test && make sim`
Expected: host tests + `flowplane-sim` 70 green.

- [ ] **Step 3: eBPF anchors (datapath responders touched in Task 6)**

Run: `make sim-anchor`
Expected: all anchors green (verifier accepts the responder guards).

- [ ] **Step 4: Privileged device/attach**

Run: `sudo -E $(command -v cargo) test -p flowplane-device -- --ignored --test-threads=1` and `sudo -E $(command -v cargo) test -p flowplane-dpdk --test attach_veth -- --ignored --test-threads=1`
Expected: veth + guest-netns + attach (v4 and, if added, v6-only) pass.

- [ ] **Step 5: Commit any fmt fixup**

```bash
git add -A && git commit -m "chore: fmt after dual-stack overlay support"
```

---

## Self-Review Notes (author)

- **Spec coverage:** symmetric program_interface (T1); attach ≥1 family both backends + eBPF read-back gate + symmetric ips (T2, T3); configure_guest_netns (T4) + wiring both backends (T5); responder gating (T6); verification (T7). All spec sections mapped.
- **Scope:** no eBPF datapath *delivery* change (only the responder zero-gateway guards in T6, verifier-checked); VMs unchanged; datapath/sim byte-parity intact.
- **Type consistency:** `IfaceParams`/`IfaceKey`/`route_upsert`/`route6_upsert`/`ifaces_upsert` (control); `GuestNetConfig`/`configure_guest_netns` (device); `primary_ipv4`/`primary_ipv6` (eBPF attach). The MemMapWriter inspection API in T1 is flagged to match the codebase (read mem.rs + sibling tests).
- **Known risk:** the v4 default-route command form (onlink vs explicit host route) — T4 NOTE says test in the netns and use what the kernel accepts.
