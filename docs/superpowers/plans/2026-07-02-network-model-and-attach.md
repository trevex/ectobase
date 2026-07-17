# Network Model + Underlay + Real Attach — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the placeholder overlay IPAM with real **underlay `/128`-from-inferred-`/64`** allocation, add the `net.ectobase.dev/v1alpha1` CRD types (`VPC`, `NetworkInterface`), extend the `dataplane.v1` gRPC with `underlay_route`, implement the real `AttachInterface`, and stand up a **containerlab IPv6-fabric e2e harness** so underlay inference is testable end-to-end.

**Architecture:** The node agent (`flowplane`, Rust) infers its host underlay `/64` from the loopback/dummy fabric IPv6 (the kubelet IP in an unnumbered IPv6 BGP fabric) and hands out `/128`s to VM endpoints; the CNI (later) resolves `VPC`/`NetworkInterface` CRDs and calls `AttachInterface{vni, overlay_ips}`. Testing uses nix (Rust), Go unit/envtest (CRDs), netns (attach), and **containerlab + kind** (IPv6 fabric e2e).

**Tech Stack:** Rust (aya, tonic, rtnetlink/ip), Go (`apiserver-kit`, controller-runtime), protobuf/gRPC, containerlab + FRR + kind, KubeVirt.

**Parent spec:** `docs/superpowers/specs/2026-07-02-network-api-design.md`
**Supersedes:** the overlay allocator in `flowplane/src/ipam.rs` (commit `10df2ff`).

---

## File Structure

- `flowplane/src/underlay.rs` — **Create**: pure `infer_underlay_prefix()` + `UnderlayIpam` (`/128` from `/64`). Replaces `ipam.rs`.
- `flowplane/src/ipam.rs` — **Delete** (overlay allocator, wrong abstraction).
- `flowplane/src/main.rs` — **Modify**: `mod underlay;` (drop `mod ipam;`).
- `api/proto/dataplane/v1/dataplane.proto` — **Modify**: add `underlay_route` to `AttachInterfaceResponse`.
- `api/net.ectobase.dev/v1alpha1/*.go` — **Create**: `VPC`, `NetworkInterface` types (+ deepcopy, registration).
- `flowplane/src/attach.rs` — **Create**: real `AttachInterface`/`DetachInterface` (netns + eBPF + underlay).
- `flowplane/src/node.rs` — **Modify**: call `attach`.
- `test/attach-netns.sh` — **Create**: netns attach acceptance test.
- `hack/clab/ipv6-fabric.clab.yml`, `hack/clab-up.sh` — **Create**: containerlab IPv6-fabric topology + bring-up.
- `test/e2e/fabric_test.go` — **Create**: containerlab+kind underlay-inference e2e (skips if tooling absent).

---

### Task 1: Underlay IPAM — infer host `/64`, allocate `/128`s (Rust)

**Files:** Create `flowplane/src/underlay.rs`; delete `flowplane/src/ipam.rs`; modify `flowplane/src/main.rs`.

- [ ] **Step 1: Write failing unit tests** for the *pure* inference + allocation. Create `flowplane/src/underlay.rs` starting with tests:

```rust
//! Underlay addressing: infer the host /64 from the fabric loopback, hand out /128s.
use ipnet::Ipv6Net;
use std::net::Ipv6Addr;

/// One address seen on a host interface (name, addr, prefix_len).
pub struct IfAddr { pub ifname: String, pub addr: Ipv6Addr, pub prefix_len: u8 }

#[cfg(test)]
mod tests {
    use super::*;
    fn a(n: &str, ip: &str, p: u8) -> IfAddr { IfAddr{ ifname:n.into(), addr:ip.parse().unwrap(), prefix_len:p } }

    #[test]
    fn infers_global_unicast_64_prefers_loopback_dummy() {
        let addrs = vec![
            a("eth0", "fe80::1", 64),                 // link-local: skip
            a("lo",   "::1", 128),                    // loopback host: skip
            a("dummy0","2001:db8:fefe:1::1", 64),     // fabric loopback: PICK
            a("eth0", "2001:db8:aaaa::5", 64),        // uplink: not preferred
        ];
        assert_eq!(infer_underlay_prefix(&addrs).unwrap(),
                   "2001:db8:fefe:1::/64".parse::<Ipv6Net>().unwrap());
    }

    #[test]
    fn allocates_128s_and_reuses_on_release() {
        let mut ip = UnderlayIpam::new("2001:db8:fefe:1::/64".parse().unwrap());
        let x = ip.allocate().unwrap();
        let y = ip.allocate().unwrap();
        assert_ne!(x, y);
        ip.release(x);
        assert_eq!(ip.allocate().unwrap(), x); // lowest free reused
    }

    #[test]
    fn none_when_no_global_unicast() {
        let addrs = vec![a("eth0","fe80::1",64), a("lo","::1",128)];
        assert!(infer_underlay_prefix(&addrs).is_none());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail.** Run: `nix develop --command cargo test -p flowplane underlay` — Expected: FAIL (`infer_underlay_prefix`/`UnderlayIpam` undefined).

- [ ] **Step 3: Implement the pure logic.**
  - `infer_underlay_prefix(&[IfAddr]) -> Option<Ipv6Net>`: filter to **global unicast** (exclude link-local `fe80::/10`, loopback `::1`, ULA optional), truncate each to its `/64`; **prefer** an address on a `lo`/`dummy*` interface, else the first global-unicast `/64`. Return the `/64`.
  - `UnderlayIpam { prefix: Ipv6Net, used: BTreeSet<u128>, next: u128 }`: `new(prefix)`, `allocate() -> Option<Ipv6Addr>` (lowest free host in the `/64`, skipping the all-zeros subnet-router anycast), `release(Ipv6Addr)`.

- [ ] **Step 4: Run tests to verify they pass.** Run: `nix develop --command cargo test -p flowplane underlay` — Expected: PASS (3 tests).

- [ ] **Step 5: Add the real host reader + a root-gated netns test.** Add `pub fn read_host_ifaddrs() -> anyhow::Result<Vec<IfAddr>>` (use the `rtnetlink` crate, or shell out to `ip -6 -o addr`). Add an `#[ignore]`-marked test `infers_from_dummy_iface` that (when run as root) creates a netns + `dummy0` with `2001:db8:fefe:9::1/64`, calls `read_host_ifaddrs()` + `infer_underlay_prefix()`, asserts `2001:db8:fefe:9::/64`. Document `cargo test -p flowplane -- --ignored` needs root.

- [ ] **Step 6: Delete the old overlay allocator.** `git rm flowplane/src/ipam.rs`; in `flowplane/src/main.rs` replace `mod ipam;` with `mod underlay;`. Run: `nix develop --command cargo build -p flowplane && nix develop --command cargo test -p flowplane` — Expected: PASS, no dangling `ipam` references.

- [ ] **Step 7: Commit** (explicit paths only — the tree has unrelated uncommitted docs; never `git add -A`):
```bash
git add flowplane/src/underlay.rs flowplane/src/main.rs flowplane/Cargo.toml Cargo.lock
git rm flowplane/src/ipam.rs
git commit -m "feat(underlay): infer host /64 from fabric loopback + /128 IPAM (replaces overlay ipam)"
```
Verify `git show --stat HEAD` shows only those files.

---

### Task 2: `dataplane.v1` — add `underlay_route` to `AttachInterfaceResponse`

**Files:** Modify `api/proto/dataplane/v1/dataplane.proto`; regen Rust + Go.

- [ ] **Step 1: Add the field.** In `AttachInterfaceResponse`, add:
```proto
    string underlay_route = 5; // allocated underlay /128 the overlay encaps to
```

- [ ] **Step 2: Regenerate + verify Rust.** Run: `nix develop --command cargo build -p flowplane` — Expected: PASS.

- [ ] **Step 3: Regenerate + verify Go.** Run: `make proto-go && go build ./cni/...` — Expected: PASS (regenerated `cni/gen/dataplanev1/*` compiles).

- [ ] **Step 4: Commit.**
```bash
git add api/proto/dataplane/v1/dataplane.proto cni/gen
git commit -m "feat(api): add underlay_route to AttachInterfaceResponse"
```
Verify the commit contains only the proto + regenerated Go stubs.

---

### Task 3: Real `AttachInterface`/`DetachInterface` (Rust)

**Integration-heavy** (touches the existing eBPF maps/loader). Begins with a codebase-read step; acceptance is a netns test.

**Files:** Create `flowplane/src/attach.rs`, `test/attach-netns.sh`; modify `flowplane/src/node.rs`, `flowplane/src/main.rs`.

- [ ] **Step 1: Read the existing datapath internals.** Read `flowplane/src/maps.rs` and `flowplane/src/loader.rs` (and `grpc.rs` for how the legacy `CreateInterface` programs an endpoint) to learn the exact map types + helper signatures for: programming an interface endpoint `{vni, overlay_ip, mac, ifindex, underlay_route}` and attaching the tc/XDP program. **Report the signatures you will use before writing code** (this is the integration surface).

- [ ] **Step 2: Write the failing netns acceptance test.** Create `test/attach-netns.sh` that: creates a netns `attach-t`; starts `flowplane` serving `DataplaneNode`; calls `AttachInterface{interface_id:"t0", netns_path:/var/run/netns/attach-t, vni:100, requested_ips:["10.0.0.10"]}` via `grpcurl`; asserts (a) a veth/tap exists in the netns, (b) the response `underlay_route` is a `/128` inside the host's inferred `/64`, (c) the eBPF endpoint map contains `{vni:100, ip:10.0.0.10 → underlay_route}`. Print `PASS`/`FAIL`. Run: `sudo test/attach-netns.sh` — Expected: FAIL (`attach_interface` still `unimplemented`).

- [ ] **Step 3: Implement `attach.rs`.** `attach_interface(req, &mut UnderlayIpam, &BpfMaps) -> AttachInterfaceResponse`:
  1. allocate MAC (if empty) + an underlay `/128` via `UnderlayIpam` (Task 1);
  2. create the veth pair, move one end into `netns_path`, name it, set MAC/up;
  3. program the eBPF endpoint map for `{vni, overlay_ip, mac, ifindex, underlay_route}` reusing `maps.rs` (per Step 1);
  4. attach tc/XDP via `loader.rs` helpers;
  5. return `{ifname, ips, mac, gateway, underlay_route}`.
  `detach_interface` reverses it. Wire both into `node.rs` (replace the `unimplemented!` stubs), threading a shared `UnderlayIpam` (init from `underlay::read_host_ifaddrs()` at startup).

- [ ] **Step 4: Run the netns test to verify it passes.** Run: `sudo test/attach-netns.sh` — Expected: `PASS`.

- [ ] **Step 5: No-regression.** Run: `nix develop --command cargo test -p flowplane` — Expected: PASS.

- [ ] **Step 6: Commit.**
```bash
git add flowplane/src/attach.rs flowplane/src/node.rs flowplane/src/main.rs test/attach-netns.sh
git commit -m "feat(attach): real AttachInterface with underlay allocation + eBPF programming"
```

---

### Task 4: CRD Go types for `net.ectobase.dev/v1alpha1` (`VPC`, `NetworkInterface`)

**Independent** of Tasks 1-3 (consumed by the CNI later). Begins with an `apiserver-kit` research step.

**Files:** Create `api/net.ectobase.dev/v1alpha1/{groupversion_info.go, vpc_types.go, networkinterface_types.go, zz_generated.deepcopy.go}`; a Go module for the API if needed.

- [ ] **Step 1: Research `apiserver-kit` conventions.** Read `github.com/opendefensecloud/apiserver-kit` (WebFetch its README + an example) to learn how it wants API types defined and registered (scheme builder, storage, whether it uses controller-gen deepcopy, how a group/version is wired). **Report the conventions before implementing.**

- [ ] **Step 2: Write a failing round-trip test.** In `api/net.ectobase.dev/v1alpha1/types_test.go`, marshal a `VPC` and a `NetworkInterface` (populated per the spec) to JSON and back, asserting field fidelity (`spec.vni`, `spec.defaultPolicy`; `spec.vpcRef`, `spec.ips`, `status.underlayRoute`). Run: `go test ./api/...` — Expected: FAIL (types undefined).

- [ ] **Step 3: Implement the types** per `docs/superpowers/specs/2026-07-02-network-api-design.md` §3.1-3.2:
  - `VPC`: `Spec{ VNI *int32; DefaultPolicy *string /*Allow|Deny*/ }`, `Status{ VNI int32; State string }`.
  - `NetworkInterface`: `Spec{ VPCRef LocalObjectReference; IPs []string; NodeName *string }`, `Status{ VNI int32; UnderlayRoute string; Port *PortStatus; State string }`.
  - GroupVersion `net.ectobase.dev/v1alpha1`; scheme builder + deepcopy (controller-gen or hand-written) per Step 1's findings.
  Scaffold (empty structs + TODO markers acceptable **only as separate files**) for `VPCPeering`, `NetworkPolicy`, `LoadBalancer`, `NATGateway`, `VirtualIP` — but do NOT flesh them out (YAGNI for this plan).

- [ ] **Step 4: Run the test to verify it passes.** Run: `go test ./api/...` — Expected: PASS.

- [ ] **Step 5: Commit.**
```bash
git add api/net.ectobase.dev go.work
git commit -m "feat(api): net.ectobase.dev/v1alpha1 VPC + NetworkInterface types"
```

---

### Task 5: containerlab IPv6-fabric e2e harness

**Test infrastructure.** Research-led; the e2e **skips** if `containerlab`/`kind` are absent (consistent with `test/e2e/kind_test.go`).

**Files:** Create `hack/clab/ipv6-fabric.clab.yml`, `hack/clab-up.sh`, `test/e2e/fabric_test.go`.

- [ ] **Step 1: Research containerlab + kind + IPv6 BGP-unnumbered.** WebFetch containerlab docs for (a) its `kind` node/deploy support, (b) a minimal **FRR** IPv6 unnumbered BGP leaf topology that advertises a per-node loopback `/64`. **Report the topology approach before writing it.**

- [ ] **Step 2: Write the fabric topology + bring-up.** `hack/clab/ipv6-fabric.clab.yml`: ≥2 FRR leaf nodes running BGP unnumbered over IPv6, each with a loopback `/64` (e.g. `2001:db8:fefe:1::/64`, `:2::/64`), and kind node(s) attached so the kind node's dummy/loopback sits in the fabric. `hack/clab-up.sh`: `containerlab deploy -t hack/clab/ipv6-fabric.clab.yml` (idempotent) + a matching `clab destroy`.

- [ ] **Step 3: Write the e2e test (skips if tooling absent).** `test/e2e/fabric_test.go` `TestUnderlayInferenceOnFabric`: if `containerlab` or `kind` missing → `t.Skip`. Else bring up the fabric+kind, deploy `flowplane` as a DaemonSet, and assert a node **infers a `/64` matching its fabric loopback** (e.g. exec `flowplane` a debug subcommand or read a log line reporting the inferred prefix). Tear down.

- [ ] **Step 4: Verify.** Run: `cd test/e2e && go test -run TestUnderlayInferenceOnFabric -v` — Expected: PASS if tooling present, else SKIP. Also `go vet ./test/e2e/...` passes.

- [ ] **Step 5: Commit.**
```bash
git add hack/clab hack/clab-up.sh test/e2e/fabric_test.go
git commit -m "test(e2e): containerlab IPv6-fabric harness for underlay inference"
```

---

## Notes for the executor

- **Environment:** nix provides the Rust toolchain (`nix develop --command cargo ...`); Go 1.26 is on PATH (modules pinned `go 1.23`). `kind`/`containerlab` are NOT installed here — Task 5's e2e is expected to **SKIP**; that is a passing outcome.
- **Commit hygiene (every task):** the working tree has unrelated uncommitted design docs — **never `git add -A`/`git add .`**; stage explicit paths and verify each commit with `git show --stat HEAD`.
- **Integration/research tasks (3, 4, 5):** report the discovered interface/conventions *before* writing code; if genuinely blocked (e.g. `apiserver-kit` API unclear, eBPF map surface opaque), stop and report `NEEDS_CONTEXT` rather than guessing.
