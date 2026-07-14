# D8 — North-South Egress Fabric E2E (real ranges + NAT64 interop) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove, on the live containerlab fabric, that an overlay VM egresses to the **real internet** through its own hypervisor's distributed SNAT and a WAN-edge `xdp-dp` sidecar — for both **NAT44** (v4 guest → v4 internet) and **NAT64** (v6 guest → v4 internet) — and that returns route back statelessly via NEIGHBOR_NAT.

**Architecture:** The datapath (D7, shipped) is done; D8 (a) completes the D6 **control-plane wiring** so the running agent programs local SNAT + announces/learns NAT blocks, (b) builds the **clabwan-style WAN edge** (a linux node kernel-forwarding egress + `xdp-dp --role edge` + an agent sidecar sharing its netns; masquerade-to-real-internet lives on the **host** clabwan bridge, keyed on the `nat_ip` source range), and (c) drives the **e2e** with real TEST-NET ranges. NAT64 is done by the source hypervisor's `nat64.rs` (no Tayga needed); the edge only sees IPv4 `nat_ip` flows.

**Tech Stack:** Go (netplane agent + NATGateway controller), Rust/aya (xdp-dp, already built), containerlab + kind + FRR + nftables (fabric + clabwan host masquerade), bash/Go e2e.

**Spec:** `docs/superpowers/specs/2026-07-14-north-south-gateway-design.md` (§5 egress data flow). **Parent plan:** `docs/superpowers/plans/2026-07-14-north-south-egress.md` (D7 = commit `ce70524`).

---

## Discovered state & gaps (read first — this reshapes D8)

Verified 2026-07-14 while planning:

1. **D6 NAT reconcile is unit-tested but NOT wired into the running agent.** `netplane/agent/natreconcile.go::DesiredNat` and `bus.go::AnnounceNat`/`applyNat` exist and pass `natreconcile_test.go`, but `netplane/agent/reconcile.go` never calls `DesiredNat` and never calls the dataplane `AddNatSource`. → **Task A2.**
2. **The NATGateway controller is not deployed.** `netplane/controllers/natgateway.go` has `Reconcile()`/`Sync()` but no `SetupWithManager` and no binary runs it. `NATGateway.Status.Allocations` is never populated at runtime. → **Task A1.**
3. **No `external=true` default route is announced.** `bus.go::announce()` sets `external:false` for host routes; nothing announces `0.0.0.0/0 → edge-underlay, external=true` (nor `::/0` for NAT64 guests via the 64:ff9b path). → **Task A3.**
4. **The edge learns NEIGHBOR_NAT via a normal agent.** `bus.go::applyNat` already calls `AddNeighborNat` for every non-local block. Running a stock agent on the edge (no local sources → `DesiredNat` returns empty) programs all blocks as neighbor-nat. → **Task B4.**
5. **NAT64 is distributed (source hv), not at the edge.** `xdp-dp-ebpf/src/nat64.rs` + `v6.rs:93` translate `64:ff9b::/96` → IPv4 + SNAT on `guest_tx`. The edge sees only IPv4 `nat_ip`. **Tayga is not needed.**
6. **NAT66 is unimplemented** (no v6 egress SNAT, no v6 `wan_rx`). **Out of scope** — noted as a follow-up.
7. **T4 addressing (must fix):** the shipped topology uses `wan-edge` CGNAT `100.64.0.0/24` → `wan-server` `203.0.113.10`, but `203.0.113.0/24` (TEST-NET-3) is exactly a natural `nat_ip` pool. The `nat_ip` pool MUST differ from every test target. → **Task B1** picks `nat_ip` = `203.0.113.0/28` and real targets reached via clabwan host masquerade (no toy `wan-server`).

## Design decisions

| # | Decision | Rationale |
|---|----------|-----------|
| E1 | **Edge = one linux node kernel-forwarding + `xdp-dp --role edge` + agent, both sharing its netns** (`network-mode: container:<edge>`) | Mirrors the k8s DS + the D7 harness (edge kernel forwards egress; `wan_rx` catches returns). No VyOS image dependency; VyOS's role (BGP + forward) is filled by FRR-in-node + the kernel. |
| E2 | **Masquerade-to-real-internet lives on the HOST clabwan bridge**, keyed on the `nat_ip` source range (icn/sandbox `wan-up.sh` model) | Resolves the plan spike: the edge does NOT masquerade `nat_ip` (so `wan_rx` sees the plain return); the host does the last hop to the real WAN (works over wifi/eth/vpn). |
| E3 | **No Tayga.** NAT64 is the source hv's `nat64.rs` | The edge is family-agnostic — it only forwards/returns IPv4 `nat_ip`. |
| E4 | **`nat_ip` pool = `203.0.113.0/28`**, real internet target = a stable public IP (e.g. `1.1.1.1`) + a NAT64 name | Disjoint from any overlay/underlay/test address (fixes the T4 collision). |
| E5 | **NAT66 out of scope** | Datapath gap (no v6 SNAT). Follow-up plan. |

## File Structure

**Control plane (Go):**
- `netplane/agent/reconcile.go` — call `DesiredNat` + program `AddNatSource` + `AnnounceNat`; announce the external default route (Modify).
- `netplane/cmd/agent/main.go` — pass the dataplane client + underlay into the NAT reconcile (Modify).
- `netplane/controllers/natgateway.go` — add `SetupWithManager` (Modify).
- `netplane/cmd/controller/main.go` — a controller-manager binary running the NATGateway reconciler (Create).
- `config/deploy/controller.yaml` — Deployment for the controller (Create).
- `config/samples/e2e-natgateway.yaml` — a `NATGateway` + external default route sample (Create).

**Fabric + edge (containerlab):**
- `hack/clab/wan-up.sh` — create the `clabwan` host bridge + nft masquerade keyed on `nat_ip`/underlay ranges + host return routes (Create; adapt icn/sandbox `scripts/wan-up.sh`).
- `hack/clab/wan-down.sh` — teardown (Create).
- `hack/clab/ipv6-fabric.clab.yml` — replace `wan-edge`/`wan-server` with the `edge` linux node + `edge-xdp` + `edge-agent` sidecars (`network-mode: container:edge`) + the `clabwan` bridge link (Modify).
- `hack/clab/frr/edge.conf` — FRR on the edge: eBGP to sw1/sw2, originate the `nat_ip` /28 + a default (Create).
- `hack/clab-up.sh` — call `wan-up.sh`; render the edge startup (Modify).

**E2E:**
- `test/e2e/egress_test.go` — NAT44 + NAT64 real-internet reachability + return-path assertions (Create).

**Reuse (do NOT reimplement):** `xdp-dp --role edge` + `wan_rx` + local-deliver (D7, `ce70524`); `test/edge-netns.sh` (the datapath proof); `DesiredNat`/`AnnounceNat`/`applyNat` (D6); `natgateway.go::Sync` + `allocator` (D5); `nat64.rs` (NAT64).

---

## Phase A — Complete the control-plane wiring (no fabric yet)

### Task A1: Run the NATGateway controller

**Files:** Modify `netplane/controllers/natgateway.go`; Create `netplane/cmd/controller/main.go`, `config/deploy/controller.yaml`.

- [ ] **Step 1: Add `SetupWithManager`** to `netplane/controllers/natgateway.go`:

```go
func (r *NATGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1alpha1.NATGateway{}).
		Watches(&netv1alpha1.NetworkInterface{}, handler.EnqueueRequestsFromMapFunc(r.natgwsForNIC)).
		Complete(r)
}
```

Add `natgwsForNIC(ctx, obj) []reconcile.Request` returning every `NATGateway` in the object's namespace (an NIC add/change must re-run allocation). Match the import/style of any existing `SetupWithManager` in `netplane/controllers/` (read one first).

- [ ] **Step 2: Write the controller binary** `netplane/cmd/controller/main.go`: a standard controller-runtime manager (`ctrl.NewManager` with the scheme registering `netv1alpha1`), calling `(&controllers.NATGatewayReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr)`, then `mgr.Start(ctrl.SetupSignalHandler())`. Model on `netplane/cmd/reflector/main.go` for flag/kubeconfig handling.

- [ ] **Step 3: Build.** Run: `nix develop --command sh -c 'cd netplane && GOWORK=off go build ./cmd/controller/'` → builds.

- [ ] **Step 4: Deployment manifest** `config/deploy/controller.yaml`: a single-replica Deployment (image `ghcr.io/trevex/netplane:dev`, command the controller binary), pinned to the central cluster's control-plane, using the existing `netplane-agent`/a controller ServiceAccount + RBAC (reuse `config/deploy/rbac.yaml`; add `natgateways`/`natgateways/status` verbs if absent). hostNetwork like the reflector (so it reaches the apiserver over the fabric).

- [ ] **Step 5: Commit** (`feat(netplane): run the NATGateway controller (deterministic allocations)`).

### Task A2: Wire the agent NAT reconcile loop

**Files:** Modify `netplane/agent/reconcile.go`, `netplane/cmd/agent/main.go`; Test `netplane/agent/reconcile_nat_test.go`.

**Context:** `DesiredNat(ctx, c, nodeID, underlay) → ([]NatSource, []NatBlock)` already exists. The agent must, each reconcile: program every local `NatSource` via the dataplane `AddNatSource`, and `AnnounceNat` every local `NatBlock` on the routebus session. `applyNat` (already wired in `bus.go::Run`) handles the learn side.

- [ ] **Step 1: Failing test** `reconcile_nat_test.go`: with a fake client holding a `NATGateway{Status.Allocations:[{Source:10.0.0.1,PublicIP:203.0.113.1,PortMin:1024,PortMax:2048}]}` and a local NIC `10.0.0.1@vni100` on `nodeA`, assert the reconcile calls a fake dataplane's `AddNatSource(vni=100, src=10.0.0.1, nat=203.0.113.1, 1024, 2048)` exactly once and enqueues an `AnnounceNat` with `owner_underlay=<nodeA underlay>`. Model the fakes on `natreconcile_test.go`.

- [ ] **Step 2: Run → FAIL** (`nix develop --command sh -c 'cd netplane && GOWORK=off go test ./agent/ -run Nat'`).

- [ ] **Step 3: Implement.** In `reconcile.go` where the agent computes desired state (near the `external=true` comment at line 80), call `DesiredNat`, then for each `NatSource` call `r.dp.AddNatSource(...)` (add to the `Dataplane` interface if absent — mirror `AddRoute`), and stage each `NatBlock` for `AnnounceNat` on the session (thread through the same path `announce()` uses). Idempotency: `AddNatSource` already deletes-then-adds (node.rs).

- [ ] **Step 4: Run → PASS**; **Step 5:** wire `main.go` to pass the dataplane client + resolved underlay into the reconciler (they already exist for routes). **Step 6: Commit** (`feat(agent): program local egress SNAT + announce NAT blocks`).

### Task A3: Announce the external default route

**Files:** Modify `netplane/controllers/natgateway.go` (or a small VPC default-route reconciler); Test.

**Context:** For the source datapath to SNAT+encap egress to the edge, the source's VNI needs `0.0.0.0/0 → edge-underlay, external=true` (and, for NAT64 v6 guests, `64:ff9b::/96 → edge-underlay, external=true`). The controller knows the NATGateway; it must announce this default (via the reflector, so the agent installs it with `AddRoute(..., external=true)`).

- [ ] **Step 1: Decide the source of the edge underlay** — a field on `NATGateway.Spec` (e.g. `EdgeUnderlay string`) OR a well-known `NatBlock`-style record. Add `Spec.EdgeUnderlay` (simplest; the e2e sets it to the edge's /128).

- [ ] **Step 2: Failing test** — the controller, given `Spec.EdgeUnderlay=fd00:db8:0:9::e`, produces a desired external route `0.0.0.0/0 → fd00:db8:0:9::e (external)` for the VPC's VNI (and `64:ff9b::/96 → same` when any v6 source exists). Assert the reflector receives an `Announce{prefix:"0.0.0.0/0", external:true, nexthop:...}`.

- [ ] **Step 3: Implement** the announce (the controller dials the reflector like the agent, or writes it as a route CR the agent announces — pick the pattern already used for LB VIP announcement if one exists; else controller→reflector direct). **Step 4: PASS. Step 5: Commit** (`feat(netplane): announce external default route to the WAN edge`).

### Task A4: MILESTONE — netns control-plane smoke (no fabric)

**Files:** Create `test/nat-controlplane-netns.sh` (or extend `test/nat-netns.sh`).

- [ ] Bring up a reflector + a source `xdp-dp serve` + an edge `xdp-dp serve --role edge` in netns; run the controller + two agents (source + edge) against a fake/kind apiserver holding a `VPC`+`NATGateway`+`NetworkInterface`. Assert: source logs `NAT source …`; source announces a NatBlock; edge logs `NEIGHBOR_NAT add …` (learned via routebus); source installs `ROUTE add … external`. This proves the whole control plane end-to-end before the fabric. **Commit.**

---

## Phase B — clabwan WAN edge on the fabric

### Task B1: clabwan host bridge + masquerade

**Files:** Create `hack/clab/wan-up.sh`, `hack/clab/wan-down.sh`.

**Context:** Adapt `/home/nik/Development/icn/sandbox/scripts/wan-up.sh`. Ranges: `clabwan` = `172.29.0.1/24` + `fd00:29::1/64`; the edge attaches at `fd00:29::11` / `172.29.0.11`. Masquerade the **`nat_ip` pool** `203.0.113.0/28` (and the underlay `fd00:db8::/48` for native-v6 if used) out the host's real uplink; add a host return route `203.0.113.0/28 via 172.29.0.11` (to the edge).

- [ ] **Step 1: Write `wan-up.sh`**: create bridge `clabwan`, addr `172.29.0.1/24` + `fd00:29::1/64`, up; `sysctl net.ipv4.ip_forward=1`; nft:
```bash
nft -f - <<'EOF'
table inet clabwan {
  chain postrouting {
    type nat hook postrouting priority srcnat;
    ip saddr 203.0.113.0/28 oifname != "clabwan" masquerade
  }
}
EOF
ip route replace 203.0.113.0/28 via 172.29.0.11 dev clabwan
```
- [ ] **Step 2: `wan-down.sh`** deletes the table + bridge. **Step 3: Validate** `wan-up.sh` runs cleanly + `nft list table inet clabwan` shows the rule. **Step 4: Commit** (`feat(clab): clabwan host bridge + nat_ip masquerade for real-internet egress`).

### Task B2: Replace wan-edge/wan-server with the edge + sidecars

**Files:** Modify `hack/clab/ipv6-fabric.clab.yml`, `hack/clab-up.sh`; Create `hack/clab/frr/edge.conf`.

- [ ] **Step 1:** Remove `wan-server`; retarget `wan-edge` → `edge` (kind linux, an FRR-capable image). Give `edge`: `eth1`/`eth2` to sw1/sw2 (fabric, dual-homed like the hosts), `eth3` to `clabwan` (WAN). Assign the edge underlay `/128` (e.g. `fd00:db8:0:9::e` on dummy0) and `172.29.0.11/24` on `eth3`; `ip_forward=1`; default route `via 172.29.0.1 dev eth3`.
- [ ] **Step 2: `edge-xdp` sidecar** node: `image: ghcr.io/trevex/dpservice-xdp:dev`, `network-mode: container:edge`, command `serve --role edge --uplink eth1 --wan-uplink eth3 --local-underlay fd00:db8:0:9::e --gateway 169.254.0.1 --gateway-mac <sw1 mac>` with `XDP_DP_SKB_MODE=1` (veths). (Resolve the ToR MAC dynamically like the DS wrapper.)
- [ ] **Step 3: `edge-agent` sidecar** node: `image: ghcr.io/trevex/netplane:dev`, `network-mode: container:edge`, running the agent with `--node-id edge` pointed at the central apiserver + reflector over the fabric (reuse the brokered-agent kubeconfig pattern from `hack/multicluster-e2e.sh`). It learns NEIGHBOR_NAT (Task B4).
- [ ] **Step 4: `edge.conf`** FRR: unnumbered eBGP on eth1/eth2 to sw1/sw2; `network fd00:db8:0:9::e/128`; originate the `nat_ip` reachability the WAN needs (the host route already covers clabwan; BGP into the fabric announces the edge underlay so hosts route encap to it). **Step 5:** wire `hack/clab-up.sh` to call `wan-up.sh`. **Step 6: Validate** topology parses (`containerlab inspect`). **Commit** (`feat(clab): WAN edge = kernel-forward + xdp-dp+agent sidecars (clabwan)`).

### Task B3: Bring up the fabric + confirm edge datapath attaches

- [ ] Destroy any stale fabric (`sudo containerlab destroy -t hack/clab/ipv6-fabric.clab.yml --cleanup`; `docker rm -f` orphans per [[k8s-deploy-fabric-e2e]]), `wan-up.sh`, then `clab-up.sh`. Assert: `edge-xdp` logs `edge role: wan_rx attached …` + `serving DPDKironcore`; `edge` BGP sessions Established to sw1/sw2; the edge underlay `/128` is in the hosts' FIB. **Commit** none (a live-bring-up checkpoint).

### Task B4: Edge learns NEIGHBOR_NAT via its agent

- [ ] Confirm `edge-agent` subscribes to the reflector and, when a source announces a NatBlock, calls `AddNeighborNat` on `edge-xdp` (`bus.go::applyNat`). Assert `edge-xdp` logs `NEIGHBOR_NAT add …` after a source NATGateway allocation lands. If the edge agent tries to program local sources (it shouldn't — no local NICs), confirm `DesiredNat` returns empty for `--node-id edge`. **Commit** any wiring fix.

---

## Phase C — MILESTONE: NAT44 egress to the real internet

**Files:** Create `test/e2e/egress_test.go` (first half), `config/samples/e2e-natgateway.yaml`.

- [ ] **Step 1:** Apply `VPC{vni:100}` + a source `NetworkInterface` (v4 `10.0.0.1`) on a compute node + `NATGateway{vpcRef:blue, publicIPs:[203.0.113.1..], portsPerSource:1024, edgeUnderlay:fd00:db8:0:9::e}`. Attach the source endpoint (grpcurl, per [[k8s-deploy-fabric-e2e]]); set its netns dpservice-model routes.
- [ ] **Step 2:** Wait for `NATGateway.Status.Allocations` Ready; assert the source got a deterministic block; assert `edge-xdp` learned the NEIGHBOR_NAT.
- [ ] **Step 3:** From the source netns, reach a **real** public IPv4 (e.g. `curl -4 https://1.1.1.1` or ICMP). Expected: success — the source hv SNATs `10.0.0.1 → 203.0.113.1:<block>`, encaps to the edge (external default route), the edge decaps + kernel-forwards to clabwan, the host masquerades to the real WAN; the return `→ 203.0.113.1` routes to the edge, `wan_rx` re-encaps to the owner, the owner reverse-SNATs to the VM. Assert reachability + the greppable `NAT source …` / `wan_rx` path. **Commit** (`test(e2e): NAT44 overlay VM reaches the real internet via the WAN edge`).

---

## Phase D — NAT64 interop + acceptance

**Files:** Extend `test/e2e/egress_test.go`.

- [ ] **Step 1:** Attach a **v6-only** source endpoint (overlay IPv6) in the same VPC; ensure its VNI has the `64:ff9b::/96 → edge-underlay (external)` route (Task A3) and a v4 `nat_ip` block (NAT64 SNATs to a v4 nat_ip after 6→4 translation on the hv).
- [ ] **Step 2:** From the v6 source netns, reach a real IPv4 host via NAT64: `ping6 64:ff9b::1.1.1.1` (or curl a DNS64-synthesized name). Expected: `nat64.rs` translates 6→4 + SNAT on the source hv → edge → real internet → return → `wan_rx` → owner → reverse-NAT64 4→6 → v6 VM. Assert reachability.
- [ ] **Step 3 (interop matrix):** assert **NAT44** (Phase C) and **NAT64** (this task) both pass concurrently from two sources sharing the edge. Note **NAT66 is out of scope** (datapath gap; log it explicitly — no silent omission). **Commit** (`test(e2e): NAT64 interop — v6 overlay VM reaches the v4 internet via the edge`).

---

## Self-Review

**1. Spec coverage:** egress deterministic `(public-IP, port-block)` (D5 controller A1 + allocator) → local SNAT (A2) → distributed reverse map = NatBlock/NEIGHBOR_NAT (A2 announce + B4 learn) → WAN edge decap/return (D7 datapath, B2/B3) → real-internet reachability + interop (C, D). The spec's §5 egress flow is covered end-to-end; ingress/DSR/floating-IP remain out of scope (separate plans). The [[feedback-ns-edge-real-ranges-testing]] requirement (real ranges + masquerade-to-host + cross-family interop) is met by E2/E4 + Phase C/D; **NAT66** is explicitly out of scope (E5, datapath gap).

**2. Placeholder scan:** the ToR-MAC resolution (B2), the edge FRR specifics (B4/edge.conf), and the brokered edge-agent kubeconfig (B2/B3) reference live patterns the implementer reads (the DS wrapper, `hack/multicluster-e2e.sh`) — each says "reuse pattern X," not "TBD." The controller→reflector announce path (A3) says "use the pattern already used for LB VIP announcement if one exists; else controller→reflector direct" — resolve at implementation by reading the reflector client.

**3. Consistency:** `NATGateway.Spec.{PublicIPs, PortsPerSource, VPCRef, EdgeUnderlay}` (A1/A3) → allocator `Block{PublicIP,PortMin,PortMax}` → agent `AddNatSource` + `AnnounceNat{owner_underlay}` (A2) → reflector `NatUpdate` → edge `applyNat`→`AddNeighborNat` (B4) → `wan_rx` return (D7). `nat_ip` pool `203.0.113.0/28` is used consistently (B1 masquerade set, B2 NATGateway publicIPs, and is disjoint from targets `1.1.1.1`/NAT64 — E4). Names line up.

**Deferred (follow-ups):** NAT66 (v6 egress SNAT + a v6 `wan_rx`); the centralized gateway fleet + drain e2e (parent-plan T5/T7–T9); Tayga host-NAT64 (only if non-overlay host traffic ever needs it).

---

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-07-14-north-south-egress-d8-fabric-e2e.md`. Milestone at **Phase C** (NAT44 real-internet egress), acceptance at **Phase D** (NAT64 interop). Phase A (control-plane wiring) is subagent-friendly TDD; Phases B–D are controller-driven live-fabric verification. Recommended: subagent-driven for A1–A3, inline/live for A4 + B–D.
