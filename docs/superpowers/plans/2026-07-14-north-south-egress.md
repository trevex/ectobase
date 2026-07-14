# North-South Egress (Drain-Safe Gateway Fleet) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give overlay tenants **egress to the internet** through a **fleet of `xdp-dp` gateway nodes** that is **drain-safe** (any gateway removable mid-flow with ~zero impact), and prove it on the containerlab fabric — including a **mid-flow gateway-drain e2e**.

**Architecture:** A gateway-role `xdp-dp` subscribes to a dedicated **PublicVNI**, decaps tenant egress, **SNATs** to a deterministic `(public-IP, port-block)` per source, and forwards to a WAN edge. Return traffic BGP-ECMPs to *any* gateway, which routes it to the block's owner via **NEIGHBOR_NAT** (already implemented) and reverse-SNATs — **statelessly recomputed from the deterministic map when conntrack misses**, so a drain/reassignment survives. VyOS/WAN edge does BGP + physical egress. Reuses the existing NAT datapath (`create_nat`, `add_neighbor_nat`, `nat.rs`).

**Tech Stack:** Rust/aya (xdp-dp NAT datapath), Go (netplane: NATGateway CRD, port-block allocator, gateway agent, routebus PublicVNI records), containerlab/kind/FRR (fabric + WAN edge), bash/Go e2e.

**Spec:** `docs/superpowers/specs/2026-07-14-north-south-gateway-design.md`. **Scope:** EGRESS only (this plan). Ingress L4 LB + DSR and floating-IP are separate plans (the spec's §10 DSR spike gates ingress).

**Sequencing:** Tasks are ordered so a **testable single-gateway egress** milestone lands at Task 6 (VM → WAN server through a gateway on the fabric), then the **fleet + drain-safety** completes at Tasks 7–9. Each half is independently demoable.

---

## PIVOT (2026-07-14): distributed egress first

Datapath investigation showed the existing eBPF **already implements dpservice's full distributed scalable-NAT**: egress SNAT on the source's own hypervisor when the dst route `is_external` (`nat_snat_egress`, peer-independent reverse conntrack key), ingress reverse-NAT on `uplink_rx`, and **NEIGHBOR_NAT** return-routing to the block owner. `create_nat` is keyed by a *local* `interface_id`. So the **distributed** (metalnet) model is nearly free (reuse), while the *centralized gateway* is substantial new verifier-sensitive eBPF. **Decision: do distributed egress first**; revisit the centralized gateway later (its drain-safety is via VM live-migration, not a gateway-drain).

**What stands from the original tasks:** T1 (NATGateway CRD), T2 (deterministic port-block allocator), T3 (AddNatSource/AddNeighborNat RPCs — `AddNatSource` already resolves the *local* interface, exactly right for distributed), T4 (WAN edge + gateway cluster — becomes the WAN *edge* node). **Deferred:** T5 (`--role gateway` centralized), T7 (drain-safe reverse), T8 (fleet reassignment), T9 (gateway-drain e2e) — reopened when we do the centralized gateway.

**Revised remaining tasks (distributed egress):**
- **D5 — Central NATGateway controller (Go):** the port-block allocator (T2) as a controller that reconciles `NATGateway` → writes `Status.Allocations` (deterministic `(public-IP, port-block)` per selected source).
- **D6 — Node-agent NAT reconciler (Go):** each node's agent reads allocations for its *local* sources → `AddNatSource` (program local SNAT) + announces the `nat_ip` route + `AddNeighborNat` for all sources' blocks learned via routebus (return re-routing). Also distribute a default `0.0.0.0/0 → WAN-edge underlay` route marked **external** so the source datapath SNATs + encaps egress to the edge. (Needs an `is_external` flag on the route-distribution `AddRoute`/`Announce` — small extension.)
- **D7 — WAN-edge decap/forward datapath — ✅ DONE (2026-07-14, commit `ce70524`).** Shipped:
  `serve --role edge --wan-uplink`; the `wan_rx` XDP program (plain-IPv4 return →
  `neighbor_nat_lookup_any` → encap toward owner over the fabric); the egress local-deliver path
  (`uplink_rx` matches the edge underlay's new `UNDERLAY_LOCAL_DELIVER` sentinel tap → decap →
  `XDP_PASS` to the VyOS kernel); `Control::attach_edge`. **Validated** by `test/edge-netns.sh`
  (netns harness: return encaps to the owner underlay + egress decaps and reaches the WAN uplink,
  both ways) — eBPF verifier clean, node-role datapath unaffected. Design notes below stand.
  - **`--role edge`:** attach `uplink_rx` on the fabric uplink AND a new `wan_rx` XDP program on the `--wan-uplink`; register the edge's underlay `/128` in `UNDERLAY` with its "tap" = the WAN ifindex.
  - **Egress (fabric → WAN):** the source hypervisor SNATs + encaps to the edge underlay (via the external default route). At the edge, `uplink_rx` decaps (outer dst = edge underlay) and — since the underlay's tap is the WAN ifindex — delivers the decapped inner IPv4 `(src=nat_ip, dst=public)` **out the WAN uplink as plain IP** (rewrite inner eth dst = WAN next-hop MAC; `bpf_redirect(wan_ifindex)`). Mostly reuses the existing decap+deliver path.
  - **Return (WAN → fabric):** `wan_rx` sees a *plain* IPv4 (dst=`nat_ip`, **no VNI**). It does a **VNI-agnostic** `neighbor_nat_lookup(nat_ip, dport) → (owner_underlay, vni)` — the NEIGHBOR_NAT entry must be extended to **also store the owner VNI** (register with `ALL_VNI=0` for the lookup key, à la dpservice) — then **encaps** the IPv4 into IP-in-IPv6 toward `owner_underlay` with that VNI and `bpf_redirect(fabric_ifindex)`. The owner hypervisor's reverse-conntrack key `(vni,0,nat_ip,0,nat_port)` then matches and it delivers to the source VM.
  - **BGP:** the edge announces the `nat_ip` prefixes (and a default) to the WAN so returns route to it.
  - **New eBPF:** the `wan_rx` program (the vni-agnostic lookup already landed; `NeighborNatEntry` already has `vni`). **Test:** a netns harness (edge with a WAN veth + a fabric veth + a source netns) exercising egress + return both ways BEFORE the fabric e2e. Verifier-sensitive — implement carefully.

  **Edge topology (decided):** the edge = **VyOS + an `xdp-dp` sidecar sharing VyOS's netns** — the same netns-sharing pattern as the in-node FRR and the reference fabric's Tayga-on-VyOS sidecar. **VyOS owns the WAN uplink**: physical/host egress, **BGP** (announces the `nat_ip`/VIP ranges to the real WAN), routing/firewall, and the final **lab-range → host masquerade** (`clabwan` trick, so TEST-NET ranges reach the real internet). **`xdp-dp` (sidecar)** owns only the overlay: it attaches to the fabric- and WAN-facing interfaces in VyOS's netns. This **shrinks D7** because VyOS's kernel does the WAN forwarding:
  - Egress (fabric→WAN): `uplink_rx` decaps → **`XDP_PASS`** the inner IPv4 to the VyOS kernel, which routes/masquerades to the real WAN (no custom WAN-forward needed).
  - Return (WAN→fabric): `wan_rx` catches only `nat_ip`-destined plain IPv4 → `neighbor_nat_lookup_any` → encap to owner → fabric; everything else passes to VyOS.
  - **Spike/decision:** VyOS should **route the `nat_ip` range to the sidecar and NOT masquerade it** (masquerade only the last hop to the real host if off-box internet is needed), so the `nat_ip → owner` decision stays entirely in `xdp-dp`. The netns harness + fabric e2e validate this.
- **D8 — Egress e2e on the fabric (real ranges + interop):** per [[feedback-ns-edge-real-ranges-testing]] — do NOT use a toy fixed server. Revise the WAN edge (T4) to the icn/sandbox **`clabwan` model**: the edge holds **real IPv4 AND IPv6 public ranges** (the SNAT `nat_ip` pool + a v6 pool) and **masquerades them toward the actual host/internet** (host-agnostic nftables/iptables masquerade keyed on the lab source ranges) plus a **Tayga-style NAT64** translator (v6 overlay → v4 internet, `64:ff9b::/96`; our datapath has `nat64.rs`). e2e asserts a source VM reaches the **real internet** through its hypervisor SNAT + the edge, and **tests cross-family interop** (NAT44 / NAT66 / NAT64). Fix the T4 collision: the `nat_ip` pool must differ from any test target.

---

## File Structure

**Datapath (Rust, `xdp-dp`):**
- `xdp-dp/src/main.rs` — a `--role gateway` serve mode (WAN uplink + PublicVNI subscribe; no local VMs) (Modify).
- `xdp-dp/src/control.rs` / `nat.rs` — deterministic reverse-SNAT fallback: on a conntrack miss for a return packet whose `(nat_ip, dport)` matches a local NAT block, reverse-SNAT from the block→source map instead of dropping (Modify).
- `api/proto/dataplane/v1/dataplane.proto` — `AddNatSource`/`WithdrawNatSource` + `AddNeighborNat`/`WithdrawNeighborNat` on `dataplane.v1` (protocol-agnostic, like AddRoute) (Modify).
- `xdp-dp/src/node.rs` — implement those RPCs (delegate to existing `create_nat`/`add_neighbor_nat`) (Modify).

**Control plane (Go, `netplane`):**
- `api/v1alpha1/natgateway_types.go` — flesh out the scaffold (Modify).
- `api/proto/routebus/v1/routebus.proto` — a PublicVNI `NatBlock` record (nat_ip, port-block, source, owner underlay) (Modify).
- `netplane/allocator/portblock.go` — deterministic `(public-IP, port-block)` allocator + overflow (Create).
- `netplane/agent/gateway.go` — gateway agent: reconcile NATGateway → program local gateway `xdp-dp` NAT + announce/learn NatBlocks via routebus (Create).
- `netplane/cmd/gateway/main.go` — gateway binary (Create).

**Fabric + e2e:**
- `hack/clab/wan/` — WAN edge: a `wan` bridge + a NAT/router container + a test "internet" server (Create).
- `hack/clab/ipv6-fabric.clab.yml` — add a gateway node + the WAN edge (Modify).
- `test/e2e/egress_test.go` — egress reachability + mid-flow drain e2e (Create).

**Reuse (verified — do NOT reimplement):** `Control::create_nat(vni,guest_ip,nat_ip,port_min,port_max,…)` (SNAT port-block); `Control::add_neighbor_nat(...)` + `NEIGHBOR_NAT` (return-to-owner); `nat.rs` `nat_snat_egress`; conntrack (`CONNTRACK`, `CT_REWRITE_SRC/DST`); encap/decap; `uplink_rx`. The serve flags `--nat`/`--neigh-nat` already drive these for the static case.

---

### Task 1: NATGateway CRD

**Files:** Modify `api/v1alpha1/natgateway_types.go`; Test `api/v1alpha1/roundtrip_test.go`

- [ ] **Step 1: Write the failing round-trip test**

In `api/v1alpha1/roundtrip_test.go`, add a case constructing a `NATGateway` with the new fields and asserting round-trip (follow the existing test's pattern for VPC/NetworkInterface). Fields to exercise: `Spec.PublicIPs=["203.0.113.10"]`, `Spec.PortsPerSource=1024`, `Spec.VPCRef`, `Status.State`.

- [ ] **Step 2: Run it — fails to compile (fields absent)**

Run: `nix develop --command sh -c 'cd api && go test ./v1alpha1/ -run RoundTrip 2>&1 | tail -5'`
Expected: compile error (unknown fields).

- [ ] **Step 3: Flesh out the type**

Replace the scaffold `NATGatewaySpec`/`NATGatewayStatus` in `api/v1alpha1/natgateway_types.go`:

```go
// NATGatewaySpec is the desired state of a NATGateway: a drain-safe egress SNAT
// for the sources in a VPC, using deterministic (public-IP, port-block) allocation.
type NATGatewaySpec struct {
	// VPCRef selects the VPC whose interfaces egress through this gateway.
	VPCRef LocalObjectReference `json:"vpcRef" protobuf:"bytes,1,opt,name=vpcRef"`
	// PublicIPs is the pool of public IPv4s SNAT sources are mapped onto.
	PublicIPs []string `json:"publicIPs,omitempty" protobuf:"bytes,2,rep,name=publicIPs"`
	// PortsPerSource is the deterministic port-block size handed to each source
	// (RFC 7422 / GCP-static style). Default 1024.
	// +optional
	PortsPerSource *int32 `json:"portsPerSource,omitempty" protobuf:"varint,3,opt,name=portsPerSource"`
}

// NATAllocation records one source's deterministic mapping.
type NATAllocation struct {
	// Source is the overlay IP (a NetworkInterface IP) being SNATed.
	Source string `json:"source" protobuf:"bytes,1,opt,name=source"`
	// PublicIP + [PortMin,PortMax] is the deterministic block.
	PublicIP string `json:"publicIP" protobuf:"bytes,2,opt,name=publicIP"`
	PortMin  int32  `json:"portMin" protobuf:"varint,3,opt,name=portMin"`
	PortMax  int32  `json:"portMax" protobuf:"varint,4,opt,name=portMax"`
}

// NATGatewayStatus is the observed state.
type NATGatewayStatus struct {
	// Allocations is the deterministic source→block table (published to all gateways).
	// +optional
	Allocations []NATAllocation `json:"allocations,omitempty" protobuf:"bytes,1,rep,name=allocations"`
	// +optional
	State string `json:"state,omitempty" protobuf:"bytes,2,opt,name=state"`
}
```

Keep the existing `+genclient`/deepcopy markers. Regenerate deepcopy if the repo does so (`make` target or `controller-gen object`); if the roundtrip test passes without it, defer.

- [ ] **Step 4: Run tests + regen CRD**

Run: `nix develop --command sh -c 'cd api && go test ./v1alpha1/ 2>&1 | tail -3'` → PASS.
Regenerate the CRD yaml: `nix develop --command sh -c 'cd api && go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.19.0 crd paths=./... output:crd:dir=../config/crd/bases object paths=./...'` (matches Task C2's generation). Verify `config/crd/bases/net.ectobase.dev_natgateways.yaml` now has the spec fields.

- [ ] **Step 5: Commit**

```bash
git add api/v1alpha1/natgateway_types.go api/v1alpha1/zz_generated.deepcopy.go config/crd/bases/net.ectobase.dev_natgateways.yaml api/v1alpha1/roundtrip_test.go
git commit -m "feat(api): flesh out NATGateway (deterministic egress SNAT)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Deterministic port-block allocator

**Files:** Create `netplane/allocator/portblock.go`, `netplane/allocator/portblock_test.go`

**Context:** Pure logic — given a NATGateway (public IP pool + PortsPerSource) and a set of sources, deterministically assign each source a `(public-IP, [min,max])` block, collision-free (disjoint blocks), stable as sources are added (existing sources keep their block). This is the control-plane fact that makes the datapath drain-safe.

- [ ] **Step 1: Write the failing test**

Create `netplane/allocator/portblock_test.go`:

```go
package allocator

import "testing"

func TestDeterministicDisjointBlocks(t *testing.T) {
	a := New([]string{"203.0.113.10"}, 1024) // usable ports 1024..65535 => 63 blocks per IP
	b1 := a.Assign("10.0.0.5")
	b2 := a.Assign("10.0.0.6")
	if b1.PublicIP != "203.0.113.10" || b1.PortMax-b1.PortMin+1 != 1024 {
		t.Fatalf("block1 %+v", b1)
	}
	if b1.PortMin == b2.PortMin { // disjoint
		t.Fatalf("blocks overlap: %+v %+v", b1, b2)
	}
	if got := a.Assign("10.0.0.5"); got != b1 { // stable for an existing source
		t.Fatalf("reassign changed block: %+v vs %+v", got, b1)
	}
}

func TestExhaustionSpillsToNextIP(t *testing.T) {
	a := New([]string{"203.0.113.10", "203.0.113.11"}, 1024)
	seen := map[string]bool{}
	for i := 0; i < 70; i++ { // >63 forces the second IP
		b := a.Assign(ipN(i))
		seen[b.PublicIP] = true
	}
	if !seen["203.0.113.11"] {
		t.Fatal("did not spill to the second public IP")
	}
}

func ipN(i int) string { return "10.1." + itoa(i/256) + "." + itoa(i%256) }
```

(Provide a tiny `itoa` or use `strconv` — keep the test self-contained.)

- [ ] **Step 2: Run — fails (no package)**

Run: `nix develop --command sh -c 'cd netplane && go test ./allocator/ 2>&1 | tail -5'` → FAIL.

- [ ] **Step 3: Implement the allocator**

Create `netplane/allocator/portblock.go`: a struct holding the public-IP list, block size, first usable port (1024), a `map[source]Block`, and a monotonic cursor; `New(ips, size)`, `Assign(source) Block` (stable: return existing; else next free block, spilling across IPs; error/last-IP overflow if exhausted). `Block{PublicIP string; PortMin, PortMax int32}`.

- [ ] **Step 4: Run — PASS**; **Step 5: Commit**

```bash
git add netplane/allocator
git commit -m "feat(netplane): deterministic port-block allocator (drain-safe egress)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: dataplane.v1 NAT RPCs (protocol-agnostic)

**Files:** Modify `api/proto/dataplane/v1/dataplane.proto`, `xdp-dp/src/node.rs`; regenerate stubs.

**Context:** Mirror the AddRoute pattern: give `xdp-dp` protocol-agnostic RPCs the gateway agent drives, delegating to the existing `Control::create_nat` / `add_neighbor_nat`.

- [ ] **Step 1: Add RPCs + messages**

In `dataplane.proto` add to `DataplaneNode`: `AddNatSource(AddNatSourceRequest)` / `WithdrawNatSource` and `AddNeighborNat(AddNeighborNatRequest)` / `WithdrawNeighborNat`. Messages:
```proto
message AddNatSourceRequest { uint32 vni=1; string source_ip=2; string nat_ip=3; uint32 port_min=4; uint32 port_max=5; }
message AddNatSourceResponse {}
message WithdrawNatSourceRequest { uint32 vni=1; string source_ip=2; }
message WithdrawNatSourceResponse {}
message AddNeighborNatRequest { string nat_ip=1; uint32 port_min=2; uint32 port_max=3; string owner_underlay=4; uint32 vni=5; }
message AddNeighborNatResponse {}
message WithdrawNeighborNatRequest { string nat_ip=1; uint32 port_min=2; uint32 port_max=3; }
message WithdrawNeighborNatResponse {}
```

- [ ] **Step 2: Regen + red state**

Run: `nix develop --command sh -c 'export PATH=/home/nik/go/bin:$PATH && make proto-go && cargo build -p xdp-dp 2>&1 | tail -3'` → Rust fails (trait grew). Expected.

- [ ] **Step 3: Implement handlers in node.rs**

Add the four handlers, parsing IPs (reuse the `parse_prefix`/`parse_nexthop6` helpers' style; `source_ip`/`nat_ip` are IPv4, `owner_underlay` IPv6) and delegating on the blocking pool to `attach.control.create_nat(vni, source_v4, nat_v4, port_min as u16, port_max as u16, …)` / `add_neighbor_nat(nat_v4, port_min, port_max, owner_underlay_16, vni)` / their delete variants. Print greppable `NAT source …` / `NEIGHBOR_NAT …` lines (like `ROUTE add`). Check the exact `create_nat`/`add_neighbor_nat` signatures in `control.rs` and match them.

- [ ] **Step 4: Build + clippy green**; **Step 5: netns smoke** (extend `test/route-netns.sh` or a new `test/nat-netns.sh`: AttachInterface a source, `AddNatSource`, assert the greppable line). **Step 6: Commit.**

```bash
git add api/proto/dataplane/v1/dataplane.proto cni/gen/dataplanev1 xdp-dp/src/node.rs test/nat-netns.sh
git commit -m "feat(dataplane): AddNatSource/AddNeighborNat on dataplane.v1

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Fabric WAN edge

**Files:** Create `hack/clab/wan/` (a NAT/router `frr`-or-`linux` node + a test server), Modify `hack/clab/ipv6-fabric.clab.yml`.

**Context:** Add a minimal "internet": a `wan` container (masquerades to a test server) reachable from a gateway node's WAN uplink. Model on `icn/sandbox` (`clabwan` bridge + edge). Keep it lean — one `wan-edge` linux node running an nftables masquerade + a `wan-server` (a plain container running a listener, e.g. `python3 -m http.server` or `nc`) on a `wan` net.

- [ ] **Step 1: Add a gateway kind node + WAN edge to the topology**

Add to `ipv6-fabric.clab.yml`: a `k03` k8s-kind cluster (single node = the gateway host, `/64` `fd00:db8:0:4::/64`, dual-homed like the others) OR reuse an existing node as the gateway — pick the k03 gateway-cluster approach for isolation. Add a `wan-edge` linux node + `wan-server` linux node on a `wan` bridge, and a link `k03-control-plane:eth3 ↔ wan-edge:eth1` (the gateway's WAN uplink). Add `hack/clab/prefixes/k03-control-plane.prefix` = `fd00:db8:0:4::/64` and its kind config (mirror `kind-cluster-k02.yaml`).

- [ ] **Step 2: WAN edge config**

`hack/clab/wan/wan-edge` runs nftables masquerade from the gateway's public range to `wan-server`. `wan-server` runs a trivial TCP listener. (Exact configs authored here; keep them minimal and documented.)

- [ ] **Step 3: Validate topology parses**

Run: `PATH=$HOME/go/bin:$PATH containerlab inspect -t hack/clab/ipv6-fabric.clab.yml --format json | head -3` → no parse error; `wan-edge`, `wan-server`, `k03` present.

- [ ] **Step 4: Commit** (`feat(clab): WAN edge + gateway cluster for N-S egress e2e`).

---

### Task 5: Gateway role in xdp-dp + gateway agent + binary

**Files:** Modify `xdp-dp/src/main.rs` (`--role gateway`); Create `netplane/agent/gateway.go`, `netplane/cmd/gateway/main.go`; Modify `api/proto/routebus/v1/routebus.proto` (NatBlock record).

- [ ] **Step 1: `--role gateway` serve mode**

In `xdp-dp` serve, add `--role gateway` (default `node`): a gateway attaches `uplink_rx` to BOTH the fabric uplink(s) AND a `--wan-uplink`, subscribes conceptually to the PublicVNI (decaps PublicVNI-encapped egress), and does NOT require local VM interfaces. Reuse the existing datapath; the difference is the WAN uplink + that egress SNAT is applied at this node. Verify `xdp-dp serve --role gateway --wan-uplink eth3 …` starts.

- [ ] **Step 2: routebus NatBlock record**

Add to `routebus.proto` a server/client message so gateways learn every source's block (the distributed reverse map): `NatBlock{ vni, source_ip, nat_ip, port_min, port_max, owner_underlay, op }` carried on the PublicVNI subscription. Regenerate.

- [ ] **Step 3: Gateway agent**

`netplane/agent/gateway.go`: reconcile `NATGateway` CRDs → run the allocator (Task 2) → write `Status.Allocations` → for each allocation, on THIS gateway if it owns the block: `AddNatSource` (program SNAT) + announce a `NatBlock` on routebus; on OTHER gateways: `AddNeighborNat` (return-to-owner). Subscribe to the PublicVNI NatBlock stream to learn peers' blocks. `cmd/gateway/main.go` wires it (dataplane client + reflector client + kubeconfig, like the node agent).

- [ ] **Step 4: Build all + unit-test the agent's allocation→RPC mapping** (fake dataplane, like the bus test). **Step 5: Commit.**

---

### Task 6: MILESTONE — single-gateway egress e2e on the fabric

**Files:** Create `test/e2e/egress_test.go` (first half).

- [ ] **Step 1: Deploy + drive a single gateway**

Redeploy the fabric (now with k03 gateway + WAN edge). Deploy xdp-dp (gateway role on k03) + the gateway agent + reflector. Create a `VPC` + a `NATGateway{publicIPs, portsPerSource}` + a source `NetworkInterface` on a compute node; attach a source endpoint; set the compute VPC default route → PublicVNI → the gateway.

- [ ] **Step 2: Assert egress reachability**

From the source endpoint netns, connect to `wan-server` (through the gateway SNAT). Expected: success; the gateway logs `NAT source …`; `wan-server` sees the connection from the gateway's public IP. This proves gateway-role + PublicVNI decap + SNAT + WAN edge end-to-end. **Commit** (`test(e2e): single-gateway N-S egress on the fabric`).

---

### Task 7: Drain-safe reverse-SNAT (conntrack-as-cache)

**Files:** Modify `xdp-dp-ebpf/src/nat.rs` (+ `egress.rs`/`ingress.rs` as needed), `xdp-dp/src/control.rs`.

**Context:** Today the return reverse-SNAT relies on the forward conntrack entry (`CT_REWRITE_DST`). For drain-safety, when a return packet `(nat_ip, dport)` hits a gateway with **no conntrack entry** but a **matching local NAT block** (source table), reverse-SNAT from the deterministic block→source map and re-encap to the source — instead of dropping. Conntrack stays as the fast path (cache); the deterministic map is the correctness fallback.

- [ ] **Step 1: Locate the return path** — read `nat.rs` + `ingress.rs`/`uplink_rx` where return NAT traffic is reverse-translated; identify the conntrack-miss branch.
- [ ] **Step 2: Add a `NAT_SOURCES` lookup** — a map keyed by `(nat_ip, port)` → `{source_ip, source_underlay, vni}`, populated by `create_nat` (the owner) so a conntrack-miss return recomputes the reverse translation. (The NEIGHBOR_NAT map already routes the packet to the owner; this makes the owner stateless.)
- [ ] **Step 3: eBPF: on return + conntrack miss + NAT_SOURCES hit → reverse-SNAT + deliver.** Keep it verifier-friendly.
- [ ] **Step 4: netns test** — SNAT a flow, DELETE its conntrack entry, send a return packet, assert it still reverse-translates (proves the cache-miss fallback). **Step 5: Commit.**

---

### Task 8: Gateway fleet (≥2) + block reassignment on drain

**Files:** Modify `netplane/agent/gateway.go` (ownership + reassignment), `hack/clab/ipv6-fabric.clab.yml` (2nd gateway node).

- [ ] **Step 1: Two gateways** — add a second gateway node; both announce the public prefixes (BGP/ECMP) and subscribe to the NatBlock stream. Each owns a subset of blocks; each installs NEIGHBOR_NAT for peers' blocks.
- [ ] **Step 2: Drain reassignment** — when a gateway is marked draining (or its routebus session drops, like the reflector fast-withdraw), the allocator reassigns its blocks to a surviving gateway, which installs `AddNatSource` for them (stateless — deterministic map) and announces the NatBlock; peers update NEIGHBOR_NAT. **Step 3: Unit-test** the reassignment logic (fake dataplane). **Step 4: Commit.**

---

### Task 9: ACCEPTANCE — mid-flow gateway drain e2e

**Files:** Extend `test/e2e/egress_test.go`.

- [ ] **Step 1: Long-lived egress flow through the fleet** — start a sustained connection source→`wan-server` via gateway gw-A (holds the block).
- [ ] **Step 2: Drain gw-A mid-flow** — mark gw-A draining / kill its gateway pod; the block reassigns to gw-B; return traffic ECMPs to gw-B which reverse-SNATs from the deterministic map (Task 7).
- [ ] **Step 3: Assert the flow survives** — the sustained connection keeps transferring (0 or minimal loss), proving drain-safety without state sync. **Step 4: Commit** (`test(e2e): mid-flow gateway drain — egress flow survives`).

---

## Self-Review

**1. Spec coverage:** gateway role + PublicVNI (T5), deterministic `(public-IP, port-block)` egress (T2 allocator + T3/T1 datapath+CRD), distributed reverse map = NEIGHBOR_NAT + NatBlock stream (T3/T5), drain-safe stateless reverse (T7), fleet + drain (T8), WAN edge (T4), and the **fabric drain e2e** the user asked for (T9). Dynamic overflow (spec D4) is deferred to a follow-up within egress (noted below) — v1 proves the deterministic + drain-safe core first. Ingress/DSR/floating-IP are out of scope (separate plans, per the spec).

**2. Placeholder scan:** the WAN-edge configs (T4) and some eBPF specifics (T7) are described rather than shown line-by-line because they must match live code/signatures the implementer will read (`create_nat`/`add_neighbor_nat`, `nat.rs`) — each such task says "read X, match its signature," not "TBD". No vague "handle errors" steps.

**3. Consistency:** `NATGateway.Spec.{PublicIPs,PortsPerSource,VPCRef}` (T1) feed the allocator `New(ips,size)` (T2), which produces `Block{PublicIP,PortMin,PortMax}` → `AddNatSourceRequest{nat_ip,port_min,port_max}` (T3) → `create_nat` (existing) and the `NatBlock` routebus record (T5) → `AddNeighborNat` on peers (T3) → drain-safe reverse via `NAT_SOURCES` (T7). Names line up end-to-end.

**Deferred (follow-ups / separate plans):** dynamic overflow pool (the non-drain-safe tail, spec §9); ingress L4 LB + DSR (spec §10 spike); floating IP; IPv4-thrifty graceful-drain fallback.

---

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-07-14-north-south-egress.md`. Subagent-Driven recommended: subagents for the well-scoped edits (Tasks 1–5, 7–8), controller-driven live fabric verification (Tasks 6, 9). Milestone at Task 6 (single-gateway egress), acceptance at Task 9 (mid-flow drain).
