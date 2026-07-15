# Public-VNI Egress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The WAN edge announces the default route once into a public VNI (0); egress-needing tenant nodes import it into their own VNI — replacing the per-tenant-VNI `/0` origination for both NAT and LB.

**Architecture:** Pure control-plane change (datapath untouched). The edge's `DesiredExternalRoutes` originates `0.0.0.0/0`/`64:ff9b::/96`/`::/0` into `PublicVNI (0)`. Every agent subscribes to VNI 0. When the `Bus` learns a VNI-0 route, it imports it into the local VNIs that need egress (NATGateway-VPC or LB-backend), computed by `Desired`. Mirrors metalnet: cross-VNI is control-plane route-import; the datapath derives delivery VNI from the underlay /128.

**Tech Stack:** Go (netplane agent, controller-runtime), the existing routebus per-VNI subscribe + fan-out.

**Spec:** `docs/superpowers/specs/2026-07-15-public-vni-egress-design.md`

---

## Invariants

- **Datapath untouched.** No eBPF/proto/map/anchor changes. `RouteValue.nexthop_vni` is intentionally kept (cross-VNI metadata slot).
- **Firewall unchanged** (NIC ingress/egress NetworkPolicy is orthogonal).
- The edge is **tenant-agnostic** — it must not read NATGateway/LoadBalancer to decide VNIs.
- Imports are keyed by "a VNI I host needs egress," so a node imports only for VNIs it serves.

---

## Task 1: `PublicVNI` const + edge originates the default into it

**Files:**
- Modify: `netplane/agent/natreconcile.go` (`DesiredExternalRoutes`, lines ~53-128)
- Modify/replace test: `netplane/agent/external_route_test.go`

- [ ] **Step 1: Update the edge-origination tests**

In `netplane/agent/external_route_test.go`: the edge now originates into **VNI 0** and is NOT gated on NATGateways. Replace `TestDesiredExternalRoutesEdgeAnnouncesDefault` and delete `TestDesiredExternalRoutesLoadBalancerDSR` (superseded). Keep `TestDesiredExternalRoutesNonEdgeStagesNothing` but drop its now-unused VPC/NATGateway objects. Replace the edge test with:

```go
func TestDesiredExternalRoutesEdgeIntoPublicVNI(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	// No VPC/NATGateway/LoadBalancer objects at all: the edge is tenant-agnostic.
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	routes, err := DesiredExternalRoutes(context.Background(), c, "fd00::e", "fd00:lo::1")
	if err != nil {
		t.Fatal(err)
	}
	// Every route is originated into the public VNI (0), nexthop = the edge's own underlay.
	for _, want := range []string{"0.0.0.0/0", "64:ff9b::/96", "::/0"} {
		r := findExternalRoute(routes, want)
		if r == nil {
			t.Fatalf("want %s originated, got %+v", want, routes)
		}
		if r.Vni != PublicVNI || r.Nexthop != "fd00::e" || !r.External {
			t.Fatalf("bad public-VNI route %s: %+v", want, *r)
		}
	}
}
```

And simplify the non-edge test body to just:
```go
func TestDesiredExternalRoutesNonEdgeStagesNothing(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	routes, err := DesiredExternalRoutes(context.Background(), c, "fd00::b", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatalf("non-edge node must stage no external routes, got %+v", routes)
	}
}
```

`TestReconcileEdgeStagesExternalDefault` also asserts the edge stages `0.0.0.0/0`; update its expectations to `Vni == PublicVNI (0)` (it already checks `Nexthop`/`External`); change `if r := findRoute(announce, "0.0.0.0/0"); ... r.Vni != 100` to `r.Vni != PublicVNI`, and `containsVNI(subs, 100)` to `containsVNI(subs, PublicVNI)`. Remove the NATGateway object from that test (no longer required to trigger origination).

- [ ] **Step 2: Run tests — verify they fail/compile-fail**

Run: `cd netplane && go test ./agent/ -run 'TestDesiredExternalRoutes|TestReconcileEdgeStages'`
Expected: FAIL (`PublicVNI` undefined; DesiredExternalRoutes still enumerates NATGateways).

- [ ] **Step 3: Add the `PublicVNI` const + rewrite `DesiredExternalRoutes`**

In `netplane/agent/natreconcile.go`, add near the top (after the imports / `nat64WellKnownPrefix` const):

```go
// PublicVNI is the reserved, control-plane-only aggregation VNI (dpservice ALL_VNI=0). The WAN edge
// originates the external default routes into it; egress-needing tenant nodes subscribe to it and
// import the defaults into their own tenant VNIs. It is NOT a wire/dataplane VNI.
const PublicVNI uint32 = 0
```

Replace the entire body of `DesiredExternalRoutes` (everything between the signature and the final `}`) with:

```go
func DesiredExternalRoutes(ctx context.Context, c client.Client, underlay, edgeLoopback string) ([]ExternalRoute, error) {
	if edgeLoopback == "" {
		return nil, nil // not a WAN edge: originate nothing
	}
	// The edge is tenant-agnostic: originate the external defaults ONCE into the public VNI,
	// nexthop = this edge's own anycast underlay. Egress-needing tenant nodes import them.
	return []ExternalRoute{
		{Vni: PublicVNI, Prefix: "0.0.0.0/0", Nexthop: underlay, External: true},
		{Vni: PublicVNI, Prefix: nat64WellKnownPrefix, Nexthop: underlay, External: true},
		{Vni: PublicVNI, Prefix: "::/0", Nexthop: underlay, External: true},
	}, nil
}
```

Remove the now-unused `vpcVNIFor` ONLY if nothing else references it — check with `grep -rn "vpcVNIFor" netplane/`. It IS still used by the egress-VNI computation in Task 3, so **keep it**. Remove any now-unused imports (`apierrors`, `netv1` may still be used elsewhere in the file — let the compiler guide you; run `go build ./agent/`).

- [ ] **Step 4: Run tests — verify pass**

Run: `cd netplane && go test ./agent/ -run 'TestDesiredExternalRoutes|TestReconcileEdgeStages'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add netplane/agent/natreconcile.go netplane/agent/external_route_test.go
git commit -m "feat(egress): edge originates external defaults into the public VNI (0)"
```

---

## Task 2: Revert `LoadBalancer.Spec.VPCRef` (superseded by import)

**Files:**
- Modify: `api/v1alpha1/loadbalancer_types.go`
- Regenerate: `api/v1alpha1/zz_generated.deepcopy.go`, `config/crd/bases/net.ectobase.dev_loadbalancers.yaml`

- [ ] **Step 1: Remove the VPCRef field**

In `api/v1alpha1/loadbalancer_types.go`, delete from `LoadBalancerSpec`:

```go
	// VPCRef references the VPC whose VNI the backends live in. Used to originate the external
	// default route so DSR replies (source = the public VIP, un-SNAT'd) can egress via the edge.
	VPCRef LocalObjectReference `json:"vpcRef"`
```

- [ ] **Step 2: Regenerate deepcopy + CRD**

```bash
go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.19.0 object paths=./api/v1alpha1/...
go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.19.0 crd paths=./api/v1alpha1/... output:crd:dir=config/crd/bases
```

Then revert any unrelated CRD drift the tool introduced (only `net.ectobase.dev_loadbalancers.yaml` should change):
```bash
git checkout config/crd/bases/net.ectobase.dev_natgateways.yaml config/crd/bases/net.ectobase.dev_networkpolicies.yaml 2>/dev/null || true
```
Verify `vpcRef` is gone from `config/crd/bases/net.ectobase.dev_loadbalancers.yaml`.

- [ ] **Step 3: Build**

Run: `go build ./api/... && cd netplane && go build ./...`
Expected: PASS. (Nothing should reference `LoadBalancer...VPCRef` anymore — `DesiredExternalRoutes` stopped using it in Task 1.)

- [ ] **Step 4: Commit**

```bash
git add api/v1alpha1/loadbalancer_types.go api/v1alpha1/zz_generated.deepcopy.go config/crd/bases/net.ectobase.dev_loadbalancers.yaml
git commit -m "revert(lb): drop LoadBalancer.Spec.VPCRef (egress via public-VNI import instead)"
```

---

## Task 3: `Desired` subscribes to the public VNI + computes egress VNIs

**Files:**
- Modify: `netplane/agent/reconcile.go` (`Desired`, ~line 65-140)
- Create test: `netplane/agent/importreconcile_test.go`

- [ ] **Step 1: Write the egress-VNIs helper test**

Create `netplane/agent/importreconcile_test.go`:

```go
package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func egScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func hasVNI(vs []uint32, v uint32) bool {
	for _, x := range vs {
		if x == v {
			return true
		}
	}
	return false
}

func TestDesiredEgressVNIs_NATGateway(t *testing.T) {
	s := egScheme(t)
	node := "nodeA"
	vpc := &netv1.VPC{ObjectMeta: metav1.ObjectMeta{Name: "blue", Namespace: "default"}, Status: netv1.VPCStatus{VNI: 100}}
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default"},
		Spec:       netv1.NetworkInterfaceSpec{VPCRef: netv1.LocalObjectReference{Name: "blue"}, NodeName: &node},
		Status:     netv1.NetworkInterfaceStatus{VNI: 100},
	}
	gw := &netv1.NATGateway{ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"}, Spec: netv1.NATGatewaySpec{VPCRef: netv1.LocalObjectReference{Name: "blue"}}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(vpc, nic, gw).Build()
	r := &Reconciler{client: cl, nodeID: node}

	vnis, err := r.desiredEgressVNIs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasVNI(vnis, 100) {
		t.Fatalf("VNI 100 (NATGateway-VPC, hosted here) must need egress, got %v", vnis)
	}
}

func TestDesiredEgressVNIs_LBBackend(t *testing.T) {
	s := egScheme(t)
	node := "nodeA"
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-web-0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName: node, NICRef: netv1.LocalObjectReference{Name: "web-0"}, VNI: 200,
			LB: []netv1.CompiledLB{{VIP: "203.0.113.5"}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cnic).Build()
	r := &Reconciler{client: cl, nodeID: node}
	vnis, err := r.desiredEgressVNIs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasVNI(vnis, 200) {
		t.Fatalf("VNI 200 (LB backend on this node) must need egress, got %v", vnis)
	}
}

func TestDesiredEgressVNIs_NeitherIsEmpty(t *testing.T) {
	s := egScheme(t)
	node := "nodeA"
	vpc := &netv1.VPC{ObjectMeta: metav1.ObjectMeta{Name: "blue", Namespace: "default"}, Status: netv1.VPCStatus{VNI: 100}}
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default"},
		Spec:       netv1.NetworkInterfaceSpec{VPCRef: netv1.LocalObjectReference{Name: "blue"}, NodeName: &node},
		Status:     netv1.NetworkInterfaceStatus{VNI: 100},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(vpc, nic).Build()
	r := &Reconciler{client: cl, nodeID: node}
	vnis, err := r.desiredEgressVNIs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(vnis) != 0 {
		t.Fatalf("no NATGateway + no LB backend => no egress VNIs, got %v", vnis)
	}
}
```

(Confirm the actual type names: `VPCStatus.VNI`, `NATGatewaySpec.VPCRef`, `CompiledNICSpec.{NodeName,VNI,LB}` — grep `api/v1alpha1` and adjust the literals if a field differs.)

- [ ] **Step 2: Run — verify fail**

Run: `cd netplane && go test ./agent/ -run TestDesiredEgressVNIs`
Expected: FAIL (`desiredEgressVNIs` undefined).

- [ ] **Step 3: Implement `desiredEgressVNIs`**

Create `netplane/agent/importreconcile.go`:

```go
package agent

import (
	"context"
	"fmt"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
)

// desiredEgressVNIs returns the VNIs this node hosts that need internet egress: a VNI whose VPC has a
// NATGateway (and this node hosts a NIC in it), or a VNI of a local LB-backend NIC. These VNIs import
// the public VNI's default route (0.0.0.0/0, etc.) so their egress reaches the WAN edge.
func (r *Reconciler) desiredEgressVNIs(ctx context.Context) ([]uint32, error) {
	set := map[uint32]struct{}{}

	// (a) NATGateway VNIs, intersected with VNIs this node actually hosts.
	var gws netv1.NATGatewayList
	if err := r.client.List(ctx, &gws); err != nil {
		return nil, fmt.Errorf("list natgateways: %w", err)
	}
	natVNIs := map[uint32]struct{}{}
	for i := range gws.Items {
		vni, err := vpcVNIFor(ctx, r.client, gws.Items[i].Namespace, gws.Items[i].Spec.VPCRef.Name)
		if err != nil {
			continue // VPC not resolvable yet; skip
		}
		if vni != 0 {
			natVNIs[vni] = struct{}{}
		}
	}
	if len(natVNIs) > 0 {
		var nics netv1.NetworkInterfaceList
		if err := r.client.List(ctx, &nics); err != nil {
			return nil, fmt.Errorf("list networkinterfaces: %w", err)
		}
		for i := range nics.Items {
			n := &nics.Items[i]
			if n.Spec.NodeName == nil || *n.Spec.NodeName != r.nodeID {
				continue
			}
			vni := uint32(n.Status.VNI)
			if _, ok := natVNIs[vni]; ok && vni != 0 {
				set[vni] = struct{}{}
			}
		}
	}

	// (b) LB-backend VNIs on this node (CompiledNIC.LB non-empty).
	var cnics netv1.CompiledNICList
	if err := r.client.List(ctx, &cnics); err != nil {
		return nil, fmt.Errorf("list compilednics: %w", err)
	}
	for i := range cnics.Items {
		c := &cnics.Items[i]
		if c.Spec.NodeName == r.nodeID && len(c.Spec.LB) > 0 && c.Spec.VNI != 0 {
			set[uint32(c.Spec.VNI)] = struct{}{}
		}
	}

	out := make([]uint32, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	return out, nil
}
```

- [ ] **Step 4: Run — verify pass**

Run: `cd netplane && go test ./agent/ -run TestDesiredEgressVNIs`
Expected: PASS.

- [ ] **Step 5: `Desired` subscribes to VNI 0 + returns egress VNIs**

In `netplane/agent/reconcile.go`, change the `Desired` signature to add `egressVNIs`:

```go
func (r *Reconciler) Desired(ctx context.Context) (subs []uint32, announce []Route, announceNat []NatBlock, egressVNIs []uint32, err error) {
```

Update every early `return nil, nil, nil, err` in `Desired` to `return nil, nil, nil, nil, err` (there are several). In the `vniSet` initialization, add the public VNI so the node always subscribes to it:

```go
	vniSet := map[uint32]struct{}{PublicVNI: {}} // always subscribe to the public VNI to learn defaults
```

Just before the final `return`, compute egress VNIs:

```go
	egressVNIs, err = r.desiredEgressVNIs(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
```

And update the final `return subs, announce, blocks, nil` → `return subs, announce, blocks, egressVNIs, nil`.

- [ ] **Step 6: Build (callers break — fixed in Task 5)**

Run: `cd netplane && go vet ./agent/ 2>&1 | head`
Expected: the `agent` package itself compiles for its own tests via `-run`, but `main.go` (a different package) now mismatches the `Desired` arity — that's fixed in Task 5. Run the agent unit tests with `-run` to confirm they pass:
Run: `cd netplane && go test ./agent/ -run 'TestDesiredEgressVNIs|TestDesiredExternalRoutes|TestReconcileEdgeStages'`
Expected: PASS. (`TestReconcileEdgeStagesExternalDefault` calls `edge.Desired(...)` — update its call to accept the new 5th return: `subs, announce, _, _, err := edge.Desired(...)` and the non-edge one `_, announce2, _, _, err := other.Desired(...)`.)

- [ ] **Step 7: Commit**

```bash
git add netplane/agent/reconcile.go netplane/agent/importreconcile.go netplane/agent/importreconcile_test.go netplane/agent/external_route_test.go
git commit -m "feat(egress): Desired subscribes to public VNI + computes egress VNIs"
```

---

## Task 4: `Bus` learns the public default + imports into egress VNIs

**Files:**
- Modify: `netplane/agent/bus.go` (`Bus` struct, `NewBus`, `Run`, `apply`)
- Modify test: `netplane/agent/bus_test.go`

- [ ] **Step 1: Write the learn+import test**

Append to `netplane/agent/bus_test.go`:

```go
func TestApplyPublicVNIRoute_ImportsIntoEgressVNIs(t *testing.T) {
	dp := newFakeDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	b.egressVNIs = []uint32{100, 200} // set by Run() in production

	b.apply(context.Background(), &rbv1.RouteUpdate{
		Vni: 0, Prefix: "0.0.0.0/0", Nexthops: []string{"fd00::e"}, Op: rbv1.RouteOp_ROUTE_OP_ADD,
	})

	// Imported 0.0.0.0/0 -> fd00::e into BOTH egress VNIs (external), and NOT into VNI 0.
	if got := dp.routeAdds; len(got) != 2 {
		t.Fatalf("want 2 imported routes, got %d: %+v", len(got), got)
	}
	for _, ra := range dp.routeAdds {
		if ra.prefix != "0.0.0.0/0" || ra.nexthop != "fd00::e" || !ra.external || ra.vni == 0 {
			t.Fatalf("bad imported route: %+v", ra)
		}
	}
	if b.LearnedPublic()["0.0.0.0/0"] != "fd00::e" {
		t.Fatalf("learnedPublic not recorded: %+v", b.LearnedPublic())
	}
}

func TestApplyNonPublicRoute_InstallsDirectly(t *testing.T) {
	dp := newFakeDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	b.egressVNIs = []uint32{100}
	b.apply(context.Background(), &rbv1.RouteUpdate{
		Vni: 100, Prefix: "10.0.0.5/32", Nexthops: []string{"fd00::d"}, Op: rbv1.RouteOp_ROUTE_OP_ADD,
	})
	if len(dp.routeAdds) != 1 || dp.routeAdds[0].vni != 100 || dp.routeAdds[0].external {
		t.Fatalf("non-public route must install directly (vni=100, external=false): %+v", dp.routeAdds)
	}
}
```

Extend `fakeDP` in `bus_test.go` to record routes (add fields + capture in `AddRoute`):
```go
// add to fakeDP struct:
//   routeAdds []routeCall
// and type routeCall struct{ vni uint32; prefix, nexthop string; external bool }
// in fakeDP.AddRoute:
func (f *fakeDP) AddRoute(ctx context.Context, vni uint32, prefix, nexthop string, external bool) error {
	f.routeAdds = append(f.routeAdds, routeCall{vni, prefix, nexthop, external})
	return nil
}
```
(If `fakeDP.AddRoute` already exists, just add the recording line.)

- [ ] **Step 2: Run — verify fail**

Run: `cd netplane && go test ./agent/ -run 'TestApplyPublicVNIRoute|TestApplyNonPublicRoute'`
Expected: FAIL (`egressVNIs`/`LearnedPublic` undefined; `apply` doesn't special-case VNI 0).

- [ ] **Step 3: Add `egressVNIs` + `learnedPublic` to `Bus`; special-case `apply`**

In `netplane/agent/bus.go`:

Add fields to the `Bus` struct (near `learnedEdge`):
```go
	egressVNIs    []uint32          // local VNIs that import the public default(s); set by Run
	learnedPublic map[string]string // public-VNI prefix -> nexthop (recorded, imported into egressVNIs)
```

Initialize `learnedPublic` in `NewBus`:
```go
	return &Bus{nodeID: nodeID, underlay: underlay, dp: dp, isEdge: isEdge, learnedEdge: map[string]string{}, learnedPublic: map[string]string{}}
```

Add `egressVNIs` to `Run`'s signature and store it (Run is where the reconcile's egress set is passed):
```go
func (b *Bus) Run(ctx context.Context, cc rbv1.RouteBusClient, subVNIs []uint32, announce []Route, announceNat []NatBlock, announcePublic []PublicPrefix, egressVNIs []uint32) error {
	b.egressVNIs = egressVNIs
	// ... existing body ...
```

In `apply(ctx, ru)`, special-case the public VNI at the top (before the existing switch):
```go
func (b *Bus) apply(ctx context.Context, ru *rbv1.RouteUpdate) {
	nh := ""
	if len(ru.Nexthops) > 0 {
		nh = ru.Nexthops[0]
	}
	if ru.Vni == PublicVNI {
		// Public-VNI routes are aggregation records: record them and IMPORT into each local egress VNI
		// (a tenant node has no VNI-0 table). External=true so SNAT sources follow it; LB-VIP replies
		// miss SNAT and stay public.
		b.mu.Lock()
		switch ru.Op {
		case rbv1.RouteOp_ROUTE_OP_ADD:
			b.learnedPublic[ru.Prefix] = nh
		case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
			delete(b.learnedPublic, ru.Prefix)
		}
		evs := append([]uint32(nil), b.egressVNIs...)
		b.mu.Unlock()
		for _, vni := range evs {
			switch ru.Op {
			case rbv1.RouteOp_ROUTE_OP_ADD:
				if err := b.dp.AddRoute(ctx, vni, ru.Prefix, nh, true); err != nil {
					log.Printf("import AddRoute vni=%d %s -> %s: %v", vni, ru.Prefix, nh, err)
				}
			case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
				if err := b.dp.WithdrawRoute(ctx, vni, ru.Prefix); err != nil {
					log.Printf("import WithdrawRoute vni=%d %s: %v", vni, ru.Prefix, err)
				}
			}
		}
		return
	}
	switch ru.Op {
	// ... existing ADD/WITHDRAW that calls b.dp.AddRoute(ctx, ru.Vni, ru.Prefix, nh, ru.External) ...
	}
}
```

Add `LearnedPublic()` (mirror `LearnedEdge`):
```go
func (b *Bus) LearnedPublic() map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]string, len(b.learnedPublic))
	for k, v := range b.learnedPublic {
		out[k] = v
	}
	return out
}
```

(`PublicVNI` is defined in `natreconcile.go`, same package — no import needed.)

- [ ] **Step 4: Run — verify pass**

Run: `cd netplane && go test ./agent/ -run 'TestApplyPublicVNIRoute|TestApplyNonPublicRoute'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add netplane/agent/bus.go netplane/agent/bus_test.go
git commit -m "feat(egress): Bus imports the learned public default into local egress VNIs"
```

---

## Task 5: Wire `main.go`, full build + test sweep

**Files:**
- Modify: `netplane/cmd/agent/main.go` (the reconcile loop)

- [ ] **Step 1: Thread `egressVNIs` from `Desired` into `bus.Run`**

In `netplane/cmd/agent/main.go`, the loop currently does:
```go
		subs, ann, annNat, err := r.Desired(ctx)
		...
		if err := bus.Run(ctx, rb, subs, ann, annNat, pub); err != nil {
```
Change to:
```go
		subs, ann, annNat, egressVNIs, err := r.Desired(ctx)
		...
		if err := bus.Run(ctx, rb, subs, ann, annNat, pub, egressVNIs); err != nil {
```

- [ ] **Step 2: Full build + test**

Run: `cd netplane && go build ./... && go test ./...`
Expected: PASS (all agent tests, controllers, reflector).

Run: `go build ./api/...`
Expected: PASS.

- [ ] **Step 3: Grep for stragglers**

Run: `grep -rn "DesiredExternalRoutes\|\.Desired(" netplane/ --include=*.go | grep -v _test`
Expected: only the definitions + the single `main.go` call, all 5-return-aware. Fix any other caller.

Run: `grep -rn "VPCRef" api/v1alpha1/loadbalancer_types.go`
Expected: no output (field removed).

- [ ] **Step 4: Commit**

```bash
git add netplane/cmd/agent/main.go
git commit -m "feat(egress): wire egress VNIs into the agent bus session (public-VNI import)"
```

---

## Self-Review (completed by plan author)

**Spec coverage:** §4.1 edge origination into public VNI → Task 1. VPCRef revert → Task 2. §4.2 subscribe to VNI 0 + §4.3 egress VNIs → Task 3. §4.4 learn+import in `apply` → Task 4. §4.5 wiring → Task 5. §5 peering foundation → `desiredEgressVNIs`/import shape is the reusable path (noted, not built). §7 testing → tasks 1/3/4 unit tests; datapath unchanged (no sim/anchor changes needed). Non-goals (no datapath/`nexthop_vni`/IPAM/floating/peering) respected — pure control-plane.

**Placeholder scan:** none — every step has concrete code + commands.

**Type consistency:** `PublicVNI uint32 = 0` (Task 1) used in Tasks 3/4. `Desired(...) (subs, announce, announceNat, egressVNIs, err)` (Task 3) matched by `main.go` (Task 5) and the edge-stages test (Task 3 Step 6). `Bus.Run(..., egressVNIs)` (Task 4) matched by `main.go` (Task 5). `Bus.egressVNIs`/`learnedPublic`/`LearnedPublic()` consistent Tasks 4. `fakeDP.routeAdds`/`routeCall{vni,prefix,nexthop,external}` consistent within Task 4. `desiredEgressVNIs(ctx) ([]uint32, error)` consistent Tasks 3.
