# LoadBalancer Wiring (Subproject B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the `LoadBalancer` CRD end-to-end so LB traffic reaches backends — E/W as an anycast overlay route, N/S via the existing edge maglev — with the firewall unchanged (LB membership grants no firewall permission).

**Architecture:** A compiler resolves each `LoadBalancer`'s selector/refs and stamps `CompiledNIC.LB` (pure membership) onto backend NICs. The per-node agent turns that into (a) an E/W anycast overlay route `VIP → backend /128` on the existing route channel and (b) an `LB_VIP` PublicPrefix record consumed by the edge to `AddLbBackend`. The edge reads the `LoadBalancer` CRD to `AddLbVip` and runs maglev in `wan_rx`. Backends deliver via the normal base path, gated by their NetworkPolicy ingress firewall.

**Tech Stack:** Go (controller-runtime controllers + per-node agent + reflector client), Rust (flowplane userspace `control.rs`), `flowplane-sim` (Rust datapath simulation), protobuf (stubs already generated).

**Spec:** `docs/superpowers/specs/2026-07-15-loadbalancer-wiring-design.md`

---

## Invariants (must hold across every task)

- The Subproject A firewall pipeline is untouched: `Compile`'s firewall/NAT paths unchanged; `CompiledLB` has **no** firewall fields; LB generates **no** firewall rule.
- The only control-plane IPAM is the VIP. No underlay `/128` appears in any CRD.
- VIPs may be IPv4 or IPv6 — always use `hostPrefix(vip)` (`/32` or `/128`), never a literal `/32`.
- The dataplane stays always-on deny-by-default; LB delivery is gated by the destination NIC's ingress firewall.

---

## File Structure

- `api/v1alpha1/loadbalancer_types.go` — flesh out `LoadBalancerSpec`/`Status` + `LoadBalancerPort`.
- `api/v1alpha1/compilednic_types.go` — add `LB []CompiledLB` + `CompiledLB`/`CompiledLBPort`; remove `UnderlayRoute`.
- `api/v1alpha1/zz_generated.deepcopy.go`, `config/crd/bases/*.yaml` — regenerated.
- `flowplane/src/control.rs` — guard `create_lb`'s `UNDERLAY` write for `vni==0`.
- `netplane/controllers/compilednic.go` — `Compile(…, lbs)`, `nicsForLB`, LoadBalancer watch + predicates, diff-before-write.
- `netplane/agent/bus.go` — LB methods on `Dataplane` + `dpAdapter`; `applyPublic` LB_VIP case; `Bus.isEdge`.
- `netplane/agent/lbreconcile.go` (NEW) — `desiredLB` join helper + edge `ReconcileLB`.
- `netplane/agent/reconcile.go` — emit E/W anycast routes; `DesiredPublic(ctx)` emits LB_VIP records; `appliedLbVips` field.
- `netplane/cmd/agent/main.go` — call `ReconcileLB`; pass `isEdge` to `NewBus`; `DesiredPublic(ctx)`.
- `flowplane-sim/src/compilednic.rs` — `CompiledLB` serde mirror; drop the `underlayRoute` requirement.
- `flowplane-sim/src/lb_scenario_test.rs` — model-A E/W anycast coverage.
- Tests: `netplane/controllers/compilednic_test.go` (or envtest), `netplane/agent/lbreconcile_test.go`, `netplane/agent/bus_test.go`.

---

## Task 1: API types — LoadBalancer spec/status + CompiledNIC.LB, remove UnderlayRoute

**Files:**
- Modify: `api/v1alpha1/loadbalancer_types.go:10-21`
- Modify: `api/v1alpha1/compilednic_types.go:14-33`, `:45-57`
- Regenerate: `api/v1alpha1/zz_generated.deepcopy.go`, `config/crd/bases/net.ectobase.dev_loadbalancers.yaml`, `config/crd/bases/net.ectobase.dev_compilednics.yaml`

- [ ] **Step 1: Replace the LoadBalancer spec/status stubs**

In `api/v1alpha1/loadbalancer_types.go`, replace the `LoadBalancerSpec` and `LoadBalancerStatus` structs (lines 10-21) with:

```go
// LoadBalancerSpec is the desired state of a LoadBalancer. The VIP is the LB's identity
// (v4 or v6); backends are the NetworkInterfaces matched by TargetSelector or named by TargetRefs.
type LoadBalancerSpec struct {
	// VIP is the virtual IP (IPv4 or IPv6). It is the LB identity and the AddLbVip id.
	VIP string `json:"vip"`
	// Ports are the LB service (port, proto) tuples.
	Ports []LoadBalancerPort `json:"ports"`
	// TargetSelector selects backend NetworkInterfaces by label. Mutually exclusive with TargetRefs.
	// +optional
	TargetSelector *metav1.LabelSelector `json:"targetSelector,omitempty"`
	// TargetRefs names backend NetworkInterfaces explicitly. Mutually exclusive with TargetSelector.
	// +optional
	TargetRefs []LocalObjectReference `json:"targetRefs,omitempty"`
}

// LoadBalancerPort is one LB service tuple.
type LoadBalancerPort struct {
	// Port is the service port.
	Port int32 `json:"port"`
	// Proto is the IP protocol ("TCP" or "UDP").
	Proto string `json:"proto"`
}

// LoadBalancerStatus is the observed state of a LoadBalancer.
type LoadBalancerStatus struct {
	// State is the lifecycle state (Pending | Ready).
	// +optional
	State string `json:"state,omitempty"`
}
```

- [ ] **Step 2: Add CompiledNIC.LB and remove UnderlayRoute**

In `api/v1alpha1/compilednic_types.go`, in `CompiledNICSpec` remove the `UnderlayRoute` field (lines 26-27) and add an `LB` field. The struct's underlay lines to delete:

```go
	// UnderlayRoute is the allocated underlay /128 for this NIC.
	UnderlayRoute string `json:"underlayRoute"`
```

Add, after the `NAT` field (line 32), inside `CompiledNICSpec`:

```go
	// LB lists the load balancers this NIC is a backend of. Pure forwarding membership —
	// it grants NO firewall permission (that comes solely from NetworkPolicy).
	// +optional
	LB []CompiledLB `json:"lb,omitempty"`
```

And add these new types after `CompiledNAT` (after line 67):

```go
// CompiledLB is one load-balancer this NIC backs: the VIP (v4 or v6) and its service ports.
type CompiledLB struct {
	// VIP is the load-balancer virtual IP (IPv4 or IPv6).
	VIP string `json:"vip"`
	// Ports are the LB service (port, proto) tuples.
	// +optional
	Ports []CompiledLBPort `json:"ports,omitempty"`
}

// CompiledLBPort is one LB service tuple.
type CompiledLBPort struct {
	Port  int32  `json:"port"`
	Proto string `json:"proto"`
}
```

- [ ] **Step 3: Regenerate deepcopy + CRD manifests**

Run controller-gen (available in the nix devShell; if not on `PATH`, use the `go run` form):

```bash
controller-gen object paths=./api/v1alpha1/... \
  || go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.16.0 object paths=./api/v1alpha1/...
controller-gen crd paths=./api/v1alpha1/... output:crd:dir=config/crd/bases \
  || go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.16.0 crd paths=./api/v1alpha1/... output:crd:dir=config/crd/bases
```

Expected: `zz_generated.deepcopy.go` gains `LoadBalancerPort`, `CompiledLB`, `CompiledLBPort` deepcopy funcs and updates `LoadBalancerSpec`/`CompiledNICSpec`; `net.ectobase.dev_loadbalancers.yaml` gains `vip`/`ports`/`targetSelector`/`targetRefs`; `net.ectobase.dev_compilednics.yaml` gains `lb` and drops `underlayRoute`.

- [ ] **Step 4: Build to verify types + generated code compile**

Run: `cd netplane && go build ./... && cd .. && go build ./api/...`
Expected: compiles. (compilednic.go still sets `UnderlayRoute` — that breaks; it is removed in Task 3. If Task 1 is committed before Task 3, temporarily expect the controllers package to fail build until Task 3; build only `./api/...` here.)

Run: `go build ./api/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api/v1alpha1/loadbalancer_types.go api/v1alpha1/compilednic_types.go api/v1alpha1/zz_generated.deepcopy.go config/crd/bases/
git commit -m "feat(api): LoadBalancer spec/status + CompiledNIC.LB; drop CompiledNIC.UnderlayRoute"
```

---

## Task 2: Datapath — skip the UNDERLAY write in create_lb for the WAN edge (vni==0)

**Files:**
- Modify: `flowplane/src/control.rs:897-907` (the `UNDERLAY.upsert` inside `create_lb`)
- Test: `flowplane/src/control.rs` (add a `#[cfg(test)]` test)

**Why:** the WAN edge registers its LB with `vni=0` and passes its own anycast underlay as `lb_underlay`. `wan_rx` never resolves `UNDERLAY[lb_underlay]` (it maglev-selects from a raw WAN frame), but `attach_edge` registered `UNDERLAY[edge_underlay] = LOCAL_DELIVER` for fabric→WAN egress. Writing `UNDERLAY[lb_underlay]` in `create_lb` would clobber that. For `vni==0` the entry is unnecessary, so skip it.

- [ ] **Step 1: Write the failing test**

Add to `flowplane/src/control.rs` inside (or add) a `#[cfg(test)] mod tests`. If a test module already exists, add just the function. The test builds a `Control`, calls `create_lb` with `vni=0` and an `lb_underlay`, and asserts the `UNDERLAY` map has NO entry for that address; then repeats with `vni=100` and asserts the entry IS present. Use the existing test constructors in the file for `Control` (search the file for how other `control.rs` tests build a `Control`/`GlobalState`; mirror that). Concretely:

```rust
#[test]
fn create_lb_skips_underlay_write_for_wan_edge() {
    let ctrl = test_control(); // mirror existing control.rs test setup
    let lb_ul = [0x20u8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
    ctrl.create_lb(b"vip-a", 0, crate::grpc::LbIpBytes::Ipv4([203, 0, 113, 50]), lb_ul, vec![(443, 6)]).unwrap();
    assert!(ctrl.underlay_get(&lb_ul).is_none(), "vni=0 must NOT write UNDERLAY[lb_underlay]");

    ctrl.create_lb(b"vip-b", 100, crate::grpc::LbIpBytes::Ipv4([10, 0, 100, 1]), lb_ul, vec![(443, 6)]).unwrap();
    assert!(ctrl.underlay_get(&lb_ul).is_some(), "vni!=0 must write UNDERLAY[lb_underlay]");
}
```

If no `underlay_get` test accessor exists on `Control`, read the map directly the way other tests in the file inspect `g.underlay`/maps (mirror the closest existing test). If no test harness exists in `control.rs` at all, place this test in the module that already exercises `create_lb`/`add_lb_target` (search: `grep -rn "create_lb\|add_lb_target" flowplane/src --include=*.rs | grep test`), and adapt the constructor accordingly.

- [ ] **Step 2: Run it — verify it fails**

Run: `cargo test -p flowplane create_lb_skips_underlay_write_for_wan_edge`
Expected: FAIL (the current code always writes `UNDERLAY[lb_underlay]`).

- [ ] **Step 3: Guard the UNDERLAY write**

In `flowplane/src/control.rs`, wrap the `g.underlay.upsert(lb_underlay, …)` block (lines ~897-907) in a `vni != 0` guard:

```rust
        // Program the LB's own underlay /128 into UNDERLAY so ingress can identify it — but ONLY for
        // overlay (relay) LBs. The WAN edge (vni==0) reaches the LB via wan_rx on a raw WAN frame and
        // never resolves UNDERLAY[lb_underlay]; writing it there would clobber the edge's
        // LOCAL_DELIVER egress entry (attach_edge). So skip the write for vni==0.
        if vni != 0 {
            g.underlay.upsert(
                lb_underlay,
                flowplane_common::UnderlayValue {
                    vni,
                    tap_ifindex: 0,
                    guest_mac: [0; 6],
                    _pad: [0; 2],
                },
            )?;
        }
```

- [ ] **Step 4: Run it — verify it passes**

Run: `cargo test -p flowplane create_lb_skips_underlay_write_for_wan_edge`
Expected: PASS.

- [ ] **Step 5: Run the broader flowplane tests to confirm no regression**

Run: `cargo test -p flowplane`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add flowplane/src/control.rs
git commit -m "fix(lb): create_lb skips UNDERLAY[lb_underlay] write for the WAN edge (vni==0)"
```

---

## Task 3: Compiler — resolve LB targets into CompiledNIC.LB (and drop UnderlayRoute copy)

**Files:**
- Modify: `netplane/controllers/compilednic.go:27-106` (`Compile`)
- Test: `netplane/controllers/compilednic_test.go` (create if absent)

- [ ] **Step 1: Write the failing test**

Create/append `netplane/controllers/compilednic_test.go`:

```go
package controllers

import (
	"testing"

	netv1 "github.com/trevex/flowplane/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func nicWithLabels(name string, labels map[string]string) *netv1.NetworkInterface {
	return &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Labels: labels},
	}
}

func TestCompile_LBSelectorMatch(t *testing.T) {
	nic := nicWithLabels("web-0", map[string]string{"app": "web"})
	lb := netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "web-lb", Namespace: "default"},
		Spec: netv1.LoadBalancerSpec{
			VIP:            "203.0.113.50",
			Ports:          []netv1.LoadBalancerPort{{Port: 443, Proto: "TCP"}},
			TargetSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		},
	}
	c := Compile(nic, nil, []netv1.LoadBalancer{lb})
	if len(c.Spec.LB) != 1 {
		t.Fatalf("want 1 CompiledLB, got %d", len(c.Spec.LB))
	}
	if c.Spec.LB[0].VIP != "203.0.113.50" {
		t.Fatalf("VIP = %q, want 203.0.113.50", c.Spec.LB[0].VIP)
	}
	if len(c.Spec.LB[0].Ports) != 1 || c.Spec.LB[0].Ports[0].Port != 443 || c.Spec.LB[0].Ports[0].Proto != "TCP" {
		t.Fatalf("ports = %+v, want [{443 TCP}]", c.Spec.LB[0].Ports)
	}
}

func TestCompile_LBRefMatch(t *testing.T) {
	nic := nicWithLabels("db-0", nil)
	lb := netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "db-lb", Namespace: "default"},
		Spec: netv1.LoadBalancerSpec{
			VIP:        "2001:db8::1",
			Ports:      []netv1.LoadBalancerPort{{Port: 5432, Proto: "TCP"}},
			TargetRefs: []netv1.LocalObjectReference{{Name: "db-0"}},
		},
	}
	c := Compile(nic, nil, []netv1.LoadBalancer{lb})
	if len(c.Spec.LB) != 1 || c.Spec.LB[0].VIP != "2001:db8::1" {
		t.Fatalf("ref match failed: %+v", c.Spec.LB)
	}
}

func TestCompile_LBNoMatch(t *testing.T) {
	nic := nicWithLabels("other-0", map[string]string{"app": "other"})
	lb := netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "web-lb", Namespace: "default"},
		Spec: netv1.LoadBalancerSpec{
			VIP:            "203.0.113.50",
			TargetSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		},
	}
	c := Compile(nic, nil, []netv1.LoadBalancer{lb})
	if len(c.Spec.LB) != 0 {
		t.Fatalf("want 0 CompiledLB for non-matching NIC, got %d", len(c.Spec.LB))
	}
}
```

- [ ] **Step 2: Run it — verify it fails**

Run: `cd netplane && go test ./controllers/ -run TestCompile_LB`
Expected: FAIL (Compile has 2 params, not 3; `CompiledLB` unused).

- [ ] **Step 3: Extend Compile**

In `netplane/controllers/compilednic.go`:

1. Change the signature (line 27) to add `lbs`:

```go
func Compile(nic *netv1.NetworkInterface, policies []netv1.NetworkPolicy, lbs []netv1.LoadBalancer) netv1.CompiledNIC {
```

2. Remove the `UnderlayRoute: nic.Status.UnderlayRoute,` line from the `CompiledNICSpec` literal (line 53).

3. After the firewall default-allow block (after line 103, before `return compiled`), add LB resolution:

```go
	// LB membership: for each LoadBalancer whose selector matches this NIC's labels or whose
	// TargetRefs name it, record a CompiledLB. This is forwarding membership ONLY — it adds no
	// firewall rule (permission comes solely from NetworkPolicy).
	for i := range lbs {
		lb := &lbs[i]
		if !lbMatchesNIC(lb, nic, nicLabels) {
			continue
		}
		ports := make([]netv1.CompiledLBPort, 0, len(lb.Spec.Ports))
		for _, p := range lb.Spec.Ports {
			ports = append(ports, netv1.CompiledLBPort{Port: p.Port, Proto: p.Proto})
		}
		compiled.Spec.LB = append(compiled.Spec.LB, netv1.CompiledLB{VIP: lb.Spec.VIP, Ports: ports})
	}
```

4. Add the matcher helper at the end of the file:

```go
// lbMatchesNIC reports whether the LoadBalancer targets this NIC — either its TargetSelector matches
// the NIC's labels or a TargetRef names it.
func lbMatchesNIC(lb *netv1.LoadBalancer, nic *netv1.NetworkInterface, nicLabels labels.Set) bool {
	for _, ref := range lb.Spec.TargetRefs {
		if ref.Name == nic.Name {
			return true
		}
	}
	if lb.Spec.TargetSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(lb.Spec.TargetSelector)
		if err == nil && sel.Matches(nicLabels) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run it — verify it passes**

Run: `cd netplane && go test ./controllers/ -run TestCompile_LB`
Expected: PASS. (The `Reconcile` call to `Compile` now has the wrong arity and won't build — fixed in Task 4. Run only this test with `-run`; `go test ./controllers/` compiles the whole package, so it will fail to build until Task 4. If so, proceed to Task 4 and run the combined suite there.)

- [ ] **Step 5: Commit**

```bash
git add netplane/controllers/compilednic.go netplane/controllers/compilednic_test.go
git commit -m "feat(compiler): resolve LoadBalancer targets into CompiledNIC.LB; drop UnderlayRoute copy"
```

---

## Task 4: Compiler controller — LoadBalancer watch, predicates, bounded list, diff-before-write

**Files:**
- Modify: `netplane/controllers/compilednic.go:113-180` (`Reconcile`, `SetupWithManager`, add `nicsForLB`)
- Test: `netplane/controllers/compilednic_test.go`

- [ ] **Step 1: Write the failing test (diff-before-write + nicsForLB)**

Append to `netplane/controllers/compilednic_test.go`:

```go
import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"k8s.io/apimachinery/pkg/types"
)

func lbScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestReconcile_NoWriteWhenUnchanged(t *testing.T) {
	s := lbScheme(t)
	node := "nodeA"
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default", Labels: map[string]string{"app": "web"}},
		Spec:       netv1.NetworkInterfaceSpec{NodeName: &node},
		Status:     netv1.NetworkInterfaceStatus{VNI: 100, UnderlayRoute: "2001:db8::dd"},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(nic).Build()
	r := &CompiledNICReconciler{Client: cl}
	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "web-0"}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var first netv1.CompiledNIC
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "default-web-0"}, &first); err != nil {
		t.Fatal(err)
	}
	rv1 := first.ResourceVersion

	// Second reconcile with identical inputs must NOT write (resourceVersion unchanged).
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var second netv1.CompiledNIC
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "default-web-0"}, &second); err != nil {
		t.Fatal(err)
	}
	if second.ResourceVersion != rv1 {
		t.Fatalf("resourceVersion changed on no-op reconcile: %s -> %s", rv1, second.ResourceVersion)
	}
}

func TestNicsForLB(t *testing.T) {
	s := lbScheme(t)
	nic := &netv1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default", Labels: map[string]string{"app": "web"}}}
	other := &netv1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "db-0", Namespace: "default", Labels: map[string]string{"app": "db"}}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(nic, other).Build()
	r := &CompiledNICReconciler{Client: cl}
	lb := &netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "web-lb", Namespace: "default"},
		Spec:       netv1.LoadBalancerSpec{TargetSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}},
	}
	reqs := r.nicsForLB(context.Background(), client.Object(lb))
	if len(reqs) != 1 || reqs[0].Name != "web-0" {
		t.Fatalf("nicsForLB = %+v, want [web-0]", reqs)
	}
}
```

- [ ] **Step 2: Run it — verify it fails**

Run: `cd netplane && go test ./controllers/`
Expected: FAIL to build (`Compile` arity from Task 3; `nicsForLB` undefined).

- [ ] **Step 3: Update Reconcile, SetupWithManager, add nicsForLB**

In `netplane/controllers/compilednic.go`:

1. Add imports: `"reflect"`, and controller-runtime `"sigs.k8s.io/controller-runtime/pkg/builder"`, `"sigs.k8s.io/controller-runtime/pkg/predicate"`.

2. In `Reconcile`, after listing policies (line 121) add a LoadBalancer list, pass it to `Compile`, and replace the unconditional update with a diff:

```go
	var lbs netv1.LoadBalancerList
	if err := r.Client.List(ctx, &lbs, client.InNamespace(nic.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list loadbalancers: %w", err)
	}
	compiled := Compile(&nic, policies.Items, lbs.Items)
```

Replace the `default:` branch of the existing/`err`-switch (lines 136-140) with a diff-before-write:

```go
	default:
		if reflect.DeepEqual(existing.Spec, compiled.Spec) {
			return ctrl.Result{}, nil // unchanged: no write, no resourceVersion churn
		}
		existing.Spec = compiled.Spec
		if err := r.Client.Update(ctx, &existing); err != nil {
			return ctrl.Result{}, fmt.Errorf("update compilednic: %w", err)
		}
	}
```

3. In `SetupWithManager`, add the LoadBalancer watch with a predicate, and add a predicate to the NetworkPolicy watch (leave `For(&NetworkInterface{})` UNfiltered — the compiler reads NIC **status** (VNI/UnderlayRoute/Port), and status updates keep the same generation, so a GenerationChangedPredicate there would drop needed recompiles):

```go
func (r *CompiledNICReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.NetworkInterface{}).
		Owns(&netv1.CompiledNIC{}).
		Watches(&netv1.NetworkPolicy{}, handler.EnqueueRequestsFromMapFunc(r.nicsForPolicy),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&netv1.LoadBalancer{}, handler.EnqueueRequestsFromMapFunc(r.nicsForLB),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
```

4. Add `nicsForLB` (mirror `nicsForPolicy`):

```go
// nicsForLB maps a LoadBalancer event to reconcile requests for every NetworkInterface in the same
// namespace it targets (TargetRefs by name or TargetSelector by label).
func (r *CompiledNICReconciler) nicsForLB(ctx context.Context, obj client.Object) []reconcile.Request {
	lb, ok := obj.(*netv1.LoadBalancer)
	if !ok {
		return nil
	}
	var nics netv1.NetworkInterfaceList
	if err := r.Client.List(ctx, &nics, client.InNamespace(lb.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range nics.Items {
		if lbMatchesNIC(lb, &nics.Items[i], labels.Set(nics.Items[i].Labels)) {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: nics.Items[i].Namespace, Name: nics.Items[i].Name,
			}})
		}
	}
	return reqs
}
```

- [ ] **Step 4: Run the controllers suite — verify pass**

Run: `cd netplane && go test ./controllers/`
Expected: PASS (Task 3 + Task 4 tests, plus the existing envtest).

- [ ] **Step 5: Commit**

```bash
git add netplane/controllers/compilednic.go netplane/controllers/compilednic_test.go
git commit -m "feat(compiler): LoadBalancer watch + predicates, bounded list, diff-before-write"
```

---

## Task 5: Agent — LB methods on the Dataplane interface + adapter + fake

**Files:**
- Modify: `netplane/agent/bus.go:19-44` (Dataplane interface), `:187-231` (dpAdapter)
- Modify: `netplane/agent/bus_test.go` (fakeDP)

- [ ] **Step 1: Write the failing test (fake records LB calls)**

In `netplane/agent/bus_test.go`, extend `fakeDP` to record LB calls and add an assertion test:

```go
// add to fakeDP's struct: 
//   lbVips    []string            // ids added
//   lbDels    []string            // ids deleted
//   lbBackends map[string][]string // id -> backends
// and initialize lbBackends in newFakeDP().

func (f *fakeDP) AddLbVip(ctx context.Context, id string, vni uint32, vip, lbUnderlay string, ports []LbPort) error {
	f.lbVips = append(f.lbVips, id)
	return nil
}
func (f *fakeDP) DelLbVip(ctx context.Context, id string) error {
	f.lbDels = append(f.lbDels, id)
	return nil
}
func (f *fakeDP) AddLbBackend(ctx context.Context, id, backendUnderlay string) error {
	f.lbBackends[id] = append(f.lbBackends[id], backendUnderlay)
	return nil
}
func (f *fakeDP) DelLbBackend(ctx context.Context, id, backendUnderlay string) error {
	cur := f.lbBackends[id][:0]
	for _, b := range f.lbBackends[id] {
		if b != backendUnderlay {
			cur = append(cur, b)
		}
	}
	f.lbBackends[id] = cur
	return nil
}

func TestFakeDP_LBImplementsInterface(t *testing.T) {
	var _ Dataplane = newFakeDP()
}
```

(Adjust the exact `fakeDP` field additions to match its current definition in `bus_test.go`; add `lbBackends: map[string][]string{}` wherever `newFakeDP()` constructs it.)

- [ ] **Step 2: Run it — verify it fails**

Run: `cd netplane && go test ./agent/ -run TestFakeDP_LBImplementsInterface`
Expected: FAIL (Dataplane has no LB methods; fake doesn't satisfy it once methods are added — or `LbPort` undefined).

- [ ] **Step 3: Add LB methods to the interface + adapter**

In `netplane/agent/bus.go`, add to the `Dataplane` interface (after `DelFwRule`, line 32):

```go
	// AddLbVip registers a load balancer VIP (id == VIP). vni is the WAN/public VNI (0 at the edge);
	// lbUnderlay is the edge's own anycast underlay (unused-but-required for vni==0).
	AddLbVip(ctx context.Context, id string, vni uint32, vip, lbUnderlay string, ports []LbPort) error
	// DelLbVip removes a registered LB VIP by id.
	DelLbVip(ctx context.Context, id string) error
	// AddLbBackend appends a backend underlay /128 to a registered LB VIP.
	AddLbBackend(ctx context.Context, id, backendUnderlay string) error
	// DelLbBackend removes a backend underlay /128 from a registered LB VIP.
	DelLbBackend(ctx context.Context, id, backendUnderlay string) error
```

Add the `LbPort` type near `FwRule` (after line 44):

```go
// LbPort is one LB service tuple for AddLbVip. Proto is the IP protocol number (6=TCP, 17=UDP).
type LbPort struct {
	Port  uint32
	Proto uint32
}
```

Add the adapter methods after `DelFwRule` (after line 231):

```go
func (d dpAdapter) AddLbVip(ctx context.Context, id string, vni uint32, vip, lbUnderlay string, ports []LbPort) error {
	pp := make([]*dpv1.PortProto, 0, len(ports))
	for _, p := range ports {
		pp = append(pp, &dpv1.PortProto{Port: p.Port, Proto: p.Proto})
	}
	_, err := d.c.AddLbVip(ctx, &dpv1.AddLbVipRequest{Id: id, Vni: vni, VipIpv4: vip, LbUnderlay: lbUnderlay, Ports: pp})
	return err
}
func (d dpAdapter) DelLbVip(ctx context.Context, id string) error {
	_, err := d.c.DelLbVip(ctx, &dpv1.DelLbVipRequest{Id: id})
	return err
}
func (d dpAdapter) AddLbBackend(ctx context.Context, id, backendUnderlay string) error {
	_, err := d.c.AddLbBackend(ctx, &dpv1.AddLbBackendRequest{Id: id, BackendUnderlay: backendUnderlay})
	return err
}
func (d dpAdapter) DelLbBackend(ctx context.Context, id, backendUnderlay string) error {
	_, err := d.c.DelLbBackend(ctx, &dpv1.DelLbBackendRequest{Id: id, BackendUnderlay: backendUnderlay})
	return err
}
```

(Note: `AddLbVipRequest.VipIpv4` is the proto field name even though the VIP may be v6; the dataplane parses either family. Pass the VIP string as-is.)

- [ ] **Step 4: Run it — verify it passes**

Run: `cd netplane && go test ./agent/ -run TestFakeDP_LBImplementsInterface`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add netplane/agent/bus.go netplane/agent/bus_test.go
git commit -m "feat(agent): LB methods on Dataplane interface + adapter + fake"
```

---

## Task 6: Agent — desiredLB join helper (CompiledNIC.LB × NetworkInterface /128)

**Files:**
- Create: `netplane/agent/lbreconcile.go`
- Create test: `netplane/agent/lbreconcile_test.go`

- [ ] **Step 1: Write the failing test**

Create `netplane/agent/lbreconcile_test.go`:

```go
package agent

import (
	"context"
	"testing"

	netv1 "github.com/trevex/flowplane/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func lbTestScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDesiredLB_JoinsUnderlayFromNIC(t *testing.T) {
	s := lbTestScheme(t)
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-web-0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName: "nodeA",
			NICRef:   netv1.LocalObjectReference{Name: "web-0"},
			VNI:      100,
			LB:       []netv1.CompiledLB{{VIP: "203.0.113.50", Ports: []netv1.CompiledLBPort{{Port: 443, Proto: "TCP"}}}},
		},
	}
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default"},
		Status:     netv1.NetworkInterfaceStatus{UnderlayRoute: "2001:db8::dd"},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cnic, nic).Build()
	r := &Reconciler{client: cl, nodeID: "nodeA"}

	got, err := r.desiredLB(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 lbBacking, got %d", len(got))
	}
	if got[0].VIP != "203.0.113.50" || got[0].Vni != 100 || got[0].NicUnderlay != "2001:db8::dd" {
		t.Fatalf("lbBacking = %+v", got[0])
	}
	if len(got[0].Ports) != 1 || got[0].Ports[0].Port != 443 || got[0].Ports[0].Proto != 6 {
		t.Fatalf("ports = %+v, want [{443 6}]", got[0].Ports)
	}
}

func TestDesiredLB_SkipsWhenNoUnderlay(t *testing.T) {
	s := lbTestScheme(t)
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-web-0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName: "nodeA", NICRef: netv1.LocalObjectReference{Name: "web-0"}, VNI: 100,
			LB: []netv1.CompiledLB{{VIP: "203.0.113.50"}},
		},
	}
	nic := &netv1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default"}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cnic, nic).Build()
	r := &Reconciler{client: cl, nodeID: "nodeA"}
	got, err := r.desiredLB(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 (no underlay allocated yet), got %d", len(got))
	}
}
```

- [ ] **Step 2: Run it — verify it fails**

Run: `cd netplane && go test ./agent/ -run TestDesiredLB`
Expected: FAIL (`desiredLB`, `lbBacking` undefined).

- [ ] **Step 3: Implement desiredLB**

Create `netplane/agent/lbreconcile.go`:

```go
package agent

import (
	"context"
	"fmt"

	netv1 "github.com/trevex/flowplane/api/v1alpha1"
)

// lbBacking is one (VIP, backend NIC) pairing this node hosts: the join of a CompiledNIC.LB entry
// with the NIC's own node-local underlay /128 (from NetworkInterface.Status.UnderlayRoute).
type lbBacking struct {
	VIP         string   // v4 or v6
	Vni         uint32   // the backend NIC's VPC VNI (for the E/W anycast route)
	NicUnderlay string   // the backend NIC's /128 (E/W route nexthop + LB_VIP owner_underlay)
	Ports       []LbPort // service tuples (proto as IP protocol number)
}

// desiredLB lists the CompiledNICs scheduled to this node and joins each CompiledNIC.LB entry with
// its NIC's node-local underlay /128 (from NetworkInterface.Status). A NIC without an allocated
// underlay yet is skipped (nothing to announce until it is attached).
func (r *Reconciler) desiredLB(ctx context.Context) ([]lbBacking, error) {
	var cnics netv1.CompiledNICList
	if err := r.client.List(ctx, &cnics); err != nil {
		return nil, fmt.Errorf("list compilednics: %w", err)
	}
	var nics netv1.NetworkInterfaceList
	if err := r.client.List(ctx, &nics); err != nil {
		return nil, fmt.Errorf("list networkinterfaces: %w", err)
	}
	underlayByNIC := map[string]string{} // namespace/name -> underlay /128
	for i := range nics.Items {
		n := &nics.Items[i]
		underlayByNIC[n.Namespace+"/"+n.Name] = n.Status.UnderlayRoute
	}

	var out []lbBacking
	for i := range cnics.Items {
		c := &cnics.Items[i]
		if c.Spec.NodeName != r.nodeID || len(c.Spec.LB) == 0 {
			continue
		}
		ul := underlayByNIC[c.Namespace+"/"+c.Spec.NICRef.Name]
		if ul == "" {
			continue // NIC not attached yet
		}
		for _, lb := range c.Spec.LB {
			ports := make([]LbPort, 0, len(lb.Ports))
			for _, p := range lb.Ports {
				ports = append(ports, LbPort{Port: uint32(p.Port), Proto: protoNum(p.Proto)})
			}
			out = append(out, lbBacking{VIP: lb.VIP, Vni: uint32(c.Spec.VNI), NicUnderlay: ul, Ports: ports})
		}
	}
	return out, nil
}
```

- [ ] **Step 4: Run it — verify it passes**

Run: `cd netplane && go test ./agent/ -run TestDesiredLB`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add netplane/agent/lbreconcile.go netplane/agent/lbreconcile_test.go
git commit -m "feat(agent): desiredLB join (CompiledNIC.LB x NIC underlay /128)"
```

---

## Task 7: Agent — emit the E/W anycast VIP route

**Files:**
- Modify: `netplane/agent/reconcile.go:62-99` (`Desired`)
- Test: `netplane/agent/lbreconcile_test.go`

- [ ] **Step 1: Write the failing test**

Append to `netplane/agent/lbreconcile_test.go`:

```go
func TestDesired_EmitsVIPAnycastRoute(t *testing.T) {
	s := lbTestScheme(t)
	node := "nodeA"
	// VPC provides VNI resolution via vniFor: use a NIC whose Status.VNI is set so vniFor returns it.
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default"},
		Spec:       netv1.NetworkInterfaceSpec{NodeName: &node, IPs: []string{"10.0.0.20"}},
		Status:     netv1.NetworkInterfaceStatus{VNI: 100, UnderlayRoute: "2001:db8::dd"},
	}
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-web-0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName: node, NICRef: netv1.LocalObjectReference{Name: "web-0"}, VNI: 100,
			LB: []netv1.CompiledLB{{VIP: "203.0.113.50", Ports: []netv1.CompiledLBPort{{Port: 443, Proto: "TCP"}}}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(nic, cnic).Build()
	r := &Reconciler{client: cl, nodeID: node, underlay: "2001:db8::dd"}

	_, announce, _, err := r.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, rt := range announce {
		if rt.Prefix == "203.0.113.50/32" && rt.Nexthop == "2001:db8::dd" && rt.Vni == 100 && !rt.External {
			found = true
		}
	}
	if !found {
		t.Fatalf("VIP anycast route not emitted; got %+v", announce)
	}
}
```

(Note: this relies on `vniFor` resolving the NIC to VNI 100. If `vniFor` requires a VPC object, add a minimal `VPC` to the fake client matching how the existing `Desired`/`vniFor` tests set it up — check `reconcile_test.go` for the pattern and mirror it.)

- [ ] **Step 2: Run it — verify it fails**

Run: `cd netplane && go test ./agent/ -run TestDesired_EmitsVIPAnycastRoute`
Expected: FAIL (no VIP route emitted yet).

- [ ] **Step 3: Emit the VIP anycast route in Desired**

In `netplane/agent/reconcile.go`, at the end of `Desired` (just before `return subs, announce, announceNat, nil` — after the NAT block, around line 130+), add:

```go
	// LB backends: announce each backed VIP as an anycast overlay route (nexthop = this NIC's /128).
	// Multiple backend NICs announcing the same VIP → the fabric ECMPs across them. This is the E/W
	// load-balancer path; it reuses the plain route channel and needs no LB-specific datapath state.
	lbs, err := r.desiredLB(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, lb := range lbs {
		prefix, err := hostPrefix(lb.VIP)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("lb vip %q: %w", lb.VIP, err)
		}
		announce = append(announce, Route{Vni: lb.Vni, Prefix: prefix, Nexthop: lb.NicUnderlay, External: false})
	}
```

(If `Desired`'s return statement variable names differ, adapt. `hostPrefix` already exists in `reconcile.go`.)

- [ ] **Step 4: Run it — verify it passes**

Run: `cd netplane && go test ./agent/ -run TestDesired_EmitsVIPAnycastRoute`
Expected: PASS.

- [ ] **Step 5: Run the whole agent package**

Run: `cd netplane && go test ./agent/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add netplane/agent/reconcile.go netplane/agent/lbreconcile_test.go
git commit -m "feat(agent): announce E/W anycast VIP routes for LB backends"
```

---

## Task 8: Agent — DesiredPublic emits LB_VIP records for backends

**Files:**
- Modify: `netplane/agent/public.go:28-38` (`DesiredPublic`)
- Modify: `netplane/cmd/agent/main.go:81` (call site)
- Test: `netplane/agent/lbreconcile_test.go`

- [ ] **Step 1: Write the failing test**

Append to `netplane/agent/lbreconcile_test.go`:

```go
import rbv1 "github.com/trevex/flowplane/netplane/gen/routebusv1"

func TestDesiredPublic_EmitsLBVIP(t *testing.T) {
	s := lbTestScheme(t)
	node := "nodeA"
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default"},
		Status:     netv1.NetworkInterfaceStatus{VNI: 100, UnderlayRoute: "2001:db8::dd"},
	}
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-web-0", Namespace: "default"},
		Spec: netv1.CompiledNICSpec{
			NodeName: node, NICRef: netv1.LocalObjectReference{Name: "web-0"}, VNI: 100,
			LB: []netv1.CompiledLB{{VIP: "203.0.113.50"}},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(nic, cnic).Build()
	r := &Reconciler{client: cl, nodeID: node, underlay: "2001:db8::dd"}

	recs, err := r.DesiredPublic(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, pp := range recs {
		if pp.Kind == rbv1.PublicKind_PUBLIC_KIND_LB_VIP && pp.Prefix == "203.0.113.50/32" && pp.OwnerUnderlay == "2001:db8::dd" {
			found = true
		}
	}
	if !found {
		t.Fatalf("LB_VIP record not emitted; got %+v", recs)
	}
}
```

- [ ] **Step 2: Run it — verify it fails**

Run: `cd netplane && go test ./agent/ -run TestDesiredPublic_EmitsLBVIP`
Expected: FAIL (`DesiredPublic` takes no ctx and returns no error; no LB_VIP records).

- [ ] **Step 3: Change DesiredPublic to take ctx and emit LB_VIP**

In `netplane/agent/public.go`, change the signature and body of `DesiredPublic`:

```go
func (r *Reconciler) DesiredPublic(ctx context.Context) ([]PublicPrefix, error) {
	var recs []PublicPrefix
	if r.edgeLoopback != "" {
		recs = append(recs, PublicPrefix{
			Kind:          rbv1.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY,
			Prefix:        r.underlay + "/128",
			OwnerUnderlay: r.edgeLoopback,
			Vni:           0,
		})
	}
	// LB backends on this node: one LB_VIP record per backed VIP so the edge can AddLbBackend.
	// vni=0: the edge supplies its WAN LB-VNI at AddLbVip; AddLbBackend needs no VNI.
	lbs, err := r.desiredLB(ctx)
	if err != nil {
		return nil, err
	}
	for _, lb := range lbs {
		prefix, err := hostPrefix(lb.VIP)
		if err != nil {
			return nil, fmt.Errorf("lb vip %q: %w", lb.VIP, err)
		}
		recs = append(recs, PublicPrefix{
			Kind:          rbv1.PublicKind_PUBLIC_KIND_LB_VIP,
			Prefix:        prefix,
			OwnerUnderlay: lb.NicUnderlay,
			Vni:           0,
		})
	}
	return recs, nil
}
```

Add imports `"context"` and `"fmt"` to `public.go` if not present.

- [ ] **Step 4: Update the call site in main.go**

In `netplane/cmd/agent/main.go`, replace the `bus.Run(...)` call (line 81) so it computes DesiredPublic with ctx and handles the error:

```go
		pub, err := r.DesiredPublic(ctx)
		if err != nil {
			log.Printf("desired public: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		bus := agent.NewBus(*nodeID, *underlay, dp, *edgeLoopback != "")
		if err := bus.Run(ctx, rb, subs, ann, annNat, pub); err != nil {
			log.Printf("bus session ended: %v; reconnecting", err)
		}
```

(The `NewBus` 4th arg `isEdge` is added in Task 9; if building main.go before Task 9, temporarily use the 3-arg form and add the 4th arg in Task 9. Prefer to land Task 8 + Task 9 together before building main.)

- [ ] **Step 5: Run the LB_VIP test**

Run: `cd netplane && go test ./agent/ -run TestDesiredPublic_EmitsLBVIP`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add netplane/agent/public.go netplane/cmd/agent/main.go netplane/agent/lbreconcile_test.go
git commit -m "feat(agent): DesiredPublic emits LB_VIP records for local LB backends"
```

---

## Task 9: Agent — edge consumes LB (applyPublic backend + ReconcileLB AddLbVip)

**Files:**
- Modify: `netplane/agent/bus.go` (`Bus` struct + `NewBus` + `applyPublic`)
- Modify: `netplane/agent/reconcile.go` (`Reconciler.appliedLbVips` field + `ReconcileLB`)
- Modify: `netplane/agent/lbreconcile.go` (`ReconcileLB` impl)
- Modify: `netplane/cmd/agent/main.go` (call `ReconcileLB`)
- Test: `netplane/agent/lbreconcile_test.go`, `netplane/agent/bus_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `netplane/agent/bus_test.go`:

```go
func TestApplyPublic_LBVIP_EdgeAddsBackend(t *testing.T) {
	dp := newFakeDP()
	b := NewBus("edge1", "2001:db8::e", dp, true) // isEdge = true
	b.applyPublic(&rbv1.PublicPrefix{
		Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "2001:db8::dd",
	}, rbv1.RouteOp_ROUTE_OP_ADD)
	if got := dp.lbBackends["203.0.113.50"]; len(got) != 1 || got[0] != "2001:db8::dd" {
		t.Fatalf("edge AddLbBackend not recorded: %+v", dp.lbBackends)
	}
}

func TestApplyPublic_LBVIP_NonEdgeIgnores(t *testing.T) {
	dp := newFakeDP()
	b := NewBus("nodeA", "2001:db8::dd", dp, false) // not edge
	b.applyPublic(&rbv1.PublicPrefix{
		Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "2001:db8::dd",
	}, rbv1.RouteOp_ROUTE_OP_ADD)
	if len(dp.lbBackends) != 0 {
		t.Fatalf("non-edge must ignore LB_VIP; got %+v", dp.lbBackends)
	}
}
```

Append to `netplane/agent/lbreconcile_test.go`:

```go
func TestReconcileLB_EdgeAddsAndDiffs(t *testing.T) {
	s := lbTestScheme(t)
	lb := &netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "web-lb", Namespace: "default"},
		Spec:       netv1.LoadBalancerSpec{VIP: "203.0.113.50", Ports: []netv1.LoadBalancerPort{{Port: 443, Proto: "TCP"}}},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(lb).Build()
	dp := newFakeDP()
	r := &Reconciler{client: cl, nodeID: "edge1", underlay: "2001:db8::e", edgeLoopback: "fd00::1", dp: dp}

	if err := r.ReconcileLB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.lbVips) != 1 || dp.lbVips[0] != "203.0.113.50" {
		t.Fatalf("want AddLbVip 203.0.113.50, got %+v", dp.lbVips)
	}
	// Second reconcile: unchanged → no re-add (create_lb rejects dup ids).
	dp.lbVips = nil
	if err := r.ReconcileLB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.lbVips) != 0 {
		t.Fatalf("steady-state re-added AddLbVip: %+v", dp.lbVips)
	}
}

func TestReconcileLB_NonEdgeNoop(t *testing.T) {
	s := lbTestScheme(t)
	lb := &netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "web-lb", Namespace: "default"},
		Spec:       netv1.LoadBalancerSpec{VIP: "203.0.113.50"},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(lb).Build()
	dp := newFakeDP()
	r := &Reconciler{client: cl, nodeID: "nodeA", dp: dp} // no edgeLoopback
	if err := r.ReconcileLB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(dp.lbVips) != 0 {
		t.Fatalf("non-edge must not AddLbVip: %+v", dp.lbVips)
	}
}
```

- [ ] **Step 2: Run them — verify they fail**

Run: `cd netplane && go test ./agent/ -run 'TestApplyPublic_LBVIP|TestReconcileLB'`
Expected: FAIL (`NewBus` arity; `applyPublic` LB_VIP unhandled; `ReconcileLB`/`appliedLbVips` undefined).

- [ ] **Step 3: Add isEdge to Bus + NewBus + applyPublic LB_VIP case**

In `netplane/agent/bus.go`:

1. Add `isEdge bool` to the `Bus` struct (after `dp Dataplane`, line 58).

2. Change `NewBus`:

```go
func NewBus(nodeID, underlay string, dp Dataplane, isEdge bool) *Bus {
	return &Bus{nodeID: nodeID, underlay: underlay, dp: dp, isEdge: isEdge, learnedEdge: map[string]string{}}
}
```

3. In `applyPublic`, add an `LB_VIP` case before `default:` (line 64). The VIP id is the address portion of the prefix; `AddLbBackend` needs the LB to already exist (ReconcileLB runs before `bus.Run` each loop iteration, so on session replay the VIP is present). Errors are logged (retry next session):

```go
	case rbv1.PublicKind_PUBLIC_KIND_LB_VIP:
		if !b.isEdge {
			return // only the edge runs maglev/backends; E/W uses the plain anycast route
		}
		vip := stripMask(pp.GetPrefix())
		owner := pp.GetOwnerUnderlay()
		switch op {
		case rbv1.RouteOp_ROUTE_OP_ADD:
			if err := b.dp.AddLbBackend(context.Background(), vip, owner); err != nil {
				log.Printf("AddLbBackend vip=%s backend=%s: %v", vip, owner, err)
			}
		case rbv1.RouteOp_ROUTE_OP_WITHDRAW:
			if err := b.dp.DelLbBackend(context.Background(), vip, owner); err != nil {
				log.Printf("DelLbBackend vip=%s backend=%s: %v", vip, owner, err)
			}
		}
```

Add `"context"` to `bus.go` imports if not already present (it is used elsewhere; confirm).

- [ ] **Step 4: Add appliedLbVips + ReconcileLB**

In `netplane/agent/reconcile.go`, add a field to `Reconciler` (after `appliedFw`, line 27):

```go
	// appliedLbVips tracks the LB VIPs (id == VIP) this edge has AddLbVip'd, so ReconcileLB adds new
	// ones, deletes removed ones, and never re-adds (create_lb rejects duplicate ids).
	appliedLbVips map[string][]LbPort
```

In `netplane/agent/lbreconcile.go`, add `ReconcileLB` (imports: add `"errors"`):

```go
// ReconcileLB is the EDGE-only LB VIP reconcile: it lists LoadBalancers and diffs AddLbVip/DelLbVip
// against appliedLbVips. Backends are added separately by the bus's applyPublic (LB_VIP records).
// Non-edge nodes are a no-op (they reach VIPs via the E/W anycast route, not maglev).
func (r *Reconciler) ReconcileLB(ctx context.Context) error {
	if r.dp == nil || r.edgeLoopback == "" {
		return nil
	}
	var lbs netv1.LoadBalancerList
	if err := r.client.List(ctx, &lbs); err != nil {
		return fmt.Errorf("list loadbalancers: %w", err)
	}
	desired := map[string][]LbPort{} // vip -> ports
	for i := range lbs.Items {
		lb := &lbs.Items[i]
		ports := make([]LbPort, 0, len(lb.Spec.Ports))
		for _, p := range lb.Spec.Ports {
			ports = append(ports, LbPort{Port: uint32(p.Port), Proto: protoNum(p.Proto)})
		}
		desired[lb.Spec.VIP] = ports
	}
	if r.appliedLbVips == nil {
		r.appliedLbVips = map[string][]LbPort{}
	}
	var errs []error
	// Delete VIPs no longer desired (or whose ports changed → delete then re-add below).
	for vip, prevPorts := range r.appliedLbVips {
		if want, ok := desired[vip]; ok && lbPortsEqual(want, prevPorts) {
			continue
		}
		if err := r.dp.DelLbVip(ctx, vip); err != nil {
			errs = append(errs, fmt.Errorf("DelLbVip %s: %w", vip, err))
			continue
		}
		delete(r.appliedLbVips, vip)
	}
	// Add VIPs newly desired (or just-deleted because ports changed). lbUnderlay = the edge's own
	// anycast underlay; vni=0 (WAN). create_lb skips the UNDERLAY write for vni==0 (see Task 2).
	for vip, ports := range desired {
		if cur, ok := r.appliedLbVips[vip]; ok && lbPortsEqual(cur, ports) {
			continue
		}
		if err := r.dp.AddLbVip(ctx, vip, 0, vip, r.underlay, ports); err != nil {
			errs = append(errs, fmt.Errorf("AddLbVip %s: %w", vip, err))
			continue
		}
		r.appliedLbVips[vip] = ports
	}
	return errors.Join(errs...)
}

func lbPortsEqual(a, b []LbPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
```

- [ ] **Step 5: Wire ReconcileLB + NewBus isEdge into main.go**

In `netplane/cmd/agent/main.go`, after the `ReconcileFirewall` call (line 79), add:

```go
		if err := r.ReconcileLB(ctx); err != nil {
			log.Printf("reconcile lb: %v", err)
		}
```

Ensure `NewBus` uses the 4-arg form (`agent.NewBus(*nodeID, *underlay, dp, *edgeLoopback != "")`) as set in Task 8.

- [ ] **Step 6: Run the tests — verify pass**

Run: `cd netplane && go test ./agent/ -run 'TestApplyPublic_LBVIP|TestReconcileLB'`
Expected: PASS.

- [ ] **Step 7: Build the agent binary + full agent tests**

Run: `cd netplane && go build ./... && go test ./agent/`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add netplane/agent/bus.go netplane/agent/reconcile.go netplane/agent/lbreconcile.go netplane/cmd/agent/main.go netplane/agent/bus_test.go netplane/agent/lbreconcile_test.go
git commit -m "feat(agent): edge consumes LB (applyPublic AddLbBackend + ReconcileLB AddLbVip)"
```

---

## Task 10: Sim — CompiledLB serde + model-A E/W anycast coverage

**Files:**
- Modify: `flowplane-sim/src/compilednic.rs:19-45` (serde structs; `underlay_route` optional)
- Modify: `flowplane-sim/src/lb_scenario_test.rs` (add model-A E/W tests)

- [ ] **Step 1: Make underlay_route optional + add LB serde (so the fixture drop is tolerated)**

In `flowplane-sim/src/compilednic.rs`, in `struct Spec` (lines 19-25) make `underlay_route` optional (the field is being removed from the Go CRD; keep the sim tolerant):

```rust
pub struct Spec {
    pub vni: i32,
    #[serde(default, rename = "underlayRoute")]
    pub underlay_route: String,
    #[serde(default)]
    pub firewall: Firewall,
    #[serde(default)]
    pub lb: Vec<Lb>,
}
```

Add the LB serde structs after `Rule` (after line 45):

```rust
/// Serde mirror of CompiledLB.
#[derive(Deserialize, Default)]
pub struct Lb {
    pub vip: String,
    #[serde(default)]
    pub ports: Vec<LbPort>,
}

/// Serde mirror of CompiledLBPort.
#[derive(Deserialize, Default)]
pub struct LbPort {
    pub port: i32,
    #[serde(default)]
    pub proto: String,
}
```

- [ ] **Step 2: Write the failing model-A E/W tests**

In `flowplane-sim/src/lb_scenario_test.rs`, add two tests proving model-A E/W: the backend has NO LB maps (`backend_node(false)`); an encapped guest→VIP frame delivered straight to the backend's underlay base-delivers, gated by the ingress firewall.

```rust
#[test]
fn ew_lb_anycast_delivered_with_policy() {
    // Model A: the E/W VIP is an anycast route → guest encaps straight to the backend /128.
    // The backend has NO LB maps; uplink_rx base-delivers after the ingress firewall. Internal
    // source (10.0.0.0/8) is permitted on 443, so it is delivered.
    let mut fab = Fabric::new();
    let mut b = backend_node(false);
    apply_fw(&mut b.maps, HOSTB_TAP, allow_internal_443());
    fab.add_node("hostB", b);
    fab.route(HOSTB_UL, "hostB");

    let inner = eth_ipv4_tcp(GUEST_A, OVERLAY_VIP, 443);
    let encapped = encap_to(&inner, HOSTA_UL, HOSTB_UL);
    let t = fab.deliver("hostB", Prog::UplinkRx, &encapped);
    assert_eq!(
        t.outcome,
        Outcome::Delivered { node: "hostB", tap: HOSTB_TAP },
        "hops: {}",
        t.hops.len()
    );
    assert_eq!(t.hops.len(), 1, "single uplink base-deliver, no maglev/reforward");
}

#[test]
fn ew_lb_anycast_dropped_without_policy() {
    // Same anycast delivery, but the backend has a policy that does NOT permit the guest source
    // (only 1.2.3.0/24 on 443). Deny-by-default drops it — LB membership grants no permission.
    let mut fab = Fabric::new();
    let mut b = backend_node(false);
    apply_fw(
        &mut b.maps,
        HOSTB_TAP,
        r#"[{"cidr":"1.2.3.0/24","proto":"TCP","port":443,"action":"Allow"}]"#,
    );
    fab.add_node("hostB", b);
    fab.route(HOSTB_UL, "hostB");

    let inner = eth_ipv4_tcp(GUEST_A, OVERLAY_VIP, 443);
    let encapped = encap_to(&inner, HOSTA_UL, HOSTB_UL);
    let t = fab.deliver("hostB", Prog::UplinkRx, &encapped);
    assert_eq!(
        t.outcome,
        Outcome::Dropped { node: "hostB" },
        "LB delivery must be dropped when no NetworkPolicy admits the source"
    );
}
```

- [ ] **Step 3: Run them — verify they pass (and the serde change compiles)**

Run: `cargo test -p flowplane-sim ew_lb_anycast`
Expected: PASS. (These exercise the base path + firewall directly; they should pass immediately once the serde struct compiles — they validate the model-A datapath, which needs no new datapath code.)

- [ ] **Step 4: Run the full sim + compilednic serde tests**

Run: `cargo test -p flowplane-sim`
Expected: PASS (existing `apply_and_eval_from_fixture` still parses — `underlayRoute` still present in that fixture is fine since it's now `#[serde(default)]`).

- [ ] **Step 5: Commit**

```bash
git add flowplane-sim/src/compilednic.rs flowplane-sim/src/lb_scenario_test.rs
git commit -m "test(sim): CompiledLB serde + model-A E/W anycast LB coverage (deliver iff policy admits)"
```

---

## Task 11: Full build, cross-cutting checks, docs sweep

**Files:**
- Verify only; possibly `netplane/agent/bus.go:233` (drop the `grpc.WaitForReady` keep-alive line if the import is now used).

- [ ] **Step 1: Build everything**

Run: `cd netplane && go build ./... && cd .. && go build ./api/... && cargo build -p flowplane -p flowplane-sim`
Expected: PASS.

- [ ] **Step 2: Run all Go + Rust tests**

Run: `cd netplane && go test ./... && cd .. && cargo test -p flowplane -p flowplane-sim -p flowplane-core`
Expected: PASS.

- [ ] **Step 3: Grep for stale UnderlayRoute references on CompiledNIC**

Run: `grep -rn "CompiledNIC" --include=*.go . | grep -i underlay; grep -rn "Spec.UnderlayRoute" --include=*.go netplane/`
Expected: no references to `CompiledNIC(...).Spec.UnderlayRoute` remain (only `NetworkInterface.Status.UnderlayRoute`, which is correct). Fix any stragglers.

- [ ] **Step 4: Confirm the `go vet` is clean for the touched packages**

Run: `cd netplane && go vet ./agent/... ./controllers/...`
Expected: no findings. (If `bus.go`'s trailing `var _ = grpc.WaitForReady` is now dead/duplicate, leave it unless vet complains.)

- [ ] **Step 5: Commit any cleanup**

```bash
git add -A
git commit -m "chore(lb): build/vet sweep for LoadBalancer wiring" || echo "nothing to clean up"
```

---

## Self-Review (completed by plan author)

**Spec coverage:**
- §3.1 LoadBalancer CRD → Task 1. §3.2 CompiledNIC.LB + remove UnderlayRoute → Tasks 1, 3. §4.1 E/W anycast route → Tasks 6, 7. §4.2 N/S LB_VIP + edge AddLbVip/AddLbBackend → Tasks 5, 8, 9. §4.3 datapath (edge vni handling) → Task 2 (note: no eBPF/flag needed under model A — the `vni=0` WAN sentinel is retained and `create_lb`'s UNDERLAY write is guarded; recorded as a deviation below). §5 compiler + fine-grained watches + diff-before-write → Tasks 3, 4. §6 agent reconcile → Tasks 7, 8, 9. §7 testing (sim + Go unit) → Tasks 3-10. Conformance test (§7 third bullet) → **deviation** (see below).
- **Deviations from spec, intentional:** (1) No edge LB-VNI flag / `wan_rx` parameterization — model A keeps `vni=0` as the WAN sentinel (nodes never register an LB), so the only datapath change is the `create_lb` UNDERLAY guard (Task 2). (2) No conformance test — the E/W LB is inherently multi-node (anycast across backends), which the single-instance conformance harness cannot express; the `flowplane-sim` Fabric is the correct multi-node coverage (Task 10). Update the spec's §4.3 and §7 to reflect these before/at execution.

**Placeholder scan:** none — every code step has full code; every command has an expected result.

**Type consistency:** `CompiledLB{VIP, Ports}` and `CompiledLBPort{Port, Proto}` consistent across Tasks 1/3/6/10. `LbPort{Port uint32, Proto uint32}` consistent across Tasks 5/6/9. `lbBacking{VIP, Vni, NicUnderlay, Ports}` consistent across Tasks 6/7/8. `NewBus(nodeID, underlay, dp, isEdge)` consistent across Tasks 8/9. `DesiredPublic(ctx) ([]PublicPrefix, error)` consistent across Tasks 8/9 and main.go. VIP id == VIP string consistent across compiler/agent/edge.

---

# Phase 2: v6 VIP North-South (end-to-end)

**Why:** Phase 1's E/W path is v6-correct (uses `hostPrefix`), but N/S is IPv4-only: `AddLbVipRequest.vip_ipv4` + `node.rs`'s `parse_ipv4`/`LbIpBytes::Ipv4`, AND the edge datapath `try_wan_rx` (ingress.rs:338) only handles `ETH_P_IP`. This phase makes a v6 WAN VIP work end-to-end at the edge: control-plane registration + an eBPF `wan_rx` v6 branch, proven in the sim.

**Key existing pieces:** the eBPF `lb_select_forward_v6` already exists (flowplane-ebpf/src/lb.rs — reads v6 dst at +24, last-4-byte LB key, TCP/UDP); `encap_and_redirect(ctx, local, src_ul, route, inner_len, inner_proto)` already takes `inner_proto` (`IPPROTO_IPV6 = 41` in parse.rs). The **core** `lb_select_forward` (flowplane-core/src/lb.rs) is v4-only; the sim runs core fns, so v6 sim coverage requires a core v6 variant.

## Task V6-1: Core `lb_select_forward_v6` + eBPF delegates to it

**Files:**
- Modify: `flowplane-core/src/lb.rs` (add `lb_select_forward_v6`)
- Modify: `flowplane-ebpf/src/lb.rs` (make the existing `lb_select_forward_v6` a thin core delegate, like the v4 one at lines 10-18)
- Test: `flowplane-core/src/lb.rs` (or the core test module) + verify eBPF builds

- [ ] **Step 1: Add `lb_select_forward_v6<P: Pkt, M: Maps>(pkt, maps, ip_off, vni) -> Option<[u8;16]>` to flowplane-core/src/lb.rs**, a faithful port of the eBPF hand-written v6 logic:
  - read `nexthdr = pkt.read_u8(ip_off + 6)?`; return None unless TCP(6)/UDP(17).
  - `dst6 = pkt.read_array::<16>(ip_off + 24)?`, `src6 = pkt.read_array::<16>(ip_off + 8)?`; take last-4 of each (`dst4 = [dst6[12],dst6[13],dst6[14],dst6[15]]`, same for src).
  - L4 ports at `ip_off + 40`: `sport = u16::from_be_bytes(pkt.read_array::<2>(ip_off+40)?)`, `dport = ...(ip_off+42)?`.
  - `lb = maps.lb_get(&LbKey{vni, ipv4: dst4, port: dport, proto: nexthdr, _pad:0})?`; if `lb.size==0` return None; `slot = hash5(&src4,&dst4,sport,dport,nexthdr) % lb.size`; `maps.maglev_get(&MaglevKey{table_id: lb.table_id, slot})`.
  Use the same `hash5`/`l4` helpers already imported. Match the eBPF logic byte-for-byte (it is the reference).

- [ ] **Step 2: Add a core unit test** `lb_v6_select` building a `VecPkt` of an `[IPv6][TCP]` frame (dst last-4 = VIP4, dport 443) + a `MemMaps` with the LB+maglev entry, asserting the backend is selected; and a negative (non-LB dst → None). Mirror the existing v4 lb test in the crate.

- [ ] **Step 3: Refactor eBPF `lb_select_forward_v6`** (flowplane-ebpf/src/lb.rs) to delegate to core (like the v4 `lb_select_forward` does): body becomes `flowplane_core::lb::lb_select_forward_v6(&crate::coreimpl::CtxPkt{ctx}, &crate::coreimpl::GlobalMaps, ip_off, vni)`. Remove the hand-written duplicate. Keep the `lb_select_forward_v6` public signature identical (callers in v6.rs unchanged).

- [ ] **Step 4:** `cargo test -p flowplane-core` PASS; `cargo build -p flowplane-ebpf` (or the workspace eBPF build) compiles. If a `make`/anchor build is needed for the eBPF, run it; report if the verifier/build needs privileged run.

- [ ] **Step 5: Commit** `git add flowplane-core/src/lb.rs flowplane-ebpf/src/lb.rs` — `refactor(lb): core lb_select_forward_v6 (eBPF delegates); shared v6 LB select`.

## Task V6-2: eBPF `wan_rx` v6 branch

**Files:**
- Modify: `flowplane-ebpf/src/ingress.rs` (`try_wan_rx`, around lines 338-376)

- [ ] **Step 1: Add a v6 branch in `try_wan_rx`** BEFORE the `if ethertype != ETH_P_IP { return Ok(XDP_PASS) }` guard. When `ethertype == ETH_P_IPV6`:
  - bounds: `if data + ETH_LEN + 40 > data_end { return Ok(XDP_PASS) }` (v6 header is 40 bytes).
  - `if let Some(backend) = crate::lb::lb_select_forward_v6(ctx, ETH_LEN, 0) {` build `RouteValue{ nexthop_vni:0, nexthop_ipv6: backend, is_external:0, _pad:[0;3] }`, `inner_len = (data_end - data - ETH_LEN) as u16`, and `return crate::encap::encap_and_redirect(ctx, LOCAL.get(0).ok_or(())?, &local.underlay_ipv6, &route, inner_len, IPPROTO_IPV6)` (note **IPPROTO_IPV6**, not IPPROTO_IPIP — the inner is an IPv6 packet). `}`
  - on no LB match, fall through to `return Ok(XDP_PASS)` (v6 WAN has no neighbor-NAT path — that is IPv4-only).
  Keep the existing IPv4 path (vip_rx + neighbor-nat) exactly as-is. Import `IPPROTO_IPV6` from `crate::parse`.

- [ ] **Step 2: Build + verifier.** `cargo build` the eBPF crate; if there's a `make build-ebpf`/anchor path that runs the verifier, use it. The v6 branch reads only within the `data + ETH_LEN + 40` (and `lb_select_forward_v6`'s own `+44`/`l4_off+4`) bounds — confirm the verifier accepts it. Report any verifier error verbatim (do NOT loosen bounds to force it — investigate).

- [ ] **Step 3: Commit** `git add flowplane-ebpf/src/ingress.rs` — `feat(edge): wan_rx v6 branch (v6 WAN VIP -> Maglev backend -> v6-in-IPv6 encap)`.

## Task V6-3: Proto `vip` (family-agnostic) + node.rs family parse + Go adapter

**Files:**
- Modify: `api/proto/dataplane/v1/dataplane.proto` (rename `AddLbVipRequest.vip_ipv4` → `vip`, keep field number 3)
- Regenerate: Go stubs (`make proto-go`) + Rust stubs (find the Rust proto-gen: `grep -rn "tonic_build\|dataplane.proto\|build.rs" flowplane/ cni/`)
- Modify: `flowplane/src/node.rs` (`add_lb_vip` handler)
- Modify: `netplane/agent/bus.go` (`dpAdapter.AddLbVip`)

- [ ] **Step 1: Rename the proto field.** In `AddLbVipRequest`, change `string vip_ipv4 = 3;` to `string vip = 3;` (SAME field number 3 → wire-compatible; only the generated name changes). Update the comment to "the public VIP (IPv4 or IPv6)".

- [ ] **Step 2: Regenerate stubs.** Go: `make proto-go`. Rust: locate + run the Rust generation (tonic/prost build). Verify `AddLbVipRequest` now has `vip` in both `cni/gen/dataplanev1/*.go` and the Rust generated module. If Rust stubs are generated at build time via a `build.rs`, a `cargo build` regenerates them.

- [ ] **Step 3: node.rs family parse.** In `add_lb_vip` (node.rs ~313, 334): replace `let vip = parse_ipv4(&r.vip_ipv4)...; ... LbIpBytes::Ipv4(vip)` with a family-detecting parse of `r.vip`:
  ```rust
  let lb_ip: crate::grpc::LbIpBytes = match r.vip.parse::<std::net::IpAddr>() {
      Ok(std::net::IpAddr::V4(a)) => crate::grpc::LbIpBytes::Ipv4(a.octets()),
      Ok(std::net::IpAddr::V6(a)) => crate::grpc::LbIpBytes::Ipv6(a.octets()),
      Err(e) => return Err(Status::invalid_argument(format!("invalid vip {:?}: {e}", r.vip))),
  };
  ```
  Pass `lb_ip` to `create_lb(&id, vni, lb_ip, lb_underlay, ports)`. Update the log line's `r.vip_ipv4` → `r.vip`. (If `parse_ipv4` becomes unused, leave it — other handlers use it.)

- [ ] **Step 4: Go adapter.** In `netplane/agent/bus.go` `dpAdapter.AddLbVip`, change `VipIpv4: vip` to `Vip: vip` in the `dpv1.AddLbVipRequest{...}` literal.

- [ ] **Step 5:** `cd netplane && go build ./...` PASS; `cargo build -p flowplane` PASS; `cd netplane && go test ./agent/` PASS.

- [ ] **Step 6: Commit** `git add api/proto/dataplane/v1/dataplane.proto cni/gen/dataplanev1/ flowplane/src/node.rs netplane/agent/bus.go` (+ any regenerated Rust stub path) — `feat(lb): AddLbVip accepts v6 VIP (family-agnostic vip field + node.rs parse)`.

## Task V6-4: Sim v6 wan_rx + tests + final sweep

**Files:**
- Modify: `flowplane-sim/src/sim.rs` (`wan_rx` — handle v6 via the core v6 fn)
- Modify: `flowplane-sim/src/lb_scenario_test.rs` (v6 N/S test)
- Modify: `netplane/agent/lbreconcile_test.go` (v6 VIP flows through ReconcileLB)

- [ ] **Step 1: Sim wan_rx v6.** In `SimNode::wan_rx` (sim.rs ~175), detect the frame's ethertype (bytes 12-13). For `0x86DD` (IPv6), call `lb_select_forward_v6(&VecPkt::from_bytes(plain), &self.maps, ETH_LEN, 0)` and, on Some, `edge_encap` with `inner_proto: 41` (IPPROTO_IPV6); for `0x0800` keep the existing v4 path (`inner_proto: 4`). Import the core `lb_select_forward_v6`.

- [ ] **Step 2: Sim v6 N/S test.** In lb_scenario_test.rs add `ns_lb_v6_delivered_with_policy`: an edge node whose LB map has a v6 VIP entry (LbKey vni=0, ipv4=last-4 of the v6 VIP, port 443, proto 6) → HOSTB_UL; a backend_node(false) with an ingress-allow-any-443 firewall; deliver an `[Eth(0x86DD)][IPv6][TCP]` WAN frame (dst = v6 VIP) via `Prog::WanRx`; assert `Delivered{node:"hostB", tap:HOSTB_TAP}`, 2 hops. Add a v6 frame builder + a v6 edge-LB fixture helper (mirror `eth_ipv4_tcp`/`edge_node` for v6). Reuse the existing `backend_node`/`apply_fw`. NOTE: the backend firewall evaluates the inner v6 5-tuple; ensure `apply_fw`/`allow_from_any_443` produce a rule matching v6 (source ::/0). If the sim firewall path is v4-only for the ingress gate on the backend, use an allow-all that matches (or assert delivery via the base v6 uplink path). Investigate and make the assertion honest — do not weaken it to pass.

- [ ] **Step 3: Go v6 VIP test.** In lbreconcile_test.go add `TestReconcileLB_V6VIP`: an edge Reconciler + a LoadBalancer with `VIP: "2001:db8::a"` → assert `dp.lbVips` contains `"2001:db8::a"` (the id == VIP string flows unchanged). Confirms the control-plane path is family-agnostic.

- [ ] **Step 4: Full sweep.** `cargo test -p flowplane-sim -p flowplane-core -p flowplane` and `cd netplane && go test ./...` all PASS. If the eBPF anchor (`make sim-anchor`) is runnable (CAP_BPF), run it to confirm no regression; a dedicated v6 wan_rx anchor is OPTIONAL (log if skipped — the sim + core + verifier cover it).

- [ ] **Step 5: Commit** `git add flowplane-sim/ netplane/agent/lbreconcile_test.go` — `test(sim,agent): v6 N/S wan_rx delivery + v6 VIP control-plane coverage`.

## Phase 2 note for the spec

After Phase 2, update spec §2 (VIPs v4/v6) — N/S now supports v6 too; the earlier "N/S IPv4-only" caveat is removed.
