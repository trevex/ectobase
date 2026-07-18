# VPC Peering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let guests in two different VPCs reach each other under policy, via control-plane route-import — no datapath or routebus-protocol change.

**Architecture:** Flesh out the `VPCPeering` CRD (mutual-consent, per-side `exposedPrefixes`, fail-closed). A new central **VPCPeering controller** owns consent/Status (Ready/Pending/Invalid). The **existing CompiledNIC compiler** consumes Ready peerings and emits `PeerImports` directives into each affected `CompiledNIC` (single writer). The **node agent** reads `PeerImports`, subscribes to peer VNIs on routebus, and imports their routes (filtered to the peer's `exposedPrefixes`) into the local VNI's route table, with **local (own-VNI) routes taking precedence** over imports. Firewall stays orthogonal (deny-by-default; a `NetworkPolicy` must allow the peer's CIDR).

**Tech Stack:** Go (controller-runtime, netplane controllers + agent), Rust (`flowplane-sim` conformance), bash (clab scenario). Deepcopy is **hand-maintained** (no controller-gen in the devShell — mirror the recent `NetworkInterface.Bandwidth` field addition). Build/test via `nix develop --command ...`.

**Reference spec:** `docs/superpowers/specs/2026-07-18-vpc-peering-design.md`

**Branch:** `feat/vpc-peering` (already created).

**Refinements from the spec (discovered during planning):**
- `peerVpcRef` uses a new minimal `VPCReference{Namespace,Name}` type (repo has only `LocalObjectReference`).
- `VPCPeeringStatus` uses `State string` + `Message string` (repo has no `metav1.Condition` usage; keeps hand-deepcopy simple).
- CompiledNIC has ONE producer: the CompiledNIC compiler reads Ready peerings → `PeerImports`. The VPCPeering controller does NOT write CompiledNIC; it only sets consent Status.

**Commands:** Go — `nix develop --command bash -c 'cd netplane && go build ./... && go test ./...'`; Rust sim — `nix develop --command cargo test -p flowplane-sim`. Pre-commit hook runs clippy+rustfmt (Rust) — run `cargo fmt`/`gofmt -w` before committing and verify HEAD advanced.

---

## File Structure

**API types (`api/v1alpha1/`):**
- `vpcpeering_types.go` (modify) — flesh out `VPCPeeringSpec`/`VPCPeeringStatus` + new `VPCReference`.
- `compilednic_types.go` (modify) — add `PeerImports []CompiledPeerImport` + the `CompiledPeerImport` type.
- `zz_generated.deepcopy.go` (modify) — hand-written DeepCopy for the new types/fields.

**Central controllers (`netplane/controllers/`):**
- `vpcpeering.go` (create) — `VPCPeeringReconciler`: mutual-consent Status only.
- `vpcpeering_test.go` (create) — consent/validation unit tests (fake client).
- `compilednic.go` (modify) — `Compile()` gains peering inputs → `PeerImports`; controller lists Ready peerings + VPCs, watches `VPCPeering`.
- `compilednic_test.go` (modify) — `Compile()` peering unit tests.

**Node agent (`netplane/agent/`):**
- `desired.go` (modify) — add `PeeringImports` to `DesiredState`.
- `importreconcile.go` (modify) — add `desiredPeeringImports()`.
- `bus.go` (modify) — peer-VNI subscription + `applyPeeringRoute` + local-precedence bookkeeping.
- `peeringreconcile_test.go` (create) — `desiredPeeringImports()` + precedence unit tests.
- `cmd/agent/main.go` (modify) — call `desiredPeeringImports()`, populate `DesiredState.PeeringImports`.
- `cmd/controller/main.go` (modify) — register `VPCPeeringReconciler`.

**Sim + clab:**
- `flowplane/flowplane-sim/src/peering_test.rs` (create) + `lib.rs` (modify) — cross-VNI import resolves; local shadows import.
- `test/scenario-vpc-peering.sh` (create) — clab: reachability + firewall two-step + overlap precedence.

---

## Phase 1 — API types

### Task 1: `VPCPeering` CRD spec/status

**Files:**
- Modify: `api/v1alpha1/vpcpeering_types.go`
- Modify: `api/v1alpha1/zz_generated.deepcopy.go`

- [ ] **Step 1: Flesh out the types.** Replace the empty `VPCPeeringSpec`/`VPCPeeringStatus` in `vpcpeering_types.go`:

```go
// VPCReference references a VPC by namespace + name (peering may be cross-namespace,
// since it is central-authored).
type VPCReference struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// VPCPeeringSpec is the desired state of a one-directional VPC peering. A mutual peering
// is formed by a reciprocal pair (A→B and B→A). Reachability only — never a firewall grant.
type VPCPeeringSpec struct {
	// VPCRef is this side's VPC (same namespace as this VPCPeering object).
	VPCRef LocalObjectReference `json:"vpcRef"`
	// PeerVPCRef references the other VPC (namespace + name).
	PeerVPCRef VPCReference `json:"peerVpcRef"`
	// ExposedPrefixes is the CIDR allow-list THIS side offers to the peer: only local routes
	// within these CIDRs become reachable to the peer VPC. Empty = expose nothing (fail-closed).
	// +optional
	ExposedPrefixes []string `json:"exposedPrefixes,omitempty"`
}

// VPCPeeringStatus is the observed state of a VPCPeering.
type VPCPeeringStatus struct {
	// State is the peering lifecycle: Pending (awaiting the reciprocal), Ready (both sides
	// consent), or Invalid (validation failed).
	// +optional
	State string `json:"state,omitempty"`
	// Message is a human-readable reason for the current State.
	// +optional
	Message string `json:"message,omitempty"`
}

// Peering state constants.
const (
	VPCPeeringPending = "Pending"
	VPCPeeringReady   = "Ready"
	VPCPeeringInvalid = "Invalid"
)
```

- [ ] **Step 2: Hand-write deepcopy.** In `zz_generated.deepcopy.go`, add (mirror the existing `InterfaceBandwidth`/`LocalObjectReference` deepcopy style). `VPCReference` is all-scalar (shallow). `VPCPeeringSpec` deep-copies the `ExposedPrefixes` slice:

```go
func (in *VPCReference) DeepCopyInto(out *VPCReference) { *out = *in }
func (in *VPCReference) DeepCopy() *VPCReference {
	if in == nil { return nil }
	out := new(VPCReference); in.DeepCopyInto(out); return out
}

// Replace the existing generated VPCPeeringSpec.DeepCopyInto with:
func (in *VPCPeeringSpec) DeepCopyInto(out *VPCPeeringSpec) {
	*out = *in
	out.VPCRef = in.VPCRef
	out.PeerVPCRef = in.PeerVPCRef
	if in.ExposedPrefixes != nil {
		out.ExposedPrefixes = make([]string, len(in.ExposedPrefixes))
		copy(out.ExposedPrefixes, in.ExposedPrefixes)
	}
}
```
Confirm `VPCPeeringStatus.DeepCopyInto` is `*out = *in` (all scalar) and the top-level `VPCPeering.DeepCopyInto` already calls `in.Spec.DeepCopyInto(&out.Spec)` + `out.Status = in.Status` (adjust if the existing generated code assumed empty structs).

- [ ] **Step 3: Build to verify.** Run: `nix develop --command bash -c 'cd api && go build ./...'`. Expected: clean compile.

- [ ] **Step 4: Deepcopy round-trip test.** Add to a new/existing `api/v1alpha1/vpcpeering_test.go`:

```go
func TestVPCPeeringDeepCopy(t *testing.T) {
	in := &VPCPeering{
		Spec: VPCPeeringSpec{
			VPCRef:          LocalObjectReference{Name: "prod"},
			PeerVPCRef:      VPCReference{Namespace: "shared-ns", Name: "shared"},
			ExposedPrefixes: []string{"10.0.0.0/24", "10.0.1.0/24"},
		},
		Status: VPCPeeringStatus{State: VPCPeeringReady},
	}
	out := in.DeepCopy()
	out.Spec.ExposedPrefixes[0] = "mutated"
	if in.Spec.ExposedPrefixes[0] != "10.0.0.0/24" {
		t.Fatal("deepcopy did not isolate ExposedPrefixes slice")
	}
}
```

Run: `nix develop --command bash -c 'cd api && go test ./v1alpha1/ -run TestVPCPeeringDeepCopy -v'`. Expected: PASS.

- [ ] **Step 5: Commit.** `gofmt -w api/v1alpha1/` then:
```bash
git add api/v1alpha1/vpcpeering_types.go api/v1alpha1/zz_generated.deepcopy.go api/v1alpha1/vpcpeering_test.go
git commit -m "feat(api): flesh out VPCPeering CRD (mutual-consent, exposedPrefixes)"
```
Verify HEAD advanced: `git log --oneline -1`.

### Task 2: `CompiledNIC.PeerImports`

**Files:**
- Modify: `api/v1alpha1/compilednic_types.go`
- Modify: `api/v1alpha1/zz_generated.deepcopy.go`

- [ ] **Step 1: Add the field + type.** In `compilednic_types.go`, add to `CompiledNICSpec` (after the `LB` field) and define the type:

```go
	// PeerImports lists peer VPCs whose routes this NIC imports (reachability only — grants NO
	// firewall permission; that comes solely from NetworkPolicy). Populated from Ready VPCPeerings
	// involving this NIC's VPC.
	// +optional
	PeerImports []CompiledPeerImport `json:"peerImports,omitempty"`
```
```go
// CompiledPeerImport is one peer VPC's reachability import for a NIC.
type CompiledPeerImport struct {
	// PeerVNI is the peer VPC's VNI to subscribe to on routebus.
	PeerVNI int32 `json:"peerVni"`
	// ImportPrefixes is the peer's exposedPrefixes: only peer routes within these CIDRs are
	// imported (filter applied importer-side).
	// +optional
	ImportPrefixes []string `json:"importPrefixes,omitempty"`
}
```

- [ ] **Step 2: Hand-write deepcopy.** In `zz_generated.deepcopy.go` add `CompiledPeerImport.DeepCopyInto/DeepCopy` (deep-copies `ImportPrefixes`), and extend `CompiledNICSpec.DeepCopyInto` to deep-copy the `PeerImports` slice:

```go
func (in *CompiledPeerImport) DeepCopyInto(out *CompiledPeerImport) {
	*out = *in
	if in.ImportPrefixes != nil {
		out.ImportPrefixes = make([]string, len(in.ImportPrefixes))
		copy(out.ImportPrefixes, in.ImportPrefixes)
	}
}
func (in *CompiledPeerImport) DeepCopy() *CompiledPeerImport {
	if in == nil { return nil }
	out := new(CompiledPeerImport); in.DeepCopyInto(out); return out
}
// In CompiledNICSpec.DeepCopyInto, after the existing LB handling, add:
	if in.PeerImports != nil {
		l := make([]CompiledPeerImport, len(in.PeerImports))
		for i := range in.PeerImports {
			in.PeerImports[i].DeepCopyInto(&l[i])
		}
		out.PeerImports = l
	}
```

- [ ] **Step 3: Build.** `nix develop --command bash -c 'cd api && go build ./...'`. Expected: clean.

- [ ] **Step 4: Commit.** `gofmt -w api/v1alpha1/` then:
```bash
git add api/v1alpha1/compilednic_types.go api/v1alpha1/zz_generated.deepcopy.go
git commit -m "feat(api): CompiledNIC.PeerImports directive (reachability-only)"
```

---

## Phase 2 — Central compiler + VPCPeering controller

### Task 3: `Compile()` emits `PeerImports` from Ready peerings (pure fn)

**Files:**
- Modify: `netplane/controllers/compilednic.go`
- Test: `netplane/controllers/compilednic_test.go`

Context: `Compile(nic, policies, lbs)` is a pure function. Add a peering input so it can emit `PeerImports`. Signature becomes:
`func Compile(nic *netv1.NetworkInterface, policies []netv1.NetworkPolicy, lbs []netv1.LoadBalancer, peerings []PeerImportSpec) netv1.CompiledNIC`
where the controller pre-resolves peerings to a small VNI-carrying struct (keeps `Compile` free of client lookups):

```go
// PeerImportSpec is a pre-resolved peering import for a specific VPC (peerVNI + exposed prefixes).
// The controller computes these from Ready VPCPeerings; Compile just filters by the NIC's VPC.
type PeerImportSpec struct {
	VPCName        string // the LOCAL vpc this import applies to (matches nic.Spec.VPCRef.Name)
	PeerVNI        int32
	ImportPrefixes []string
}
```

- [ ] **Step 1: Write the failing test.** Add to `compilednic_test.go`:

```go
func TestCompile_PeerImports(t *testing.T) {
	nic := testNIC() // VPCRef.Name == "prod", VNI 100 (see existing helper)
	peerings := []PeerImportSpec{
		{VPCName: "prod", PeerVNI: 200, ImportPrefixes: []string{"10.1.0.0/24"}},
		{VPCName: "other", PeerVNI: 300, ImportPrefixes: []string{"10.9.0.0/24"}}, // different VPC — must be ignored
	}
	c := Compile(nic, nil, nil, peerings)
	if len(c.Spec.PeerImports) != 1 {
		t.Fatalf("PeerImports = %d, want 1", len(c.Spec.PeerImports))
	}
	if c.Spec.PeerImports[0].PeerVNI != 200 ||
		len(c.Spec.PeerImports[0].ImportPrefixes) != 1 ||
		c.Spec.PeerImports[0].ImportPrefixes[0] != "10.1.0.0/24" {
		t.Fatalf("unexpected PeerImports: %+v", c.Spec.PeerImports)
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (`Compile` arity/field mismatch). Run: `nix develop --command bash -c 'cd netplane && go test ./controllers/ -run TestCompile_PeerImports 2>&1 | tail -5'`. Expected: compile error / FAIL.

- [ ] **Step 3: Implement.** Change `Compile`'s signature to add `peerings []PeerImportSpec`; after building `LB`, append matching imports:

```go
	for _, p := range peerings {
		if p.VPCName != nic.Spec.VPCRef.Name {
			continue
		}
		spec.PeerImports = append(spec.PeerImports, netv1.CompiledPeerImport{
			PeerVNI:        p.PeerVNI,
			ImportPrefixes: append([]string(nil), p.ImportPrefixes...),
		})
	}
```
Update the existing `Compile(...)` call site in `Reconcile` to pass `nil` for now (Task 4 wires the real peerings). Update any other `Compile(` callers in tests to pass `nil`.

- [ ] **Step 4: Run — expect PASS.** `nix develop --command bash -c 'cd netplane && go test ./controllers/ -run TestCompile_PeerImports -v'`. Then full `go test ./controllers/` (existing tests still green with the new nil arg).

- [ ] **Step 5: Commit.** `gofmt -w netplane/controllers/`:
```bash
git add netplane/controllers/compilednic.go netplane/controllers/compilednic_test.go
git commit -m "feat(compiler): Compile() emits CompiledNIC.PeerImports from resolved peerings"
```

### Task 4: CompiledNIC controller resolves Ready peerings + watches VPCPeering

**Files:**
- Modify: `netplane/controllers/compilednic.go`

- [ ] **Step 1: Resolve peerings in Reconcile.** Add a helper that lists Ready `VPCPeering`s and resolves each to a `PeerImportSpec` (LOCAL vpc = the peering's `VPCRef`; `PeerVNI` = the VNI of the peering's `PeerVPCRef` VPC; `ImportPrefixes` = the *reciprocal* peering's `ExposedPrefixes`, i.e. what the peer exposes to us):

```go
// resolvePeerImports returns, for every Ready VPCPeering, a PeerImportSpec keyed by the LOCAL vpc.
// A peering P (vpcRef=local, peerVpcRef=peer) contributes an import of the PEER's VNI, filtered by
// the peer's own exposedPrefixes — which live on the reciprocal peering (vpcRef=peer, peerVpcRef=local).
func (r *CompiledNICReconciler) resolvePeerImports(ctx context.Context) ([]PeerImportSpec, error) {
	var peerings netv1.VPCPeeringList
	if err := r.Client.List(ctx, &peerings); err != nil {
		return nil, err
	}
	// index reciprocal exposedPrefixes: key = "peerNs/peerName->localName"
	type key struct{ ns, from, to string }
	exposed := map[key][]string{}
	for i := range peerings.Items {
		p := &peerings.Items[i]
		exposed[key{p.Namespace, p.Spec.VPCRef.Name, p.Spec.PeerVPCRef.Name}] = p.Spec.ExposedPrefixes
	}
	var out []PeerImportSpec
	for i := range peerings.Items {
		p := &peerings.Items[i]
		if p.Status.State != netv1.VPCPeeringReady {
			continue
		}
		peerVNI, err := vpcVNIFor(ctx, r.Client, p.Spec.PeerVPCRef.Namespace, p.Spec.PeerVPCRef.Name)
		if err != nil || peerVNI == 0 {
			continue
		}
		// what the PEER exposes to us = reciprocal peering (peer→local) exposedPrefixes
		recip := exposed[key{p.Spec.PeerVPCRef.Namespace, p.Spec.PeerVPCRef.Name, p.Spec.VPCRef.Name}]
		out = append(out, PeerImportSpec{
			VPCName:        p.Spec.VPCRef.Name,
			PeerVNI:        int32(peerVNI),
			ImportPrefixes: recip,
		})
	}
	return out, nil
}
```
(Reuse the existing `vpcVNIFor`/`vpcVNIFor`-style helper used by `desiredEgressVNIs`; if it lives in the agent package, add an equivalent in controllers that looks up `VPC` by namespace/name and returns `status.vni`.)

Call it in `Reconcile`, pass the result to `Compile(nic, policies, lbs, peerImports)`.

- [ ] **Step 2: Watch VPCPeering.** In `SetupWithManager`, add:
```go
		Watches(&netv1.VPCPeering{}, handler.EnqueueRequestsFromMapFunc(r.nicsForPeering)).
```
Add `nicsForPeering(ctx, obj) []reconcile.Request` — for a changed `VPCPeering`, enqueue all NICs whose `VPCRef.Name` == the peering's `VPCRef.Name` (mirror `nicsForLB`/`nicsForPolicy`).

- [ ] **Step 3: Build.** `nix develop --command bash -c 'cd netplane && go build ./...'`. Expected: clean.

- [ ] **Step 4: Envtest (if present) or build-gate.** If `compilednic_envtest_test.go` exists, add a case: create two VPCs (VNI 100/200), a NIC in VPC-prod on nodeA, and a Ready peering pair → assert the produced `CompiledNIC` has `PeerImports=[{PeerVNI:200, ImportPrefixes: <peer's exposed>}]`. Run: `nix develop --command bash -c 'cd netplane && go test ./controllers/ 2>&1 | tail -5'`. If envtest isn't wired for this, rely on Task 3's unit test + note it.

- [ ] **Step 5: Commit.** `gofmt -w netplane/controllers/`:
```bash
git add netplane/controllers/compilednic.go
git commit -m "feat(compiler): resolve Ready VPCPeerings into PeerImports; watch VPCPeering"
```

### Task 5: VPCPeering controller (mutual-consent Status)

**Files:**
- Create: `netplane/controllers/vpcpeering.go`
- Create: `netplane/controllers/vpcpeering_test.go`
- Modify: `netplane/cmd/controller/main.go`

- [ ] **Step 1: Write the failing test.** `vpcpeering_test.go` (fake client, mirror `lbreconcile_test.go`'s fake-client setup):

```go
func TestVPCPeering_PendingUntilReciprocal(t *testing.T) {
	s := scheme(t) // helper building runtime.Scheme with netv1 (mirror existing tests)
	ab := &netv1.VPCPeering{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "a-to-b"},
		Spec: netv1.VPCPeeringSpec{
			VPCRef:          netv1.LocalObjectReference{Name: "a"},
			PeerVPCRef:      netv1.VPCReference{Namespace: "ns", Name: "b"},
			ExposedPrefixes: []string{"10.0.0.0/24"},
		},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(ab).WithStatusSubresource(ab).Build()
	r := &VPCPeeringReconciler{Client: cl}
	_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "a-to-b"}})
	if err != nil { t.Fatal(err) }
	var got netv1.VPCPeering
	_ = cl.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: "a-to-b"}, &got)
	if got.Status.State != netv1.VPCPeeringPending {
		t.Fatalf("state = %q, want Pending (no reciprocal)", got.Status.State)
	}
}

func TestVPCPeering_ReadyWhenReciprocalExists(t *testing.T) {
	s := scheme(t)
	ab := &netv1.VPCPeering{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "a-to-b"},
		Spec: netv1.VPCPeeringSpec{VPCRef: netv1.LocalObjectReference{Name: "a"}, PeerVPCRef: netv1.VPCReference{Namespace: "ns", Name: "b"}, ExposedPrefixes: []string{"10.0.0.0/24"}}}
	ba := &netv1.VPCPeering{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "b-to-a"},
		Spec: netv1.VPCPeeringSpec{VPCRef: netv1.LocalObjectReference{Name: "b"}, PeerVPCRef: netv1.VPCReference{Namespace: "ns", Name: "a"}, ExposedPrefixes: []string{"10.1.0.0/24"}}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(ab, ba).WithStatusSubresource(ab, ba).Build()
	r := &VPCPeeringReconciler{Client: cl}
	_, _ = r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "a-to-b"}})
	var got netv1.VPCPeering
	_ = cl.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: "a-to-b"}, &got)
	if got.Status.State != netv1.VPCPeeringReady {
		t.Fatalf("state = %q, want Ready", got.Status.State)
	}
}

func TestVPCPeering_InvalidPrefix(t *testing.T) {
	// exposedPrefixes with a malformed CIDR → Invalid
	// (build ab+ba as above but ab.Spec.ExposedPrefixes = []string{"not-a-cidr"}; assert State==Invalid)
}
```

- [ ] **Step 2: Run — expect FAIL** (no `VPCPeeringReconciler`). `nix develop --command bash -c 'cd netplane && go test ./controllers/ -run TestVPCPeering 2>&1 | tail -5'`.

- [ ] **Step 3: Implement `vpcpeering.go`.** Mirror the `CompiledNICReconciler` skeleton:

```go
type VPCPeeringReconciler struct{ Client client.Client }

func (r *VPCPeeringReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var p netv1.VPCPeering
	if err := r.Client.Get(ctx, req.NamespacedName, &p); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	state, msg := r.evaluate(ctx, &p)
	if p.Status.State != state || p.Status.Message != msg {
		p.Status.State, p.Status.Message = state, msg
		if err := r.Client.Status().Update(ctx, &p); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// evaluate returns (State, Message): Invalid on malformed prefix; Ready if a reciprocal
// peering (peer→local) exists; else Pending.
func (r *VPCPeeringReconciler) evaluate(ctx context.Context, p *netv1.VPCPeering) (string, string) {
	for _, c := range p.Spec.ExposedPrefixes {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return netv1.VPCPeeringInvalid, "malformed exposedPrefix: " + c
		}
	}
	var list netv1.VPCPeeringList
	if err := r.Client.List(ctx, &list); err != nil {
		return netv1.VPCPeeringPending, "list error"
	}
	for i := range list.Items {
		q := &list.Items[i]
		// reciprocal: q.vpcRef == our peer, q.peerVpcRef == our vpc
		if q.Spec.VPCRef.Name == p.Spec.PeerVPCRef.Name &&
			q.Namespace == p.Spec.PeerVPCRef.Namespace &&
			q.Spec.PeerVPCRef.Name == p.Spec.VPCRef.Name &&
			q.Spec.PeerVPCRef.Namespace == p.Namespace {
			return netv1.VPCPeeringReady, "reciprocal peering present"
		}
	}
	return netv1.VPCPeeringPending, "awaiting reciprocal peering"
}

func (r *VPCPeeringReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.VPCPeering{}).
		Watches(&netv1.VPCPeering{}, handler.EnqueueRequestsFromMapFunc(r.reciprocals)).
		Complete(r)
}
```
Add `reciprocals(ctx, obj)` to re-enqueue the counterpart peering when one side changes (so the pair converges to Ready together). Add the `scheme(t)` test helper if not already shared.

- [ ] **Step 4: Run — expect PASS.** `nix develop --command bash -c 'cd netplane && go test ./controllers/ -run TestVPCPeering -v'`.

- [ ] **Step 5: Register in the manager.** In `netplane/cmd/controller/main.go`, after the CompiledNIC setup:
```go
	if err := (&controllers.VPCPeeringReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		log.Fatalf("setup vpcpeering controller: %v", err)
	}
```
Build: `nix develop --command bash -c 'cd netplane && go build ./...'`.

- [ ] **Step 6: Commit.** `gofmt -w netplane/`:
```bash
git add netplane/controllers/vpcpeering.go netplane/controllers/vpcpeering_test.go netplane/cmd/controller/main.go
git commit -m "feat(controller): VPCPeering mutual-consent Status (Pending/Ready/Invalid)"
```

---

## Phase 3 — Node agent: import + precedence

### Task 6: `desiredPeeringImports()` — scan CompiledNIC

**Files:**
- Modify: `netplane/agent/desired.go`
- Modify: `netplane/agent/importreconcile.go`
- Test: `netplane/agent/peeringreconcile_test.go` (create)

- [ ] **Step 1: Add the DesiredState field.** In `desired.go`, add to `DesiredState`:
```go
	// PeeringImports maps a LOCAL vni -> the peer imports for it ({peerVNI, importPrefixes}).
	PeeringImports map[uint32][]PeerImport
```
and define:
```go
type PeerImport struct {
	PeerVNI        uint32
	ImportPrefixes []string
}
```

- [ ] **Step 2: Write the failing test.** `peeringreconcile_test.go` (mirror `lbreconcile_test.go`'s fake-client setup):

```go
func TestDesiredPeeringImports(t *testing.T) {
	s := scheme(t)
	cnic := &netv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-0"},
		Spec: netv1.CompiledNICSpec{
			NodeName: "nodeA", VNI: 100,
			PeerImports: []netv1.CompiledPeerImport{{PeerVNI: 200, ImportPrefixes: []string{"10.1.0.0/24"}}},
		},
	}
	offNode := &netv1.CompiledNIC{ // different node — must be ignored
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-1"},
		Spec: netv1.CompiledNICSpec{NodeName: "nodeB", VNI: 300,
			PeerImports: []netv1.CompiledPeerImport{{PeerVNI: 400}}},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(cnic, offNode).Build()
	r := &Reconciler{client: cl, nodeID: "nodeA"}
	got, err := r.desiredPeeringImports(context.Background())
	if err != nil { t.Fatal(err) }
	if len(got) != 1 || len(got[100]) != 1 || got[100][0].PeerVNI != 200 {
		t.Fatalf("unexpected imports: %+v", got)
	}
}
```

- [ ] **Step 3: Run — expect FAIL.** `nix develop --command bash -c 'cd netplane && go test ./agent/ -run TestDesiredPeeringImports 2>&1 | tail -5'`.

- [ ] **Step 4: Implement `desiredPeeringImports`** in `importreconcile.go` (mirror `desiredEgressVNIs`'s CompiledNIC scan):
```go
func (r *Reconciler) desiredPeeringImports(ctx context.Context) (map[uint32][]PeerImport, error) {
	var cnics netv1.CompiledNICList
	if err := r.client.List(ctx, &cnics); err != nil {
		return nil, err
	}
	out := map[uint32][]PeerImport{}
	for i := range cnics.Items {
		c := &cnics.Items[i]
		if c.Spec.NodeName != r.nodeID || c.Spec.VNI == 0 {
			continue
		}
		local := uint32(c.Spec.VNI)
		for _, pi := range c.Spec.PeerImports {
			if pi.PeerVNI == 0 { continue }
			out[local] = append(out[local], PeerImport{
				PeerVNI:        uint32(pi.PeerVNI),
				ImportPrefixes: append([]string(nil), pi.ImportPrefixes...),
			})
		}
	}
	// dedup identical (peerVNI) entries per local VNI (same-VPC NICs carry identical directives)
	return dedupPeerImports(out), nil
}
```
Add a small `dedupPeerImports` helper (union by `PeerVNI`, merging prefixes). Also add peer VNIs to the subscription set: in `Desired()` (or wherever `subs`/`Subs` is built), include every `PeerVNI` from `desiredPeeringImports`.

- [ ] **Step 5: Run — expect PASS.** `nix develop --command bash -c 'cd netplane && go test ./agent/ -run TestDesiredPeeringImports -v'`.

- [ ] **Step 6: Commit.** `gofmt -w netplane/agent/`:
```bash
git add netplane/agent/desired.go netplane/agent/importreconcile.go netplane/agent/peeringreconcile_test.go
git commit -m "feat(agent): desiredPeeringImports scans CompiledNIC.PeerImports"
```

### Task 7: Bus import with local precedence (the load-bearing task)

**Files:**
- Modify: `netplane/agent/bus.go`
- Test: `netplane/agent/peeringreconcile_test.go`

- [ ] **Step 1: Add Bus state.** In the `Bus` struct add:
```go
	peerImports  map[uint32][]PeerImport   // localVNI -> imports (set each reconcile)
	origin       map[uint32]map[string]string // vni -> prefix -> "own"|"peer" (precedence tag)
	learnedPeer  map[uint32]map[string]string // peerVNI -> prefix -> nexthop (raw learned peer routes)
```
Initialize the maps in `NewBus`. Populate `peerImports` from `DesiredState.PeeringImports` on each reconcile (alongside `egressVNIs`).

- [ ] **Step 2: Write the failing precedence tests.** In `peeringreconcile_test.go`, drive the Bus's apply path directly with a `recordingDP` (mirror how `bus_test.go` asserts `dp.get`). Cover:

```go
// (a) import-within-prefixes installs into the local VNI; outside is dropped.
func TestPeeringImport_FilterByPrefix(t *testing.T) { /* peerVNI 200 learned 10.1.0.5/32 in-prefix -> AddRoute(local=100,...); 10.9.9.9/32 out-of-prefix -> no AddRoute */ }

// (b) local precedence: an OWN route for a prefix is never overwritten by a peer import.
func TestPeeringImport_LocalPrecedence(t *testing.T) {
	// mark (vni=100, "10.1.0.5/32") as own (via the own-route apply path), THEN deliver a peer
	// import for the same prefix -> assert dp still has the OWN nexthop, not the peer's.
}

// (c) own route arriving AFTER an import evicts the import; own withdraw restores the import.
func TestPeeringImport_EvictAndRestore(t *testing.T) { /* import -> own arrives (WithdrawRoute peer + AddRoute own) -> own withdraws (AddRoute peer restored) */ }
```
Use the helper that invokes the Bus's route-application function directly (expose an internal `applyRouteUpdate`/`apply` you can call from the test in-package, as `bus_test.go` already does for `apply`).

- [ ] **Step 3: Run — expect FAIL.** `nix develop --command bash -c 'cd netplane && go test ./agent/ -run TestPeeringImport 2>&1 | tail -8'`.

- [ ] **Step 4: Implement.** Generalize `apply()`:
  - Tag every OWN route (routes learned on a local VNI, and locally-announced host routes) in `origin[vni][prefix]="own"` when installed.
  - For a `RouteUpdate` on a `peerVNI` that appears in some `peerImports[local]`: for each local VNI importing it, if `prefix ∈ importPrefixes` → **install only if** `origin[local][prefix] != "own"`; tag `origin[local][prefix]="peer"`; call `dp.AddRoute(local, prefix, nh, false)` and `markInstalled(local, prefix)`.
  - When an OWN route for `(local, prefix)` is installed and `origin[local][prefix]=="peer"`: evict — `dp.WithdrawRoute(local, prefix)` for the peer, then install own, set tag `"own"`.
  - When an OWN route for `(local, prefix)` withdraws and a learned peer route still exists in `learnedPeer` within an active import: restore the peer import (re-`AddRoute` peer, tag `"peer"`).
  - Peer-route withdraw / EndOfRIB prune reuse `markWithdrawn`, and clear the `origin` tag.
Keep the existing public-VNI and direct-route paths unchanged. Extract the shared install/withdraw into small helpers so the precedence logic is in one place.

- [ ] **Step 5: Run — expect PASS.** `nix develop --command bash -c 'cd netplane && go test ./agent/ -run TestPeeringImport -v'` then full `go test ./agent/`.

- [ ] **Step 6: Commit.** `gofmt -w netplane/agent/`:
```bash
git add netplane/agent/bus.go netplane/agent/peeringreconcile_test.go
git commit -m "feat(agent): import peer routes with local-VNI precedence"
```

### Task 8: Wire into the agent reconcile loop

**Files:**
- Modify: `netplane/cmd/agent/main.go`
- Modify: `netplane/agent/desired.go` (if the reconcile closure builds `DesiredState` there)

- [ ] **Step 1: Populate `DesiredState.PeeringImports`.** In the agent's reconcile closure (where `r.Desired()` / `desiredEgressVNIs` results are assembled into `DesiredState`), call `r.desiredPeeringImports(ctx)` and set `ds.PeeringImports`; union its `PeerVNI`s into `ds.Subs`.

- [ ] **Step 2: Consume in Bus.** Ensure `Bus.Run`/reconcile applies `ds.PeeringImports` into `b.peerImports` before processing route updates (mirror how `egressVNIs` is set each tick).

- [ ] **Step 3: Build + full agent test.** `nix develop --command bash -c 'cd netplane && go build ./... && go test ./agent/ 2>&1 | tail -5'`. Expected: green.

- [ ] **Step 4: Commit.** `gofmt -w netplane/`:
```bash
git add netplane/cmd/agent/main.go netplane/agent/desired.go
git commit -m "feat(agent): wire peering imports into the reconcile loop"
```

---

## Phase 4 — Sim + clab conformance

### Task 9: Sim — imported cross-VNI route resolves; local shadows import

**Files:**
- Create: `flowplane/flowplane-sim/src/peering_test.rs`
- Modify: `flowplane/flowplane-sim/src/lib.rs` (add `mod peering_test;` under `#[cfg(test)]`, sorted)

Context: peering adds no datapath code — this pins the route-table semantics peering relies on. Mirror `vni_test.rs` (program routes into `MemMaps`, run `SimNode::guest_tx`, assert `Action`).

- [ ] **Step 1: Write the tests.** In `peering_test.rs`:
  - `imported_cross_vni_route_resolves_and_delivers`: program a route for dest `D` **under VNI-A** whose nexthop is a peer guest's underlay (exactly as the agent would after import); run `guest_tx` for a VNI-A guest to `D`; assert `Action::Redirect(...)` (delivers) — the contrast to `vni_test`'s isolation `Pass`.
  - `local_route_shadows_imported_peer_route`: program BOTH a local route for `D` (own nexthop) and confirm a same-prefix import does not change the delivered nexthop/route (assert the local nexthop's encap). (Since the datapath map holds one value per key, this asserts the *agent's* precedence produces the local entry; model it by only inserting the local route and asserting delivery, with a comment that the agent guarantees local wins.)
  Read `vni_test.rs` for the exact `MemMaps` route-insertion API + the `route4`/`deliver` verdict shapes; PIN the asserted action/ifindex.

- [ ] **Step 2: Run — expect PASS (regression guard).** `nix develop --command cargo test -p flowplane-sim peering`. Then full `cargo test -p flowplane-sim` (all green).

- [ ] **Step 3: Commit.** `nix develop --command cargo fmt`:
```bash
git add flowplane/flowplane-sim/src/peering_test.rs flowplane/flowplane-sim/src/lib.rs
git commit -m "test(sim): VPC-peering cross-VNI import resolves; local precedence"
```

### Task 10: clab scenario — reachability + firewall two-step + overlap

**Files:**
- Create: `test/scenario-vpc-peering.sh`

Context: privileged/manual clab scenario (mirror `test/scenario-restart-continuity.sh` gating + node-exec conventions). Not CI.

- [ ] **Step 1: Write the script.** Bring up two VPCs (distinct VNIs) with a guest each; create a Ready `VPCPeering` pair with `exposedPrefixes` covering each guest. Assert:
  1. Cross-VPC ping **fails** initially (deny-by-default ingress firewall) — proves the two-step.
  2. After applying a `NetworkPolicy` allowing the peer CIDR on the destination NIC, cross-VPC ping **succeeds** — proves reachability + policy.
  3. Overlap case: give the destination VPC a local guest at the same address the peer exposes; assert the local guest answers (local precedence), not the peer.
  Gate: run only under sudo on the clab host; clear skip/exit message otherwise. Emit a single-line PASS/FAIL per assertion.

- [ ] **Step 2: Syntax-check.** `bash -n test/scenario-vpc-peering.sh` (+ shellcheck if available). Run live on the fabric only if available; else deliver + syntax-check and note it (mirrors the restart-continuity script).

- [ ] **Step 3: Commit.**
```bash
git add test/scenario-vpc-peering.sh
git commit -m "test(clab): VPC-peering reachability + firewall two-step + overlap"
```

---

## Phase 5 — Final

- [ ] Dispatch a final review over the branch (spec coverage, the precedence bookkeeping in Task 7 especially); then `superpowers:finishing-a-development-branch`.
- [ ] Update memory: `[[compiled-nic-synthetic-testing]]` (peering = control-plane route-import on CompiledNIC.PeerImports + routebus) and `[[metalbond-metalnet-ipam-lineage]]` (our peering model: mutual-consent, importer-side exposedPrefixes, local-VNI precedence).

## Self-review notes

- **Spec coverage:** §1 CRD → Task 1; §2 compiler/PeerImports → Tasks 2–4; consent Status → Task 5; §3 agent subscribe/import/precedence → Tasks 6–8; §4 data flow → exercised by Tasks 9–10; §5 testing → Tasks 3/5/6/7 (Go), 9 (sim), 10 (clab). Non-goals (no datapath/routebus change, no firewall coupling, no transitive peering, overlap-allowed-local-wins) are respected — no task touches `flowplane-core`/`routebus.proto`, and precedence is agent-only.
- **Deepcopy is hand-maintained** — every API-type task writes the DeepCopy methods and build-verifies (mirrors the merged `NetworkInterface.Bandwidth` change).
- **Single writer for CompiledNIC:** only the CompiledNIC compiler writes `PeerImports`; the VPCPeering controller writes only its own Status. No two controllers contend for CompiledNIC.
- **Riskiest task = 7** (local-precedence eviction/restore). Its three transition tests (filter, precedence, evict+restore) are written before the implementation.
- **Type consistency:** `PeerImportSpec` (controller-internal, pre-resolved) vs `netv1.CompiledPeerImport` (API) vs `PeerImport` (agent runtime) are three intentionally distinct types across the layers; names kept distinct to avoid confusion.
