// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package failover

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/api/validate"
	"github.com/trevex/ectobase/dispatch/pkg/clusterpool"
)

type okFencer struct{}

func (okFencer) Fence(context.Context, string) error   { return nil }
func (okFencer) Release(context.Context, string) error { return nil }

type denyFencer struct{ err error }

func (d denyFencer) Fence(context.Context, string) error { return d.err }
func (denyFencer) Release(context.Context, string) error { return nil }

// recordingFencer records exactly which prefixes were fenced, so a test can assert the fence
// COORDINATE and not just the outcome — the point of the aggregate path is that it fences
// something different from the reported node /64s.
type recordingFencer struct{ fenced []string }

func (f *recordingFencer) Fence(_ context.Context, p string) error {
	f.fenced = append(f.fenced, p)
	return nil
}
func (*recordingFencer) Release(context.Context, string) error { return nil }

// isBlocked reports whether the VM carries FailoverBlocked=True.
func isBlocked(vm *computev1.VirtualMachine) bool {
	for _, c := range vm.Status.Conditions {
		if c.Type == "FailoverBlocked" && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

type releaseErrFencer struct{}

func (releaseErrFencer) Fence(context.Context, string) error { return nil }
func (releaseErrFencer) Release(context.Context, string) error {
	return errors.New("release unconfirmed")
}

func lostPoolObj(name string, prefixes ...string) *platformv1.ClusterPool {
	old := metav1.NewMicroTime(time.Now().Add(-10 * time.Minute))
	return &platformv1.ClusterPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: platformv1.ClusterPoolStatus{
			Phase:        clusterpool.PhaseUnknown,
			Lease:        &platformv1.ClusterPoolLease{RenewTime: &old},
			NodePrefixes: prefixes,
		},
	}
}

func vmOn(name, pool string) *computev1.VirtualMachine {
	return &computev1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: computev1.VirtualMachineSpec{ClusterName: pool}}
}

// The happy path: fences confirm, so the batch rebinds. Uses ONE node /64 — the ordinary
// single-/64-per-cluster topology, where fencing that prefix provably covers every node including
// any central never observed. A pool reporting several distinct /64s is a different case now: see
// TestFailover_MultipleDistinctNodePrefixes_BlocksWithoutADeclaredAggregate.
func TestFailover_WholePoolFence_ThenRebind(t *testing.T) {
	scheme := testScheme(t)
	lost := lostPoolObj("A", "2001:db8:0:1::/64")
	healthy := readyPoolObj("B")
	vm := vmOn("vm1", "A")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lost, healthy, vm).WithStatusSubresource(vm, lost).Build()
	r := &Reconciler{Client: c, StorageFencer: okFencer{}, NetworkFencer: okFencer{}, FailoverThreshold: time.Minute}

	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &computev1.VirtualMachine{}
	_ = c.Get(context.Background(), key("vm1"), got)
	if got.Spec.ClusterName != "B" {
		t.Fatalf("want rebind to B, got %q", got.Spec.ClusterName)
	}
}

func TestFailover_PartialFence_Blocks(t *testing.T) {
	scheme := testScheme(t)
	lost := lostPoolObj("A", "2001:db8:0:1::/64")
	vm := vmOn("vm1", "A")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lost, readyPoolObj("B"), vm).WithStatusSubresource(vm, lost).Build()
	r := &Reconciler{Client: c, StorageFencer: denyFencer{errors.New("no ceph")}, NetworkFencer: okFencer{}, FailoverThreshold: time.Minute}

	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &computev1.VirtualMachine{}
	_ = c.Get(context.Background(), key("vm1"), got)
	if got.Spec.ClusterName != "A" {
		t.Fatalf("must NOT rebind when a fence is unconfirmed, got %q", got.Spec.ClusterName)
	}
}

func TestFailover_ReleaseDrained_ReleasesOnlyDrained(t *testing.T) {
	scheme := testScheme(t)
	// Pool is fenced on two /64s; the broker reports only the first drained.
	pool := readyPoolObj("A")
	pool.Status.FencedPrefixes = []string{"2001:db8:0:1::/64", "2001:db8:0:2::/64"}
	pool.Status.NodeDrain = []platformv1.NodeDrainStatus{
		{Prefix: "2001:db8:0:1::/64", Drained: true},
		{Prefix: "2001:db8:0:2::/64", Drained: false},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool).WithStatusSubresource(pool).Build()
	r := &Reconciler{Client: c, StorageFencer: okFencer{}, NetworkFencer: okFencer{}, FailoverThreshold: time.Minute}

	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &platformv1.ClusterPool{}
	_ = c.Get(context.Background(), key("A"), got)
	if len(got.Status.FencedPrefixes) != 1 || got.Status.FencedPrefixes[0] != "2001:db8:0:2::/64" {
		t.Fatalf("drained /64 must be released, undrained held; got %v", got.Status.FencedPrefixes)
	}
}

func TestFailover_ReleaseDrained_HoldsOnReleaseError(t *testing.T) {
	scheme := testScheme(t)
	pool := readyPoolObj("A")
	pool.Status.FencedPrefixes = []string{"2001:db8:0:1::/64"}
	pool.Status.NodeDrain = []platformv1.NodeDrainStatus{{Prefix: "2001:db8:0:1::/64", Drained: true}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool).WithStatusSubresource(pool).Build()
	// Storage release fails -> the /64 must stay fenced (held).
	r := &Reconciler{Client: c, StorageFencer: releaseErrFencer{}, NetworkFencer: okFencer{}, FailoverThreshold: time.Minute}

	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &platformv1.ClusterPool{}
	_ = c.Get(context.Background(), key("A"), got)
	if len(got.Status.FencedPrefixes) != 1 {
		t.Fatalf("release-failed /64 must be HELD, got %v", got.Status.FencedPrefixes)
	}
}

func TestFailover_MultiPrefix_PartialBarrier_TracksAppliedFence(t *testing.T) {
	scheme := testScheme(t)
	lost := lostPoolObj("A", "2001:db8:0:1::/64", "2001:db8:0:2::/64")
	vm := vmOn("vm1", "A")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lost, readyPoolObj("B"), vm).WithStatusSubresource(vm, lost).Build()
	// Storage confirms; network fails -> on the FIRST /64, storage is applied+tracked, then network errors.
	r := &Reconciler{Client: c, StorageFencer: okFencer{}, NetworkFencer: denyFencer{errors.New("no overlay")}, FailoverThreshold: time.Minute}

	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// VM must NOT rebind (barrier blocked).
	got := &computev1.VirtualMachine{}
	_ = c.Get(context.Background(), key("vm1"), got)
	if got.Spec.ClusterName != "A" {
		t.Fatalf("must NOT rebind on partial barrier, got %q", got.Spec.ClusterName)
	}
	// The already-applied storage fence (first /64) must be tracked in FencedPrefixes.
	gp := &platformv1.ClusterPool{}
	_ = c.Get(context.Background(), key("A"), gp)
	if len(gp.Status.FencedPrefixes) != 1 || gp.Status.FencedPrefixes[0] != "2001:db8:0:1::/64" {
		t.Fatalf("already-applied fence must be tracked for later release, got %v", gp.Status.FencedPrefixes)
	}
}

// A fence coordinate must never be derived from the entity being fenced — that entity is by
// definition the one central has lost contact with. Node /64s are broker-reported, so the set is
// frozen at whatever was last seen: a node that joined during the outage is absent from it. That is
// harmless while every node in a cluster shares ONE /64 (each node's identity is a /128 inside it),
// because fencing that /64 covers nodes central never observed. It is NOT harmless when the
// cluster spans several /64s — an unobserved node could sit in an unreported one, and fencing the
// reported subset would let it keep writing while its VMs are reattached elsewhere. So that case
// blocks instead.
func TestFailover_MultipleDistinctNodePrefixes_BlocksWithoutADeclaredAggregate(t *testing.T) {
	scheme := testScheme(t)
	lost := lostPoolObj("A", "2001:db8:0:1::/64", "2001:db8:0:2::/64")
	vm := vmOn("vm1", "A")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lost, readyPoolObj("B"), vm).WithStatusSubresource(vm, lost).Build()
	r := &Reconciler{Client: c, StorageFencer: okFencer{}, NetworkFencer: okFencer{}, FailoverThreshold: time.Minute}

	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &computev1.VirtualMachine{}
	_ = c.Get(context.Background(), key("vm1"), got)
	if got.Spec.ClusterName != "A" {
		t.Fatalf("VM must stay on the lost pool: an incomplete fence must not rebind; got %q", got.Spec.ClusterName)
	}
	if !isBlocked(got) {
		t.Fatalf("want FailoverBlocked recorded, got conditions %+v", got.Status.Conditions)
	}
}

// The escape hatch, and the architecturally correct coordinate: a pool that declares its underlay
// aggregate is fenced COMPLETELY by construction — one prefix covering every node, observed or not
// — so failover proceeds even across several node /64s.
func TestFailover_DeclaredUnderlayPrefix_FencesTheAggregateAndRebinds(t *testing.T) {
	scheme := testScheme(t)
	lost := lostPoolObj("A", "2001:db8:0:1::/64", "2001:db8:0:2::/64")
	lost.Spec.UnderlayPrefix = "2001:db8::/48"
	vm := vmOn("vm1", "A")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lost, readyPoolObj("B"), vm).WithStatusSubresource(vm, lost).Build()
	rec := &recordingFencer{}
	r := &Reconciler{Client: c, StorageFencer: rec, NetworkFencer: okFencer{}, FailoverThreshold: time.Minute}

	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &computev1.VirtualMachine{}
	_ = c.Get(context.Background(), key("vm1"), got)
	if got.Spec.ClusterName != "B" {
		t.Fatalf("a completely-fenced pool must fail over; got %q", got.Spec.ClusterName)
	}
	// The aggregate is what got fenced — not the reported node /64s, which are an incomplete view.
	if len(rec.fenced) != 1 || rec.fenced[0] != "2001:db8::/48" {
		t.Fatalf("want the declared aggregate fenced exactly once, got %v", rec.fenced)
	}
	var pool platformv1.ClusterPool
	_ = c.Get(context.Background(), key("A"), &pool)
	if len(pool.Status.FencedPrefixes) != 1 || pool.Status.FencedPrefixes[0] != "2001:db8::/48" {
		t.Fatalf("FencedPrefixes must record the aggregate so recovery can release it, got %v", pool.Status.FencedPrefixes)
	}
}

// The ordinary single-/64 cluster: unchanged behaviour, and the reason the fallback stays allowed
// at all. Duplicate reports of the one /64 (one per node) are the same coordinate, not a span.
func TestFailover_SingleNodePrefixRepeatedPerNode_StillRebinds(t *testing.T) {
	scheme := testScheme(t)
	lost := lostPoolObj("A", "2001:db8:0:1::/64", "2001:db8:0:1::/64", "2001:db8:0:1::/64")
	vm := vmOn("vm1", "A")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lost, readyPoolObj("B"), vm).WithStatusSubresource(vm, lost).Build()
	rec := &recordingFencer{}
	r := &Reconciler{Client: c, StorageFencer: rec, NetworkFencer: okFencer{}, FailoverThreshold: time.Minute}

	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &computev1.VirtualMachine{}
	_ = c.Get(context.Background(), key("vm1"), got)
	if got.Spec.ClusterName != "B" {
		t.Fatalf("a single-/64 pool must still fail over; got %q", got.Spec.ClusterName)
	}
	if len(rec.fenced) != 1 {
		t.Fatalf("the one distinct /64 should be fenced once, not once per reporting node: %v", rec.fenced)
	}
}

// retiredTwinOn is a CompiledVM twin on pool, retired by a rebind (Terminating, held by the
// release finalizer).
func retiredTwinOn(pool string) *compiledv1.CompiledVM {
	now := metav1.Now()
	return &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{
		Namespace: validate.PoolNamespace(pool), Name: "default-vm1",
		DeletionTimestamp: &now, Finalizers: []string{"compiled.ectobase.dev/source-released"},
	}, Spec: compiledv1.CompiledVMSpec{ClusterName: pool}}
}

// A lost pool's broker cannot report release; the fence is the proof instead.
func TestFailover_FencedPool_ReleasesRetiredTwins(t *testing.T) {
	scheme := testScheme(t)
	lost := lostPoolObj("A", "2001:db8:0:1::/64")
	twin := retiredTwinOn("A")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lost, readyPoolObj("B"), twin).
		WithStatusSubresource(lost, twin).Build()
	r := &Reconciler{Client: c, StorageFencer: okFencer{}, NetworkFencer: okFencer{}, FailoverThreshold: time.Minute}

	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got compiledv1.CompiledVM
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(twin), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Status.Released {
		t.Fatal("a fenced pool's retired twin was not released")
	}
}

// Without complete fence coverage nothing is proven, so nothing is released.
func TestFailover_PartialFence_ReleasesNothing(t *testing.T) {
	scheme := testScheme(t)
	lost := lostPoolObj("A", "2001:db8:0:1::/64")
	twin := retiredTwinOn("A")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lost, readyPoolObj("B"), twin).
		WithStatusSubresource(lost, twin).Build()
	r := &Reconciler{Client: c, StorageFencer: okFencer{}, NetworkFencer: denyFencer{err: errors.New("no")}, FailoverThreshold: time.Minute}

	_, _ = r.Reconcile(context.Background(), req("A"))
	var got compiledv1.CompiledVM
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(twin), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Released {
		t.Fatal("released a twin on a pool whose fence did not confirm")
	}
}
