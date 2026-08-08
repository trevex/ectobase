// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package failover

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/central/pkg/clusterpool"
)

type okFencer struct{}

func (okFencer) Fence(context.Context, string) error   { return nil }
func (okFencer) Release(context.Context, string) error { return nil }

type denyFencer struct{ err error }

func (d denyFencer) Fence(context.Context, string) error { return d.err }
func (denyFencer) Release(context.Context, string) error { return nil }

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

func vmOn(name, pool string) *netv1.VirtualMachine {
	return &netv1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: netv1.VirtualMachineSpec{ClusterName: pool}}
}

func TestFailover_WholePoolFence_ThenRebind(t *testing.T) {
	scheme := testScheme(t)
	lost := lostPoolObj("A", "2001:db8:0:1::/64", "2001:db8:0:2::/64")
	healthy := readyPoolObj("B")
	vm := vmOn("vm1", "A")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(lost, healthy, vm).WithStatusSubresource(vm, lost).Build()
	r := &Reconciler{Client: c, StorageFencer: okFencer{}, NetworkFencer: okFencer{}, FailoverThreshold: time.Minute}

	if _, err := r.Reconcile(context.Background(), req("A")); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &netv1.VirtualMachine{}
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
	got := &netv1.VirtualMachine{}
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
	got := &netv1.VirtualMachine{}
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
