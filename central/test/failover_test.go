// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
	"github.com/trevex/ectobase/central/pkg/clusterpool"
	"github.com/trevex/ectobase/central/pkg/failover"
)

// confirmingFencer confirms every fence (storage + network) for any /64 — the
// happy path that lets the fence-gated failover reach the re-bind. Contrast with
// failover.DenyFencer, which refuses both (fail-safe).
type confirmingFencer struct{}

func (confirmingFencer) Fence(context.Context, string) error   { return nil }
func (confirmingFencer) Release(context.Context, string) error { return nil }

// TestFailover_RebindsOffLostPool proves Tier-2 fence-gated failover against the
// REAL kit aggregated apiserver:
//
//   - c1 is lost (Phase=Unknown, lease RenewTime stale by 1h), c2 is Ready (cpu:8);
//   - vm1 is bound to c1.
//
// With a CONFIRMING fencer the reconciler must re-bind vm1 to c2. With the prod
// DenyFencer it must fail safe: vm1 STAYS on c1 and gets FailoverBlocked=True.
func TestFailover_RebindsOffLostPool(t *testing.T) {
	c, ctx := startNetEnv(t)
	const ns = "default"

	// c1: lost — Unknown phase + stale lease (RenewTime an hour ago).
	c1 := &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "c1"}}
	if err := c.Create(ctx, c1); err != nil {
		t.Fatalf("create pool c1: %v", err)
	}
	stale := metav1.NewMicroTime(time.Now().Add(-time.Hour))
	cur1 := &platformv1.ClusterPool{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(c1), cur1); err != nil {
		t.Fatalf("get pool c1: %v", err)
	}
	cur1.Status.Phase = clusterpool.PhaseUnknown
	cur1.Status.Lease = &platformv1.ClusterPoolLease{HolderIdentity: "b1", RenewTime: &stale}
	cur1.Status.NodePrefixes = []string{"2001:db8:0:1::/64"}
	if err := c.Status().Update(ctx, cur1); err != nil {
		t.Fatalf("status update pool c1: %v", err)
	}

	// c2: Ready with cpu:8 — the failover target.
	c2 := &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "c2"}}
	if err := c.Create(ctx, c2); err != nil {
		t.Fatalf("create pool c2: %v", err)
	}
	cur2 := &platformv1.ClusterPool{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(c2), cur2); err != nil {
		t.Fatalf("get pool c2: %v", err)
	}
	cur2.Status.Phase = clusterpool.PhaseReady
	cur2.Status.Allocatable = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("8")}
	if err := c.Status().Update(ctx, cur2); err != nil {
		t.Fatalf("status update pool c2: %v", err)
	}

	// vm1 bound to c1, requesting cpu:2.
	vm := &netv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm1"},
		Spec: netv1.VirtualMachineSpec{
			ClusterName: "c1",
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
			},
		},
	}
	if err := c.Create(ctx, vm); err != nil {
		t.Fatalf("create vm1: %v", err)
	}

	reqC1 := ctrl.Request{NamespacedName: client.ObjectKey{Name: "c1"}}

	t.Run("confirming fencer rebinds to c2", func(t *testing.T) {
		r := &failover.Reconciler{Client: c, StorageFencer: confirmingFencer{}, NetworkFencer: confirmingFencer{}, FailoverThreshold: time.Minute}
		if _, err := r.Reconcile(ctx, reqC1); err != nil {
			t.Fatalf("failover Reconcile: %v", err)
		}
		got := &netv1.VirtualMachine{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm1"}, got); err != nil {
			t.Fatalf("get vm1: %v", err)
		}
		if got.Spec.ClusterName != "c2" {
			t.Fatalf("expected vm1 failed over to c2, got %q", got.Spec.ClusterName)
		}
		t.Log("failover: PASS (confirming fencer -> vm1 rebound c1->c2)")
	})

	t.Run("deny fencer keeps vm on c1 and blocks", func(t *testing.T) {
		// Re-bind vm1 back to the lost c1 for this sub-test.
		back := &netv1.VirtualMachine{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm1"}, back); err != nil {
			t.Fatalf("get vm1: %v", err)
		}
		back.Spec.ClusterName = "c1"
		if err := c.Update(ctx, back); err != nil {
			t.Fatalf("re-bind vm1 to c1: %v", err)
		}

		r := &failover.Reconciler{Client: c, StorageFencer: failover.DenyFencer{}, NetworkFencer: failover.DenyFencer{}, FailoverThreshold: time.Minute}
		if _, err := r.Reconcile(ctx, reqC1); err != nil {
			t.Fatalf("failover Reconcile (deny): %v", err)
		}
		got := &netv1.VirtualMachine{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm1"}, got); err != nil {
			t.Fatalf("get vm1: %v", err)
		}
		if got.Spec.ClusterName != "c1" {
			t.Fatalf("fail-safe: expected vm1 to STAY on c1, got %q", got.Spec.ClusterName)
		}
		cond := meta.FindStatusCondition(got.Status.Conditions, "FailoverBlocked")
		if cond == nil || cond.Status != metav1.ConditionTrue {
			t.Fatalf("expected FailoverBlocked=True, got %+v", cond)
		}
		t.Logf("failover fail-safe: PASS (deny fencer -> vm1 stays c1, FailoverBlocked=True reason=%s)", cond.Reason)
	})
}
