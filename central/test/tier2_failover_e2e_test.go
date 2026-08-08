// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	platformv1 "github.com/trevex/ectobase/api/platform/v1alpha1"
	"github.com/trevex/ectobase/central/pkg/clusterpool"
	"github.com/trevex/ectobase/central/pkg/failover"
)

// TestTier2_Failover_FenceRebindRelease drives the WHOLE Tier-2 flow through the
// REAL kit aggregated apiserver (conversions, status subresource, the reconciler):
//
//   - poolA is lost (Phase=Unknown, lease RenewTime stale by 10m) with one node /64;
//     poolB is Ready; vm1 (default ns) is bound to poolA.
//   - With CONFIRMING fencers one Reconcile must (1) fence the /64 and record it in
//     poolA.Status.FencedPrefixes, then (2) re-bind vm1 poolA->poolB.
//   - Recovery: poolA comes back (Phase=Ready) and its returning broker confirms the
//     /64 drained (NodeDrain[Drained=true]); the next Reconcile must RELEASE the fence,
//     leaving FencedPrefixes empty.
//
// Note the recovery step marks poolA Ready as well as drained: a still-lost pool would
// be re-fenced on the same pass (releaseDrained runs, then the fence barrier re-applies),
// so a genuine release is only observable once the pool is no longer lost — matching the
// reconciler's design (see the readyPoolObj release unit tests in internal/failover).
func TestTier2_Failover_FenceRebindRelease(t *testing.T) {
	c, ctx := startNetEnv(t)
	const ns = "default"
	const prefix = "2001:db8:0:1::/64"

	// poolA: lost — Unknown phase + a lease that renewed 10 minutes ago.
	poolA := &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "poolA"}}
	if err := c.Create(ctx, poolA); err != nil {
		t.Fatalf("create poolA: %v", err)
	}
	stale := metav1.NewMicroTime(time.Now().Add(-10 * time.Minute))
	curA := &platformv1.ClusterPool{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(poolA), curA); err != nil {
		t.Fatalf("get poolA: %v", err)
	}
	curA.Status.Phase = clusterpool.PhaseUnknown
	curA.Status.Lease = &platformv1.ClusterPoolLease{HolderIdentity: "brokerA", RenewTime: &stale}
	curA.Status.NodePrefixes = []string{prefix}
	if err := c.Status().Update(ctx, curA); err != nil {
		t.Fatalf("status update poolA: %v", err)
	}

	// poolB: the healthy failover target.
	poolB := &platformv1.ClusterPool{ObjectMeta: metav1.ObjectMeta{Name: "poolB"}}
	if err := c.Create(ctx, poolB); err != nil {
		t.Fatalf("create poolB: %v", err)
	}
	curB := &platformv1.ClusterPool{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(poolB), curB); err != nil {
		t.Fatalf("get poolB: %v", err)
	}
	curB.Status.Phase = clusterpool.PhaseReady
	if err := c.Status().Update(ctx, curB); err != nil {
		t.Fatalf("status update poolB: %v", err)
	}

	// vm1 bound to the lost poolA.
	vm := &netv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "vm1"},
		Spec:       netv1.VirtualMachineSpec{ClusterName: "poolA"},
	}
	if err := c.Create(ctx, vm); err != nil {
		t.Fatalf("create vm1: %v", err)
	}

	reqA := ctrl.Request{NamespacedName: client.ObjectKey{Name: "poolA"}}
	r := &failover.Reconciler{
		Client:            c,
		StorageFencer:     confirmingFencer{},
		NetworkFencer:     confirmingFencer{},
		FailoverThreshold: time.Minute,
	}

	// --- Fence + re-bind. ---
	if _, err := r.Reconcile(ctx, reqA); err != nil {
		t.Fatalf("reconcile (fence/rebind): %v", err)
	}

	got := &netv1.VirtualMachine{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vm1"}, got); err != nil {
		t.Fatalf("get vm1: %v", err)
	}
	if got.Spec.ClusterName != "poolB" {
		t.Fatalf("expected vm1 re-bound to poolB, got %q", got.Spec.ClusterName)
	}

	fencedA := &platformv1.ClusterPool{}
	if err := c.Get(ctx, client.ObjectKey{Name: "poolA"}, fencedA); err != nil {
		t.Fatalf("get poolA after fence: %v", err)
	}
	if len(fencedA.Status.FencedPrefixes) != 1 || fencedA.Status.FencedPrefixes[0] != prefix {
		t.Fatalf("expected FencedPrefixes=[%s], got %v", prefix, fencedA.Status.FencedPrefixes)
	}
	t.Logf("fence+rebind: PASS (vm1 poolA->poolB, FencedPrefixes=%v)", fencedA.Status.FencedPrefixes)

	// --- Recovery: pool returns (Ready) and its broker confirms the /64 drained. ---
	recovered := fencedA
	recovered.Status.Phase = clusterpool.PhaseReady
	recovered.Status.NodeDrain = []platformv1.NodeDrainStatus{{Prefix: prefix, Drained: true}}
	if err := c.Status().Update(ctx, recovered); err != nil {
		t.Fatalf("status update poolA (recovery): %v", err)
	}

	if _, err := r.Reconcile(ctx, reqA); err != nil {
		t.Fatalf("reconcile (recovery release): %v", err)
	}

	releasedA := &platformv1.ClusterPool{}
	if err := c.Get(ctx, client.ObjectKey{Name: "poolA"}, releasedA); err != nil {
		t.Fatalf("get poolA after release: %v", err)
	}
	if len(releasedA.Status.FencedPrefixes) != 0 {
		t.Fatalf("drained /64 fence must be released, still: %v", releasedA.Status.FencedPrefixes)
	}
	t.Log("recovery release: PASS (drained /64 fence released, FencedPrefixes empty)")
}
