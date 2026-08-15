// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"sort"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

// VNI allocation bounds for the auto-allocated pool. Explicit pins
// (spec.vni) may be any value; auto-allocation draws only from [Start, End].
const (
	VNIAllocStart int32 = 1000
	VNIAllocEnd   int32 = 1<<24 - 1 // 16777215
)

// VPC lifecycle states written to VPC.status.state.
const (
	vpcStateReady     = "Ready"
	vpcStateConflict  = "Conflict"
	vpcStateExhausted = "Exhausted"
)

// VPCReconciler allocates a globally-unique VNI for every VPC and publishes it to
// VPC.status.vni (+ state=Ready). A VPC either PINS a VNI (spec.vni set) or is
// auto-allocated the lowest free VNI in [VNIAllocStart, VNIAllocEnd].
//
// Correctness rests on two things together: MaxConcurrentReconciles=1 serializes
// allocation, and the used-set is built from a strong (non-cached) List via
// APIReader so a serialized reconcile always observes every prior allocation and
// never double-allocates.
type VPCReconciler struct {
	Client    client.Client
	APIReader client.Reader
}

// Reconcile resolves and persists the VPC's VNI (pin or lowest-free allocation),
// writing status.state = Ready / Conflict / Exhausted.
func (r *VPCReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var vpc netv1.VPC
	if err := r.Client.Get(ctx, req.NamespacedName, &vpc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// A deleted VPC drops out of the used-set on its own, so its VNI becomes
	// reusable with no finalizer/cleanup needed.
	if vpc.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}

	pinned := vpc.Spec.VNI != nil && *vpc.Spec.VNI != 0

	// Strong, non-cached read of every VPC so serialized reconciles never race on
	// a stale cache and double-allocate.
	var list netv1.VPCList
	if err := r.APIReader.List(ctx, &list); err != nil {
		return ctrl.Result{}, fmt.Errorf("list vpcs: %w", err)
	}
	// used holds every VNI claimed by another VPC (its pin and/or its committed
	// status.vni) — auto-allocation must avoid all of these. pinnedBy records, for
	// each pinned VNI, the other VPCs pinning it, so a pin collision is resolved
	// deterministically (not by reconcile order) rather than flapping.
	used := make(map[int32]struct{})
	pinnedBy := make(map[int32][]*netv1.VPC)
	for i := range list.Items {
		other := &list.Items[i]
		if other.UID == vpc.UID ||
			(other.Name == vpc.Name && other.Namespace == vpc.Namespace) {
			continue // skip self
		}
		if other.Spec.VNI != nil && *other.Spec.VNI != 0 {
			used[*other.Spec.VNI] = struct{}{}
			pinnedBy[*other.Spec.VNI] = append(pinnedBy[*other.Spec.VNI], other)
		}
		if other.Status.VNI != 0 {
			used[other.Status.VNI] = struct{}{}
		}
	}

	var desired int32
	if pinned {
		desired = *vpc.Spec.VNI
		// Resolve a contested pin to exactly one Ready, independent of reconcile
		// order. Priority: (1) whoever COMMITTED the VNI first (status.vni==desired,
		// Ready) holds it — first-committer-wins, which keeps a winner stable even if
		// a later-arriving pinner would outrank it; (2) if nobody has committed it,
		// the deterministic tiebreaker (older creationTimestamp, then smaller UID)
		// picks the winner. We yield (Conflict) only when we are NOT the current
		// holder and someone outranks/holds it.
		heldBySelf := vpc.Status.VNI == desired && vpc.Status.State == vpcStateReady
		if !heldBySelf &&
			(committedElsewhere(list.Items, &vpc, desired) || losesPin(&vpc, pinnedBy[desired])) {
			// A human must resolve the losing pin; we do not requeue-error — a
			// re-reconcile fires when either VPC changes. Leave status.vni as-is.
			return ctrl.Result{}, r.setState(ctx, &vpc, vpc.Status.VNI, vpcStateConflict)
		}
	} else {
		free, ok := lowestFreeVNI(used)
		if !ok {
			return ctrl.Result{}, r.setState(ctx, &vpc, vpc.Status.VNI, vpcStateExhausted)
		}
		desired = free
	}

	// Idempotent: already allocated to the desired VNI and Ready.
	if vpc.Status.VNI == desired && vpc.Status.State == vpcStateReady {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, r.setState(ctx, &vpc, desired, vpcStateReady)
}

// committedElsewhere reports whether some OTHER VPC has already committed vni to
// its status (state=Ready) — an unambiguous claim we must yield to.
func committedElsewhere(items []netv1.VPC, self *netv1.VPC, vni int32) bool {
	for i := range items {
		o := &items[i]
		if o.UID == self.UID || (o.Name == self.Name && o.Namespace == self.Namespace) {
			continue
		}
		if o.Status.VNI == vni && o.Status.State == vpcStateReady {
			return true
		}
	}
	return false
}

// losesPin reports whether self loses the pin to any competitor pinning the same
// VNI, by the deterministic tiebreaker (older creationTimestamp wins; ties broken
// by smaller UID). The single global winner becomes Ready; every other pinner
// becomes Conflict, regardless of reconcile order.
func losesPin(self *netv1.VPC, competitors []*netv1.VPC) bool {
	for _, c := range competitors {
		if outranks(c, self) {
			return true
		}
	}
	return false
}

// outranks reports whether a should win a contested pin over b: earlier
// creationTimestamp wins; equal timestamps break by smaller UID.
func outranks(a, b *netv1.VPC) bool {
	at, bt := a.CreationTimestamp.Time, b.CreationTimestamp.Time
	if at.Before(bt) {
		return true
	}
	if bt.Before(at) {
		return false
	}
	return a.UID < b.UID
}

// lowestFreeVNI returns the smallest VNI in [VNIAllocStart, VNIAllocEnd] absent
// from used, or ok=false if the range is exhausted. It sorts the used set and
// walks for the first gap (O(n log n) in the number of allocated VNIs) rather
// than probing the whole 16M range, which would be a serialized cliff once the
// low end fills up.
func lowestFreeVNI(used map[int32]struct{}) (int32, bool) {
	taken := make([]int32, 0, len(used))
	for v := range used {
		if v >= VNIAllocStart && v <= VNIAllocEnd {
			taken = append(taken, v)
		}
	}
	sort.Slice(taken, func(i, j int) bool { return taken[i] < taken[j] })
	next := int32(VNIAllocStart)
	for _, v := range taken {
		if v > next {
			break // gap at next
		}
		if v == next {
			next++
		}
	}
	if next <= VNIAllocEnd {
		return next, true
	}
	return 0, false
}

// setState writes status.vni + status.state via the status subresource.
func (r *VPCReconciler) setState(ctx context.Context, vpc *netv1.VPC, vni int32, state string) error {
	vpc.Status.VNI = vni
	vpc.Status.State = state
	if err := r.Client.Status().Update(ctx, vpc); err != nil {
		return fmt.Errorf("update vpc status: %w", err)
	}
	return nil
}

// SetupWithManager registers the VPCReconciler. MaxConcurrentReconciles=1 is
// REQUIRED: serialized reconciles + the strong-read used-set are what make
// allocation collision-free.
func (r *VPCReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1.VPC{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}
