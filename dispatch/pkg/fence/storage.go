// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package fence

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/trevex/ectobase/dispatch/pkg/failover"
)

// NetworkFenceGVR is the csi-addons NetworkFence group/version (cluster-scoped CR).
var NetworkFenceGVR = schema.GroupVersion{Group: "csiaddons.openshift.io", Version: "v1alpha1"}

// StorageFencer must satisfy the failover StorageFencer seam.
var _ failover.StorageFencer = (*StorageFencer)(nil)

// FencedForPoolLabel names, on a NetworkFence, the ClusterPool the dispatch fenced the prefix for.
// It is the dispatch's own record of whose fence this is: NetworkFence CRs live on the dispatch
// host cluster, which no broker has credentials for, unlike a pool's status, which its broker
// writes. Failover releases a fence only for the pool this label names.
const FencedForPoolLabel = "ectobase.dev/fenced-for-pool"

// StorageFencer is the storage half of Tier-2 fencing: it blocklists a node /64 at
// Ceph via a csi-addons NetworkFence CR (fenceState=Fenced), confirming active via
// status.result==Succeeded for the fence op (see Fence and fenceSucceededMsg). It writes to an injected client (the Ceph-management
// cluster; the same cluster in the single-cluster lab).
type StorageFencer struct {
	c         client.Client
	driver    string
	clusterID string
	secret    client.ObjectKey
}

// NewStorageFencer wraps the management-cluster client + the CSI driver + the Ceph clusterID
// (fsid) + provisioner secret. clusterID is written to spec.parameters.clusterID: the ceph-csi
// NetworkFence RPC rejects a fence with "missing or empty clusterID", so it is required against a
// real driver (an empty clusterID is accepted for the fake-client envtests, which never dial ceph).
func NewStorageFencer(c client.Client, driver, clusterID string, secret client.ObjectKey) *StorageFencer {
	return &StorageFencer{c: c, driver: driver, clusterID: clusterID, secret: secret}
}

// The status.message csi-addons writes with result Succeeded, one per op: its exported
// FenceOperationSuccessfulMessage and UnFenceOperationSuccessfulMessage (stable since csi-addons
// v0.9.0; v0.5.0 wrote the fence message for both). csi-addons keeps ONE result per CR,
// overwritten by whichever op ran last, never sets status.conditions and records no generation,
// so the message is the only thing saying which op a Succeeded belongs to.
const (
	fenceSucceededMsg   = "fencing operation successful"
	unfenceSucceededMsg = "unfencing operation successful"
)

func fenceName(prefix string) string {
	r := strings.NewReplacer(":", "-", "/", "--", ".", "-")
	return "ectobase-" + r.Replace(prefix)
}

func (f *StorageFencer) obj(pool, prefix, state string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: NetworkFenceGVR.Group, Version: NetworkFenceGVR.Version, Kind: "NetworkFence"})
	u.SetName(fenceName(prefix))
	u.SetLabels(map[string]string{FencedForPoolLabel: pool})
	_ = unstructured.SetNestedField(u.Object, state, "spec", "fenceState")
	_ = unstructured.SetNestedField(u.Object, f.driver, "spec", "driver")
	_ = unstructured.SetNestedStringSlice(u.Object, []string{prefix}, "spec", "cidrs")
	_ = unstructured.SetNestedField(u.Object, f.secret.Name, "spec", "secret", "name")
	_ = unstructured.SetNestedField(u.Object, f.secret.Namespace, "spec", "secret", "namespace")
	// The ceph-csi NetworkFence RPC reads clusterID (the ceph fsid) from spec.parameters to select
	// the mon set to blocklist against; omitted only in the fake-client tests (never dials a driver).
	if f.clusterID != "" {
		_ = unstructured.SetNestedStringMap(u.Object, map[string]string{"clusterID": f.clusterID}, "spec", "parameters")
	}
	return u
}

// Fence ensures a Fenced NetworkFence exists for the /64 and returns nil ONLY when csi-addons
// reports the FENCE op Succeeded on it (fail-safe: a Pending/absent-status fence returns an error).
//
// A CR that is not Fenced was left Unfenced by a release in flight. It is never flipped back in
// place: its status would keep the fence op's old Succeeded until csi-addons got round to the
// flip, confirming a fence that is being removed. Nor is it deleted before its unfence is
// reported: csi-addons' delete only drops its finalizer and never unfences, so the blocklist
// entry would stay with nothing tracking it (a later Release would find no CR and call it
// released). So Fence waits, touching nothing, until the unfence op is reported Succeeded; then
// the CR is spent, and Fence deletes it and creates a fresh Fenced one, whose only possible
// Succeeded is a fence op's. A CR being deleted is waited out.
//
// The CR is labelled with the pool it fences for. One already held for another pool (or carrying
// no label) is not this pool's to fence over or replace: Fence reports it and touches nothing.
func (f *StorageFencer) Fence(ctx context.Context, pool, prefix string) error {
	want := f.obj(pool, prefix, "Fenced")
	cur := &unstructured.Unstructured{}
	cur.SetGroupVersionKind(want.GroupVersionKind())
	err := f.c.Get(ctx, client.ObjectKey{Name: want.GetName()}, cur)
	if apierrors.IsNotFound(err) {
		if cerr := f.c.Create(ctx, want); cerr != nil {
			return fmt.Errorf("create NetworkFence %s: %w", want.GetName(), cerr)
		}
		return fmt.Errorf("NetworkFence %s created; awaiting Succeeded", want.GetName())
	}
	if err != nil {
		return fmt.Errorf("get NetworkFence %s: %w", want.GetName(), err)
	}
	if !cur.GetDeletionTimestamp().IsZero() {
		return fmt.Errorf("NetworkFence %s is being deleted; awaiting it to re-fence", want.GetName())
	}
	if owner := cur.GetLabels()[FencedForPoolLabel]; owner != pool {
		return fmt.Errorf("NetworkFence %s is held for pool %q, not %s; not touching it", want.GetName(), owner, pool)
	}
	result, _, _ := unstructured.NestedString(cur.Object, "status", "result")
	msg, _, _ := unstructured.NestedString(cur.Object, "status", "message")
	if state, _, _ := unstructured.NestedString(cur.Object, "spec", "fenceState"); state != "Fenced" {
		if result != "Succeeded" || msg != unfenceSucceededMsg {
			return fmt.Errorf("NetworkFence %s is %s with its unfence not yet reported (result=%q, message=%q); "+
				"awaiting it before re-fencing", want.GetName(), state, result, msg)
		}
		if derr := f.c.Delete(ctx, cur); derr != nil && !apierrors.IsNotFound(derr) {
			return fmt.Errorf("delete unfenced NetworkFence %s to re-fence: %w", want.GetName(), derr)
		}
		return fmt.Errorf("NetworkFence %s was unfenced; replacing it with a fresh Fenced one", want.GetName())
	}
	if result != "Succeeded" || msg != fenceSucceededMsg {
		return fmt.Errorf("NetworkFence %s not active (result=%q, message=%q)", want.GetName(), result, msg)
	}
	return nil
}

// Release drives the NetworkFence Fenced->Unfenced so csi-addons runs
// `ceph osd blocklist rm`, then deletes the CR. Like Fence it is fail-safe: it returns
// nil ONLY once the un-fence has completed (the CR was observed Unfenced AND csi-addons
// reported the UNFENCE op Succeeded) and the CR is removed; while the transition is in
// flight it returns an error so the caller holds the drain and retries on the next
// reconcile. Right after the flip the status still reports the fence op's Succeeded, which
// is why the message is checked: deleting then would drop the CR before its unfence ran.
//
// A missing CR means already released. That holds because no path deletes a NetworkFence
// before csi-addons has reported its unfence: Release and Fence both wait for it.
//
// It must NOT simply delete a Fenced CR: ceph removes the blocklist entry only on the
// Fenced->Unfenced state transition (this driver runs no delete-finalizer un-fence), so
// a bare delete leaves the blocklist in place (with a multi-year expiry) even though the
// CR is gone — exactly the recovery leak this replaces.
//
// It releases only a CR labelled for pool. One held for another pool, or carrying no label, is
// refused with an error and left as it is: a pool's status, which names the prefix to release, is
// written by its broker, and must not be able to unfence another pool.
func (f *StorageFencer) Release(ctx context.Context, pool, prefix string) error {
	name := fenceName(prefix)
	cur := &unstructured.Unstructured{}
	cur.SetGroupVersionKind(schema.GroupVersionKind{Group: NetworkFenceGVR.Group, Version: NetworkFenceGVR.Version, Kind: "NetworkFence"})
	err := f.c.Get(ctx, client.ObjectKey{Name: name}, cur)
	if apierrors.IsNotFound(err) {
		return nil // already released
	}
	if err != nil {
		return fmt.Errorf("get NetworkFence %s: %w", name, err)
	}
	if owner := cur.GetLabels()[FencedForPoolLabel]; owner != pool {
		return fmt.Errorf("NetworkFence %s is held for pool %q, not %s; refusing to release it", name, owner, pool)
	}
	state, _, _ := unstructured.NestedString(cur.Object, "spec", "fenceState")
	if state != "Unfenced" {
		// Flip to Unfenced IN PLACE (preserve resourceVersion) so csi-addons
		// un-blocklists. status.result still reflects the prior Fenced op, so it is NOT
		// trusted here — await a later reconcile once the CR is observed Unfenced.
		_ = unstructured.SetNestedField(cur.Object, "Unfenced", "spec", "fenceState")
		if uerr := f.c.Update(ctx, cur); uerr != nil {
			return fmt.Errorf("update NetworkFence %s to Unfenced: %w", name, uerr)
		}
		return fmt.Errorf("NetworkFence %s set Unfenced; awaiting un-fence", name)
	}
	// Observed Unfenced: only a Succeeded that names the unfence op means it ran.
	result, _, _ := unstructured.NestedString(cur.Object, "status", "result")
	msg, _, _ := unstructured.NestedString(cur.Object, "status", "message")
	if result != "Succeeded" || msg != unfenceSucceededMsg {
		return fmt.Errorf("NetworkFence %s un-fence not confirmed (result=%q, message=%q)", name, result, msg)
	}
	if derr := f.c.Delete(ctx, cur); derr != nil && !apierrors.IsNotFound(derr) {
		return fmt.Errorf("delete NetworkFence %s: %w", name, derr)
	}
	return nil
}

// FencedFor reports the pool the NetworkFence for prefix was fenced for ("" for a CR with no label),
// and whether one exists at all.
func (f *StorageFencer) FencedFor(ctx context.Context, prefix string) (pool string, found bool, err error) {
	cur := &unstructured.Unstructured{}
	cur.SetGroupVersionKind(schema.GroupVersionKind{Group: NetworkFenceGVR.Group, Version: NetworkFenceGVR.Version, Kind: "NetworkFence"})
	err = f.c.Get(ctx, client.ObjectKey{Name: fenceName(prefix)}, cur)
	if apierrors.IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get NetworkFence %s: %w", fenceName(prefix), err)
	}
	return cur.GetLabels()[FencedForPoolLabel], true, nil
}
