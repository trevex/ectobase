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

	"github.com/trevex/ectobase/hub/pkg/failover"
)

// NetworkFenceGVR is the csi-addons NetworkFence group/version (cluster-scoped CR).
var NetworkFenceGVR = schema.GroupVersion{Group: "csiaddons.openshift.io", Version: "v1alpha1"}

// StorageFencer must satisfy the failover PrefixFencer seam.
var _ failover.PrefixFencer = (*StorageFencer)(nil)

// StorageFencer is the storage half of Tier-2 fencing: it blocklists a node /64 at
// Ceph via a csi-addons NetworkFence CR (fenceState=Fenced), confirming active via
// status.result==Succeeded. It writes to an injected client (the Ceph-management
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

func fenceName(prefix string) string {
	r := strings.NewReplacer(":", "-", "/", "--", ".", "-")
	return "ectobase-" + r.Replace(prefix)
}

func (f *StorageFencer) obj(prefix, state string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: NetworkFenceGVR.Group, Version: NetworkFenceGVR.Version, Kind: "NetworkFence"})
	u.SetName(fenceName(prefix))
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

// Fence ensures a Fenced NetworkFence exists for the /64 and returns nil ONLY when its
// status.result == Succeeded (fail-safe: a Pending/absent-status fence returns an error).
func (f *StorageFencer) Fence(ctx context.Context, prefix string) error {
	want := f.obj(prefix, "Fenced")
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
	result, _, _ := unstructured.NestedString(cur.Object, "status", "result")
	if result != "Succeeded" {
		return fmt.Errorf("NetworkFence %s not active (result=%q)", want.GetName(), result)
	}
	return nil
}

// Release drives the NetworkFence Fenced->Unfenced so csi-addons runs
// `ceph osd blocklist rm`, then deletes the CR. Like Fence it is fail-safe: it returns
// nil ONLY once the un-fence has completed (the CR was observed Unfenced AND reported
// status.result==Succeeded) and the CR is removed; while the transition is in flight it
// returns an error so the caller holds the drain and retries on the next reconcile. A
// missing CR means already released.
//
// It must NOT simply delete a Fenced CR: ceph removes the blocklist entry only on the
// Fenced->Unfenced state transition (this driver runs no delete-finalizer un-fence), so
// a bare delete leaves the blocklist in place (with a multi-year expiry) even though the
// CR is gone — exactly the recovery leak this replaces.
func (f *StorageFencer) Release(ctx context.Context, prefix string) error {
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
	// Observed Unfenced (from a prior reconcile): status.result now reflects the un-fence.
	result, _, _ := unstructured.NestedString(cur.Object, "status", "result")
	if result != "Succeeded" {
		return fmt.Errorf("NetworkFence %s un-fence not confirmed (result=%q)", name, result)
	}
	if derr := f.c.Delete(ctx, cur); derr != nil && !apierrors.IsNotFound(derr) {
		return fmt.Errorf("delete NetworkFence %s: %w", name, derr)
	}
	return nil
}
