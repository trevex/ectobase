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

	"github.com/trevex/ectobase/central/internal/failover"
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
	c      client.Client
	driver string
	secret client.ObjectKey
}

// NewStorageFencer wraps the management-cluster client + the CSI driver + provisioner secret.
func NewStorageFencer(c client.Client, driver string, secret client.ObjectKey) *StorageFencer {
	return &StorageFencer{c: c, driver: driver, secret: secret}
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

// Release flips the CR to Unfenced and deletes it; nil once removed/not-found.
func (f *StorageFencer) Release(ctx context.Context, prefix string) error {
	u := f.obj(prefix, "Unfenced")
	if err := f.c.Delete(ctx, u); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete NetworkFence %s: %w", u.GetName(), err)
	}
	return nil
}
