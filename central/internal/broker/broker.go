// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"fmt"
	"maps"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
)

// Broker is the per-cluster set-reconcile engine: it makes the downstream compiled
// objects (CompiledNIC via SyncOnce, CompiledVM via SyncCompiledVMs,
// CompiledVolumeAttachment via SyncCompiledVolumeAttachments) exactly match the
// central objects bound to ClusterName (spec.clusterName), per-type. Both spec AND
// labels are mirrored: the `workload` label is load-bearing downstream (the
// vm-materializer joins a VM to its volume attachments by it).
type Broker struct {
	Central     client.Client
	Downstream  client.Client
	ClusterName string
}

// key identifies a namespaced CompiledNIC as "namespace/name".
func key(o *netv1.CompiledNIC) string { return o.Namespace + "/" + o.Name }

// SyncOnce is a declarative set-reconcile: desired = central CompiledNICs with
// spec.clusterName==ClusterName; make downstream match (create/update/delete).
// Idempotent and restart-safe (no in-memory diff; derived from live sets each call).
func (b *Broker) SyncOnce(ctx context.Context) error {
	// Fetch desired set from central, filtered by clusterName field index.
	desired := &netv1.CompiledNICList{}
	if err := b.Central.List(ctx, desired, client.MatchingFields{"spec.clusterName": b.ClusterName}); err != nil {
		return fmt.Errorf("list central: %w", err)
	}
	want := make(map[string]netv1.CompiledNIC, len(desired.Items))
	for _, o := range desired.Items {
		want[key(&o)] = o
	}

	// Fetch current set from downstream.
	have := &netv1.CompiledNICList{}
	if err := b.Downstream.List(ctx, have); err != nil {
		return fmt.Errorf("list downstream: %w", err)
	}

	// Reconcile existing downstream objects: update drifted, delete extras.
	haveKeys := make(map[string]bool, len(have.Items))
	for i := range have.Items {
		cur := &have.Items[i]
		haveKeys[key(cur)] = true
		w, ok := want[key(cur)]
		if !ok {
			// Not in desired set — GC it.
			if err := b.Downstream.Delete(ctx, cur); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("gc %s: %w", key(cur), err)
			}
			continue
		}
		// In desired set — update if spec OR labels drifted. Spec has slices, so use a
		// semantic deep-equal (NOT ==, which does not compile on struct-with-slice).
		if !equality.Semantic.DeepEqual(cur.Spec, w.Spec) || !maps.Equal(cur.Labels, w.Labels) {
			cur.Spec = w.Spec
			cur.Labels = maps.Clone(w.Labels)
			if err := b.Downstream.Update(ctx, cur); err != nil {
				return fmt.Errorf("update %s: %w", key(cur), err)
			}
		}
	}

	// Create objects present in desired but absent from downstream.
	for k, w := range want {
		if haveKeys[k] {
			continue
		}
		local := &netv1.CompiledNIC{}
		local.Namespace = w.Namespace
		local.Name = w.Name
		local.Spec = w.Spec
		local.Labels = maps.Clone(w.Labels)
		if err := b.Downstream.Create(ctx, local); err != nil {
			return fmt.Errorf("create %s: %w", k, err)
		}
	}
	return nil
}

// keyVM identifies a namespaced CompiledVM as "namespace/name".
func keyVM(o *netv1.CompiledVM) string { return o.Namespace + "/" + o.Name }

// keyAtt identifies a namespaced CompiledVolumeAttachment as "namespace/name".
func keyAtt(o *netv1.CompiledVolumeAttachment) string { return o.Namespace + "/" + o.Name }

// SyncCompiledVMs is the CompiledVM twin of SyncOnce: declarative set-reconcile of
// CompiledVMs bound to ClusterName, central->downstream (create/update/delete).
func (b *Broker) SyncCompiledVMs(ctx context.Context) error {
	desired := &netv1.CompiledVMList{}
	if err := b.Central.List(ctx, desired, client.MatchingFields{"spec.clusterName": b.ClusterName}); err != nil {
		return fmt.Errorf("list central vms: %w", err)
	}
	want := make(map[string]netv1.CompiledVM, len(desired.Items))
	for _, o := range desired.Items {
		want[keyVM(&o)] = o
	}
	have := &netv1.CompiledVMList{}
	if err := b.Downstream.List(ctx, have); err != nil {
		return fmt.Errorf("list downstream vms: %w", err)
	}
	haveKeys := make(map[string]bool, len(have.Items))
	for i := range have.Items {
		cur := &have.Items[i]
		haveKeys[keyVM(cur)] = true
		w, ok := want[keyVM(cur)]
		if !ok {
			if err := b.Downstream.Delete(ctx, cur); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("gc vm %s: %w", keyVM(cur), err)
			}
			continue
		}
		if !equality.Semantic.DeepEqual(cur.Spec, w.Spec) || !maps.Equal(cur.Labels, w.Labels) {
			cur.Spec = w.Spec
			cur.Labels = maps.Clone(w.Labels)
			if err := b.Downstream.Update(ctx, cur); err != nil {
				return fmt.Errorf("update vm %s: %w", keyVM(cur), err)
			}
		}
	}
	for k, w := range want {
		if haveKeys[k] {
			continue
		}
		local := &netv1.CompiledVM{}
		local.Namespace = w.Namespace
		local.Name = w.Name
		local.Spec = w.Spec
		local.Labels = maps.Clone(w.Labels)
		if err := b.Downstream.Create(ctx, local); err != nil {
			return fmt.Errorf("create vm %s: %w", k, err)
		}
	}
	return nil
}

// SyncCompiledVolumeAttachments is the CompiledVolumeAttachment twin of SyncOnce:
// declarative set-reconcile of attachments bound to ClusterName, central->downstream.
func (b *Broker) SyncCompiledVolumeAttachments(ctx context.Context) error {
	desired := &netv1.CompiledVolumeAttachmentList{}
	if err := b.Central.List(ctx, desired, client.MatchingFields{"spec.clusterName": b.ClusterName}); err != nil {
		return fmt.Errorf("list central attachments: %w", err)
	}
	want := make(map[string]netv1.CompiledVolumeAttachment, len(desired.Items))
	for _, o := range desired.Items {
		want[keyAtt(&o)] = o
	}
	have := &netv1.CompiledVolumeAttachmentList{}
	if err := b.Downstream.List(ctx, have); err != nil {
		return fmt.Errorf("list downstream attachments: %w", err)
	}
	haveKeys := make(map[string]bool, len(have.Items))
	for i := range have.Items {
		cur := &have.Items[i]
		haveKeys[keyAtt(cur)] = true
		w, ok := want[keyAtt(cur)]
		if !ok {
			if err := b.Downstream.Delete(ctx, cur); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("gc attachment %s: %w", keyAtt(cur), err)
			}
			continue
		}
		if !equality.Semantic.DeepEqual(cur.Spec, w.Spec) || !maps.Equal(cur.Labels, w.Labels) {
			cur.Spec = w.Spec
			cur.Labels = maps.Clone(w.Labels)
			if err := b.Downstream.Update(ctx, cur); err != nil {
				return fmt.Errorf("update attachment %s: %w", keyAtt(cur), err)
			}
		}
	}
	for k, w := range want {
		if haveKeys[k] {
			continue
		}
		local := &netv1.CompiledVolumeAttachment{}
		local.Namespace = w.Namespace
		local.Name = w.Name
		local.Spec = w.Spec
		local.Labels = maps.Clone(w.Labels)
		if err := b.Downstream.Create(ctx, local); err != nil {
			return fmt.Errorf("create attachment %s: %w", k, err)
		}
	}
	return nil
}
