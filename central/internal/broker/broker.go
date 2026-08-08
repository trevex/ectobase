// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	platformv1 "github.com/trevex/ectobase/central/apis/platform/v1alpha1"
)

// Broker is the per-cluster set-reconcile engine: it makes the downstream compiled
// objects (CompiledNIC via SyncOnce, CompiledVM via SyncCompiledVMs,
// CompiledVolumeAttachment via SyncCompiledVolumeAttachments, CompiledContainer via
// SyncCompiledContainers) exactly match the
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

// keyCtr identifies a namespaced CompiledContainer as "namespace/name".
func keyCtr(o *netv1.CompiledContainer) string { return o.Namespace + "/" + o.Name }

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

// SyncCompiledContainers is the CompiledContainer twin of SyncOnce: declarative
// set-reconcile of CompiledContainers bound to ClusterName, central->downstream.
func (b *Broker) SyncCompiledContainers(ctx context.Context) error {
	desired := &netv1.CompiledContainerList{}
	if err := b.Central.List(ctx, desired, client.MatchingFields{"spec.clusterName": b.ClusterName}); err != nil {
		return fmt.Errorf("list central containers: %w", err)
	}
	want := make(map[string]netv1.CompiledContainer, len(desired.Items))
	for _, o := range desired.Items {
		want[keyCtr(&o)] = o
	}
	have := &netv1.CompiledContainerList{}
	if err := b.Downstream.List(ctx, have); err != nil {
		return fmt.Errorf("list downstream containers: %w", err)
	}
	haveKeys := make(map[string]bool, len(have.Items))
	for i := range have.Items {
		cur := &have.Items[i]
		haveKeys[keyCtr(cur)] = true
		w, ok := want[keyCtr(cur)]
		if !ok {
			if err := b.Downstream.Delete(ctx, cur); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("gc container %s: %w", keyCtr(cur), err)
			}
			continue
		}
		if !equality.Semantic.DeepEqual(cur.Spec, w.Spec) || !maps.Equal(cur.Labels, w.Labels) {
			cur.Spec = w.Spec
			cur.Labels = maps.Clone(w.Labels)
			if err := b.Downstream.Update(ctx, cur); err != nil {
				return fmt.Errorf("update container %s: %w", keyCtr(cur), err)
			}
		}
	}
	for k, w := range want {
		if haveKeys[k] {
			continue
		}
		local := &netv1.CompiledContainer{}
		local.Namespace = w.Namespace
		local.Name = w.Name
		local.Spec = w.Spec
		local.Labels = maps.Clone(w.Labels)
		if err := b.Downstream.Create(ctx, local); err != nil {
			return fmt.Errorf("create container %s: %w", k, err)
		}
	}
	return nil
}

// ReportStatus stamps this pool's fence coordinates + per-VM placement + drain status
// into central. Called each sync tick alongside the lease heartbeat. nodes are the
// downstream nodes' fence identities (name + /64 underlay prefix); vmNode maps a VM's
// "namespace/name" key -> the running node's name.
//
// The status write is split into a pool update (NodePrefixes + NodeDrain) and a
// best-effort per-VM Placement update. A VM present in vmNode but absent from central
// (e.g. a raw KubeVirt VMI with no central VirtualMachine anchor) is skipped, not
// treated as an error — vmNode is a superset gathered from the live downstream.
func (b *Broker) ReportStatus(ctx context.Context, nodes []NodeFact, vmNode map[string]string) error {
	var pool platformv1.ClusterPool
	if err := b.Central.Get(ctx, client.ObjectKey{Name: b.ClusterName}, &pool); err != nil {
		return fmt.Errorf("get pool %s: %w", b.ClusterName, err)
	}
	orig := pool.DeepCopy()
	pool.Status.NodePrefixes = NodePrefixesFromNodes(nodes)

	// A fenced /64 is "busy" if any VM still runs on a node in it: map each node to
	// its prefix, then mark a prefix busy if any vmNode target lands on such a node.
	nodePrefix := make(map[string]string, len(nodes))
	for _, n := range nodes {
		nodePrefix[n.Name] = n.Prefix
	}
	busy := map[string]bool{}
	for _, nodeName := range vmNode {
		if p := nodePrefix[nodeName]; p != "" {
			busy[p] = true
		}
	}
	pool.Status.NodeDrain = DrainStatus(pool.Status.FencedPrefixes, busy)
	// Merge Patch (not Update): the Heartbeater concurrently writes Lease/Allocatable and the
	// pool-health controller writes Phase on this same status subresource. A full Update from a
	// cached Get 409-conflicts against them and clobbers their fields; MergeFrom patches only
	// NodePrefixes/NodeDrain (this pool's fence facts) with no resourceVersion precondition.
	if err := b.Central.Status().Patch(ctx, &pool, client.MergeFrom(orig)); err != nil {
		return fmt.Errorf("patch pool %s status: %w", b.ClusterName, err)
	}

	// Per-VM placement: stamp each central VirtualMachine we can resolve. Failures are
	// swallowed (the pool status — the fence-gating signal — already landed above).
	for vmKey, nodeName := range vmNode {
		ns, name := splitVMKey(vmKey)
		var vm netv1.VirtualMachine
		if err := b.Central.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &vm); err != nil {
			continue // VM may not be a central-tracked object; skip.
		}
		placement := PlacementForVM(b.ClusterName, nodeName, nodes)
		if placement == nil {
			continue // node unknown (no prefix resolved) — nothing to report yet.
		}
		vmOrig := vm.DeepCopy()
		vm.Status.Placement = placement
		_ = b.Central.Status().Patch(ctx, &vm, client.MergeFrom(vmOrig))
	}
	return nil
}

// splitVMKey splits a "namespace/name" vmNode key. A key with no slash is treated as
// a bare name in the "default" namespace.
func splitVMKey(k string) (namespace, name string) {
	if i := strings.IndexByte(k, '/'); i >= 0 {
		return k[:i], k[i+1:]
	}
	return "default", k
}
