// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Compiled twins are torn down by a finalizer on their SOURCE object rather than by
// ownerReferences. Kubernetes forbids a namespaced owner from owning an object in a different
// namespace — controllerutil.SetControllerReference hard-errors on it — so once twins move into a
// per-pool namespace, owner-ref GC stops working entirely. Finalizing on the source is correct in
// both layouts. The trade is the usual one: a source sits in Terminating while its compiler is
// down. The orphan sweep covers the inverse case (a twin whose source vanished anyway, e.g. via a
// force-removed finalizer, or a twin left behind by an older layout).
//
// Each compiler owns its OWN finalizer: CompiledVMReconciler and
// CompiledVolumeAttachmentReconciler both source from VirtualMachine, so a single shared
// finalizer would let whichever reconciler ran first release it and let the VM disappear before
// the other had torn its twins down.
const (
	finalizerCompiledNIC              = "compiled.ectobase.dev/compilednic"
	finalizerCompiledVM               = "compiled.ectobase.dev/compiledvm"
	finalizerCompiledContainer        = "compiled.ectobase.dev/compiledcontainer"
	finalizerCompiledVolumeAttachment = "compiled.ectobase.dev/compiledvolumeattachment"
)

// Source back-reference stamped on every compiled twin. Annotations rather than labels: an object
// name may exceed the 63-character label-value limit, and nothing selects on these — the orphan
// sweep only reads them to resolve a twin back to its source.
const (
	annSourceNamespace = "compiled.ectobase.dev/source-namespace"
	annSourceName      = "compiled.ectobase.dev/source-name"
)

// compiledTwinName is the name of a 1:1 twin for a source object. It is namespace-qualified so
// twins compiled from different tenant namespaces cannot collide once they share one per-pool
// namespace.
func compiledTwinName(namespace, name string) string { return namespace + "-" + name }

// stampSource records the source object on a twin so the orphan sweep can resolve it.
func stampSource(obj client.Object, namespace, name string) {
	ann := obj.GetAnnotations()
	if ann == nil {
		ann = map[string]string{}
	}
	ann[annSourceNamespace] = namespace
	ann[annSourceName] = name
	obj.SetAnnotations(ann)
}

// sourceOf returns the source object a twin was compiled from, and whether it was stamped.
func sourceOf(obj client.Object) (namespace, name string, ok bool) {
	ann := obj.GetAnnotations()
	namespace, name = ann[annSourceNamespace], ann[annSourceName]
	return namespace, name, namespace != "" && name != ""
}

// ensureFinalizer adds fin to obj when absent. It must run BEFORE the twin is created: a delete
// racing an un-finalized source would otherwise complete and orphan the twin.
func ensureFinalizer(ctx context.Context, c client.Client, obj client.Object, fin string) error {
	if controllerutil.ContainsFinalizer(obj, fin) {
		return nil
	}
	controllerutil.AddFinalizer(obj, fin)
	return c.Update(ctx, obj)
}

// releaseFinalizer removes fin, letting Kubernetes complete the pending delete. A no-op when the
// finalizer was never added (a source that never compiled a twin).
func releaseFinalizer(ctx context.Context, c client.Client, obj client.Object, fin string) error {
	if !controllerutil.ContainsFinalizer(obj, fin) {
		return nil
	}
	controllerutil.RemoveFinalizer(obj, fin)
	return c.Update(ctx, obj)
}

// deleteIfExists deletes obj, treating an already-gone object as success — teardown is retried on
// conflict, so it has to be idempotent.
func deleteIfExists(ctx context.Context, c client.Client, obj client.Object) error {
	if err := c.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// twinsOfSource returns every twin in list stamped with the given source.
//
// It searches across ALL namespaces rather than computing where the twin ought to be, because a
// twin's namespace is derived from its source's PLACEMENT, and placement is frequently
// unresolvable exactly when we need it: a VM may be deleted before the NIC it owns, at which
// point recomputing would resolve to the wrong pool and silently leak the twin. The stamped
// back-reference is the only thing that stays true. This also means twins left in a previous
// layout are still found and cleaned up.
//
// The list is served from the manager's cache (the compilers watch these types), so a
// cluster-wide list here is an in-memory scan, not an API round trip.
func twinsOfSource(ctx context.Context, c client.Client, list client.ObjectList, srcNamespace, srcName string) ([]client.Object, error) {
	if err := c.List(ctx, list); err != nil {
		return nil, fmt.Errorf("list twins: %w", err)
	}
	items, err := meta.ExtractList(list)
	if err != nil {
		return nil, fmt.Errorf("extract twins: %w", err)
	}
	var out []client.Object
	for _, item := range items {
		twin, ok := item.(client.Object)
		if !ok {
			continue
		}
		ns, name, stamped := sourceOf(twin)
		if stamped && ns == srcNamespace && name == srcName {
			out = append(out, twin)
		}
	}
	return out, nil
}

// deleteTwinsOfSource removes every twin stamped with the given source (teardown).
func deleteTwinsOfSource(ctx context.Context, c client.Client, list client.ObjectList, srcNamespace, srcName string) error {
	twins, err := twinsOfSource(ctx, c, list, srcNamespace, srcName)
	if err != nil {
		return err
	}
	for _, twin := range twins {
		if err := deleteIfExists(ctx, c, twin); err != nil {
			return fmt.Errorf("delete twin %s/%s: %w", twin.GetNamespace(), twin.GetName(), err)
		}
	}
	return nil
}

// pruneTwinsOfSource deletes twins of this source that are not in keep. It covers two cases with
// one mechanism: twins for inputs that were removed (e.g. a dropped VolumeRef), and twins stranded
// in a namespace the compiler no longer writes to after a layout change.
func pruneTwinsOfSource(ctx context.Context, c client.Client, list client.ObjectList, srcNamespace, srcName string, keep map[types.NamespacedName]bool) error {
	twins, err := twinsOfSource(ctx, c, list, srcNamespace, srcName)
	if err != nil {
		return err
	}
	for _, twin := range twins {
		if keep[types.NamespacedName{Namespace: twin.GetNamespace(), Name: twin.GetName()}] {
			continue
		}
		if err := deleteIfExists(ctx, c, twin); err != nil {
			return fmt.Errorf("prune twin %s/%s: %w", twin.GetNamespace(), twin.GetName(), err)
		}
	}
	return nil
}

// requestForSource maps a compiled twin back to the source that produced it.
//
// This replaces .Owns(): EnqueueRequestForOwner derives the request from the DEPENDENT's
// namespace, so once a twin lives in a pool namespace it would enqueue a source key that does not
// exist. The stamped back-reference survives the move.
func requestForSource(_ context.Context, obj client.Object) []reconcile.Request {
	ns, name, ok := sourceOf(obj)
	if !ok {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}}
}
