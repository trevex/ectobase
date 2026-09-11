// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
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
