// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
)

// launcherSelector matches every virt-launcher pod: KubeVirt labels them all with this fixed value.
// Which VMI a launcher runs is read from its owner reference, not from a per-VMI label, because a
// label VALUE is capped at 63 characters and a twin's name (<namespace>-<vm>) is not.
var launcherSelector = client.MatchingLabels{"kubevirt.io": "virt-launcher"}

// ReportReleases reports, onto each RETIRED CompiledVM twin in this pool's namespace, that the pool
// has let go of the VM it names. A move is break-before-make, and this is the "break": nothing is
// compiled into the VM's new pool until this pool says so (see mesh/controllers/movegate.go).
//
// pending is true while any retired twin is still held, so the caller can look again sooner than
// its periodic resync — each check is cheap, and a move waits on it. A twin that cannot be checked
// or patched stays pending and its error is returned, but only after every other twin has had its
// turn: one bad twin must not stall the release of the rest.
func (b *Broker) ReportReleases(ctx context.Context) (pending bool, err error) {
	var twins compiledv1.CompiledVMList
	if err := b.Dispatch.List(ctx, &twins, client.InNamespace(b.poolNamespace())); err != nil {
		return false, fmt.Errorf("list dispatch vms: %w", err)
	}
	var errs []error
	for i := range twins.Items {
		twin := &twins.Items[i]
		if twin.DeletionTimestamp.IsZero() || twin.Status.Released {
			continue
		}
		free, err := b.letGo(ctx, twin)
		if err != nil {
			pending = true
			errs = append(errs, fmt.Errorf("check release of %s: %w", twin.Name, err))
			continue
		}
		if !free {
			pending = true
			continue
		}
		// Optimistic-locked, because the read above is cached and a twin's name is not unique over
		// time: a reversed move recreates a LIVE twin under the same name in this namespace. Were the
		// cache still showing the old, retired one, a plain patch would land released=true on the new
		// twin — nothing ever resets it, so its own retirement would later pass with no proof. A
		// conflict means the twin changed under us; look again on the next pass.
		orig := twin.DeepCopy()
		twin.Status.Released = true
		switch err := b.Dispatch.Status().Patch(ctx, twin,
			client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{})); {
		case err == nil, apierrors.IsNotFound(err):
		case apierrors.IsConflict(err):
			pending = true
		default:
			pending = true
			errs = append(errs, fmt.Errorf("report release of %s: %w", twin.Name, err))
		}
	}
	return pending, errors.Join(errs...)
}

// letGo reports whether nothing on this pool can still run the VM a twin names or write its disks.
//
// Each check closes a different gap. The CompiledVM, KubeVirt VM and VMI would each recreate what
// comes after them. The virt-launcher pod is the actual writer: a pod leaves the API only after
// kubelet has torn its volumes down, so its absence means qemu is gone. And the claims: the disk
// teardown issues its deletes without waiting for them, so a claim still present is still in use.
func (b *Broker) letGo(ctx context.Context, twin *compiledv1.CompiledVM) (bool, error) {
	key := client.ObjectKey{Namespace: downstreamNamespace(twin), Name: twin.Name}
	for _, obj := range []client.Object{
		&compiledv1.CompiledVM{},
		kubevirtObject("VirtualMachine"),
		kubevirtObject("VirtualMachineInstance"),
	} {
		switch err := b.Downstream.Get(ctx, key, obj); {
		case err == nil:
			return false, nil
		case apierrors.IsNotFound(err), meta.IsNoMatchError(err): // gone, or no KubeVirt on this pool
		default:
			return false, err
		}
	}
	// The launcher runs the VMI, which the vm-materializer names after the twin.
	var pods corev1.PodList
	if err := b.Downstream.List(ctx, &pods, client.InNamespace(key.Namespace), launcherSelector); err != nil {
		return false, err
	}
	for i := range pods.Items {
		for _, ref := range pods.Items[i].OwnerReferences {
			if ref.Kind == "VirtualMachineInstance" && ref.Name == key.Name {
				return false, nil
			}
		}
	}
	// CDI copies the DataVolume's workload label onto the claim it provisions. The prime claim of
	// an import still in progress may not carry it, and so does not hold the release; that is safe,
	// because a disk's identity is captured only once its own claim is Bound, so a half-imported
	// image is never adopted by the target.
	if w := twin.Labels["workload"]; w != "" {
		var claims corev1.PersistentVolumeClaimList
		if err := b.Downstream.List(ctx, &claims, client.InNamespace(key.Namespace),
			client.MatchingLabels{"workload": w}); err != nil {
			return false, err
		}
		if len(claims.Items) > 0 {
			return false, nil
		}
	}
	return true, nil
}

func kubevirtObject(kind string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: "kubevirt.io", Version: "v1", Kind: kind})
	return u
}
