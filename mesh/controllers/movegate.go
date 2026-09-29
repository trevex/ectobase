// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"sigs.k8s.io/controller-runtime/pkg/client"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
)

// A move is a spec.clusterName change, whoever makes it — an operator, the scheduler, failover —
// and it is break-before-make. Nothing is compiled into a VM's pool while any other CompiledVM twin
// of that VM still exists: the pool that twin names may still be running the VM, and two pools
// running one VM means two writers on one ReadWriteOnce image (ReadWriteOnce is enforced per cluster,
// and Ceph does not refuse a second mapper).
//
// A twin that has to go is RETIRED rather than simply deleted: finalizerSourceReleased keeps it on
// the dispatch until its pool proves it let go — the pool's broker sets status.released once no VM,
// VMI, virt-launcher or disk claim is left, or failover sets it once a lost pool is fenced — and
// CompiledVMReleaseReconciler then drops the finalizer. Its disappearance is what opens the gate.

// awaitingRelease returns the twins that keep poolNS closed: every twin outside it, and a twin inside
// it that is itself terminating (a move reversed before the pool it returns to had let go). Sorted
// by cluster, then namespace, so what is reported about them does not churn between reconciles. Pure.
func awaitingRelease(poolNS string, twins []client.Object) []*compiledv1.CompiledVM {
	var out []*compiledv1.CompiledVM
	for _, o := range twins {
		cvm, ok := o.(*compiledv1.CompiledVM)
		if !ok {
			continue
		}
		if cvm.Namespace != poolNS || !cvm.DeletionTimestamp.IsZero() {
			out = append(out, cvm)
		}
	}
	slices.SortFunc(out, func(a, b *compiledv1.CompiledVM) int {
		return cmp.Or(cmp.Compare(a.Spec.ClusterName, b.Spec.ClusterName), cmp.Compare(a.Namespace, b.Namespace))
	})
	return out
}

// gateTwins returns every CompiledVM twin of the source srcNamespace/srcName, read UNCACHED through
// r. The gate must not trust the informer cache: a twin created moments before a clusterName change
// can still be missing from it, and a gate that cannot see the source's twin opens while that pool
// runs the VM. (A cache lagging the other way — a released twin still listed — only holds the gate
// shut a little longer.) The workload label, which CompileVM stamps with the VM name, narrows the
// cluster-wide list server-side — a label selector works on both the aggregated apiserver and CRDs,
// a field selector does not — and the stamped source then drops a same-named VM of another
// namespace.
func gateTwins(ctx context.Context, r client.Reader, srcNamespace, srcName string) ([]client.Object, error) {
	if r == nil {
		return nil, errors.New("move gate needs an uncached reader")
	}
	var list compiledv1.CompiledVMList
	if err := r.List(ctx, &list, client.MatchingLabels{"workload": srcName}); err != nil {
		return nil, fmt.Errorf("list compiledvms uncached: %w", err)
	}
	var out []client.Object
	for i := range list.Items {
		ns, name, stamped := sourceOf(&list.Items[i])
		if stamped && ns == srcNamespace && name == srcName {
			out = append(out, &list.Items[i])
		}
	}
	return out, nil
}

// retireTwin starts the handover of a twin. A twin compiled before the finalizer existed gets it
// FIRST, so an upgrade cannot wave a move through unproven. A no-op on a twin already terminating.
func retireTwin(ctx context.Context, c client.Client, twin *compiledv1.CompiledVM) error {
	if !twin.DeletionTimestamp.IsZero() {
		return nil
	}
	if err := ensureFinalizer(ctx, c, twin, finalizerSourceReleased); err != nil {
		return err
	}
	return deleteIfExists(ctx, c, twin)
}
