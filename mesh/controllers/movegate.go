// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"

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
// it that is itself terminating (a move reversed before the pool it returns to had let go). Pure.
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
	return out
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
