// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func placementScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{compiledv1.AddToScheme, computev1.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// reportedTwin is a CompiledVM as the broker leaves it: in the pool namespace, stamped with its
// source, carrying the placement the pool observed.
func reportedTwin(poolNS, name, srcNS, srcName string, p *compiledv1.VMPlacement) *compiledv1.CompiledVM {
	cvm := &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: poolNS, Name: name}}
	stampSource(cvm, srcNS, srcName)
	cvm.Status.Placement = p
	return cvm
}

// TestVMPlacementMirrorsToSourceVM is the point of the whole placement path: the pool writes into
// its own namespace, and the mirror performs the cross-namespace hop onto the VirtualMachine that
// a pool's broker is deliberately not allowed to make.
func TestVMPlacementMirrorsToSourceVM(t *testing.T) {
	s := placementScheme(t)
	cvm := reportedTwin("pool-k02", "default-vm1", "default", "vm1",
		&compiledv1.VMPlacement{ClusterName: "k02", NodeName: "k02-1", NodePrefix: "fd00:cafe:1::/64"})
	vm := &computev1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vm1"}}

	cl := fake.NewClientBuilder().WithScheme(s).
		WithObjects(cvm, vm).WithStatusSubresource(cvm, vm).Build()
	r := &VMPlacementMirrorReconciler{Client: cl}

	if _, err := r.Reconcile(context.Background(),
		ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "pool-k02", Name: "default-vm1"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got computev1.VirtualMachine
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "vm1"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Placement == nil {
		t.Fatal("placement not mirrored onto the source VirtualMachine")
	}
	if got.Status.Placement.ClusterName != "k02" ||
		got.Status.Placement.NodeName != "k02-1" ||
		got.Status.Placement.NodePrefix != "fd00:cafe:1::/64" {
		t.Fatalf("mirrored placement = %+v", got.Status.Placement)
	}
}

// An unstamped twin cannot be resolved to a source, and guessing would stamp placement onto
// whatever VM happens to share the name — worse than reporting nothing.
func TestVMPlacementMirrorSkipsUnstampedTwin(t *testing.T) {
	s := placementScheme(t)
	cvm := &compiledv1.CompiledVM{ObjectMeta: metav1.ObjectMeta{Namespace: "pool-k02", Name: "default-vm1"}}
	cvm.Status.Placement = &compiledv1.VMPlacement{ClusterName: "k02", NodeName: "k02-1"}
	vm := &computev1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vm1"}}

	cl := fake.NewClientBuilder().WithScheme(s).
		WithObjects(cvm, vm).WithStatusSubresource(cvm, vm).Build()
	r := &VMPlacementMirrorReconciler{Client: cl}
	if _, err := r.Reconcile(context.Background(),
		ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "pool-k02", Name: "default-vm1"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got computev1.VirtualMachine
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "vm1"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Placement != nil {
		t.Fatalf("placement written from an unresolvable twin: %+v", got.Status.Placement)
	}
}

// Nothing reported yet must not wipe a placement already on the VM.
func TestVMPlacementMirrorIgnoresEmptyReport(t *testing.T) {
	s := placementScheme(t)
	cvm := reportedTwin("pool-k02", "default-vm1", "default", "vm1", nil)
	vm := &computev1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vm1"}}
	vm.Status.Placement = &computev1.VMPlacement{ClusterName: "k02", NodeName: "k02-1"}

	cl := fake.NewClientBuilder().WithScheme(s).
		WithObjects(cvm, vm).WithStatusSubresource(cvm, vm).Build()
	r := &VMPlacementMirrorReconciler{Client: cl}
	if _, err := r.Reconcile(context.Background(),
		ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "pool-k02", Name: "default-vm1"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got computev1.VirtualMachine
	if err := cl.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "vm1"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Placement == nil {
		t.Fatal("an empty report cleared an existing placement")
	}
}
