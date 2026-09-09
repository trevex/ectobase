// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	computev1 "github.com/trevex/ectobase/api/compute/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func readyVPC(name string, vni int32) *netv1.VPC {
	v := &netv1.VPC{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}}
	v.Status.VNI = vni
	v.Status.State = "Ready"
	return v
}

func TestCompileGatedUntilAllocated(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = netv1.AddToScheme(scheme)
	_ = compiledv1.AddToScheme(scheme)
	_ = computev1.AddToScheme(scheme)

	vpc := readyVPC("blue", 1000)
	n := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "nic", Namespace: "default", Generation: 1},
		Spec:       netv1.NetworkInterfaceSpec{VPCRef: netv1.LocalObjectReference{Name: "blue"}},
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, n).
		WithStatusSubresource(&netv1.NetworkInterface{}, &netv1.VPC{}).Build()
	r := &CompiledNICReconciler{Client: cl, DefaultClusterName: "pool-a"}
	ctx := context.Background()
	key := client.ObjectKey{Namespace: "default", Name: "nic"}
	// Compile names the CompiledNIC "<namespace>-<name>"; the reconcile request keys on the NIC.
	compiledKey := client.ObjectKey{Namespace: "default", Name: "default-nic"}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile (ungated): %v", err)
	}
	var c compiledv1.CompiledNIC
	if err := cl.Get(ctx, compiledKey, &c); !apierrors.IsNotFound(err) {
		t.Fatalf("expected NO CompiledNIC before allocation, got err=%v", err)
	}

	n.Status.State = "Allocated"
	n.Status.ObservedGeneration = 1
	n.Status.AllocatedIPs = []string{"10.0.1.5"}
	if err := cl.Status().Update(ctx, n); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile (allocated): %v", err)
	}
	if err := cl.Get(ctx, compiledKey, &c); err != nil {
		t.Fatalf("expected CompiledNIC after allocation: %v", err)
	}
	if len(c.Spec.OverlayIPs) != 1 || c.Spec.OverlayIPs[0] != "10.0.1.5" {
		t.Fatalf("OverlayIPs = %v want [10.0.1.5]", c.Spec.OverlayIPs)
	}
}
