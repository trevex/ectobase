// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func sp(s string) *string { return &s }

func newSubnet(name, vpc, v4 string) *netv1.Subnet {
	return &netv1.Subnet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       netv1.SubnetSpec{VPCRef: netv1.LocalObjectReference{Name: vpc}, V4Prefix: sp(v4)},
	}
}

func TestSubnetReadyAndOverlap(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	a := newSubnet("a", "blue", "10.0.1.0/24")
	b := newSubnet("b", "blue", "10.0.1.0/25")
	c := newSubnet("c", "blue", "10.0.2.0/24")

	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(a, b, c).
		WithStatusSubresource(&netv1.Subnet{}).Build()
	r := &SubnetReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()

	if err := r.Sync(ctx, a); err != nil {
		t.Fatalf("sync a: %v", err)
	}
	if err := r.Sync(ctx, c); err != nil {
		t.Fatalf("sync c: %v", err)
	}
	if err := r.Sync(ctx, b); err != nil {
		t.Fatalf("sync b: %v", err)
	}

	get := func(n string) netv1.Subnet {
		var s netv1.Subnet
		if err := cl.Get(ctx, keyOf(&netv1.Subnet{ObjectMeta: metav1.ObjectMeta{Name: n, Namespace: "default"}}), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if get("a").Status.State != "Ready" {
		t.Fatalf("a state = %q want Ready", get("a").Status.State)
	}
	if get("c").Status.State != "Ready" {
		t.Fatalf("c state = %q want Ready", get("c").Status.State)
	}
	if get("b").Status.State != "Conflict" {
		t.Fatalf("b state = %q want Conflict (overlaps a)", get("b").Status.State)
	}
}
