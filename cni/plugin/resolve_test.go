// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	v1alpha1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestResolveCompiledNIC(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}

	// The compiler names the CompiledNIC "<ns>-<nic>": for NetworkInterface default/vm0
	// the CNI GETs default/default-vm0.
	cn := &v1alpha1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-vm0", Namespace: "default"},
		Spec: v1alpha1.CompiledNICSpec{
			VNI:        100,
			OverlayIPs: []string{"10.0.0.1"},
			MAC:        "52:54:00:00:00:aa",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cn).
		Build()

	res, err := resolveCompiledNIC(context.Background(), c, "default", "vm0")
	if err != nil {
		t.Fatalf("resolveCompiledNIC returned error: %v", err)
	}
	if res.VNI != 100 {
		t.Errorf("vni = %d, want 100", res.VNI)
	}
	if len(res.IPs) != 1 || res.IPs[0] != "10.0.0.1" {
		t.Errorf("ips = %v, want [10.0.0.1]", res.IPs)
	}
	if res.MAC != "52:54:00:00:00:aa" {
		t.Errorf("mac = %q, want 52:54:00:00:00:aa", res.MAC)
	}
}

// A CompiledNIC that exists but has no VNI (spec.vni==0) must fail clearly so the
// kubelet retries CNI ADD once the broker finishes syncing.
func TestResolveCompiledNICNotSynced(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}

	cn := &v1alpha1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-vm0", Namespace: "default"},
		Spec:       v1alpha1.CompiledNICSpec{VNI: 0},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cn).Build()

	if _, err := resolveCompiledNIC(context.Background(), c, "default", "vm0"); err == nil {
		t.Fatal("expected an error for a CompiledNIC with VNI 0, got nil")
	}
}
