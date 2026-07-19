// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	v1alpha1 "github.com/trevex/ectobase/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestResolve(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}

	nic := &v1alpha1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "vm0", Namespace: "default"},
		Spec: v1alpha1.NetworkInterfaceSpec{
			VPCRef: v1alpha1.LocalObjectReference{Name: "prod"},
			IPs:    []string{"10.0.0.1"},
			MAC:    "52:54:00:00:00:aa",
		},
	}
	vpc := &v1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: "prod"},
		Status:     v1alpha1.VPCStatus{VNI: 100},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(nic, vpc).
		Build()

	res, err := resolve(context.Background(), c, "default", "vm0")
	if err != nil {
		t.Fatalf("resolve returned error: %v", err)
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
