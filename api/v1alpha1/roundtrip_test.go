// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"encoding/json"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func int32Ptr(i int32) *int32 { return &i }
func strPtr(s string) *string { return &s }

func TestVPCRoundTrip(t *testing.T) {
	orig := &VPC{
		TypeMeta: metav1.TypeMeta{
			APIVersion: SchemeGroupVersion.String(),
			Kind:       "VPC",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "prod",
			Labels: map[string]string{"env": "prod"},
		},
		Spec: VPCSpec{
			VNI:           int32Ptr(0),
			DefaultPolicy: strPtr("Allow"),
		},
		Status: VPCStatus{
			VNI:   100,
			State: "Ready",
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal VPC: %v", err)
	}

	got := &VPC{}
	if err := json.Unmarshal(data, got); err != nil {
		t.Fatalf("unmarshal VPC: %v", err)
	}

	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("VPC round-trip mismatch:\n orig=%#v\n got =%#v", orig, got)
	}

	// Field-level fidelity assertions.
	if got.Spec.VNI == nil || *got.Spec.VNI != 0 {
		t.Errorf("spec.vni: want 0, got %v", got.Spec.VNI)
	}
	if got.Spec.DefaultPolicy == nil || *got.Spec.DefaultPolicy != "Allow" {
		t.Errorf("spec.defaultPolicy: want Allow, got %v", got.Spec.DefaultPolicy)
	}
	if got.Status.VNI != 100 {
		t.Errorf("status.vni: want 100, got %d", got.Status.VNI)
	}

	// Verify the wire keys use the spec's camelCase names.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	spec := raw["spec"].(map[string]interface{})
	if _, ok := spec["vni"]; !ok {
		t.Errorf("expected wire key spec.vni, keys=%v", spec)
	}
	if _, ok := spec["defaultPolicy"]; !ok {
		t.Errorf("expected wire key spec.defaultPolicy, keys=%v", spec)
	}
}

func TestNetworkInterfaceRoundTrip(t *testing.T) {
	orig := &NetworkInterface{
		TypeMeta: metav1.TypeMeta{
			APIVersion: SchemeGroupVersion.String(),
			Kind:       "NetworkInterface",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "web-0-nic0",
			Labels: map[string]string{"app": "web", "role": "frontend"},
		},
		Spec: NetworkInterfaceSpec{
			VPCRef:   LocalObjectReference{Name: "prod"},
			IPs:      []string{"10.0.0.10", "2001:db8::10"},
			NodeName: strPtr("node-1"),
		},
		Status: NetworkInterfaceStatus{
			VNI:           100,
			UnderlayRoute: "2001:db8:fefe::a1b2",
			Port:          &PortStatus{Type: "tap", Name: "dtapvf_0"},
			State:         "Ready",
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal NetworkInterface: %v", err)
	}

	got := &NetworkInterface{}
	if err := json.Unmarshal(data, got); err != nil {
		t.Fatalf("unmarshal NetworkInterface: %v", err)
	}

	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("NetworkInterface round-trip mismatch:\n orig=%#v\n got =%#v", orig, got)
	}

	// Field-level fidelity assertions.
	if got.Spec.VPCRef.Name != "prod" {
		t.Errorf("spec.vpcRef.name: want prod, got %q", got.Spec.VPCRef.Name)
	}
	if !reflect.DeepEqual(got.Spec.IPs, []string{"10.0.0.10", "2001:db8::10"}) {
		t.Errorf("spec.ips mismatch: got %v", got.Spec.IPs)
	}
	if got.Status.UnderlayRoute != "2001:db8:fefe::a1b2" {
		t.Errorf("status.underlayRoute mismatch: got %q", got.Status.UnderlayRoute)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	spec := raw["spec"].(map[string]interface{})
	if _, ok := spec["vpcRef"]; !ok {
		t.Errorf("expected wire key spec.vpcRef, keys=%v", spec)
	}
	if _, ok := spec["ips"]; !ok {
		t.Errorf("expected wire key spec.ips, keys=%v", spec)
	}
	status := raw["status"].(map[string]interface{})
	if _, ok := status["underlayRoute"]; !ok {
		t.Errorf("expected wire key status.underlayRoute, keys=%v", status)
	}
}
