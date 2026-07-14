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

func TestNATGatewayRoundTrip(t *testing.T) {
	orig := &NATGateway{
		TypeMeta: metav1.TypeMeta{
			APIVersion: SchemeGroupVersion.String(),
			Kind:       "NATGateway",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "prod-egress",
			Labels: map[string]string{"env": "prod"},
		},
		Spec: NATGatewaySpec{
			VPCRef:         LocalObjectReference{Name: "prod"},
			PublicIPs:      []string{"203.0.113.10"},
			PortsPerSource: int32Ptr(1024),
			EdgeUnderlay:   "fd00::e",
		},
		Status: NATGatewayStatus{
			Allocations: []NATAllocation{
				{Source: "10.0.0.5", PublicIP: "203.0.113.10", PortMin: 1024, PortMax: 2047},
			},
			State: "Ready",
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal NATGateway: %v", err)
	}

	got := &NATGateway{}
	if err := json.Unmarshal(data, got); err != nil {
		t.Fatalf("unmarshal NATGateway: %v", err)
	}

	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("NATGateway round-trip mismatch:\n orig=%#v\n got =%#v", orig, got)
	}

	// Field-level fidelity assertions.
	if got.Spec.VPCRef.Name != "prod" {
		t.Errorf("spec.vpcRef.name: want prod, got %q", got.Spec.VPCRef.Name)
	}
	if !reflect.DeepEqual(got.Spec.PublicIPs, []string{"203.0.113.10"}) {
		t.Errorf("spec.publicIPs mismatch: got %v", got.Spec.PublicIPs)
	}
	if got.Spec.PortsPerSource == nil || *got.Spec.PortsPerSource != 1024 {
		t.Errorf("spec.portsPerSource: want 1024, got %v", got.Spec.PortsPerSource)
	}
	if got.Spec.EdgeUnderlay != "fd00::e" {
		t.Errorf("spec.edgeUnderlay: want fd00::e, got %q", got.Spec.EdgeUnderlay)
	}
	if got.Status.State != "Ready" {
		t.Errorf("status.state: want Ready, got %q", got.Status.State)
	}
	if len(got.Status.Allocations) != 1 || got.Status.Allocations[0].PortMax != 2047 {
		t.Errorf("status.allocations mismatch: got %v", got.Status.Allocations)
	}

	// Verify the wire keys use the spec's camelCase names.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	spec := raw["spec"].(map[string]interface{})
	if _, ok := spec["vpcRef"]; !ok {
		t.Errorf("expected wire key spec.vpcRef, keys=%v", spec)
	}
	if _, ok := spec["publicIPs"]; !ok {
		t.Errorf("expected wire key spec.publicIPs, keys=%v", spec)
	}
	if _, ok := spec["portsPerSource"]; !ok {
		t.Errorf("expected wire key spec.portsPerSource, keys=%v", spec)
	}
	if _, ok := spec["edgeUnderlay"]; !ok {
		t.Errorf("expected wire key spec.edgeUnderlay, keys=%v", spec)
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
