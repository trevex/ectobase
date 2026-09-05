// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestResolveCompiledNIC(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := compiledv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}

	// The compiler names the CompiledNIC "<ns>-<nic>": for NetworkInterface default/vm0
	// the CNI GETs default/default-vm0.
	cn := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-vm0", Namespace: "default"},
		Spec: compiledv1.CompiledNICSpec{
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
	if err := compiledv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}

	cn := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-vm0", Namespace: "default"},
		Spec:       compiledv1.CompiledNICSpec{VNI: 0},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cn).Build()

	if _, err := resolveCompiledNIC(context.Background(), c, "default", "vm0"); err == nil {
		t.Fatal("expected an error for a CompiledNIC with VNI 0, got nil")
	}
}

// A KubeVirt virt-launcher pod has no net.ectobase.dev/network-interface annotation, so the CNI
// resolves the CompiledNIC by the interface MAC (CompiledNIC-only — no CompiledVM). Match is
// case-insensitive; a no-match and a VNI-0 match both error clearly.
func TestResolveCompiledNICByMAC(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := compiledv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	nicA := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-vm-a", Namespace: "default"},
		Spec:       compiledv1.CompiledNICSpec{VNI: 202, OverlayIPs: []string{"10.0.5.10"}, MAC: "52:54:00:00:05:0a"},
	}
	nicB := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-vm-b", Namespace: "default"},
		Spec:       compiledv1.CompiledNICSpec{VNI: 202, OverlayIPs: []string{"10.0.5.11"}, MAC: "52:54:00:00:05:0b"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(nicA, nicB).Build()

	// Case-insensitive match picks the right NIC.
	res, err := resolveCompiledNICByMAC(context.Background(), c, "default", "52:54:00:00:05:0A")
	if err != nil {
		t.Fatalf("resolveCompiledNICByMAC: %v", err)
	}
	if res.VNI != 202 || len(res.IPs) != 1 || res.IPs[0] != "10.0.5.10" || res.MAC != "52:54:00:00:05:0a" {
		t.Errorf("resolved = %+v, want vni 202 / [10.0.5.10] / ...05:0a", res)
	}

	// No CompiledNIC carries this MAC -> clear error.
	if _, err := resolveCompiledNICByMAC(context.Background(), c, "default", "52:54:00:00:05:ff"); err == nil {
		t.Fatal("expected an error for an unmatched MAC, got nil")
	}

	// A match with VNI 0 (not synced) -> error.
	nic0 := &compiledv1.CompiledNIC{
		ObjectMeta: metav1.ObjectMeta{Name: "default-vm-c", Namespace: "default"},
		Spec:       compiledv1.CompiledNICSpec{VNI: 0, MAC: "52:54:00:00:05:0c"},
	}
	c0 := fake.NewClientBuilder().WithScheme(scheme).WithObjects(nic0).Build()
	if _, err := resolveCompiledNICByMAC(context.Background(), c0, "default", "52:54:00:00:05:0c"); err == nil {
		t.Fatal("expected an error for a VNI-0 MAC match, got nil")
	}
}

func TestMacFromNetworksAnnotation(t *testing.T) {
	// A real KubeVirt launcher annotation: our NAD's selection element carries the interface MAC.
	const launcher = `[{"name":"flowplane","mac":"52:54:00:00:05:0a","cni-args":{"logicNetworkName":"net0"}}]`
	mac, err := macFromNetworksAnnotation(launcher, "flowplane")
	if err != nil {
		t.Fatalf("macFromNetworksAnnotation: %v", err)
	}
	if mac != "52:54:00:00:05:0a" {
		t.Errorf("mac = %q, want 52:54:00:00:05:0a", mac)
	}

	// Single MAC-bearing element is used even when the NAD name does not match (single-NIC fallback).
	mac, err = macFromNetworksAnnotation(`[{"name":"other","mac":"52:54:00:00:05:0b"}]`, "flowplane")
	if err != nil || mac != "52:54:00:00:05:0b" {
		t.Fatalf("single-element fallback: mac=%q err=%v", mac, err)
	}

	// No MAC anywhere -> error.
	if _, err := macFromNetworksAnnotation(`[{"name":"flowplane"}]`, "flowplane"); err == nil {
		t.Fatal("expected an error when no selection element carries a MAC")
	}
	// Empty annotation -> error.
	if _, err := macFromNetworksAnnotation("", "flowplane"); err == nil {
		t.Fatal("expected an error for an empty annotation")
	}
	// Multiple MAC-bearing elements, none matching the NAD -> ambiguous (multi-NIC unsupported).
	if _, err := macFromNetworksAnnotation(`[{"name":"a","mac":"aa:bb:cc:dd:ee:01"},{"name":"b","mac":"aa:bb:cc:dd:ee:02"}]`, "flowplane"); err == nil {
		t.Fatal("expected an error for multiple unmatched MAC-bearing elements")
	}
}
