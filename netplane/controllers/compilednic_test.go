// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	netv1 "github.com/trevex/xdp-dp/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// testNIC builds a NetworkInterface with the standard test fixture values.
func testNIC() *netv1.NetworkInterface {
	node := "node-1"
	nic := &netv1.NetworkInterface{}
	nic.Name = "nic-frontend"
	nic.Namespace = "default"
	nic.Labels = map[string]string{"role": "frontend"}
	nic.Spec.VPCRef = netv1.LocalObjectReference{Name: "blue"}
	nic.Spec.IPs = []string{"10.0.0.10"}
	nic.Spec.NodeName = &node
	nic.Status.VNI = 100
	nic.Status.UnderlayRoute = "2001:db8:fefe::bb"
	nic.Status.Port = &netv1.PortStatus{
		Type: netv1.PortTypeTap,
		Name: "dtapvf_0",
	}
	return nic
}

// testPolicy builds a NetworkPolicy that selects {role: frontend} and allows TCP:443 from 10.0.0.0/24.
func testPolicy() netv1.NetworkPolicy {
	pol := netv1.NetworkPolicy{}
	pol.Name = "allow-https"
	pol.Namespace = "default"
	pol.Spec.InterfaceSelector = &metav1.LabelSelector{
		MatchLabels: map[string]string{"role": "frontend"},
	}
	pol.Spec.Ingress = []netv1.NetworkPolicyRule{
		{
			CIDR:   "10.0.0.0/24",
			Proto:  "TCP",
			Port:   443,
			Action: "Allow",
		},
	}
	return pol
}

func TestCompile_ProducesCompiledNIC(t *testing.T) {
	nic := testNIC()
	pol := testPolicy()

	c := Compile(nic, []netv1.NetworkPolicy{pol})

	if c.Spec.VNI != 100 {
		t.Fatalf("VNI = %d, want 100", c.Spec.VNI)
	}
	if c.Spec.UnderlayRoute != "2001:db8:fefe::bb" {
		t.Fatalf("UnderlayRoute = %q, want 2001:db8:fefe::bb", c.Spec.UnderlayRoute)
	}
	if c.Spec.Port.Type != netv1.PortTypeTap {
		t.Fatalf("Port.Type = %q, want tap", c.Spec.Port.Type)
	}
	if c.Spec.Port.Name != "dtapvf_0" {
		t.Fatalf("Port.Name = %q, want dtapvf_0", c.Spec.Port.Name)
	}
	if len(c.Spec.Firewall.Ingress) != 1 {
		t.Fatalf("Ingress rules = %d, want 1", len(c.Spec.Firewall.Ingress))
	}
	r := c.Spec.Firewall.Ingress[0]
	if r.Port != 443 {
		t.Fatalf("rule Port = %d, want 443", r.Port)
	}
	if r.Proto != "TCP" {
		t.Fatalf("rule Proto = %q, want TCP", r.Proto)
	}
	if r.Action != "Allow" {
		t.Fatalf("rule Action = %q, want Allow", r.Action)
	}
	if r.CIDR != "10.0.0.0/24" {
		t.Fatalf("rule CIDR = %q, want 10.0.0.0/24", r.CIDR)
	}
}

func TestCompile_SelectorMismatch(t *testing.T) {
	nic := testNIC()
	nic.Labels = map[string]string{"role": "backend"}
	pol := testPolicy() // selects {role: frontend}

	c := Compile(nic, []netv1.NetworkPolicy{pol})

	if len(c.Spec.Firewall.Ingress) != 0 {
		t.Fatalf("expected no ingress rules for non-matching selector, got %d", len(c.Spec.Firewall.Ingress))
	}
}

func TestCompile_WritesFixture(t *testing.T) {
	nic := testNIC()
	pol := testPolicy()

	c := Compile(nic, []netv1.NetworkPolicy{pol})

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}

	// Write to xdp-dp-sim/testdata/compilednic.json (2 dirs up from netplane/controllers).
	out := filepath.Join("..", "..", "xdp-dp-sim", "testdata", "compilednic.json")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Logf("wrote fixture to %s (%d bytes)", out, len(data))
}
