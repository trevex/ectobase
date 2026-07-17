// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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

	c := Compile(nic, []netv1.NetworkPolicy{pol}, nil)

	if c.Spec.VNI != 100 {
		t.Fatalf("VNI = %d, want 100", c.Spec.VNI)
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

	c := Compile(nic, []netv1.NetworkPolicy{pol}, nil)

	// No policy selects this NIC, so it is unpolicied → gets the k8s default-allow-all rule.
	if len(c.Spec.Firewall.Ingress) != 1 || c.Spec.Firewall.Ingress[0].CIDR != "0.0.0.0/0" || c.Spec.Firewall.Ingress[0].Action != "Allow" {
		t.Fatalf("expected one allow-all ingress rule for non-matching selector, got %+v", c.Spec.Firewall.Ingress)
	}
	if len(c.Spec.Firewall.Egress) != 1 || c.Spec.Firewall.Egress[0].Action != "Allow" {
		t.Fatalf("expected one allow-all egress rule for non-matching selector, got %+v", c.Spec.Firewall.Egress)
	}
}

func TestCompile_UnpoliciedGetsAllowAll(t *testing.T) {
	nic := testNIC()            // has labels that testPolicy() selects
	c := Compile(nic, nil, nil) // no policies
	if len(c.Spec.Firewall.Ingress) != 1 || c.Spec.Firewall.Ingress[0].Action != "Allow" ||
		c.Spec.Firewall.Ingress[0].CIDR != "0.0.0.0/0" || c.Spec.Firewall.Ingress[0].Port != 0 {
		t.Fatalf("expected one allow-all ingress rule, got %+v", c.Spec.Firewall.Ingress)
	}
	if len(c.Spec.Firewall.Egress) != 1 || c.Spec.Firewall.Egress[0].Action != "Allow" {
		t.Fatalf("expected one allow-all egress rule, got %+v", c.Spec.Firewall.Egress)
	}
	// A policied NIC keeps ONLY its policy rules — no allow-all appended.
	c2 := Compile(nic, []netv1.NetworkPolicy{testPolicy()}, nil)
	for _, r := range c2.Spec.Firewall.Ingress {
		if r.CIDR == "0.0.0.0/0" && r.Port == 0 && r.Proto == "" {
			t.Fatalf("policied NIC must not get allow-all: %+v", c2.Spec.Firewall.Ingress)
		}
	}
}

func TestCompile_WritesFixture(t *testing.T) {
	nic := testNIC()
	pol := testPolicy()

	c := Compile(nic, []netv1.NetworkPolicy{pol}, nil)

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}

	// The committed fixture (2 dirs up) is consumed by the Rust sim's apply() bridge test, so it
	// must stay in sync with the compiler output. Guard it golden-style: assert-equal by default,
	// regenerate only under UPDATE_FIXTURES=1.
	out := filepath.Join("..", "..", "flowplane", "flowplane-sim", "testdata", "compilednic.json")

	if os.Getenv("UPDATE_FIXTURES") != "" {
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(out, data, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		t.Logf("updated fixture %s (%d bytes)", out, len(data))
		return
	}

	want, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read committed fixture (re-run with UPDATE_FIXTURES=1 to regenerate): %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(data)) {
		t.Fatalf("committed fixture %s is stale vs the compiler output; re-run with UPDATE_FIXTURES=1.\n--- committed ---\n%s\n--- compiled ---\n%s", out, want, data)
	}
}

// nicWithLabels builds a minimal NetworkInterface with the given name and labels.
func nicWithLabels(name string, labels map[string]string) *netv1.NetworkInterface {
	return &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Labels: labels},
	}
}

func TestCompile_LBSelectorMatch(t *testing.T) {
	nic := nicWithLabels("web-0", map[string]string{"app": "web"})
	lb := netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "web-lb", Namespace: "default"},
		Spec: netv1.LoadBalancerSpec{
			VIP:            "203.0.113.50",
			Ports:          []netv1.LoadBalancerPort{{Port: 443, Proto: "TCP"}},
			TargetSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		},
	}
	c := Compile(nic, nil, []netv1.LoadBalancer{lb})
	if len(c.Spec.LB) != 1 {
		t.Fatalf("want 1 CompiledLB, got %d", len(c.Spec.LB))
	}
	if c.Spec.LB[0].VIP != "203.0.113.50" {
		t.Fatalf("VIP = %q, want 203.0.113.50", c.Spec.LB[0].VIP)
	}
	if len(c.Spec.LB[0].Ports) != 1 || c.Spec.LB[0].Ports[0].Port != 443 || c.Spec.LB[0].Ports[0].Proto != "TCP" {
		t.Fatalf("ports = %+v, want [{443 TCP}]", c.Spec.LB[0].Ports)
	}
}

func TestCompile_LBRefMatch(t *testing.T) {
	nic := nicWithLabels("db-0", nil)
	lb := netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "db-lb", Namespace: "default"},
		Spec: netv1.LoadBalancerSpec{
			VIP:        "2001:db8::1",
			Ports:      []netv1.LoadBalancerPort{{Port: 5432, Proto: "TCP"}},
			TargetRefs: []netv1.LocalObjectReference{{Name: "db-0"}},
		},
	}
	c := Compile(nic, nil, []netv1.LoadBalancer{lb})
	if len(c.Spec.LB) != 1 || c.Spec.LB[0].VIP != "2001:db8::1" {
		t.Fatalf("ref match failed: %+v", c.Spec.LB)
	}
}

func TestCompile_LBNoMatch(t *testing.T) {
	nic := nicWithLabels("other-0", map[string]string{"app": "other"})
	lb := netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "web-lb", Namespace: "default"},
		Spec: netv1.LoadBalancerSpec{
			VIP:            "203.0.113.50",
			TargetSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		},
	}
	c := Compile(nic, nil, []netv1.LoadBalancer{lb})
	if len(c.Spec.LB) != 0 {
		t.Fatalf("want 0 CompiledLB for non-matching NIC, got %d", len(c.Spec.LB))
	}
}

func lbScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := netv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestReconcile_NoWriteWhenUnchanged(t *testing.T) {
	s := lbScheme(t)
	node := "nodeA"
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default", Labels: map[string]string{"app": "web"}},
		Spec:       netv1.NetworkInterfaceSpec{NodeName: &node},
		Status:     netv1.NetworkInterfaceStatus{VNI: 100, UnderlayRoute: "2001:db8::dd"},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(nic).Build()
	r := &CompiledNICReconciler{Client: cl}
	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "web-0"}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var first netv1.CompiledNIC
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "default-web-0"}, &first); err != nil {
		t.Fatal(err)
	}
	rv1 := first.ResourceVersion

	// Second reconcile with identical inputs must NOT write (resourceVersion unchanged).
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var second netv1.CompiledNIC
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "default-web-0"}, &second); err != nil {
		t.Fatal(err)
	}
	if second.ResourceVersion != rv1 {
		t.Fatalf("resourceVersion changed on no-op reconcile: %s -> %s", rv1, second.ResourceVersion)
	}
}

func TestNicsForLB(t *testing.T) {
	s := lbScheme(t)
	nic := &netv1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default", Labels: map[string]string{"app": "web"}}}
	other := &netv1.NetworkInterface{ObjectMeta: metav1.ObjectMeta{Name: "db-0", Namespace: "default", Labels: map[string]string{"app": "db"}}}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(nic, other).Build()
	r := &CompiledNICReconciler{Client: cl}
	lb := &netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: "web-lb", Namespace: "default"},
		Spec:       netv1.LoadBalancerSpec{TargetSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}},
	}
	reqs := r.nicsForLB(context.Background(), client.Object(lb))
	if len(reqs) != 1 || reqs[0].Name != "web-0" {
		t.Fatalf("nicsForLB = %+v, want [web-0]", reqs)
	}
}
