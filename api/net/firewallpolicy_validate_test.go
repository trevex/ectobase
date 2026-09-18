// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func i32(v int32) *int32 { return &v }

func validPolicy() *FirewallPolicy {
	return &FirewallPolicy{Spec: FirewallPolicySpec{
		InterfaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		Ingress: []FirewallPolicyRule{
			{CIDR: "10.0.0.0/24", Proto: "TCP", Port: 443, Action: "Allow"},
			{CIDR: "2001:db8::/32", Proto: "ICMP", Action: "Allow"},
			{CIDR: "0.0.0.0/0", Action: "Deny", Priority: i32(65535)},
		},
		Egress:   []FirewallPolicyRule{{CIDR: "::/0", Proto: "UDP", Action: "Allow", Priority: i32(0)}},
		Priority: i32(100),
	}}
}

func TestFirewallPolicyValidate_AcceptsValid(t *testing.T) {
	if errs := validPolicy().Validate(context.Background()); len(errs) != 0 {
		t.Fatalf("valid policy rejected: %v", errs)
	}
	// An empty selector is legal: it selects every interface in the namespace.
	p := validPolicy()
	p.Spec.InterfaceSelector = &metav1.LabelSelector{}
	if errs := p.Validate(context.Background()); len(errs) != 0 {
		t.Fatalf("empty selector rejected: %v", errs)
	}
}

// Each case breaks exactly one field of an otherwise valid policy and names the path that must be
// reported, so a validator that rejects for the wrong reason does not pass.
func TestFirewallPolicyValidate_RejectsInvalid(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(p *FirewallPolicy)
		path   string
	}{
		{"missing selector", func(p *FirewallPolicy) { p.Spec.InterfaceSelector = nil }, "spec.interfaceSelector"},
		{"bad selector operator", func(p *FirewallPolicy) {
			p.Spec.InterfaceSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "a", Operator: "Near"}}}
		}, "spec.interfaceSelector.matchExpressions[0].operator"},
		{"policy priority too high", func(p *FirewallPolicy) { p.Spec.Priority = i32(65536) }, "spec.priority"},
		{"policy priority negative", func(p *FirewallPolicy) { p.Spec.Priority = i32(-1) }, "spec.priority"},
		{"rule priority too high", func(p *FirewallPolicy) { p.Spec.Ingress[0].Priority = i32(70000) }, "spec.ingress[0].priority"},
		{"unknown action", func(p *FirewallPolicy) { p.Spec.Ingress[0].Action = "Reject" }, "spec.ingress[0].action"},
		{"missing action", func(p *FirewallPolicy) { p.Spec.Egress[0].Action = "" }, "spec.egress[0].action"},
		{"lowercase action", func(p *FirewallPolicy) { p.Spec.Ingress[1].Action = "allow" }, "spec.ingress[1].action"},
		{"unknown proto", func(p *FirewallPolicy) { p.Spec.Ingress[0].Proto = "SCTP" }, "spec.ingress[0].proto"},
		{"lowercase proto", func(p *FirewallPolicy) { p.Spec.Ingress[0].Proto = "tcp" }, "spec.ingress[0].proto"},
		{"port too high", func(p *FirewallPolicy) { p.Spec.Ingress[0].Port = 65536 }, "spec.ingress[0].port"},
		{"port negative", func(p *FirewallPolicy) { p.Spec.Ingress[0].Port = -1 }, "spec.ingress[0].port"},
		// A port only means something for TCP/UDP; on any-proto or ICMP it would be silently ignored
		// by one dataplane and matched against garbage by another.
		{"port without proto", func(p *FirewallPolicy) { p.Spec.Ingress[2].Port = 22 }, "spec.ingress[2].port"},
		{"port on ICMP", func(p *FirewallPolicy) { p.Spec.Ingress[1].Port = 8 }, "spec.ingress[1].port"},
		{"missing cidr", func(p *FirewallPolicy) { p.Spec.Ingress[0].CIDR = "" }, "spec.ingress[0].cidr"},
		{"unparseable cidr", func(p *FirewallPolicy) { p.Spec.Ingress[0].CIDR = "10.0.0.0/33" }, "spec.ingress[0].cidr"},
		{"bare address", func(p *FirewallPolicy) { p.Spec.Egress[0].CIDR = "10.0.0.1" }, "spec.egress[0].cidr"},
		// 10.0.0.5/24 is ambiguous (the /24, or a typo for /32?); a firewall must not guess.
		{"host bits set", func(p *FirewallPolicy) { p.Spec.Ingress[0].CIDR = "10.0.0.5/24" }, "spec.ingress[0].cidr"},
		{"v6 host bits set", func(p *FirewallPolicy) { p.Spec.Ingress[1].CIDR = "2001:db8::1/32" }, "spec.ingress[1].cidr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validPolicy()
			tc.mutate(p)
			errs := p.Validate(context.Background())
			if len(errs) != 1 {
				t.Fatalf("want exactly 1 error at %s, got %d: %v", tc.path, len(errs), errs)
			}
			if errs[0].Field != tc.path {
				t.Fatalf("error at %q, want %q: %v", errs[0].Field, tc.path, errs)
			}
		})
	}
}

// Policies are edited in place, so an update must be validated as strictly as a create.
func TestFirewallPolicyValidateUpdate_Validates(t *testing.T) {
	old := validPolicy()
	p := validPolicy()
	p.Spec.Ingress[0].Action = "Reject"
	if errs := p.ValidateUpdate(context.Background(), old); len(errs) == 0 {
		t.Fatal("invalid update accepted")
	}
	if errs := validPolicy().ValidateUpdate(context.Background(), old); len(errs) != 0 {
		t.Fatalf("valid update rejected: %v", errs)
	}
}

// The kit's status subresource runs the same ValidateUpdate, so re-validating an unchanged spec
// would let an object stored before this validation existed block its own status writes forever.
// An update that leaves the spec untouched is not a spec change and must pass.
func TestFirewallPolicyValidateUpdate_UnchangedSpecPasses(t *testing.T) {
	legacy := validPolicy()
	legacy.Spec.Ingress[0].Action = "allow" // accepted before admission validation existed
	updated := legacy.DeepCopy()
	if errs := updated.ValidateUpdate(context.Background(), legacy); len(errs) != 0 {
		t.Fatalf("unchanged spec rejected: %v", errs)
	}
}
