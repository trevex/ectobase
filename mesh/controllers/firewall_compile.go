// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// FirewallRuleBudget is the most rules a NIC's firewall may hold PER ADDRESS FAMILY after
// shadowing, ingress and egress together. It is a quota, not a datapath constant: the dataplane
// compiles each direction's rules into a classifier scope and refuses only a scope over its size
// limits (4096 peer classes, 16384 policy entries — flowplane-common FW_SCOPE_MAX_*), which a rule
// count cannot bound exactly, since port ranges and nested CIDRs expand. 256 keeps real policies
// far below those limits. The compiler enforces it: the dataplane refusing an oversized set is too
// late, since the agent can only log the refusal.
const FirewallRuleBudget = 256

// ConditionFirewallCompiled is the NetworkInterface condition reporting whether the policies
// selecting it compiled into the rule set its datapath enforces.
const ConditionFirewallCompiled = "FirewallCompiled"

// FirewallCompiled condition reasons. The failure reasons double as FirewallCompileError.Reason.
const (
	FirewallReasonCompiled           = "Compiled"
	FirewallReasonRuleBudgetExceeded = "RuleBudgetExceeded"
	FirewallReasonInvalidRule        = "InvalidRule"
)

// FirewallCompileError explains why an interface's firewall could not be compiled. The caller keeps
// the last good rule set applied and reports Reason and Message on the interface.
type FirewallCompileError struct {
	Reason  string
	Message string
}

func (e *FirewallCompileError) Error() string { return e.Reason + ": " + e.Message }

// fwRank is a rule's position in the firewall's total order. Lower sorts first and wins at every
// level: policy priority, then rule priority, then policy namespace and name, then list index. It
// is total over distinct rules, so the compiled order never depends on apiserver list order.
type fwRank struct {
	policy    int32
	rule      int32
	namespace string
	name      string
	index     int
}

func (a fwRank) compare(b fwRank) int {
	return cmp.Or(
		cmp.Compare(a.policy, b.policy),
		cmp.Compare(a.rule, b.rule),
		cmp.Compare(a.namespace, b.namespace),
		cmp.Compare(a.name, b.name),
		cmp.Compare(a.index, b.index),
	)
}

// implicitRank places the VPC's default-allow below every real rule.
func implicitRank(index int) fwRank {
	return fwRank{policy: netv1.FirewallPriorityMax + 1, index: index}
}

// fwEntry is one rule with its match parsed for coverage checks.
type fwEntry struct {
	rule   compiledv1.CompiledFwRule
	prefix netip.Prefix // masked
	// portLo..portHi is the destination-port range (0..65535 = any); meaningful for TCP/UDP only.
	portLo, portHi int32
	rank           fwRank
}

func newFwEntry(r netv1.FirewallPolicyRule, rank fwRank) (fwEntry, error) {
	p, err := netip.ParsePrefix(r.CIDR)
	if err != nil {
		return fwEntry{}, fmt.Errorf("cidr %q is not a CIDR", r.CIDR)
	}
	if r.Action != "Allow" && r.Action != "Deny" {
		return fwEntry{}, fmt.Errorf("action %q is not Allow or Deny", r.Action)
	}
	switch r.Proto {
	case "", "TCP", "UDP", "ICMP":
	default:
		return fwEntry{}, fmt.Errorf("proto %q is not TCP, UDP or ICMP", r.Proto)
	}
	e := fwEntry{
		rule:   compiledv1.CompiledFwRule{CIDR: r.CIDR, Proto: r.Proto, Port: r.Port, Action: r.Action},
		prefix: p.Masked(),
		portLo: 0, portHi: 65535,
		rank: rank,
	}
	if r.Port != 0 {
		e.portLo, e.portHi = r.Port, r.Port
		if r.EndPort != nil && *r.EndPort > r.Port {
			e.portHi = *r.EndPort
			e.rule.EndPort = *r.EndPort // a one-port range is just the port
		}
	}
	if r.ICMPType != nil {
		t := *r.ICMPType
		e.rule.ICMPType = &t
		if r.ICMPCode != nil {
			c := *r.ICMPCode
			e.rule.ICMPCode = &c
		}
	}
	return e, nil
}

func (e fwEntry) v6() bool { return e.prefix.Addr().Is6() }

// covers reports whether every packet e matches is also matched by a (a's match is a superset).
func (a fwEntry) covers(e fwEntry) bool {
	if a.v6() != e.v6() || a.prefix.Bits() > e.prefix.Bits() || !a.prefix.Contains(e.prefix.Addr()) {
		return false
	}
	switch {
	case a.rule.Proto == "":
		return true // any protocol, and admission forbids ports or ICMP types on it
	case a.rule.Proto != e.rule.Proto:
		return false
	case a.rule.Proto == "ICMP":
		return optCovers(a.rule.ICMPType, e.rule.ICMPType) && optCovers(a.rule.ICMPCode, e.rule.ICMPCode)
	default:
		return a.portLo <= e.portLo && e.portHi <= a.portHi
	}
}

// optCovers: an unset selector matches everything; a set one covers only the same value.
func optCovers(a, e *int32) bool {
	return a == nil || (e != nil && *a == *e)
}

// fwSet holds one direction's rules with precedence resolved at insert time (Cilium's mapstate
// discipline): a rule a higher-precedence rule already covers is refused, and an arriving rule
// evicts the lower-precedence rules it covers. The result is the same for any insertion order —
// exactly the rules that can ever be the first match — so no rule slot is spent on a dead rule.
type fwSet struct{ entries []fwEntry }

func (s *fwSet) insert(e fwEntry) {
	for _, x := range s.entries {
		if x.rank.compare(e.rank) < 0 && x.covers(e) {
			return
		}
	}
	s.entries = slices.DeleteFunc(s.entries, func(x fwEntry) bool {
		return e.rank.compare(x.rank) < 0 && e.covers(x)
	})
	s.entries = append(s.entries, e)
}

// rules returns the surviving rules in first-match-wins order.
func (s *fwSet) rules() []compiledv1.CompiledFwRule {
	sorted := slices.SortedFunc(slices.Values(s.entries), func(a, b fwEntry) int { return a.rank.compare(b.rank) })
	out := make([]compiledv1.CompiledFwRule, 0, len(sorted))
	for _, e := range sorted {
		out = append(out, e.rule)
	}
	return out
}

func (s *fwSet) count(v6 bool) int {
	n := 0
	for _, e := range s.entries {
		if e.v6() == v6 {
			n++
		}
	}
	return n
}

func priorityOr(p *int32) int32 {
	if p == nil {
		return netv1.FirewallPriorityDefault
	}
	return *p
}

// CompileFirewall lowers the FirewallPolicies selecting an interface (by its labels) into ordered,
// first-match-wins ingress and egress rule lists for the datapath.
//
// Precedence is resolved here, where it is unit-testable, not in the datapath: rules are ranked by
// (policy priority, rule priority, policy namespace, policy name, rule index), lower wins, and a rule
// that a higher-ranked rule fully covers is dropped. defaultPolicy is the VPC's
// spec.defaultPolicy: "Allow" appends an allow-all per family below every rule, "Deny" appends
// nothing, and nil keeps Kubernetes NetworkPolicy semantics per direction — a direction with no rules
// is open, a direction with rules admits only what they allow.
//
// It fails, rather than guessing, on a rule it cannot interpret (only possible for objects stored
// before admission validation) and when a family exceeds FirewallRuleBudget.
func CompileFirewall(nicLabels map[string]string, policies []netv1.FirewallPolicy, defaultPolicy *string) (compiledv1.CompiledFirewall, error) {
	var ingress, egress fwSet
	set := labels.Set(nicLabels)
	for i := range policies {
		pol := &policies[i]
		if pol.Spec.InterfaceSelector == nil {
			continue // selects nothing (admission now requires a selector)
		}
		sel, err := metav1.LabelSelectorAsSelector(pol.Spec.InterfaceSelector)
		if err != nil || !sel.Matches(set) {
			continue
		}
		for _, dir := range []struct {
			rules []netv1.FirewallPolicyRule
			set   *fwSet
			name  string
		}{{pol.Spec.Ingress, &ingress, "ingress"}, {pol.Spec.Egress, &egress, "egress"}} {
			for idx, r := range dir.rules {
				rank := fwRank{
					policy:    priorityOr(pol.Spec.Priority),
					rule:      priorityOr(r.Priority),
					namespace: pol.Namespace,
					name:      pol.Name,
					index:     idx,
				}
				e, err := newFwEntry(r, rank)
				if err != nil {
					return compiledv1.CompiledFirewall{}, &FirewallCompileError{
						Reason:  FirewallReasonInvalidRule,
						Message: fmt.Sprintf("FirewallPolicy %s/%s %s[%d]: %v", pol.Namespace, pol.Name, dir.name, idx, err),
					}
				}
				dir.set.insert(e)
			}
		}
	}

	for _, s := range []*fwSet{&ingress, &egress} {
		perDirection := defaultPolicy == nil && len(s.entries) == 0
		if perDirection || (defaultPolicy != nil && *defaultPolicy == string(netv1.VPCPolicyAllow)) {
			for i, cidr := range []string{"0.0.0.0/0", "::/0"} {
				e, _ := newFwEntry(netv1.FirewallPolicyRule{CIDR: cidr, Action: "Allow"}, implicitRank(i))
				s.insert(e)
			}
		}
	}

	for _, fam := range []struct {
		v6   bool
		name string
	}{{false, "IPv4"}, {true, "IPv6"}} {
		if n := ingress.count(fam.v6) + egress.count(fam.v6); n > FirewallRuleBudget {
			return compiledv1.CompiledFirewall{}, &FirewallCompileError{
				Reason: FirewallReasonRuleBudgetExceeded,
				Message: fmt.Sprintf("%d %s rules after removing shadowed ones (ingress and egress combined), over the per-interface budget of %d",
					n, fam.name, FirewallRuleBudget),
			}
		}
	}
	return compiledv1.CompiledFirewall{Ingress: ingress.rules(), Egress: egress.rules()}, nil
}
