// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var webLabels = map[string]string{"app": "web"}

func prio(p int32) *int32 { return &p }

func posture(p netv1.VPCPolicy) *string { s := string(p); return &s }

// fwPolicy builds a policy selecting app=web. Name doubles as the tiebreak key.
func fwPolicy(name string, priority *int32, ingress, egress []netv1.FirewallPolicyRule) netv1.FirewallPolicy {
	return netv1.FirewallPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: netv1.FirewallPolicySpec{
			InterfaceSelector: &metav1.LabelSelector{MatchLabels: webLabels},
			Priority:          priority,
			Ingress:           ingress,
			Egress:            egress,
		},
	}
}

func allow(cidr string) netv1.FirewallPolicyRule {
	return netv1.FirewallPolicyRule{CIDR: cidr, Action: "Allow"}
}
func deny(cidr string) netv1.FirewallPolicyRule {
	return netv1.FirewallPolicyRule{CIDR: cidr, Action: "Deny"}
}
func tcp(r netv1.FirewallPolicyRule, port int32) netv1.FirewallPolicyRule {
	r.Proto, r.Port = "TCP", port
	return r
}
func withPrio(r netv1.FirewallPolicyRule, p int32) netv1.FirewallPolicyRule {
	r.Priority = &p
	return r
}

// render flattens a compiled direction to "Action cidr proto/port" strings for readable asserts.
func render(rules []compiledv1.CompiledFwRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		s := r.Action + " " + r.CIDR
		if r.Proto != "" {
			s += fmt.Sprintf(" %s/%d", r.Proto, r.Port)
		}
		out = append(out, s)
	}
	return out
}

func mustCompileFirewall(t *testing.T, policies []netv1.FirewallPolicy, defaultPolicy *string) compiledv1.CompiledFirewall {
	t.Helper()
	fw, err := CompileFirewall(webLabels, policies, defaultPolicy)
	if err != nil {
		t.Fatalf("CompileFirewall: %v", err)
	}
	return fw
}

func assertRules(t *testing.T, dir string, got []compiledv1.CompiledFwRule, want ...string) {
	t.Helper()
	if g := renderFull(got); !reflect.DeepEqual(g, want) && (len(g) != 0 || len(want) != 0) {
		t.Fatalf("%s:\n got  %q\n want %q", dir, g, want)
	}
}

// Total order: (policy priority, rule priority, policy namespace, policy name, rule index) — lower
// wins at every level. Non-overlapping rules so nothing is shadowed: this is order alone.
func TestCompileFirewall_PriorityOrder(t *testing.T) {
	closed := posture(netv1.VPCPolicyDeny) // no synthesized rules in the way
	t.Run("policy priority beats name", func(t *testing.T) {
		fw := mustCompileFirewall(t, []netv1.FirewallPolicy{
			fwPolicy("a", nil, []netv1.FirewallPolicyRule{allow("192.168.0.0/16")}, nil),
			fwPolicy("b", prio(10), []netv1.FirewallPolicyRule{allow("10.0.0.0/8")}, nil),
		}, closed)
		assertRules(t, "ingress", fw.Ingress, "Allow 10.0.0.0/8", "Allow 192.168.0.0/16")
	})
	t.Run("rule priority beats list order", func(t *testing.T) {
		fw := mustCompileFirewall(t, []netv1.FirewallPolicy{
			fwPolicy("a", nil, []netv1.FirewallPolicyRule{allow("10.0.0.0/8"), withPrio(deny("10.9.0.0/16"), 1)}, nil),
		}, closed)
		assertRules(t, "ingress", fw.Ingress, "Deny 10.9.0.0/16", "Allow 10.0.0.0/8")
	})
	t.Run("rule priority beats policy name", func(t *testing.T) {
		fw := mustCompileFirewall(t, []netv1.FirewallPolicy{
			fwPolicy("a", nil, []netv1.FirewallPolicyRule{allow("192.168.0.0/16")}, nil),
			fwPolicy("z", nil, []netv1.FirewallPolicyRule{withPrio(allow("10.0.0.0/8"), 5)}, nil),
		}, closed)
		assertRules(t, "ingress", fw.Ingress, "Allow 10.0.0.0/8", "Allow 192.168.0.0/16")
	})
	t.Run("policy priority beats rule priority", func(t *testing.T) {
		fw := mustCompileFirewall(t, []netv1.FirewallPolicy{
			fwPolicy("p2", prio(2), []netv1.FirewallPolicyRule{withPrio(allow("192.168.0.0/16"), 0)}, nil),
			fwPolicy("p1", prio(1), []netv1.FirewallPolicyRule{withPrio(allow("10.0.0.0/8"), 60000)}, nil),
		}, closed)
		assertRules(t, "ingress", fw.Ingress, "Allow 10.0.0.0/8", "Allow 192.168.0.0/16")
	})
	t.Run("equal priorities keep name then list order", func(t *testing.T) {
		fw := mustCompileFirewall(t, []netv1.FirewallPolicy{
			fwPolicy("b", nil, []netv1.FirewallPolicyRule{allow("10.2.0.0/16"), allow("10.3.0.0/16")}, nil),
			fwPolicy("a", nil, []netv1.FirewallPolicyRule{allow("10.1.0.0/16")}, nil),
		}, closed)
		assertRules(t, "ingress", fw.Ingress, "Allow 10.1.0.0/16", "Allow 10.2.0.0/16", "Allow 10.3.0.0/16")
	})
}

// The apiserver's list order is not a contract. Whatever order the policies arrive in, the compiled
// firewall must be byte-identical — otherwise every relist churns the CompiledNIC (and, with
// overlapping rules, could flip which one wins).
func TestCompileFirewall_DeterministicUnderShuffledListOrder(t *testing.T) {
	policies := []netv1.FirewallPolicy{
		fwPolicy("base", nil, []netv1.FirewallPolicyRule{deny("0.0.0.0/0"), allow("::/0")}, []netv1.FirewallPolicyRule{allow("0.0.0.0/0")}),
		fwPolicy("web", prio(100), []netv1.FirewallPolicyRule{tcp(allow("10.0.0.0/8"), 443), tcp(allow("10.0.0.0/8"), 80)}, nil),
		fwPolicy("ops", prio(100), []netv1.FirewallPolicyRule{tcp(allow("10.9.0.0/16"), 22), withPrio(deny("10.9.9.0/24"), 1)}, nil),
		fwPolicy("block", prio(50), nil, []netv1.FirewallPolicyRule{deny("198.51.100.0/24"), deny("2001:db8:bad::/48")}),
		fwPolicy("dup", nil, []netv1.FirewallPolicyRule{deny("0.0.0.0/0")}, nil),
		fwPolicy("late", prio(65535), []netv1.FirewallPolicyRule{allow("172.16.0.0/12")}, nil),
	}
	want, err := json.Marshal(mustCompileFirewall(t, policies, posture(netv1.VPCPolicyAllow)))
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		shuffled := append([]netv1.FirewallPolicy(nil), policies...)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		got, err := json.Marshal(mustCompileFirewall(t, shuffled, posture(netv1.VPCPolicyAllow)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("permutation %d compiled differently:\n got  %s\n want %s", i, got, want)
		}
	}
}

// A rule that a higher-precedence rule fully covers can never match first, so it is dropped: it
// would only burn a rule slot. Partial overlap keeps both (first match still decides).
func TestCompileFirewall_Shadowing(t *testing.T) {
	closed := posture(netv1.VPCPolicyDeny)
	for _, tc := range []struct {
		name  string
		rules []netv1.FirewallPolicyRule
		want  []string
	}{
		{"wider cidr covers narrower", []netv1.FirewallPolicyRule{deny("0.0.0.0/0"), tcp(allow("10.0.0.0/8"), 443)},
			[]string{"Deny 0.0.0.0/0"}},
		{"narrower first is not covered", []netv1.FirewallPolicyRule{tcp(allow("10.0.0.0/8"), 443), deny("0.0.0.0/0")},
			[]string{"Allow 10.0.0.0/8 TCP/443", "Deny 0.0.0.0/0"}},
		{"any proto covers tcp", []netv1.FirewallPolicyRule{deny("10.0.0.0/8"), tcp(allow("10.0.0.0/8"), 0)},
			[]string{"Deny 10.0.0.0/8"}},
		{"tcp does not cover udp", []netv1.FirewallPolicyRule{tcp(deny("10.0.0.0/8"), 0), {CIDR: "10.0.0.0/8", Proto: "UDP", Action: "Allow"}},
			[]string{"Deny 10.0.0.0/8 TCP/0", "Allow 10.0.0.0/8 UDP/0"}},
		{"any port covers one port", []netv1.FirewallPolicyRule{tcp(deny("10.0.0.0/8"), 0), tcp(allow("10.1.0.0/16"), 443)},
			[]string{"Deny 10.0.0.0/8 TCP/0"}},
		{"distinct ports both kept", []netv1.FirewallPolicyRule{tcp(deny("10.0.0.0/8"), 22), tcp(allow("10.0.0.0/8"), 443)},
			[]string{"Deny 10.0.0.0/8 TCP/22", "Allow 10.0.0.0/8 TCP/443"}},
		{"v4 does not cover v6", []netv1.FirewallPolicyRule{deny("0.0.0.0/0"), allow("::/0")},
			[]string{"Deny 0.0.0.0/0", "Allow ::/0"}},
		{"duplicate collapses", []netv1.FirewallPolicyRule{allow("10.0.0.0/8"), allow("10.0.0.0/8")},
			[]string{"Allow 10.0.0.0/8"}},
		{"same match other action: first wins", []netv1.FirewallPolicyRule{allow("10.0.0.0/8"), deny("10.0.0.0/8")},
			[]string{"Allow 10.0.0.0/8"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := mustCompileFirewall(t, []netv1.FirewallPolicy{fwPolicy("p", nil, tc.rules, nil)}, closed)
			assertRules(t, "ingress", fw.Ingress, tc.want...)
		})
	}
	t.Run("directions are independent", func(t *testing.T) {
		fw := mustCompileFirewall(t, []netv1.FirewallPolicy{
			fwPolicy("p", nil, []netv1.FirewallPolicyRule{deny("0.0.0.0/0")}, []netv1.FirewallPolicyRule{allow("10.0.0.0/8")}),
		}, closed)
		assertRules(t, "egress", fw.Egress, "Allow 10.0.0.0/8")
	})
	t.Run("across policies", func(t *testing.T) {
		fw := mustCompileFirewall(t, []netv1.FirewallPolicy{
			fwPolicy("low", prio(900), []netv1.FirewallPolicyRule{tcp(allow("10.1.0.0/16"), 22)}, nil),
			fwPolicy("high", prio(1), []netv1.FirewallPolicyRule{deny("10.0.0.0/8")}, nil),
		}, closed)
		assertRules(t, "ingress", fw.Ingress, "Deny 10.0.0.0/8")
	})
}

// Insert-time resolution (Cilium's mapstate discipline) must not depend on insertion order: a rule
// is refused when a higher-precedence rule already covers it, and removes lower-precedence rules it
// covers when it arrives first. Inserting every permutation must yield the same set.
func TestFwSetInsertIsOrderIndependent(t *testing.T) {
	entries := []fwEntry{}
	for i, r := range []netv1.FirewallPolicyRule{
		tcp(allow("10.1.0.0/16"), 443),
		deny("10.1.2.0/24"),
		deny("10.0.0.0/8"),
		tcp(allow("10.1.2.0/24"), 22),
		allow("::/0"),
	} {
		e, err := newFwEntry(r, fwRank{rule: int32(i)})
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	var want []string
	permute(len(entries), func(order []int) {
		var s fwSet
		for _, i := range order {
			s.insert(entries[i])
		}
		got := render(s.rules())
		if want == nil {
			want = got
			return
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("insertion order %v gave %q, want %q", order, got, want)
		}
	})
	// And the answer is the first-match reading: 10.1.2.0/24:22 is covered by the earlier
	// deny 10.1.2.0/24; the /8 deny survives (not covered by anything above it).
	assertRules(t, "set", fwSetOf(entries).rules(),
		"Allow 10.1.0.0/16 TCP/443", "Deny 10.1.2.0/24", "Deny 10.0.0.0/8", "Allow ::/0")
}

func fwSetOf(entries []fwEntry) *fwSet {
	var s fwSet
	for _, e := range entries {
		s.insert(e)
	}
	return &s
}

// permute calls fn with every permutation of 0..n-1 (Heap's algorithm).
func permute(n int, fn func([]int)) {
	a := make([]int, n)
	for i := range a {
		a[i] = i
	}
	var gen func(k int)
	gen = func(k int) {
		if k == 1 {
			fn(append([]int(nil), a...))
			return
		}
		for i := 0; i < k; i++ {
			gen(k - 1)
			if k%2 == 0 {
				a[i], a[k-1] = a[k-1], a[i]
			} else {
				a[0], a[k-1] = a[k-1], a[0]
			}
		}
	}
	gen(n)
}

// VPC.spec.defaultPolicy decides what no rule matching means.
func TestCompileFirewall_DefaultPolicy(t *testing.T) {
	loneDeny := []netv1.FirewallPolicy{fwPolicy("p", nil, []netv1.FirewallPolicyRule{deny("10.0.0.0/8")}, nil)}

	t.Run("unset: per-direction NetworkPolicy semantics", func(t *testing.T) {
		fw := mustCompileFirewall(t, nil, nil)
		assertRules(t, "ingress", fw.Ingress, "Allow 0.0.0.0/0", "Allow ::/0")
		assertRules(t, "egress", fw.Egress, "Allow 0.0.0.0/0", "Allow ::/0")
		// A governed direction admits only what its rules allow: the lone deny denies EVERYTHING
		// (the trap Allow exists to avoid); the ungoverned direction stays open.
		fw = mustCompileFirewall(t, loneDeny, nil)
		assertRules(t, "ingress", fw.Ingress, "Deny 10.0.0.0/8")
		assertRules(t, "egress", fw.Egress, "Allow 0.0.0.0/0", "Allow ::/0")
	})
	t.Run("Allow: implicit lowest-priority allow-all", func(t *testing.T) {
		fw := mustCompileFirewall(t, loneDeny, posture(netv1.VPCPolicyAllow))
		assertRules(t, "ingress", fw.Ingress, "Deny 10.0.0.0/8", "Allow 0.0.0.0/0", "Allow ::/0")
		assertRules(t, "egress", fw.Egress, "Allow 0.0.0.0/0", "Allow ::/0")
		// The implicit allow is shadowed like any rule: an explicit v4 deny-all removes it.
		fw = mustCompileFirewall(t, []netv1.FirewallPolicy{fwPolicy("p", nil, []netv1.FirewallPolicyRule{deny("0.0.0.0/0")}, nil)}, posture(netv1.VPCPolicyAllow))
		assertRules(t, "ingress", fw.Ingress, "Deny 0.0.0.0/0", "Allow ::/0")
	})
	t.Run("Deny: nothing synthesized, every direction closed", func(t *testing.T) {
		fw := mustCompileFirewall(t, nil, posture(netv1.VPCPolicyDeny))
		assertRules(t, "ingress", fw.Ingress)
		assertRules(t, "egress", fw.Egress)
		fw = mustCompileFirewall(t, []netv1.FirewallPolicy{fwPolicy("p", nil, []netv1.FirewallPolicyRule{allow("10.0.0.0/8")}, nil)}, posture(netv1.VPCPolicyDeny))
		assertRules(t, "ingress", fw.Ingress, "Allow 10.0.0.0/8")
		assertRules(t, "egress", fw.Egress)
	})
}

func nRules(n int, v6 bool, action string) []netv1.FirewallPolicyRule {
	out := make([]netv1.FirewallPolicyRule, 0, n)
	for i := 0; i < n; i++ {
		cidr := fmt.Sprintf("10.%d.0.0/16", i)
		if v6 {
			cidr = fmt.Sprintf("2001:db8:%x::/48", i)
		}
		out = append(out, netv1.FirewallPolicyRule{CIDR: cidr, Action: action})
	}
	return out
}

func budgetError(t *testing.T, err error) *FirewallCompileError {
	t.Helper()
	var fe *FirewallCompileError
	if !errors.As(err, &fe) || fe.Reason != FirewallReasonRuleBudgetExceeded {
		t.Fatalf("want a %s FirewallCompileError, got %v", FirewallReasonRuleBudgetExceeded, err)
	}
	return fe
}

// The old datapath holds 16 rules per interface PER FAMILY, ingress and egress sharing the budget.
// The compiler enforces it (the dataplane refusing is too late: the agent can only log it).
func TestCompileFirewall_RuleBudget(t *testing.T) {
	closed := posture(netv1.VPCPolicyDeny)
	t.Run("exactly at the cap in both families", func(t *testing.T) {
		_, err := CompileFirewall(webLabels, []netv1.FirewallPolicy{
			fwPolicy("p", nil, append(nRules(8, false, "Allow"), nRules(16, true, "Allow")...), nRules(8, false, "Deny")),
		}, closed)
		if err != nil {
			t.Fatalf("16 v4 + 16 v6 must fit: %v", err)
		}
	})
	t.Run("one over, split across directions", func(t *testing.T) {
		_, err := CompileFirewall(webLabels, []netv1.FirewallPolicy{
			fwPolicy("p", nil, nRules(9, false, "Allow"), nRules(8, false, "Allow")),
		}, closed)
		if fe := budgetError(t, err); !strings.Contains(fe.Message, "IPv4") || !strings.Contains(fe.Message, "17") {
			t.Fatalf("message must name the family and count: %q", fe.Message)
		}
	})
	t.Run("shadowed rules cost nothing", func(t *testing.T) {
		rules := append([]netv1.FirewallPolicyRule{deny("10.0.0.0/8")}, nRules(20, false, "Allow")...) // all 20 inside 10/8
		fw, err := CompileFirewall(webLabels, []netv1.FirewallPolicy{fwPolicy("p", nil, rules, nil)}, closed)
		if err != nil {
			t.Fatalf("covered rules must not count against the budget: %v", err)
		}
		assertRules(t, "ingress", fw.Ingress, "Deny 10.0.0.0/8")
	})
	t.Run("implicit allow-all counts", func(t *testing.T) {
		// 15 v4 user rules + Allow's implicit v4 allow-all in BOTH directions = 17.
		_, err := CompileFirewall(webLabels, []netv1.FirewallPolicy{
			fwPolicy("p", nil, nRules(15, false, "Deny"), nil),
		}, posture(netv1.VPCPolicyAllow))
		budgetError(t, err)
	})
}

// Rules stored before admission validation existed can still be malformed. Guessing is unsafe in
// both directions (dropping a Deny opens traffic), so the whole firewall fails to compile and the
// caller keeps the last good one.
func TestCompileFirewall_InvalidLegacyRuleFailsCompile(t *testing.T) {
	for _, r := range []netv1.FirewallPolicyRule{
		{CIDR: "not-a-cidr", Action: "Deny"},
		{CIDR: "10.0.0.0/8", Action: "Reject"},
		{CIDR: "10.0.0.0/8", Proto: "SCTP", Action: "Allow"},
	} {
		_, err := CompileFirewall(webLabels, []netv1.FirewallPolicy{fwPolicy("legacy", nil, []netv1.FirewallPolicyRule{r}, nil)}, nil)
		var fe *FirewallCompileError
		if !errors.As(err, &fe) || fe.Reason != FirewallReasonInvalidRule || !strings.Contains(fe.Message, "legacy") {
			t.Fatalf("rule %+v: want an InvalidRule error naming the policy, got %v", r, err)
		}
	}
}

// Policies that cannot select anything (no selector, or one that fails to parse) are skipped; they
// never governed any interface.
func TestCompileFirewall_SkipsUnselectablePolicies(t *testing.T) {
	noSel := fwPolicy("nosel", nil, []netv1.FirewallPolicyRule{deny("0.0.0.0/0")}, nil)
	noSel.Spec.InterfaceSelector = nil
	badSel := fwPolicy("badsel", nil, []netv1.FirewallPolicyRule{deny("0.0.0.0/0")}, nil)
	badSel.Spec.InterfaceSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "a", Operator: "Near"}}}
	other := fwPolicy("other", nil, []netv1.FirewallPolicyRule{deny("0.0.0.0/0")}, nil)
	other.Spec.InterfaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}}
	fw := mustCompileFirewall(t, []netv1.FirewallPolicy{noSel, badSel, other}, nil)
	assertRules(t, "ingress", fw.Ingress, "Allow 0.0.0.0/0", "Allow ::/0")
}

func portRange(r netv1.FirewallPolicyRule, lo, hi int32) netv1.FirewallPolicyRule {
	r.Proto, r.Port, r.EndPort = "TCP", lo, &hi
	return r
}

func icmp(r netv1.FirewallPolicyRule, typ, code *int32) netv1.FirewallPolicyRule {
	r.Proto, r.ICMPType, r.ICMPCode = "ICMP", typ, code
	return r
}

// renderFull adds the range and ICMP fields to render's form.
func renderFull(rules []compiledv1.CompiledFwRule) []string {
	out := render(rules)
	for i, r := range rules {
		if r.EndPort != 0 {
			out[i] += fmt.Sprintf("-%d", r.EndPort)
		}
		if r.ICMPType != nil {
			out[i] += fmt.Sprintf(" type %d", *r.ICMPType)
		}
		if r.ICMPCode != nil {
			out[i] += fmt.Sprintf(" code %d", *r.ICMPCode)
		}
	}
	return out
}

// Port ranges and ICMP type/code reach the compiled rule; a one-port range is just a port.
func TestCompileFirewall_LowersRangesAndICMP(t *testing.T) {
	fw := mustCompileFirewall(t, []netv1.FirewallPolicy{fwPolicy("p", nil, []netv1.FirewallPolicyRule{
		portRange(allow("10.1.0.0/16"), 8000, 8100),
		portRange(allow("10.2.0.0/16"), 53, 53),
		icmp(allow("10.3.0.0/16"), prio(8), nil),
		icmp(allow("2001:db8::/32"), prio(1), prio(4)),
	}, nil)}, posture(netv1.VPCPolicyDeny))
	want := []string{
		"Allow 10.1.0.0/16 TCP/8000-8100",
		"Allow 10.2.0.0/16 TCP/53",
		"Allow 10.3.0.0/16 ICMP/0 type 8",
		"Allow 2001:db8::/32 ICMP/0 type 1 code 4",
	}
	if got := renderFull(fw.Ingress); !reflect.DeepEqual(got, want) {
		t.Fatalf("ingress:\n got  %q\n want %q", got, want)
	}
}

// Coverage understands ranges (containment, not equality) and ICMP type/code wildcards.
func TestCompileFirewall_ShadowingRangesAndICMP(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []netv1.FirewallPolicyRule
		want  []string
	}{
		{"range covers a port inside it", []netv1.FirewallPolicyRule{portRange(deny("10.0.0.0/8"), 1, 1024), tcp(allow("10.0.0.0/8"), 443)},
			[]string{"Deny 10.0.0.0/8 TCP/1-1024"}},
		{"range covers a sub-range", []netv1.FirewallPolicyRule{portRange(deny("10.0.0.0/8"), 1, 1024), portRange(allow("10.0.0.0/8"), 80, 90)},
			[]string{"Deny 10.0.0.0/8 TCP/1-1024"}},
		{"port does not cover a range around it", []netv1.FirewallPolicyRule{tcp(deny("10.0.0.0/8"), 443), portRange(allow("10.0.0.0/8"), 400, 500)},
			[]string{"Deny 10.0.0.0/8 TCP/443", "Allow 10.0.0.0/8 TCP/400-500"}},
		{"overlapping ranges both kept", []netv1.FirewallPolicyRule{portRange(deny("10.0.0.0/8"), 1, 100), portRange(allow("10.0.0.0/8"), 50, 150)},
			[]string{"Deny 10.0.0.0/8 TCP/1-100", "Allow 10.0.0.0/8 TCP/50-150"}},
		{"any-port covers a range", []netv1.FirewallPolicyRule{tcp(deny("10.0.0.0/8"), 0), portRange(allow("10.0.0.0/8"), 8000, 8100)},
			[]string{"Deny 10.0.0.0/8 TCP/0"}},
		{"any ICMP covers a type", []netv1.FirewallPolicyRule{icmp(deny("10.0.0.0/8"), nil, nil), icmp(allow("10.0.0.0/8"), prio(8), nil)},
			[]string{"Deny 10.0.0.0/8 ICMP/0"}},
		{"type covers its codes", []netv1.FirewallPolicyRule{icmp(deny("10.0.0.0/8"), prio(3), nil), icmp(allow("10.0.0.0/8"), prio(3), prio(4))},
			[]string{"Deny 10.0.0.0/8 ICMP/0 type 3"}},
		{"code does not cover its type", []netv1.FirewallPolicyRule{icmp(deny("10.0.0.0/8"), prio(3), prio(1)), icmp(allow("10.0.0.0/8"), prio(3), nil)},
			[]string{"Deny 10.0.0.0/8 ICMP/0 type 3 code 1", "Allow 10.0.0.0/8 ICMP/0 type 3"}},
		{"distinct types both kept", []netv1.FirewallPolicyRule{icmp(deny("10.0.0.0/8"), prio(8), nil), icmp(allow("10.0.0.0/8"), prio(0), nil)},
			[]string{"Deny 10.0.0.0/8 ICMP/0 type 8", "Allow 10.0.0.0/8 ICMP/0 type 0"}},
		{"any proto covers typed ICMP", []netv1.FirewallPolicyRule{deny("10.0.0.0/8"), icmp(allow("10.0.0.0/8"), prio(8), prio(0))},
			[]string{"Deny 10.0.0.0/8"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := mustCompileFirewall(t, []netv1.FirewallPolicy{fwPolicy("p", nil, tc.rules, nil)}, posture(netv1.VPCPolicyDeny))
			assertRules(t, "ingress", fw.Ingress, tc.want...)
		})
	}
}
