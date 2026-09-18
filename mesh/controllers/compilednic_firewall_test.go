// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"strings"
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// fwReconcileEnv is a CompiledNIC reconciler over a fake client holding one allocated NIC (app=web)
// in VPC "blue" with the given defaultPolicy, plus the given policies.
type fwReconcileEnv struct {
	t   *testing.T
	cl  client.Client
	r   *CompiledNICReconciler
	req reconcile.Request
}

func newFwReconcileEnv(t *testing.T, defaultPolicy *string, policies ...netv1.FirewallPolicy) *fwReconcileEnv {
	t.Helper()
	nic := &netv1.NetworkInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "default", Labels: webLabels},
		Spec:       netv1.NetworkInterfaceSpec{VPCRef: netv1.LocalObjectReference{Name: "blue"}},
		Status:     netv1.NetworkInterfaceStatus{State: "Allocated", AllocatedIPs: []string{"10.0.0.30"}, VNI: 100},
	}
	vpc := &netv1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: "blue", Namespace: "default"},
		Spec:       netv1.VPCSpec{DefaultPolicy: defaultPolicy},
		Status:     netv1.VPCStatus{VNI: 100, State: "Ready"},
	}
	objs := []client.Object{nic, vpc}
	for i := range policies {
		objs = append(objs, &policies[i])
	}
	cl := fake.NewClientBuilder().WithScheme(lbScheme(t)).
		WithStatusSubresource(&netv1.NetworkInterface{}, &netv1.VPC{}).
		WithObjects(objs...).Build()
	return &fwReconcileEnv{
		t: t, cl: cl,
		r:   &CompiledNICReconciler{Client: cl, DefaultClusterName: "c1"},
		req: reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "web-0"}},
	}
}

func (e *fwReconcileEnv) reconcile() {
	e.t.Helper()
	if _, err := e.r.Reconcile(context.Background(), e.req); err != nil {
		e.t.Fatalf("Reconcile: %v", err)
	}
}

func (e *fwReconcileEnv) compiled() compiledv1.CompiledNIC {
	e.t.Helper()
	var c compiledv1.CompiledNIC
	if err := e.cl.Get(context.Background(), types.NamespacedName{Namespace: "pool-c1", Name: "default-web-0"}, &c); err != nil {
		e.t.Fatalf("get compilednic: %v", err)
	}
	return c
}

func (e *fwReconcileEnv) nic() netv1.NetworkInterface {
	e.t.Helper()
	var n netv1.NetworkInterface
	if err := e.cl.Get(context.Background(), e.req.NamespacedName, &n); err != nil {
		e.t.Fatalf("get nic: %v", err)
	}
	return n
}

func (e *fwReconcileEnv) condition() *metav1.Condition {
	e.t.Helper()
	n := e.nic()
	return meta.FindStatusCondition(n.Status.Conditions, ConditionFirewallCompiled)
}

func (e *fwReconcileEnv) apply(p netv1.FirewallPolicy) {
	e.t.Helper()
	var cur netv1.FirewallPolicy
	err := e.cl.Get(context.Background(), client.ObjectKeyFromObject(&p), &cur)
	if err == nil {
		cur.Spec = p.Spec
		err = e.cl.Update(context.Background(), &cur)
	} else {
		err = e.cl.Create(context.Background(), &p)
	}
	if err != nil {
		e.t.Fatalf("apply policy: %v", err)
	}
}

func (e *fwReconcileEnv) delete(name string) {
	e.t.Helper()
	p := &netv1.FirewallPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}}
	if err := e.cl.Delete(context.Background(), p); err != nil {
		e.t.Fatalf("delete policy: %v", err)
	}
}

// The compiler reads the posture from the NIC's VPC: Deny closes an interface no policy selects.
func TestReconcileFirewall_UsesVPCDefaultPolicy(t *testing.T) {
	e := newFwReconcileEnv(t, posture(netv1.VPCPolicyDeny))
	e.reconcile()
	fw := e.compiled().Spec.Firewall
	if len(fw.Ingress) != 0 || len(fw.Egress) != 0 {
		t.Fatalf("defaultPolicy Deny must synthesize nothing, got %+v", fw)
	}
	if c := e.condition(); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("FirewallCompiled must be True, got %+v", c)
	}
}

// Over budget, the interface keeps enforcing its last good rule set (a truncated set could drop a
// Deny; an emptied one would cut a running workload off) and the NIC says why, instead of the
// agent logging a refused replace nobody reads. Fixing the policy recovers.
func TestReconcileFirewall_OverBudgetKeepsLastGoodAndReports(t *testing.T) {
	closed := posture(netv1.VPCPolicyDeny)
	e := newFwReconcileEnv(t, closed, fwPolicy("base", nil, []netv1.FirewallPolicyRule{allow("10.0.0.0/8")}, nil))
	e.reconcile()
	good := e.compiled().Spec.Firewall

	e.apply(fwPolicy("big", nil, nRules(17, true, "Allow"), nil))
	e.reconcile()
	if got := e.compiled().Spec.Firewall; len(got.Ingress) != len(good.Ingress) || got.Ingress[0] != good.Ingress[0] {
		t.Fatalf("over-budget compile must keep the last good firewall %+v, got %+v", good, got)
	}
	c := e.condition()
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != FirewallReasonRuleBudgetExceeded {
		t.Fatalf("want FirewallCompiled=False/%s, got %+v", FirewallReasonRuleBudgetExceeded, c)
	}
	if !strings.Contains(c.Message, "IPv6") || !strings.Contains(c.Message, "last good") {
		t.Fatalf("condition message must name the family and say what stays applied: %q", c.Message)
	}

	e.delete("big")
	e.reconcile()
	if c := e.condition(); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("fixing the policy must clear the condition, got %+v", c)
	}
}

// With no last good set to keep (first compile), the interface fails CLOSED: an empty firewall is
// deny-all in the datapath.
func TestReconcileFirewall_OverBudgetOnFirstCompileFailsClosed(t *testing.T) {
	e := newFwReconcileEnv(t, nil, fwPolicy("big", nil, nRules(17, false, "Allow"), nil))
	e.reconcile()
	if fw := e.compiled().Spec.Firewall; len(fw.Ingress) != 0 || len(fw.Egress) != 0 {
		t.Fatalf("first compile over budget must fail closed (empty = deny-all), got %+v", fw)
	}
	c := e.condition()
	if c == nil || c.Status != metav1.ConditionFalse || !strings.Contains(c.Message, "denies all traffic") {
		t.Fatalf("condition must report the fail-closed state, got %+v", c)
	}
}

// Writing the condition must not churn: an unchanged reconcile leaves the NIC untouched (a status
// write re-enqueues the NIC for both the compiler and the IP allocator).
func TestReconcileFirewall_ConditionWriteIsIdempotent(t *testing.T) {
	e := newFwReconcileEnv(t, nil)
	e.reconcile()
	rv := e.nic().ResourceVersion
	e.reconcile()
	if got := e.nic().ResourceVersion; got != rv {
		t.Fatalf("no-op reconcile rewrote the NIC: resourceVersion %s -> %s", rv, got)
	}
}
