// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// The VPC reports the default firewall posture in effect, including the unset case, whose meaning
// (per-direction NetworkPolicy semantics) is otherwise invisible.
func TestVPCReconcile_ReportsFirewallDefault(t *testing.T) {
	vpc := &netv1.VPC{ObjectMeta: metav1.ObjectMeta{Name: "blue", Namespace: "default"}}
	cl := fake.NewClientBuilder().WithScheme(lbScheme(t)).WithStatusSubresource(&netv1.VPC{}).WithObjects(vpc).Build()
	r := &VPCReconciler{Client: cl, APIReader: cl}
	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "blue"}}
	ctx := context.Background()
	get := func() *netv1.VPC {
		t.Helper()
		var v netv1.VPC
		if err := cl.Get(ctx, req.NamespacedName, &v); err != nil {
			t.Fatal(err)
		}
		return &v
	}
	reconcileAndExpect := func(reason string) {
		t.Helper()
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatal(err)
		}
		c := meta.FindStatusCondition(get().Status.Conditions, ConditionFirewallDefault)
		if c == nil || c.Status != metav1.ConditionTrue || c.Reason != reason || c.Message == "" {
			t.Fatalf("FirewallDefault = %+v, want True/%s with a message", c, reason)
		}
	}

	reconcileAndExpect("PerDirection")
	if get().Status.State != "Ready" {
		t.Fatalf("VNI allocation must still happen, state %q", get().Status.State)
	}

	// A posture change on an already-Ready VPC must be reported (the allocator's idempotent
	// early return used to end the reconcile before any status write).
	for _, p := range []netv1.VPCPolicy{netv1.VPCPolicyDeny, netv1.VPCPolicyAllow} {
		v := get()
		v.Spec.DefaultPolicy = posture(p)
		if err := cl.Update(ctx, v); err != nil {
			t.Fatal(err)
		}
		reconcileAndExpect(string(p))
	}

	rv := get().ResourceVersion
	reconcileAndExpect(string(netv1.VPCPolicyAllow))
	if got := get().ResourceVersion; got != rv {
		t.Fatalf("unchanged VPC was rewritten: resourceVersion %s -> %s", rv, got)
	}
}
