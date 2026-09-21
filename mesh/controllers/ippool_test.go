// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"
	"time"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ipPool(name string, spec netv1.IPPoolSpec) *netv1.IPPool {
	return &netv1.IPPool{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}, Spec: spec}
}

func ipPoolScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func TestIPPoolStates(t *testing.T) {
	for _, tc := range []struct {
		name      string
		spec      netv1.IPPoolSpec
		wantState string
		wantTotal int32
	}{
		{"v4 only", netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic, V4Prefix: sp("198.51.100.0/24")}, "Ready", 256},
		{"v6 only", netv1.IPPoolSpec{Type: netv1.IPPoolTypeInternal, V6Prefix: sp("2001:db8::/120")}, "Ready", 256},
		{"both", netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic, V4Prefix: sp("198.51.100.0/24"), V6Prefix: sp("2001:db8::/120")}, "Ready", 512},
		{"neither", netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic}, "Invalid", 0},
		{"unparseable", netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic, V4Prefix: sp("bogus")}, "Invalid", 0},
		{"v6 in v4Prefix", netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic, V4Prefix: sp("2001:db8::/120")}, "Invalid", 0},
		{"v4 in v6Prefix", netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic, V6Prefix: sp("198.51.100.0/24")}, "Invalid", 0},
		{"bad type", netv1.IPPoolSpec{Type: "secret", V4Prefix: sp("198.51.100.0/24")}, "Invalid", 0},
		{"empty type", netv1.IPPoolSpec{V4Prefix: sp("198.51.100.0/24")}, "Invalid", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := ipPoolScheme(t)
			p := ipPool("p", tc.spec)
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(p).WithStatusSubresource(&netv1.IPPool{}).Build()
			r := &IPPoolReconciler{Client: cl, APIReader: cl}
			if err := r.Sync(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			var got netv1.IPPool
			if err := cl.Get(context.Background(), keyOf(p), &got); err != nil {
				t.Fatal(err)
			}
			if got.Status.State != tc.wantState {
				t.Fatalf("state = %q want %q", got.Status.State, tc.wantState)
			}
			if got.Status.Total != tc.wantTotal {
				t.Fatalf("total = %d want %d", got.Status.Total, tc.wantTotal)
			}
		})
	}
}

// Two pools whose prefixes overlap hand the same address to two consumers, and no
// IPAllocation name collision catches it (names are pool-scoped). Exactly one must lose,
// and which one must not depend on reconcile order.
func TestIPPoolOverlapIsDeterministic(t *testing.T) {
	t0 := metav1.NewTime(time.Unix(1_700_000_000, 0))
	t1 := metav1.NewTime(time.Unix(1_700_000_060, 0))

	for _, order := range []string{"older first", "newer first"} {
		t.Run(order, func(t *testing.T) {
			scheme := ipPoolScheme(t)
			older := ipPool("older", netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic, V4Prefix: sp("198.51.100.0/24")})
			older.CreationTimestamp = t0
			newer := ipPool("newer", netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic, V4Prefix: sp("198.51.100.128/25")})
			newer.CreationTimestamp = t1
			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(older, newer).WithStatusSubresource(&netv1.IPPool{}).Build()
			r := &IPPoolReconciler{Client: cl, APIReader: cl}
			ctx := context.Background()

			seq := []*netv1.IPPool{older, newer}
			if order == "newer first" {
				seq = []*netv1.IPPool{newer, older}
			}
			for _, p := range seq {
				if err := r.Sync(ctx, p); err != nil {
					t.Fatal(err)
				}
			}

			state := func(n string) string {
				var got netv1.IPPool
				if err := cl.Get(ctx, keyOf(ipPool(n, netv1.IPPoolSpec{})), &got); err != nil {
					t.Fatal(err)
				}
				return got.Status.State
			}
			if s := state("older"); s != "Ready" {
				t.Fatalf("older (first created) = %q want Ready", s)
			}
			if s := state("newer"); s != "Conflict" {
				t.Fatalf("newer = %q want Conflict", s)
			}
		})
	}
}

// A disjoint sibling is not a conflict; only genuine prefix overlap is.
func TestIPPoolDisjointSiblingsBothReady(t *testing.T) {
	scheme := ipPoolScheme(t)
	a := ipPool("a", netv1.IPPoolSpec{Type: netv1.IPPoolTypePublic, V4Prefix: sp("198.51.100.0/25")})
	b := ipPool("b", netv1.IPPoolSpec{Type: netv1.IPPoolTypeInternal, V4Prefix: sp("198.51.100.128/25")})
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(a, b).WithStatusSubresource(&netv1.IPPool{}).Build()
	r := &IPPoolReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	for _, p := range []*netv1.IPPool{a, b} {
		if err := r.Sync(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"a", "b"} {
		var got netv1.IPPool
		if err := cl.Get(ctx, keyOf(ipPool(n, netv1.IPPoolSpec{})), &got); err != nil {
			t.Fatal(err)
		}
		if got.Status.State != "Ready" {
			t.Fatalf("%s = %q want Ready", n, got.Status.State)
		}
	}
}
