// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	netv1 "github.com/trevex/ectobase/api/net/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestLBPoolReady(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := netv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	good := &netv1.LBPool{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"}, Spec: netv1.LBPoolSpec{V4Prefix: sp("198.51.100.0/24")}}
	bad := &netv1.LBPool{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "default"}, Spec: netv1.LBPoolSpec{V4Prefix: sp("bogus")}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(good, bad).WithStatusSubresource(&netv1.LBPool{}).Build()
	r := &LBPoolReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	if err := r.Sync(ctx, good); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(ctx, bad); err != nil {
		t.Fatal(err)
	}
	var g netv1.LBPool
	_ = cl.Get(ctx, keyOf(good), &g)
	if g.Status.State != "Ready" {
		t.Fatalf("good state = %q want Ready", g.Status.State)
	}
	var b netv1.LBPool
	_ = cl.Get(ctx, keyOf(bad), &b)
	if b.Status.State != "Invalid" {
		t.Fatalf("bad state = %q want Invalid", b.Status.State)
	}
}
