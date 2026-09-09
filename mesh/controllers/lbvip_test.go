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

func readyPool(name, v4 string) *netv1.LBPool {
	p := &netv1.LBPool{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}, Spec: netv1.LBPoolSpec{V4Prefix: sp(v4)}}
	p.Status.State = "Ready"
	return p
}

func lb(name, pool, vip string) *netv1.LoadBalancer {
	return &netv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Generation: 1},
		Spec:       netv1.LoadBalancerSpec{PoolRef: netv1.LocalObjectReference{Name: pool}, VIP: vip},
	}
}

func TestLBVIPAllocateAndAdopt(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = netv1.AddToScheme(scheme)
	pool := readyPool("p", "198.51.100.0/24")
	byo := lb("byo", "p", "198.51.100.10")
	auto := lb("auto", "p", "")
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, byo, auto).WithStatusSubresource(&netv1.LoadBalancer{}).Build()
	r := &LBVIPReconciler{Client: cl, APIReader: cl}
	ctx := context.Background()
	_ = r.Sync(ctx, byo)
	_ = r.Sync(ctx, auto)

	get := func(n string) netv1.LoadBalancer {
		var x netv1.LoadBalancer
		_ = cl.Get(ctx, keyOf(&netv1.LoadBalancer{ObjectMeta: metav1.ObjectMeta{Name: n, Namespace: "default"}}), &x)
		return x
	}
	if g := get("byo"); g.Status.State != "Allocated" || g.Status.AllocatedVIP != "198.51.100.10" {
		t.Fatalf("byo = %+v", g.Status)
	}
	if g := get("auto"); g.Status.State != "Allocated" || g.Status.AllocatedVIP != "198.51.100.1" {
		t.Fatalf("auto = %+v want .1", g.Status)
	}
}
