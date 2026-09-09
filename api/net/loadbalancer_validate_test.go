// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"testing"
)

func TestLoadBalancerValidate(t *testing.T) {
	ctx := context.Background()

	// PoolRef set, empty VIP (allocate) => no errors.
	lb := &LoadBalancer{Spec: LoadBalancerSpec{PoolRef: LocalObjectReference{Name: "p"}}}
	if errs := lb.Validate(ctx); len(errs) != 0 {
		t.Fatalf("valid LB rejected: %v", errs)
	}

	// PoolRef set, valid bring-your-own VIP => no errors.
	lb = &LoadBalancer{Spec: LoadBalancerSpec{PoolRef: LocalObjectReference{Name: "p"}, VIP: "203.0.113.5"}}
	if errs := lb.Validate(ctx); len(errs) != 0 {
		t.Fatalf("valid LB with VIP rejected: %v", errs)
	}

	// Malformed VIP => error.
	lb = &LoadBalancer{Spec: LoadBalancerSpec{PoolRef: LocalObjectReference{Name: "p"}, VIP: "nope"}}
	if errs := lb.Validate(ctx); len(errs) == 0 {
		t.Fatal("expected error for malformed vip")
	}

	// Missing PoolRef.Name => error.
	lb = &LoadBalancer{Spec: LoadBalancerSpec{}}
	if errs := lb.Validate(ctx); len(errs) == 0 {
		t.Fatal("expected error when poolRef.name is empty")
	}
}
