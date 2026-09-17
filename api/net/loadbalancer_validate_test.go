// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"testing"
)

func TestLoadBalancerValidate(t *testing.T) {
	ctx := context.Background()

	// PoolRef set, empty LB address (allocate) => no errors.
	lb := &LoadBalancer{Spec: LoadBalancerSpec{PoolRef: LocalObjectReference{Name: "p"}}}
	if errs := lb.Validate(ctx); len(errs) != 0 {
		t.Fatalf("valid LB rejected: %v", errs)
	}

	// PoolRef set, valid bring-your-own LB address => no errors.
	lb = &LoadBalancer{Spec: LoadBalancerSpec{PoolRef: LocalObjectReference{Name: "p"}, IP: "203.0.113.5"}}
	if errs := lb.Validate(ctx); len(errs) != 0 {
		t.Fatalf("valid LB with LB address rejected: %v", errs)
	}

	// Malformed LB address => error.
	lb = &LoadBalancer{Spec: LoadBalancerSpec{PoolRef: LocalObjectReference{Name: "p"}, IP: "nope"}}
	if errs := lb.Validate(ctx); len(errs) == 0 {
		t.Fatal("expected error for malformed lbIP")
	}

	// Missing PoolRef.Name => error.
	lb = &LoadBalancer{Spec: LoadBalancerSpec{}}
	if errs := lb.Validate(ctx); len(errs) == 0 {
		t.Fatal("expected error when poolRef.name is empty")
	}
}
