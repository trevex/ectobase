// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"testing"
)

func TestIPAllocationValidate(t *testing.T) {
	ctx := context.Background()
	valid := IPAllocationSpec{
		PoolRef:     LocalObjectReference{Name: "pub"},
		Address:     "192.0.2.40",
		ConsumerRef: TypedLocalObjectReference{Kind: "LoadBalancer", Name: "lb"},
	}
	mutate := func(f func(*IPAllocationSpec)) IPAllocationSpec {
		s := *valid.DeepCopy()
		f(&s)
		return s
	}
	for _, tc := range []struct {
		name    string
		spec    IPAllocationSpec
		wantErr bool
	}{
		{"valid", valid, false},
		{"valid v6", mutate(func(s *IPAllocationSpec) { s.Address = "2001:db8::a" }), false},
		{"empty", IPAllocationSpec{}, true},
		{"no pool", mutate(func(s *IPAllocationSpec) { s.PoolRef.Name = "" }), true},
		{"no address", mutate(func(s *IPAllocationSpec) { s.Address = "" }), true},
		{"bad address", mutate(func(s *IPAllocationSpec) { s.Address = "192.0.2.40/32" }), true},
		{"no consumer kind", mutate(func(s *IPAllocationSpec) { s.ConsumerRef.Kind = "" }), true},
		{"no consumer name", mutate(func(s *IPAllocationSpec) { s.ConsumerRef.Name = "" }), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := (&IPAllocation{Spec: tc.spec}).Validate(ctx)
			if tc.wantErr && len(errs) == 0 {
				t.Fatalf("expected a rejection, got none")
			}
			if !tc.wantErr && len(errs) != 0 {
				t.Fatalf("valid allocation rejected: %v", errs)
			}
		})
	}
}
