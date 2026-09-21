// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"testing"
)

func TestNATGatewayValidate(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		spec    NATGatewaySpec
		wantErr bool
	}{
		// No poolRef and no pins is the pre-pool gateway, still legal.
		{"empty", NATGatewaySpec{}, false},
		{"literal publicIPs, no pool", NATGatewaySpec{PublicIPs: []string{"192.0.2.40"}}, false},
		{"pins inside a pool", NATGatewaySpec{
			PoolRef:   LocalObjectReference{Name: "pub"},
			PublicIPs: []string{"192.0.2.40", "2001:db8::1"},
		}, false},
		{"malformed pin", NATGatewaySpec{PublicIPs: []string{"192.0.2.40", "nope"}}, true},
		{"a prefix is not an address", NATGatewaySpec{PublicIPs: []string{"192.0.2.0/24"}}, true},
		// Admission is stateless: whether the pin is IN the pool is the reconciler's call,
		// so an out-of-pool-looking address is accepted here and refused by status.
		{"pin admission cannot judge", NATGatewaySpec{
			PoolRef:   LocalObjectReference{Name: "pub"},
			PublicIPs: []string{"203.0.113.9"},
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := (&NATGateway{Spec: tc.spec}).Validate(ctx)
			if tc.wantErr && len(errs) == 0 {
				t.Fatalf("expected a rejection, got none")
			}
			if !tc.wantErr && len(errs) != 0 {
				t.Fatalf("expected acceptance, got %v", errs)
			}
		})
	}
}
