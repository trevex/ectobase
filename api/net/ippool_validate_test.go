// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"testing"
)

func TestIPPoolValidate(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		spec    IPPoolSpec
		wantErr bool
	}{
		{"empty", IPPoolSpec{}, true},
		{"no prefix", IPPoolSpec{Type: "public"}, true},
		{"bad type", IPPoolSpec{Type: "secret", V4Prefix: strptr("198.51.100.0/24")}, true},
		{"empty type", IPPoolSpec{V4Prefix: strptr("198.51.100.0/24")}, true},
		{"malformed v4Prefix", IPPoolSpec{Type: "public", V4Prefix: strptr("bogus")}, true},
		{"v6 in v4Prefix", IPPoolSpec{Type: "public", V4Prefix: strptr("2001:db8::/64")}, true},
		{"v4 in v6Prefix", IPPoolSpec{Type: "public", V6Prefix: strptr("198.51.100.0/24")}, true},
		{"bad reservedIP", IPPoolSpec{Type: "public", V4Prefix: strptr("198.51.100.0/24"), ReservedIPs: []string{"nope"}}, true},
		{"valid public v4", IPPoolSpec{Type: "public", V4Prefix: strptr("198.51.100.0/24")}, false},
		{"valid internal v6", IPPoolSpec{Type: "internal", V6Prefix: strptr("2001:db8::/64")}, false},
		{"valid dual-stack with reservations", IPPoolSpec{
			Type:        "public",
			V4Prefix:    strptr("198.51.100.0/24"),
			V6Prefix:    strptr("2001:db8::/64"),
			ReservedIPs: []string{"198.51.100.1", "2001:db8::1"},
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := (&IPPool{Spec: tc.spec}).Validate(ctx)
			if tc.wantErr && len(errs) == 0 {
				t.Fatalf("expected a rejection, got none")
			}
			if !tc.wantErr && len(errs) != 0 {
				t.Fatalf("valid pool rejected: %v", errs)
			}
		})
	}
}
