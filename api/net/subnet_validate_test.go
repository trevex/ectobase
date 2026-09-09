// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"testing"
)

func strptr(s string) *string { return &s }

func TestSubnetValidate(t *testing.T) {
	ctx := context.Background()

	s := &Subnet{Spec: SubnetSpec{VPCRef: LocalObjectReference{Name: "v"}}}
	if errs := s.Validate(ctx); len(errs) == 0 {
		t.Fatal("expected error when neither v4 nor v6 prefix set")
	}
	s = &Subnet{Spec: SubnetSpec{VPCRef: LocalObjectReference{Name: "v"}, V4Prefix: strptr("not-a-cidr")}}
	if errs := s.Validate(ctx); len(errs) == 0 {
		t.Fatal("expected error for malformed v4 prefix")
	}
	s = &Subnet{Spec: SubnetSpec{VPCRef: LocalObjectReference{Name: "v"}, V4Prefix: strptr("fd00::/64")}}
	if errs := s.Validate(ctx); len(errs) == 0 {
		t.Fatal("expected error for v6 value in v4Prefix")
	}
	s = &Subnet{Spec: SubnetSpec{VPCRef: LocalObjectReference{Name: "v"}, V4Prefix: strptr("10.0.1.0/24"), V6Prefix: strptr("fd00:1::/64")}}
	if errs := s.Validate(ctx); len(errs) != 0 {
		t.Fatalf("valid subnet rejected: %v", errs)
	}
}
