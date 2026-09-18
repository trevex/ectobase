// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"testing"
)

func strp(s string) *string { return &s }

func TestVPCValidate_DefaultPolicy(t *testing.T) {
	for _, ok := range []*string{nil, strp("Allow"), strp("Deny")} {
		if errs := (&VPC{Spec: VPCSpec{DefaultPolicy: ok}}).Validate(context.Background()); len(errs) != 0 {
			t.Fatalf("defaultPolicy %v rejected: %v", ok, errs)
		}
	}
	// "allow" used to be accepted and then silently ignored; "" is neither posture.
	for _, bad := range []string{"allow", "Permit", ""} {
		errs := (&VPC{Spec: VPCSpec{DefaultPolicy: strp(bad)}}).Validate(context.Background())
		if len(errs) != 1 || errs[0].Field != "spec.defaultPolicy" {
			t.Fatalf("defaultPolicy %q: want one error at spec.defaultPolicy, got %v", bad, errs)
		}
	}
}

func TestVPCValidateUpdate(t *testing.T) {
	old := &VPC{Spec: VPCSpec{DefaultPolicy: strp("Allow")}}
	bad := &VPC{Spec: VPCSpec{DefaultPolicy: strp("allow")}}
	if errs := bad.ValidateUpdate(context.Background(), old); len(errs) == 0 {
		t.Fatal("update to an invalid defaultPolicy accepted")
	}
	// A status write (spec unchanged) on a VPC stored before validation existed must not be
	// blocked: the VNI allocator writes status through the same ValidateUpdate.
	legacy := bad.DeepCopy()
	legacy.Status.VNI = 1000
	if errs := legacy.ValidateUpdate(context.Background(), bad); len(errs) != 0 {
		t.Fatalf("unchanged spec rejected: %v", errs)
	}
}
