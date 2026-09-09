// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"testing"
)

func TestLBPoolValidate(t *testing.T) {
	ctx := context.Background()
	if errs := (&LBPool{}).Validate(ctx); len(errs) == 0 {
		t.Fatal("expected error when no prefix set")
	}
	if errs := (&LBPool{Spec: LBPoolSpec{V4Prefix: strptr("bogus")}}).Validate(ctx); len(errs) == 0 {
		t.Fatal("expected error for malformed v4Prefix")
	}
	if errs := (&LBPool{Spec: LBPoolSpec{V4Prefix: strptr("198.51.100.0/24")}}).Validate(ctx); len(errs) != 0 {
		t.Fatalf("valid pool rejected: %v", errs)
	}
}
