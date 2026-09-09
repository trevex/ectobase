// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"testing"
)

func TestNetworkInterfaceValidate(t *testing.T) {
	ctx := context.Background()

	nic := &NetworkInterface{Spec: NetworkInterfaceSpec{IPs: []string{"10.0.0.1"}}}
	if errs := nic.Validate(ctx); len(errs) != 0 {
		t.Fatalf("valid IP rejected: %v", errs)
	}
	nic = &NetworkInterface{Spec: NetworkInterfaceSpec{IPs: []string{"nope"}}}
	if errs := nic.Validate(ctx); len(errs) == 0 {
		t.Fatal("expected error for malformed IP")
	}
}
