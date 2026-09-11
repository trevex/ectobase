// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package compute

import (
	"context"
	"testing"
)

// The aggregated apiserver serves these types from Go structs with no structural schema, so
// kubebuilder markers never run — these Validate methods are the only thing standing between a
// malformed clusterName and a later failure deriving the pool-<name> namespace from it.
func TestComputeClusterNameValidation(t *testing.T) {
	ctx := context.Background()

	vm := &VirtualMachine{}
	vm.Spec.ClusterName = "k02"
	if errs := vm.Validate(ctx); len(errs) != 0 {
		t.Fatalf("valid VM clusterName rejected: %v", errs)
	}
	vm.Spec.ClusterName = "poolA"
	if errs := vm.Validate(ctx); len(errs) == 0 {
		t.Fatal("expected an error for a non-DNS-label VM clusterName")
	}

	ctr := &Container{}
	ctr.Spec.ClusterName = "pool-a"
	if errs := ctr.Validate(ctx); len(errs) != 0 {
		t.Fatalf("valid Container clusterName rejected: %v", errs)
	}
	ctr.Spec.ClusterName = "pool.a"
	if errs := ctr.Validate(ctx); len(errs) == 0 {
		t.Fatal("expected an error for a dotted Container clusterName")
	}

	// Empty stays legal: a workload without an explicit pool is placed by the compiler default.
	vm.Spec.ClusterName = ""
	if errs := vm.Validate(ctx); len(errs) != 0 {
		t.Fatalf("empty clusterName rejected: %v", errs)
	}
}
