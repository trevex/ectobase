// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"context"
	"testing"
)

// A ClusterPool's NAME is the cluster identifier workloads reference and the suffix of the
// per-pool namespace, so it is constrained more tightly than a generic object name (which only
// has to be a path segment).
func TestClusterPoolNameValidation(t *testing.T) {
	ctx := context.Background()

	ok := &ClusterPool{}
	ok.Name = "k02"
	if errs := ok.Validate(ctx); len(errs) != 0 {
		t.Fatalf("valid pool name rejected: %v", errs)
	}

	for _, bad := range []string{"poolA", "pool.a", "-pool", "pool_a"} {
		p := &ClusterPool{}
		p.Name = bad
		errs := p.Validate(ctx)
		if len(errs) == 0 {
			t.Fatalf("pool name %q accepted, want rejected", bad)
		}
		// The complaint must point at the name, since that is what the operator has to change.
		if got := errs[0].Field; got != "metadata.name" {
			t.Fatalf("error field = %q, want metadata.name", got)
		}
	}
}
