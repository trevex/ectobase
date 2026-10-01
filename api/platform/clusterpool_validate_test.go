// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"context"
	"strings"
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

// spec.underlayPrefix is the pool's route-bus certificate constraint and its fence. It is matched
// as a string in places (fenced prefixes, NetworkFence names), so only one spelling is accepted.
func TestClusterPoolUnderlayPrefixValidation(t *testing.T) {
	ctx := context.Background()
	pool := func(prefix string) *ClusterPool {
		p := &ClusterPool{Spec: ClusterPoolSpec{UnderlayPrefix: prefix}}
		p.Name = "k02"
		return p
	}
	for _, ok := range []string{"", "fd00:cafe:1914::/48", "2001:db8::/32", "fd00:cafe:1914::1/128", "10.20.0.0/16", "10.20.30.0/24"} {
		if errs := pool(ok).Validate(ctx); len(errs) != 0 {
			t.Errorf("underlayPrefix %q rejected: %v", ok, errs)
		}
	}
	for bad, why := range map[string]string{
		"fd00:cafe:1914::":      "not a CIDR",
		"fd00:cafe:1914::1/48":  "host bits",
		"fd00:CAFE:1914::/48":   "canonical",
		"fd00:cafe:1914:0::/48": "canonical",
		"::ffff:10.20.0.0/112":  "IPv4-mapped",
		"fd00::/16":             "at least /32",
		"::/0":                  "at least /32",
		"10.0.0.0/8":            "at least /16",
		"10.20.0.1/16":          "host bits",
		"fd00:cafe:1914::/48 ":  "not a CIDR",
	} {
		errs := pool(bad).Validate(ctx)
		if len(errs) == 0 {
			t.Errorf("underlayPrefix %q accepted, want rejected (%s)", bad, why)
			continue
		}
		if errs[0].Field != "spec.underlayPrefix" || !strings.Contains(errs[0].Detail, why) {
			t.Errorf("underlayPrefix %q: got %s %q, want spec.underlayPrefix mentioning %q", bad, errs[0].Field, errs[0].Detail, why)
		}
	}
}

// The status subresource runs the update hook too. A pool stored before the check existed must not
// be locked out of its own status writes (the broker's heartbeat), but a spec change is checked.
func TestClusterPoolValidateUpdate(t *testing.T) {
	ctx := context.Background()
	old := &ClusterPool{Spec: ClusterPoolSpec{UnderlayPrefix: "fd00::/8"}}
	old.Name = "k02"
	same := old.DeepCopy()
	same.Status.Phase = "Ready"
	if errs := same.ValidateUpdate(ctx, old); len(errs) != 0 {
		t.Fatalf("an unchanged spec must pass on update: %v", errs)
	}
	changed := old.DeepCopy()
	changed.Spec.UnderlayPrefix = "fd00:cafe:1914::1/48"
	if errs := changed.ValidateUpdate(ctx, old); len(errs) == 0 {
		t.Fatal("a changed, invalid underlayPrefix must be rejected on update")
	}
}
