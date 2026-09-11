// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestClusterName(t *testing.T) {
	path := field.NewPath("spec", "clusterName")
	for _, tc := range []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"empty is allowed (placement resolved elsewhere)", "", false},
		{"simple", "k02", false},
		{"hyphenated", "pool-a", false},
		{"digits", "cluster1", false},
		{"uppercase rejected", "poolA", true},
		{"dots rejected (would split the namespace)", "pool.a", true},
		{"leading hyphen rejected", "-pool", true},
		{"trailing hyphen rejected", "pool-", true},
		{"underscore rejected", "pool_a", true},
		// 58 is the 63-char namespace limit minus len("pool-"): the boundary matters because the
		// name itself is still a legal DNS label well past the point the prefixed namespace isn't.
		{"at the prefixed-length limit", strings.Repeat("a", 58), false},
		{"one over the prefixed-length limit", strings.Repeat("a", 59), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := ClusterName(path, tc.value)
			if tc.wantErr && len(errs) == 0 {
				t.Fatalf("ClusterName(%q) = no errors, want an error", tc.value)
			}
			if !tc.wantErr && len(errs) != 0 {
				t.Fatalf("ClusterName(%q) = %v, want no errors", tc.value, errs)
			}
		})
	}
}

// TestClusterNameLimitLeavesRoomForNamespace guards the arithmetic rather than the message: a
// name at the limit must still yield a namespace Kubernetes will accept.
func TestClusterNameLimitLeavesRoomForNamespace(t *testing.T) {
	if got := len(clusterNameNamespacePrefix) + maxClusterNameLen; got != 63 {
		t.Fatalf("prefix+max = %d, want 63 (the DNS-1123 label limit)", got)
	}
}
