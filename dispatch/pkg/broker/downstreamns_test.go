// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"testing"

	compiledv1 "github.com/trevex/ectobase/api/compiled/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The per-pool namespace is a DISPATCH-side detail, adopted so the broker's reads there can be
// scoped by a namespaced RoleBinding. Downstream consumers must not inherit it: the CNI resolves a
// pod's CompiledNIC in the pod's own namespace, and the materializers create workloads in the
// twin's namespace — so mirroring the pool namespace through would break pod attach and relocate
// guest workloads. This rewrite is what keeps that contained.
func TestDownstreamNamespaceUsesSourceNotPoolNamespace(t *testing.T) {
	twin := &compiledv1.CompiledNIC{ObjectMeta: metav1.ObjectMeta{
		Namespace: "pool-k02",
		Name:      "default-nic-a",
		Annotations: map[string]string{
			compiledv1.SourceNamespaceAnnotation: "default",
			compiledv1.SourceNameAnnotation:      "nic-a",
		},
	}}
	if got := downstreamNamespace(twin); got != "default" {
		t.Fatalf("downstreamNamespace = %q, want the SOURCE namespace %q", got, "default")
	}
}

// A twin compiled before the back-reference existed has nothing to resolve, so it must mirror
// where it already is rather than vanish into an empty namespace.
func TestDownstreamNamespaceFallsBackWhenUnstamped(t *testing.T) {
	twin := &compiledv1.CompiledNIC{ObjectMeta: metav1.ObjectMeta{
		Namespace: "legacy-ns",
		Name:      "legacy-ns-nic-a",
	}}
	if got := downstreamNamespace(twin); got != "legacy-ns" {
		t.Fatalf("downstreamNamespace = %q, want the twin's own namespace %q", got, "legacy-ns")
	}
}
