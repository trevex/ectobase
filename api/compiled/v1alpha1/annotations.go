// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// Back-reference from a compiled twin to the source object it was compiled from.
//
// Annotations rather than labels because an object name may exceed the 63-character label-value
// limit, and nothing selects on these — they are read, not queried.
//
// They carry real weight, because a twin does NOT live in its source's namespace: the compiler
// writes twins into the per-pool namespace on the dispatch, which is what lets per-pool RBAC scope
// a broker's reads. That makes this back-reference the only durable link to the source, and three
// things depend on it:
//
//   - teardown, which must find a twin whose placement may no longer be resolvable (the owning
//     workload can be deleted before the NIC it owns);
//   - the compiler's watch mapping, since ownerReferences cannot cross namespaces;
//   - the broker, which mirrors each twin back into its SOURCE namespace downstream, so the pool
//     namespace is a dispatch-side detail and downstream consumers (CNI, materializers) keep
//     seeing twins where they always were.
const (
	SourceNamespaceAnnotation = "compiled.ectobase.dev/source-namespace"
	SourceNameAnnotation      = "compiled.ectobase.dev/source-name"
)
