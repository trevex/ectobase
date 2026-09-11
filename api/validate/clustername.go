// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package validate holds validation helpers shared by the api groups. It exists because a few
// constraints (notably the pool-identifier shape) are enforced on several unrelated kinds, and
// duplicating them per group is how they drift apart.
package validate

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// clusterNameNamespacePrefix is the namespace a pool's compiled objects live in. Kept here (not
// in the controllers) because it is what bounds the legal length of a cluster name.
const clusterNameNamespacePrefix = "pool-"

// maxClusterNameLen is 63 (the DNS-1123 label limit for a namespace name) minus the prefix, so
// "pool-" + ClusterName is itself always a legal namespace.
var maxClusterNameLen = validation.DNS1123LabelMaxLength - len(clusterNameNamespacePrefix)

// ClusterName validates a pool identifier. The value is not free-form: each pool's compiled
// objects are stored in a per-pool `pool-<clusterName>` namespace on the dispatch and mirrored
// into the same namespace on the pool cluster, and per-pool RBAC is bound to it. So the name has
// to be a DNS-1123 label AND short enough that the prefixed namespace is one too.
//
// An empty name is allowed here — callers that require placement enforce that separately (a NIC
// with no clusterName is resolved from its owning workload or the compiler default).
func ClusterName(fldPath *field.Path, name string) field.ErrorList {
	var errs field.ErrorList
	if name == "" {
		return errs
	}
	if len(name) > maxClusterNameLen {
		errs = append(errs, field.Invalid(fldPath, name, fmt.Sprintf(
			"must be at most %d characters so the derived %q namespace stays a valid DNS-1123 label",
			maxClusterNameLen, clusterNameNamespacePrefix+name)))
		return errs
	}
	for _, msg := range validation.IsDNS1123Label(name) {
		errs = append(errs, field.Invalid(fldPath, name, msg))
	}
	return errs
}
