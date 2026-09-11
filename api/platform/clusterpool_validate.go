// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"context"

	"github.com/trevex/ectobase/api/validate"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Validate constrains the pool's NAME, not a spec field: a ClusterPool's name IS the cluster
// identifier that workloads reference via spec.clusterName, and that identifier becomes the
// `pool-<name>` namespace holding the pool's compiled objects (and the per-pool RBAC bound to it).
// Generic object-name validation only requires a path segment, which would happily accept
// `pool.a` or a 200-character name and then fail later at namespace creation.
func (o *ClusterPool) Validate(ctx context.Context) field.ErrorList {
	return validate.ClusterName(field.NewPath("metadata", "name"), o.Name)
}
