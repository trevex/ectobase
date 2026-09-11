// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package compute

import (
	"context"

	"github.com/trevex/ectobase/api/validate"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Validate: format only. See VirtualMachine.Validate — kubebuilder markers do not apply on the
// aggregated apiserver, so this method is the enforcement point.
func (o *Container) Validate(ctx context.Context) field.ErrorList {
	return validate.ClusterName(field.NewPath("spec", "clusterName"), o.Spec.ClusterName)
}
