// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package compute

import (
	"context"

	"github.com/trevex/ectobase/api/validate"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Validate: format only. Whether the named pool actually exists is not checked here — that needs a
// client, and placement is surfaced through status instead.
//
// Note these run on the AGGREGATED apiserver, which serves these types from Go structs with no
// structural schema, so kubebuilder validation markers are inert. This method is the only
// enforcement point.
func (o *VirtualMachine) Validate(ctx context.Context) field.ErrorList {
	return validate.ClusterName(field.NewPath("spec", "clusterName"), o.Spec.ClusterName)
}
