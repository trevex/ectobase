// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Validate implements the kit rest.Validater hook (central CREATE admission).
// Stateless only: format + intra-object rules. Cross-object checks are enforced
// by the LBPool reconciler and surfaced via status.
func (o *LBPool) Validate(ctx context.Context) field.ErrorList {
	var errs field.ErrorList
	spec := field.NewPath("spec")
	if o.Spec.V4Prefix == nil && o.Spec.V6Prefix == nil {
		errs = append(errs, field.Required(spec, "at least one of v4Prefix or v6Prefix is required"))
	}
	errs = append(errs, validatePrefix(spec.Child("v4Prefix"), o.Spec.V4Prefix, true)...)
	errs = append(errs, validatePrefix(spec.Child("v6Prefix"), o.Spec.V6Prefix, false)...)
	for i, r := range o.Spec.ReservedIPs {
		if _, err := netip.ParseAddr(r); err != nil {
			errs = append(errs, field.Invalid(spec.Child("reservedIPs").Index(i), r, "not a valid IP address"))
		}
	}
	return errs
}
