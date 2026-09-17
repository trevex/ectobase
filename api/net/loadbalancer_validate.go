// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Validate implements the kit rest.Validater hook (central CREATE admission).
// Stateless only: format + intra-object rules. Cross-object checks (pool exists,
// LB address membership) are enforced by the LoadBalancer reconciler and surfaced via status.
func (o *LoadBalancer) Validate(ctx context.Context) field.ErrorList {
	var errs field.ErrorList
	if o.Spec.IP != "" {
		if _, err := netip.ParseAddr(o.Spec.IP); err != nil {
			errs = append(errs, field.Invalid(field.NewPath("spec", "lbIP"), o.Spec.IP, "not a valid IP address"))
		}
	}
	if o.Spec.PoolRef.Name == "" {
		errs = append(errs, field.Required(field.NewPath("spec", "poolRef", "name"), "an LBPool reference is required"))
	}
	return errs
}
