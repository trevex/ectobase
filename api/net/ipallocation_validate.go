// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Validate implements the kit rest.Validater hook (central CREATE admission).
// Stateless only: format + intra-object rules. Whether the address is actually inside the
// pool, free, or not reserved is the allocator's business — and the uniqueness that matters
// is enforced by the object NAME, not here.
func (o *IPAllocation) Validate(ctx context.Context) field.ErrorList {
	var errs field.ErrorList
	spec := field.NewPath("spec")

	if o.Spec.PoolRef.Name == "" {
		errs = append(errs, field.Required(spec.Child("poolRef", "name"), "an IPPool reference is required"))
	}
	if o.Spec.Address == "" {
		errs = append(errs, field.Required(spec.Child("address"), "an address is required"))
	} else if _, err := netip.ParseAddr(o.Spec.Address); err != nil {
		errs = append(errs, field.Invalid(spec.Child("address"), o.Spec.Address, "not a valid IP address"))
	}
	if o.Spec.ConsumerRef.Kind == "" {
		errs = append(errs, field.Required(spec.Child("consumerRef", "kind"), "a consumer kind is required"))
	}
	if o.Spec.ConsumerRef.Name == "" {
		errs = append(errs, field.Required(spec.Child("consumerRef", "name"), "a consumer name is required"))
	}
	return errs
}
