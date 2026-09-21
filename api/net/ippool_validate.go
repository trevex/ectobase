// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// IPPoolTypes are the legal values of IPPoolSpec.Type. The CRD path is covered by the
// kubebuilder enum marker in v1alpha1, but the aggregated apiserver admits through Validate,
// so the same rule has to be stated here or an aggregated create would accept anything.
var IPPoolTypes = []string{"public", "internal"}

// Validate implements the kit rest.Validater hook (central CREATE admission).
// Stateless only: format + intra-object rules. Cross-object checks (sibling prefix
// overlap) are enforced by the IPPool reconciler and surfaced via status.
func (o *IPPool) Validate(ctx context.Context) field.ErrorList {
	var errs field.ErrorList
	spec := field.NewPath("spec")

	known := false
	for _, t := range IPPoolTypes {
		if o.Spec.Type == t {
			known = true
			break
		}
	}
	if !known {
		errs = append(errs, field.NotSupported(spec.Child("type"), o.Spec.Type, IPPoolTypes))
	}

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
