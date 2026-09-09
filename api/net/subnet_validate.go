// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Validate implements the kit rest.Validater hook (central CREATE admission).
// Stateless only: format + intra-object rules. Cross-object checks (VPC exists,
// sibling overlap) are enforced by the Subnet reconciler and surfaced via status.
func (o *Subnet) Validate(ctx context.Context) field.ErrorList {
	var errs field.ErrorList
	spec := field.NewPath("spec")

	if o.Spec.VPCRef.Name == "" {
		errs = append(errs, field.Required(spec.Child("vpcRef", "name"), "a VPC reference is required"))
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

// validatePrefix checks a CIDR string and that its family matches wantV4.
func validatePrefix(path *field.Path, s *string, wantV4 bool) field.ErrorList {
	if s == nil {
		return nil
	}
	p, err := netip.ParsePrefix(*s)
	if err != nil {
		return field.ErrorList{field.Invalid(path, *s, "not a valid CIDR prefix")}
	}
	if p.Addr().Is4() != wantV4 {
		fam := "IPv4"
		if !wantV4 {
			fam = "IPv6"
		}
		return field.ErrorList{field.Invalid(path, *s, "must be an "+fam+" prefix")}
	}
	return nil
}
