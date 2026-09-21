// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Validate implements the kit rest.Validater hook (central CREATE admission).
//
// Stateless only: an entry of publicIPs has to parse as an IP address, and that is all admission
// can honestly decide. Whether a pin is INSIDE the referenced pool, reserved there, or already
// claimed by another consumer are all facts about other objects at another moment — the
// NATGateway reconciler decides them and surfaces the answer as status.state=Invalid. Checking
// them here would only mean checking them twice, against a view that can be stale by the time
// the write lands.
//
// poolRef is likewise not required: a gateway with none keeps the pre-pool meaning of publicIPs
// (literal addresses), so demanding one would break every gateway written before pools existed.
func (o *NATGateway) Validate(ctx context.Context) field.ErrorList {
	var errs field.ErrorList
	spec := field.NewPath("spec")
	for i, ip := range o.Spec.PublicIPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			errs = append(errs, field.Invalid(spec.Child("publicIPs").Index(i), ip, "not a valid IP address"))
		}
	}
	return errs
}
