// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"net"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Validate: format only. Membership and uniqueness are enforced by the IP and
// MAC allocators (which need a client) and surfaced via Status.State.
func (o *NetworkInterface) Validate(ctx context.Context) field.ErrorList {
	var errs field.ErrorList
	ipsPath := field.NewPath("spec", "ips")
	for i, s := range o.Spec.IPs {
		if _, err := netip.ParseAddr(s); err != nil {
			errs = append(errs, field.Invalid(ipsPath.Index(i), s, "not a valid IP address"))
		}
	}
	if o.Spec.MAC != "" {
		if _, err := net.ParseMAC(o.Spec.MAC); err != nil {
			errs = append(errs, field.Invalid(field.NewPath("spec", "mac"), o.Spec.MAC, "not a valid MAC address"))
		}
	}
	return errs
}
