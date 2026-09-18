// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"net/netip"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1validation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Priority bounds; the versioned API (v1alpha1.FirewallPriorityMin/Max) documents the same range.
const (
	firewallPriorityMin = 0
	firewallPriorityMax = 65535
)

// Validate implements the kit rest.Validater hook (central CREATE admission). Stateless: every
// rule is checked on its own. Whether the rules selecting an interface fit its rule budget depends
// on the other policies, so the compiler checks that and reports it on the NetworkInterface.
func (o *FirewallPolicy) Validate(ctx context.Context) field.ErrorList {
	var errs field.ErrorList
	spec := field.NewPath("spec")
	if o.Spec.InterfaceSelector == nil {
		// Without a selector the policy applies to nothing; the compiler used to skip it silently.
		errs = append(errs, field.Required(spec.Child("interfaceSelector"),
			"select the interfaces this policy applies to ({} selects all in the namespace)"))
	} else {
		errs = append(errs, metav1validation.ValidateLabelSelector(o.Spec.InterfaceSelector,
			metav1validation.LabelSelectorValidationOptions{}, spec.Child("interfaceSelector"))...)
	}
	errs = append(errs, validateFirewallPriority(o.Spec.Priority, spec.Child("priority"))...)
	for i := range o.Spec.Ingress {
		errs = append(errs, validateFirewallRule(&o.Spec.Ingress[i], spec.Child("ingress").Index(i))...)
	}
	for i := range o.Spec.Egress {
		errs = append(errs, validateFirewallRule(&o.Spec.Egress[i], spec.Child("egress").Index(i))...)
	}
	return errs
}

// ValidateUpdate implements the kit rest.ValidateUpdater hook: policies are edited in place, so a
// spec change gets the same checks as a create. The status subresource runs this too, so an
// unchanged spec passes — a policy stored before this check existed must not block its own writes.
func (o *FirewallPolicy) ValidateUpdate(ctx context.Context, old runtime.Object) field.ErrorList {
	if prev, ok := old.(*FirewallPolicy); ok && equality.Semantic.DeepEqual(prev.Spec, o.Spec) {
		return nil
	}
	return o.Validate(ctx)
}

func validateFirewallPriority(p *int32, path *field.Path) field.ErrorList {
	if p != nil && (*p < firewallPriorityMin || *p > firewallPriorityMax) {
		return field.ErrorList{field.Invalid(path, *p, "must be between 0 and 65535 (lower wins)")}
	}
	return nil
}

func validateFirewallRule(r *FirewallPolicyRule, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	switch r.CIDR {
	case "":
		errs = append(errs, field.Required(path.Child("cidr"), "use 0.0.0.0/0 or ::/0 to match any address"))
	default:
		if p, err := netip.ParsePrefix(r.CIDR); err != nil {
			errs = append(errs, field.Invalid(path.Child("cidr"), r.CIDR, "not a CIDR (address/length)"))
		} else if p.Masked() != p {
			// 10.0.0.5/24 could mean the /24 or be a typo for /32; a firewall must not guess.
			errs = append(errs, field.Invalid(path.Child("cidr"), r.CIDR,
				"host bits are set; use "+p.Masked().String()+" or a longer prefix"))
		}
	}
	switch r.Action {
	case "Allow", "Deny":
	case "":
		errs = append(errs, field.Required(path.Child("action"), "Allow or Deny"))
	default:
		errs = append(errs, field.NotSupported(path.Child("action"), r.Action, []string{"Allow", "Deny"}))
	}
	protoOK := true
	switch r.Proto {
	case "", "TCP", "UDP", "ICMP":
	default:
		protoOK = false
		errs = append(errs, field.NotSupported(path.Child("proto"), r.Proto, []string{"TCP", "UDP", "ICMP"}))
	}
	switch {
	case r.Port < 0 || r.Port > 65535:
		errs = append(errs, field.Invalid(path.Child("port"), r.Port, "must be between 0 (any) and 65535"))
	case r.Port != 0 && protoOK && r.Proto != "TCP" && r.Proto != "UDP":
		errs = append(errs, field.Invalid(path.Child("port"), r.Port, "a port requires proto TCP or UDP"))
	}
	errs = append(errs, validateFirewallPriority(r.Priority, path.Child("priority"))...)
	return errs
}
