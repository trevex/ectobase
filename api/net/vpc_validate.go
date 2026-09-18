// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Validate implements the kit rest.Validater hook (central CREATE admission).
func (o *VPC) Validate(ctx context.Context) field.ErrorList {
	var errs field.ErrorList
	if p := o.Spec.DefaultPolicy; p != nil && *p != "Allow" && *p != "Deny" {
		errs = append(errs, field.NotSupported(field.NewPath("spec", "defaultPolicy"), *p, []string{"Allow", "Deny"}))
	}
	return errs
}

// ValidateUpdate implements the kit rest.ValidateUpdater hook. The status subresource runs it too,
// so an unchanged spec passes: re-validating it would let a VPC stored before this check existed
// block its own VNI allocation.
func (o *VPC) ValidateUpdate(ctx context.Context, old runtime.Object) field.ErrorList {
	if prev, ok := old.(*VPC); ok && equality.Semantic.DeepEqual(prev.Spec, o.Spec) {
		return nil
	}
	return o.Validate(ctx)
}
