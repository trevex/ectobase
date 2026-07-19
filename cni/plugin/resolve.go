// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	v1alpha1 "github.com/trevex/ectobase/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// resolved is the overlay config the CNI programs for an interface.
type resolved struct {
	VNI uint32
	IPs []string
	MAC string // the interface L2 address (set for VMs; empty = dataplane derives)
}

// resolve reads the NetworkInterface <ns>/<name> and, via its VPCRef, the VPC's
// effective VNI. It returns the overlay VNI plus the interface's user-specified
// overlay IPs and MAC. It is kept pure (client.Client injected) so it unit-tests
// against a controller-runtime fake client.
func resolve(ctx context.Context, c client.Client, ns, name string) (resolved, error) {
	var nic v1alpha1.NetworkInterface
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &nic); err != nil {
		return resolved{}, fmt.Errorf("get NetworkInterface %s/%s: %w", ns, name, err)
	}

	vpcName := nic.Spec.VPCRef.Name
	if vpcName == "" {
		return resolved{}, fmt.Errorf("NetworkInterface %s/%s has an empty vpcRef.name", ns, name)
	}

	// VPCRef is a same-namespace LocalObjectReference, and VPC is namespaced — get it in the
	// NetworkInterface's namespace (a bare name would fail "empty namespace ... resource name").
	var vpc v1alpha1.VPC
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: vpcName}, &vpc); err != nil {
		return resolved{}, fmt.Errorf("get VPC %s/%s: %w", ns, vpcName, err)
	}

	vni := vpc.Status.VNI
	if vni == 0 {
		return resolved{}, fmt.Errorf("VPC %s has no allocated VNI (status.vni is 0)", vpcName)
	}

	return resolved{VNI: uint32(vni), IPs: nic.Spec.IPs, MAC: nic.Spec.MAC}, nil
}
