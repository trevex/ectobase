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

// resolve reads the NetworkInterface <ns>/<name> and, via its VPCRef, the VPC's
// effective VNI. It returns the overlay VNI plus the interface's user-specified
// overlay IPs. It is kept pure (client.Client injected) so it unit-tests against
// a controller-runtime fake client.
func resolve(ctx context.Context, c client.Client, ns, name string) (uint32, []string, error) {
	var nic v1alpha1.NetworkInterface
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &nic); err != nil {
		return 0, nil, fmt.Errorf("get NetworkInterface %s/%s: %w", ns, name, err)
	}

	vpcName := nic.Spec.VPCRef.Name
	if vpcName == "" {
		return 0, nil, fmt.Errorf("NetworkInterface %s/%s has an empty vpcRef.name", ns, name)
	}

	var vpc v1alpha1.VPC
	if err := c.Get(ctx, types.NamespacedName{Name: vpcName}, &vpc); err != nil {
		return 0, nil, fmt.Errorf("get VPC %s: %w", vpcName, err)
	}

	vni := vpc.Status.VNI
	if vni == 0 {
		return 0, nil, fmt.Errorf("VPC %s has no allocated VNI (status.vni is 0)", vpcName)
	}

	return uint32(vni), nic.Spec.IPs, nil
}
