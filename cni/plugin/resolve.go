// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	v1alpha1 "github.com/trevex/ectobase/api/net/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// resolved is the overlay config the CNI programs for an interface.
type resolved struct {
	VNI uint32
	IPs []string
	MAC string // the interface L2 address (set for VMs; empty = dataplane derives)
}

// resolveCompiledNIC reads the broker-synced CompiledNIC (central policy) for the
// NetworkInterface <ns>/<name> and returns the overlay {vni, ips, mac}. The compiler
// names the CompiledNIC "<ns>-<nic>" in the NIC's namespace. The CNI reads THIS lowered
// object — not the raw NetworkInterface + VPC — so the compute cluster never needs the
// source CRDs. It is kept pure (client.Client injected) so it unit-tests against a
// controller-runtime fake client.
func resolveCompiledNIC(ctx context.Context, c client.Client, ns, name string) (resolved, error) {
	compiledName := ns + "-" + name
	var cn v1alpha1.CompiledNIC
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: compiledName}, &cn); err != nil {
		return resolved{}, fmt.Errorf("get CompiledNIC %s/%s (not compiled/synced yet?): %w", ns, compiledName, err)
	}

	// VNI==0 means the object exists but has not been fully compiled/synced (or the VPC
	// has no allocated VNI yet). Fail clearly so the kubelet retries CNI ADD.
	if cn.Spec.VNI == 0 {
		return resolved{}, fmt.Errorf("CompiledNIC %s/%s has no VNI (spec.vni is 0) — not compiled/synced yet", ns, compiledName)
	}

	return resolved{VNI: uint32(cn.Spec.VNI), IPs: cn.Spec.OverlayIPs, MAC: cn.Spec.MAC}, nil
}
