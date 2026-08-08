// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"
)

func TestVPCPeeringDeepCopy(t *testing.T) {
	in := &VPCPeering{
		Spec: VPCPeeringSpec{
			VPCRef:          LocalObjectReference{Name: "prod"},
			PeerVPCRef:      VPCReference{Namespace: "shared-ns", Name: "shared"},
			ExposedPrefixes: []string{"10.0.0.0/24", "10.0.1.0/24"},
		},
		Status: VPCPeeringStatus{State: VPCPeeringReady},
	}
	out := in.DeepCopy()
	out.Spec.ExposedPrefixes[0] = "mutated"
	if in.Spec.ExposedPrefixes[0] != "10.0.0.0/24" {
		t.Fatal("deepcopy did not isolate ExposedPrefixes slice")
	}
}
