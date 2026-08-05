// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	netv1 "github.com/trevex/ectobase/api/v1alpha1"
	net "github.com/trevex/ectobase/central/apis/net"
)

func TestVirtualMachine_PlacementAndAntiAffinity_Roundtrip(t *testing.T) {
	in := &netv1.VirtualMachine{}
	in.Spec.AntiAffinity = &netv1.VMAntiAffinity{Group: "web"}
	in.Status.Placement = &netv1.VMPlacement{ClusterName: "poolA", NodeName: "n1", NodePrefix: "2001:db8:0:1::/64"}

	var hub net.VirtualMachine
	if err := Convert_v1alpha1_VirtualMachine_To_net_VirtualMachine(in, &hub, nil); err != nil {
		t.Fatalf("to hub: %v", err)
	}
	if hub.Spec.AntiAffinity == nil || hub.Spec.AntiAffinity.Group != "web" {
		t.Fatalf("anti-affinity lost to hub: %+v", hub.Spec.AntiAffinity)
	}
	if hub.Status.Placement == nil || hub.Status.Placement.NodePrefix != "2001:db8:0:1::/64" {
		t.Fatalf("placement lost to hub: %+v", hub.Status.Placement)
	}

	var out netv1.VirtualMachine
	if err := Convert_net_VirtualMachine_To_v1alpha1_VirtualMachine(&hub, &out, nil); err != nil {
		t.Fatalf("to versioned: %v", err)
	}
	if out.Spec.AntiAffinity.Group != "web" || out.Status.Placement.ClusterName != "poolA" {
		t.Fatalf("roundtrip mismatch: %+v %+v", out.Spec.AntiAffinity, out.Status.Placement)
	}
}
