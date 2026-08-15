// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package reflector

import (
	"context"
	"testing"

	pb "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

func TestAdminServer_SetClearFence(t *testing.T) {
	rib := NewRIB()
	rib.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	a := NewAdminServer(rib)

	if _, err := a.SetFence(context.Background(), &pb.FenceRequest{Prefix: "2001:db8:0:1::/64"}); err != nil {
		t.Fatalf("SetFence: %v", err)
	}
	if rib.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("SetFence must withdraw the fenced route")
	}
	if _, err := a.ClearFence(context.Background(), &pb.FenceRequest{Prefix: "2001:db8:0:1::/64"}); err != nil {
		t.Fatalf("ClearFence: %v", err)
	}
	rib.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	if !rib.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("ClearFence must re-allow the route")
	}
}

func TestAdminServer_SetFence_RejectsInvalidPrefix(t *testing.T) {
	a := NewAdminServer(NewRIB())
	if _, err := a.SetFence(context.Background(), &pb.FenceRequest{Prefix: "not-a-cidr"}); err == nil {
		t.Fatalf("SetFence must reject an invalid prefix")
	}
}
