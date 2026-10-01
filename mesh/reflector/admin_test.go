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
		t.Fatalf("SetFence must hide the fenced route")
	}
	if _, err := a.ClearFence(context.Background(), &pb.FenceRequest{Prefix: "2001:db8:0:1::/64"}); err != nil {
		t.Fatalf("ClearFence: %v", err)
	}
	// No re-announce: the agent never resends a route on a live session.
	if !rib.HasRoute(100, "10.0.0.5/32") {
		t.Fatalf("ClearFence must re-advertise the route")
	}
}

func TestAdminServer_AnnouncedFrom(t *testing.T) {
	rib := NewRIB()
	rib.Announce("nodeA", 100, "10.0.0.5/32", []string{"2001:db8:0:1::a"}, false)
	rib.Announce("nodeA", 100, "10.0.0.9/32", []string{"2001:db8:0:1::a"}, false)
	a := NewAdminServer(rib)
	if _, err := a.SetFence(context.Background(), &pb.FenceRequest{Prefix: "2001:db8:0:1::/64"}); err != nil {
		t.Fatal(err)
	}
	rep, err := a.AnnouncedFrom(context.Background(), &pb.AnnouncedFromRequest{
		Prefix: "2001:db8:0:1::/64",
		Keys:   []*pb.RouteKey{{Vni: 100, Prefix: "10.0.0.5/32"}, {Vni: 100, Prefix: "10.0.0.6/32"}},
	})
	if err != nil {
		t.Fatalf("AnnouncedFrom: %v", err)
	}
	if len(rep.GetKeys()) != 1 || rep.GetKeys()[0].GetPrefix() != "10.0.0.5/32" {
		t.Fatalf("want only the asked, held key 10.0.0.5/32, got %v", rep.GetKeys())
	}
	hs := rep.GetHoldings()
	if len(hs) != 1 || hs[0].GetOrigin() != "nodeA" || hs[0].GetNexthop() != "2001:db8:0:1::a" || hs[0].GetKey().GetPrefix() != "10.0.0.5/32" {
		t.Fatalf("want the holding to name nodeA via 2001:db8:0:1::a, got %v", hs)
	}
	if _, err := a.AnnouncedFrom(context.Background(), &pb.AnnouncedFromRequest{Prefix: "bogus"}); err == nil {
		t.Fatal("AnnouncedFrom must reject an invalid prefix")
	}
}

func TestAdminServer_SetFence_RejectsInvalidPrefix(t *testing.T) {
	a := NewAdminServer(NewRIB())
	if _, err := a.SetFence(context.Background(), &pb.FenceRequest{Prefix: "not-a-cidr"}); err == nil {
		t.Fatalf("SetFence must reject an invalid prefix")
	}
}
