// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"testing"
	"time"

	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// The dataplane's self-route owns the key of every locally attached interface's host prefix. A bus
// route for that same (vni, prefix) — the guest's own /32 announced by another node, as in a VM move
// or the reflector re-advertising a fenced route — must never be programmed over it, nor withdrawn
// from under it: flowplane stores both in one key, so an AddRoute replaces local delivery with an
// encap and a WithdrawRoute deletes the self-route.

const (
	guestIP   = "10.0.0.5"
	guestHost = "10.0.0.5/32"
	remoteNH  = "fd00::b" // another node's VTEP announcing the same /32
)

func localGuest(dp *recordingDP) {
	dp.mu.Lock()
	dp.ifaces = []LocalInterface{{InterfaceID: "vm", Vni: 100, OverlayIPs: []string{guestIP}, Underlay: "fd00::a"}}
	dp.mu.Unlock()
}

func noLocalGuest(dp *recordingDP) {
	dp.mu.Lock()
	dp.ifaces = nil
	dp.mu.Unlock()
}

func withdrewKey(dp *recordingDP, vni uint32, prefix string) bool {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	return dp.withdrew[key(vni, prefix)]
}

func routeAdd(vni uint32, prefix string, nhs ...string) *rbv1.RouteUpdate {
	return &rbv1.RouteUpdate{Vni: vni, Prefix: prefix, Nexthops: nhs, Op: rbv1.RouteOp_ROUTE_OP_ADD}
}

func routeWithdraw(vni uint32, prefix string) *rbv1.RouteUpdate {
	return &rbv1.RouteUpdate{Vni: vni, Prefix: prefix, Op: rbv1.RouteOp_ROUTE_OP_WITHDRAW}
}

// (1) An ADD for a local guest's own /32 is recorded, not programmed.
func TestBusRouteForALocalHostPrefixIsNotProgrammed(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	localGuest(dp)
	b.refreshLocalHosts(ctx)

	b.apply(ctx, routeAdd(100, guestHost, remoteNH))
	if nh, ok := dp.get(100, guestHost); ok {
		t.Fatalf("a bus route over a local guest's host prefix must not be programmed, got -> %s", nh)
	}
}

// (2) A WITHDRAW for a local guest's own /32 never reaches the dataplane.
func TestBusWithdrawForALocalHostPrefixIsNotSent(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	localGuest(dp)
	b.refreshLocalHosts(ctx)

	b.apply(ctx, routeAdd(100, guestHost, remoteNH))
	b.apply(ctx, routeWithdraw(100, guestHost))
	if withdrewKey(dp, 100, guestHost) {
		t.Fatal("a WITHDRAW for a local guest's host prefix must not reach the dataplane: it would delete the self-route")
	}
}

// (3) The guest leaves (moved away) while another node's route for its /32 is known: the node must
// now program that route, or it black-holes traffic to the moved VM.
func TestBusRouteIsProgrammedOnceTheLocalInterfaceLeaves(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	localGuest(dp)
	b.refreshLocalHosts(ctx)
	b.apply(ctx, routeAdd(100, guestHost, remoteNH))

	noLocalGuest(dp)
	b.refreshLocalHosts(ctx)
	if nh, ok := dp.get(100, guestHost); !ok || nh != remoteNH {
		t.Fatalf("once the guest left, the held route must be programmed -> %s, got %q ok=%v", remoteNH, nh, ok)
	}
	// It is an ordinary installed route from here on: a later WITHDRAW removes it.
	b.apply(ctx, routeWithdraw(100, guestHost))
	if !withdrewKey(dp, 100, guestHost) {
		t.Fatal("the programmed route must be withdrawn when its origin withdraws it")
	}
}

// (3b) A route withdrawn while the guest was still local is not resurrected when it leaves.
func TestBusRouteWithdrawnWhileLocalIsNotProgrammedOnLeave(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	localGuest(dp)
	b.refreshLocalHosts(ctx)
	b.apply(ctx, routeAdd(100, guestHost, remoteNH))
	b.apply(ctx, routeWithdraw(100, guestHost))

	noLocalGuest(dp)
	b.refreshLocalHosts(ctx)
	if nh, ok := dp.get(100, guestHost); ok {
		t.Fatalf("a withdrawn route must not be programmed when the guest leaves, got -> %s", nh)
	}
}

// (4) The guest arrives while a bus route for its /32 is programmed (a VM moving here): the
// dataplane's program_interface has overwritten the key, so the agent drops the route from its
// bookkeeping WITHOUT a WithdrawRoute — and a later WITHDRAW from the old node or an EndOfRIB
// prune must not send one either.
func TestLocalInterfaceArrivingOverAProgrammedRouteIsNotWithdrawn(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	b.refreshLocalHosts(ctx)
	b.apply(ctx, routeAdd(100, guestHost, remoteNH))
	if _, ok := dp.get(100, guestHost); !ok {
		t.Fatal("precondition: the remote route is programmed while the guest is elsewhere")
	}

	localGuest(dp)
	b.refreshLocalHosts(ctx)
	if withdrewKey(dp, 100, guestHost) {
		t.Fatal("the guest arriving must not withdraw the key: that would delete its self-route")
	}
	if b.installed[100][guestHost] {
		t.Fatal("the agent must stop owning the route once a local interface holds its key")
	}

	b.apply(ctx, routeWithdraw(100, guestHost))
	b.seen = map[uint32]map[string]bool{}
	b.rxRoutes = map[uint32]uint32{}
	b.handleServerMsg(ctx, &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfRib{EndOfRib: &rbv1.EndOfRIB{Vni: 100}}})
	if withdrewKey(dp, 100, guestHost) {
		t.Fatal("neither the old node's WITHDRAW nor the prune may withdraw a local guest's host prefix")
	}
}

// Between reconcile ticks the agent's view of its interfaces can lag the dataplane. A guest that
// arrived since the last refresh must still be protected: a stale view is refreshed before a
// host-prefix update touches the dataplane.
func TestLocalInterfaceArrivingBetweenTicksIsProtected(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	b.refreshLocalHosts(ctx)
	b.apply(ctx, routeAdd(100, guestHost, remoteNH))

	localGuest(dp) // program_interface ran; no reconcile tick yet
	b.localHostsAt = time.Now().Add(-time.Hour)
	b.apply(ctx, routeWithdraw(100, guestHost))
	if withdrewKey(dp, 100, guestHost) {
		t.Fatal("a guest that arrived between ticks must be protected from a WITHDRAW of its host prefix")
	}
}

// (5) An E/W LB address is an anycast key with no self-route behind it: it is not any local
// interface's host prefix, so it keeps today's behaviour — programmed on ADD, withdrawn on WITHDRAW —
// even on a node that hosts a guest in the same VNI.
func TestAnycastLBAddressIsUnaffected(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	localGuest(dp)
	b.refreshLocalHosts(ctx)

	const lb = "10.0.0.100/32"
	b.apply(ctx, routeAdd(100, lb, "fd00::a", remoteNH))
	if nh, ok := dp.get(100, lb); !ok || nh != "fd00::a" {
		t.Fatalf("an LB address must be programmed as today (primary nexthop), got %q ok=%v", nh, ok)
	}
	b.apply(ctx, routeWithdraw(100, lb))
	if !withdrewKey(dp, 100, lb) {
		t.Fatal("an LB address must be withdrawn as today")
	}
}

// (6) Prune respects the guard: a route the node held while its guest was local, and which the
// reflector no longer has, is forgotten at EndOfRIB — so it is not programmed when the guest leaves.
// A plain stale mesh route in the same VNI is still pruned.
func TestPruneForgetsAHeldRouteAndStillPrunesOthers(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	localGuest(dp)
	b.refreshLocalHosts(ctx)
	b.apply(ctx, routeAdd(100, guestHost, remoteNH))
	b.apply(ctx, routeAdd(100, "10.0.0.9/32", remoteNH))

	// Reconnect: nothing is replayed.
	b.seen = map[uint32]map[string]bool{}
	b.rxRoutes = map[uint32]uint32{}
	b.handleServerMsg(ctx, &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfRib{EndOfRib: &rbv1.EndOfRIB{Vni: 100}}})
	if withdrewKey(dp, 100, guestHost) {
		t.Fatal("the prune must not withdraw a local guest's host prefix")
	}
	if !withdrewKey(dp, 100, "10.0.0.9/32") {
		t.Fatal("the prune must still withdraw a stale mesh route")
	}

	noLocalGuest(dp)
	b.refreshLocalHosts(ctx)
	if nh, ok := dp.get(100, guestHost); ok {
		t.Fatalf("a held route the reflector no longer has must not be programmed when the guest leaves, got -> %s", nh)
	}
}

// A peer import is guarded the same way: it is not programmed over a local interface's host prefix
// in the importing VNI, and is restored once that interface leaves.
func TestPeerImportOverALocalHostPrefixWaitsForTheInterfaceToLeave(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	setPeerImports(b, map[uint32][]PeerImport{100: {{PeerVNI: 200, ImportPrefixes: []string{"10.0.0.0/24"}}}})
	localGuest(dp)
	b.refreshLocalHosts(ctx)

	b.apply(ctx, routeAdd(200, guestHost, remoteNH))
	if nh, ok := dp.get(100, guestHost); ok {
		t.Fatalf("a peer import must not be programmed over a local host prefix, got -> %s", nh)
	}
	noLocalGuest(dp)
	b.refreshLocalHosts(ctx)
	if nh, ok := dp.get(100, guestHost); !ok || nh != remoteNH {
		t.Fatalf("the peer import must be restored once the guest leaves, got %q ok=%v", nh, ok)
	}
}
