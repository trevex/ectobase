// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"testing"

	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// A bus route for a locally attached interface's host prefix — the guest's own /32 announced by
// another node during a VM move, say — is handed to the dataplane like any other: flowplane holds
// that key for the interface and applies the add/withdraw to its shadow only, reinstalling the
// shadowed route when the interface detaches. The agent adds one fallback on top: once the
// interface leaves, it re-asserts the bus route it holds for the key, in case flowplane lost its
// shadow across a restart.

const (
	guestIP   = "10.0.0.5"
	guestHost = "10.0.0.5/32"
	selfNH    = "fd00::a" // this node's VTEP
	remoteNH  = "fd00::b" // another node's VTEP announcing the same /32
)

func localGuest(dp *recordingDP) {
	dp.mu.Lock()
	dp.ifaces = []LocalInterface{{InterfaceID: "vm", Vni: 100, OverlayIPs: []string{guestIP}, Underlay: selfNH}}
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

// addsFor returns every AddRoute call for (vni, prefix), in order.
func addsFor(dp *recordingDP, vni uint32, prefix string) []routeCall {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	var out []routeCall
	for _, c := range dp.routeAdds {
		if c.vni == vni && c.prefix == prefix {
			out = append(out, c)
		}
	}
	return out
}

func routeAdd(vni uint32, prefix string, nhs ...string) *rbv1.RouteUpdate {
	return &rbv1.RouteUpdate{Vni: vni, Prefix: prefix, Nexthops: nhs, Op: rbv1.RouteOp_ROUTE_OP_ADD}
}

func routeWithdraw(vni uint32, prefix string) *rbv1.RouteUpdate {
	return &rbv1.RouteUpdate{Vni: vni, Prefix: prefix, Op: rbv1.RouteOp_ROUTE_OP_WITHDRAW}
}

func newGuestBus(dp *recordingDP) *Bus { return NewBus("nodeA", selfNH, dp, false) }

// An ADD and a WITHDRAW for a local guest's own /32 reach the dataplane like any other key, and
// the agent keeps its ordinary bookkeeping for it.
func TestBusRouteForALocalHostPrefixIsPassedThrough(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := newGuestBus(dp)
	localGuest(dp)
	b.refreshLocalHosts(ctx)

	b.apply(ctx, routeAdd(100, guestHost, remoteNH))
	if nh, ok := dp.get(100, guestHost); !ok || nh != remoteNH {
		t.Fatalf("the ADD must reach the dataplane (flowplane shadows it while the key is held), got %q ok=%v", nh, ok)
	}
	if !b.installed[100][guestHost] {
		t.Fatal("the agent must keep its installed bookkeeping for a local host key")
	}
	b.apply(ctx, routeWithdraw(100, guestHost))
	if !withdrewKey(dp, 100, guestHost) {
		t.Fatal("the WITHDRAW must reach the dataplane, or flowplane's shadow keeps a stale route")
	}
}

// An interface arriving over a programmed bus route changes nothing on the agent's side: no
// withdraw, no bookkeeping drop. The old node's later WITHDRAW is passed through, so flowplane's
// shadow does not keep a stale route to reinstall on detach.
func TestLocalInterfaceArrivingOverAProgrammedRouteKeepsItsBookkeeping(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := newGuestBus(dp)
	b.refreshLocalHosts(ctx)
	b.apply(ctx, routeAdd(100, guestHost, remoteNH))

	localGuest(dp)
	b.refreshLocalHosts(ctx)
	if withdrewKey(dp, 100, guestHost) {
		t.Fatal("the interface arriving must not withdraw the key")
	}
	if !b.installed[100][guestHost] {
		t.Fatal("the interface arriving must not drop the route from the bookkeeping")
	}
	b.apply(ctx, routeWithdraw(100, guestHost))
	if !withdrewKey(dp, 100, guestHost) {
		t.Fatal("the old node's WITHDRAW must reach the dataplane")
	}
}

// Fallback: once the guest leaves, the agent re-asserts the bus route it holds for the key, in case
// flowplane lost its shadow across a restart.
func TestHeldRouteIsReassertedOnceTheLocalInterfaceLeaves(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := newGuestBus(dp)
	localGuest(dp)
	b.refreshLocalHosts(ctx)
	b.apply(ctx, routeAdd(100, guestHost, remoteNH))
	n := len(addsFor(dp, 100, guestHost))

	noLocalGuest(dp)
	b.refreshLocalHosts(ctx)
	got := addsFor(dp, 100, guestHost)
	if len(got) != n+1 || got[n].nexthop != remoteNH {
		t.Fatalf("the held route must be re-asserted -> %s once the guest leaves, got %+v", remoteNH, got[n:])
	}
}

// The fallback never reinstates what the bus has withdrawn.
func TestRouteWithdrawnWhileLocalIsNotReassertedOnLeave(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := newGuestBus(dp)
	localGuest(dp)
	b.refreshLocalHosts(ctx)
	b.apply(ctx, routeAdd(100, guestHost, remoteNH))
	b.apply(ctx, routeWithdraw(100, guestHost))
	n := len(addsFor(dp, 100, guestHost))

	noLocalGuest(dp)
	b.refreshLocalHosts(ctx)
	if got := addsFor(dp, 100, guestHost); len(got) != n {
		t.Fatalf("a withdrawn route must not be re-asserted when the guest leaves, got %+v", got[n:])
	}
}

// The held set can carry this node's own VTEP (it announced the /32 too, e.g. mid-move). The
// fallback must re-assert a nexthop that is NOT this node — and nothing when only this node is left.
func TestReassertSkipsThisNodesOwnNexthop(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := newGuestBus(dp)
	localGuest(dp)
	b.refreshLocalHosts(ctx)
	b.apply(ctx, routeAdd(100, guestHost, selfNH, remoteNH))
	n := len(addsFor(dp, 100, guestHost))

	noLocalGuest(dp)
	b.refreshLocalHosts(ctx)
	got := addsFor(dp, 100, guestHost)
	if len(got) != n+1 || got[n].nexthop != remoteNH {
		t.Fatalf("the re-assert must skip this node's own nexthop and use %s, got %+v", remoteNH, got[n:])
	}

	// Only this node left in the set: nothing to re-assert.
	dp2 := newRecordingDP()
	b2 := newGuestBus(dp2)
	localGuest(dp2)
	b2.refreshLocalHosts(ctx)
	b2.apply(ctx, routeAdd(100, guestHost, selfNH))
	n2 := len(addsFor(dp2, 100, guestHost))
	noLocalGuest(dp2)
	b2.refreshLocalHosts(ctx)
	if got := addsFor(dp2, 100, guestHost); len(got) != n2 {
		t.Fatalf("with only this node's own nexthop there is nothing to re-assert, got %+v", got[n2:])
	}
}

// A local host key sent a set that includes this node (it announced the /32 too, mid-move) is
// programmed to the first nexthop that is NOT this node, so flowplane's shadow never holds X->self.
func TestLocalHostKeySkipsThisNodesOwnNexthop(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := newGuestBus(dp)
	localGuest(dp)
	b.refreshLocalHosts(ctx)

	b.apply(ctx, routeAdd(100, guestHost, selfNH, remoteNH))
	if nh, ok := dp.get(100, guestHost); !ok || nh != remoteNH {
		t.Fatalf("a local host key must be programmed to the first nexthop that is not this node (%s), got %q ok=%v", remoteNH, nh, ok)
	}
}

// Sent only this node, a local host key has nothing to program: the dataplane gets a withdraw, and
// neither then nor when the guest leaves does X->self ever reach it.
func TestLocalHostKeyWithOnlyThisNodeIsWithdrawn(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := newGuestBus(dp)
	localGuest(dp)
	b.refreshLocalHosts(ctx)
	b.apply(ctx, routeAdd(100, guestHost, remoteNH)) // the other node's route, programmed

	b.apply(ctx, routeAdd(100, guestHost, selfNH)) // now only this node announces it
	if !withdrewKey(dp, 100, guestHost) {
		t.Fatal("a local host key sent only this node must be withdrawn from the dataplane")
	}
	if b.installed[100][guestHost] {
		t.Fatal("nothing is installed for it any more")
	}

	noLocalGuest(dp)
	b.refreshLocalHosts(ctx)
	for _, c := range addsFor(dp, 100, guestHost) {
		if c.nexthop == selfNH {
			t.Fatalf("X->self must never reach the dataplane, got %+v", c)
		}
	}
}

// Peer imports into a local host key choose their nexthop the same way.
func TestPeerImportIntoALocalHostKeySkipsThisNodesOwnNexthop(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := newGuestBus(dp)
	setPeerImports(b, map[uint32][]PeerImport{100: {{PeerVNI: 200, ImportPrefixes: []string{"10.0.0.0/24"}}}})
	localGuest(dp)
	b.refreshLocalHosts(ctx)

	b.apply(ctx, routeAdd(200, guestHost, selfNH, remoteNH))
	if nh, ok := dp.get(100, guestHost); !ok || nh != remoteNH {
		t.Fatalf("a peer import into a local host key must skip this node's own nexthop, got %q ok=%v", nh, ok)
	}
}

// An E/W LB address is an anycast key with no self-route behind it: not a local host prefix, so it
// keeps today's behaviour even on a node that hosts a guest in the same VNI — including a self
// nexthop first, which flowplane delivers locally.
func TestAnycastLBAddressIsUnaffected(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := newGuestBus(dp)
	localGuest(dp)
	b.refreshLocalHosts(ctx)

	const lb = "10.0.0.100/32"
	b.apply(ctx, routeAdd(100, lb, selfNH, remoteNH))
	if nh, ok := dp.get(100, lb); !ok || nh != selfNH {
		t.Fatalf("an LB address must be programmed as today (primary nexthop), got %q ok=%v", nh, ok)
	}
	b.apply(ctx, routeWithdraw(100, lb))
	if !withdrewKey(dp, 100, lb) {
		t.Fatal("an LB address must be withdrawn as today")
	}
}

// The EndOfRIB prune treats a local host key like any other: a route the reflector no longer has is
// withdrawn (flowplane drops it from its shadow) and forgotten, so the fallback cannot re-assert it
// when the guest leaves.
func TestPruneWithdrawsAndForgetsAStaleRouteForALocalHostKey(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := newGuestBus(dp)
	localGuest(dp)
	b.refreshLocalHosts(ctx)
	b.apply(ctx, routeAdd(100, guestHost, remoteNH))

	// Reconnect: nothing is replayed.
	b.seen = map[uint32]map[string]bool{}
	b.rxRoutes = map[uint32]uint32{}
	b.handleServerMsg(ctx, &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfRib{EndOfRib: &rbv1.EndOfRIB{Vni: 100}}})
	if !withdrewKey(dp, 100, guestHost) {
		t.Fatal("the prune must withdraw a stale route for a local host key too")
	}
	n := len(addsFor(dp, 100, guestHost))
	noLocalGuest(dp)
	b.refreshLocalHosts(ctx)
	if got := addsFor(dp, 100, guestHost); len(got) != n {
		t.Fatalf("a pruned route must not be re-asserted when the guest leaves, got %+v", got[n:])
	}
}

// A route re-asserted on leave is recorded as installed but not as replayed: if the reflector no
// longer has it, the in-progress replay's prune still removes it.
func TestReassertedRouteIsStillPrunable(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := newGuestBus(dp)
	localGuest(dp)
	b.refreshLocalHosts(ctx)
	b.apply(ctx, routeAdd(100, guestHost, remoteNH))

	// Reconnect; the guest leaves before the replay closes, and the replay does not carry the /32.
	b.seen = map[uint32]map[string]bool{}
	b.rxRoutes = map[uint32]uint32{}
	noLocalGuest(dp)
	b.refreshLocalHosts(ctx)
	b.handleServerMsg(ctx, &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfRib{EndOfRib: &rbv1.EndOfRIB{Vni: 100}}})
	if !withdrewKey(dp, 100, guestHost) {
		t.Fatal("a re-asserted route the replay did not carry must be pruned")
	}
}

// Peer imports pass through the same way.
func TestPeerImportOverALocalHostPrefixIsPassedThrough(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := newGuestBus(dp)
	setPeerImports(b, map[uint32][]PeerImport{100: {{PeerVNI: 200, ImportPrefixes: []string{"10.0.0.0/24"}}}})
	localGuest(dp)
	b.refreshLocalHosts(ctx)

	b.apply(ctx, routeAdd(200, guestHost, remoteNH))
	if nh, ok := dp.get(100, guestHost); !ok || nh != remoteNH {
		t.Fatalf("a peer import must reach the dataplane like any other, got %q ok=%v", nh, ok)
	}
}
