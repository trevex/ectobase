package agent

import (
	"context"
	"testing"

	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// An edge attracts its share of the anycast ECMP the moment its prefix is advertised. If that
// happens before the bus session has replayed the LB addresses and their backends, the edge
// DSR-dispatches traffic it has no Maglev table for — a blackhole on every cold start, and the gap
// docs/features/ns-edge.md calls out as "not built: convergence gating". `Converged` is the signal
// a deployment gates the advertisement on (readiness probe → BGP speaker / Service).

// Convergence means the whole picture arrived: every subscribed VNI's routes AND the global
// snapshot that carries the LB/NAT state the edge actually runs on.
func TestConvergedRequiresBothTheGlobalSnapshotAndEveryVNI(t *testing.T) {
	ctx := context.Background()
	b := NewBus("edge", "fd00::e", newRecordingDP(), true)
	b.noteSubscribed([]uint32{100, 200})

	if b.Converged() {
		t.Fatal("a fresh bus has received nothing; it must not report converged")
	}

	// Global snapshot done, but the VNIs have not caught up.
	b.handleServerMsg(ctx, endOfGlobal(0))
	if b.Converged() {
		t.Fatal("global snapshot alone is not convergence: subscribed VNIs are still outstanding")
	}

	b.handleServerMsg(ctx, &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfRib{EndOfRib: &rbv1.EndOfRIB{Vni: 100}}})
	if b.Converged() {
		t.Fatal("vni 200 has not sent EndOfRIB yet")
	}

	b.handleServerMsg(ctx, &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfRib{EndOfRib: &rbv1.EndOfRIB{Vni: 200}}})
	if !b.Converged() {
		t.Fatal("every subscribed VNI plus the global snapshot arrived; must be converged")
	}
}

// A node that subscribes to nothing (a bare edge has no tenant guests of its own) converges on the
// global snapshot alone — otherwise it would never become ready and would never advertise.
func TestConvergedWithNoSubscriptionsNeedsOnlyTheGlobalSnapshot(t *testing.T) {
	ctx := context.Background()
	b := NewBus("edge", "fd00::e", newRecordingDP(), true)
	b.noteSubscribed(nil)

	if b.Converged() {
		t.Fatal("nothing received yet")
	}
	b.handleServerMsg(ctx, endOfGlobal(0))
	if !b.Converged() {
		t.Fatal("with no subscriptions the global snapshot is the whole picture")
	}
}

// Deliberately LATCHING. Once converged, a reconnect must not un-advertise: the dataplane tables
// are already programmed and a brief reflector blip does not make them wrong, so dropping
// readiness would reshuffle every WAN flow across the remaining edges for nothing. The bug being
// fixed is the COLD-START blackhole, not steady-state churn.
func TestConvergedLatchesAcrossReconnects(t *testing.T) {
	ctx := context.Background()
	b := NewBus("edge", "fd00::e", newRecordingDP(), true)
	b.noteSubscribed([]uint32{100})
	b.handleServerMsg(ctx, endOfGlobal(0))
	b.handleServerMsg(ctx, &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfRib{EndOfRib: &rbv1.EndOfRIB{Vni: 100}}})
	if !b.Converged() {
		t.Fatal("setup: expected convergence")
	}

	// Session drops and reopens: per-session progress resets, the latch does not.
	b.resetGlobalSnapshot()
	b.seen = map[uint32]map[string]bool{}
	if !b.Converged() {
		t.Fatal("convergence must latch: a reconnect does not invalidate already-programmed tables")
	}
}

// A VNI subscribed AFTER convergence (a new VPC lands on this node) must not retroactively
// un-converge it — same churn argument as the reconnect case.
func TestConvergedIsNotRevokedByANewSubscription(t *testing.T) {
	ctx := context.Background()
	b := NewBus("edge", "fd00::e", newRecordingDP(), true)
	b.noteSubscribed([]uint32{100})
	b.handleServerMsg(ctx, endOfGlobal(0))
	b.handleServerMsg(ctx, &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfRib{EndOfRib: &rbv1.EndOfRIB{Vni: 100}}})
	if !b.Converged() {
		t.Fatal("setup: expected convergence")
	}

	b.noteSubscribed([]uint32{100, 300})
	if !b.Converged() {
		t.Fatal("a later subscription must not revoke an established advertisement")
	}
}
