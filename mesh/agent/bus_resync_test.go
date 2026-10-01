// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The routes the bus taught this node converge on the dataplane level-triggered, not only when a
// RouteUpdate arrives: a failed AddRoute or WithdrawRoute is retried on the next reconcile tick, and
// a dataplane that restarted gets every route the bus still holds re-sent — including a mesh route
// a local self-route was holding back, which flowplane cannot recover from its pinned maps.

// tick runs one reconcile tick of b against a reconcile that returns ds, with nothing to send on
// the stream (the delta against an identical applied set is empty).
func tick(t *testing.T, b *Bus, ds DesiredState) {
	t.Helper()
	applied := ds
	if err := b.reconcileStep(context.Background(), nil, func(context.Context) (DesiredState, error) { return ds, nil }, &applied); err != nil {
		t.Fatal(err)
	}
}

func subs(vnis ...uint32) DesiredState { return DesiredState{Subs: vnis} }

func failNextAdd(dp *recordingDP, vni uint32, prefix string, n int) {
	dp.mu.Lock()
	dp.failAdd[key(vni, prefix)] = n
	dp.mu.Unlock()
}

func failNextWithdraw(dp *recordingDP, vni uint32, prefix string, n int) {
	dp.mu.Lock()
	dp.failWithdraw[key(vni, prefix)] = n
	dp.mu.Unlock()
}

func attempts(dp *recordingDP) int {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	return dp.routeAttempts
}

// (1) An AddRoute that failed is re-sent on the next tick, and once it landed the tick is quiet.
func TestFailedAddRouteIsRetriedOnTheNextTick(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", selfNH, dp, false)
	failNextAdd(dp, 100, "10.0.0.7/32", 1)

	b.apply(ctx, routeAdd(100, "10.0.0.7/32", remoteNH))
	if _, ok := dp.get(100, "10.0.0.7/32"); ok {
		t.Fatal("setup: the first AddRoute must have failed")
	}
	tick(t, b, subs(100))
	if nh, ok := dp.get(100, "10.0.0.7/32"); !ok || nh != remoteNH {
		t.Fatalf("the failed AddRoute must be retried on the next tick, got %q ok=%v", nh, ok)
	}
	n := attempts(dp)
	tick(t, b, subs(100))
	if got := attempts(dp); got != n {
		t.Fatalf("a converged tick must not call the dataplane, got %d more route calls", got-n)
	}
}

// (2) A WithdrawRoute that failed is retried, so the dataplane does not keep a route the bus dropped.
func TestFailedWithdrawRouteIsRetriedOnTheNextTick(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", selfNH, dp, false)
	b.apply(ctx, routeAdd(100, "10.0.0.7/32", remoteNH))
	failNextWithdraw(dp, 100, "10.0.0.7/32", 1)

	b.apply(ctx, routeWithdraw(100, "10.0.0.7/32"))
	if withdrewKey(dp, 100, "10.0.0.7/32") {
		t.Fatal("setup: the first WithdrawRoute must have failed")
	}
	tick(t, b, subs(100))
	if !withdrewKey(dp, 100, "10.0.0.7/32") {
		t.Fatal("the failed WithdrawRoute must be retried on the next tick")
	}
}

// A failed peer import and a failed public-default import are retried the same way.
func TestFailedImportsAreRetriedOnTheNextTick(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", selfNH, dp, false)
	ds := DesiredState{
		Subs:           []uint32{PublicVNI, 100, 200},
		EgressVNIs:     []uint32{100},
		PeeringImports: map[uint32][]PeerImport{100: {{PeerVNI: 200, ImportPrefixes: []string{"10.1.0.0/24"}}}},
	}
	tick(t, b, ds)
	failNextAdd(dp, 100, "10.1.0.5/32", 1)
	failNextAdd(dp, 100, "0.0.0.0/0", 1)

	b.apply(ctx, routeAdd(200, "10.1.0.5/32", remoteNH))
	b.apply(ctx, &rbv1.RouteUpdate{Vni: PublicVNI, Prefix: "0.0.0.0/0", Nexthops: []string{"fd00::e"}, Op: rbv1.RouteOp_ROUTE_OP_ADD})
	tick(t, b, ds)
	if nh, ok := dp.get(100, "10.1.0.5/32"); !ok || nh != remoteNH {
		t.Fatalf("a failed peer import must be retried, got %q ok=%v", nh, ok)
	}
	if nh, ok := dp.get(100, "0.0.0.0/0"); !ok || nh != "fd00::e" {
		t.Fatalf("a failed public-default import must be retried, got %q ok=%v", nh, ok)
	}
}

// (3) A restarted dataplane gets every route the bus holds re-sent on the next tick — and none
// the bus withdrew.
func TestDataplaneRestartReassertsTheLearnedRoutes(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	dp.instanceID = "boot-1"
	b := NewBus("nodeA", selfNH, dp, false)
	tick(t, b, subs(100))
	b.apply(ctx, routeAdd(100, "10.0.0.7/32", remoteNH))
	b.apply(ctx, routeAdd(100, "10.0.0.8/32", remoteNH))
	b.apply(ctx, routeWithdraw(100, "10.0.0.8/32"))
	tick(t, b, subs(100))
	if _, ok := dp.get(100, "10.0.0.7/32"); !ok {
		t.Fatal("setup: the route must be programmed")
	}

	dp.restart()
	tick(t, b, subs(100))
	if nh, ok := dp.get(100, "10.0.0.7/32"); !ok || nh != remoteNH {
		t.Fatalf("a restarted dataplane must get the learned route back, got %q ok=%v", nh, ok)
	}
	if _, ok := dp.get(100, "10.0.0.8/32"); ok {
		t.Fatal("a withdrawn route must not be re-sent to a restarted dataplane")
	}
}

// A dataplane that cannot say whether it restarted (no instance id) is re-sent everything once it
// answers again after being unreachable, and on the slow full sweep regardless.
func TestDataplaneWithoutAnInstanceIDIsResentAfterAnOutageAndOnTheSweep(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", selfNH, dp, false)
	b.apply(ctx, routeAdd(100, "10.0.0.7/32", remoteNH))
	tick(t, b, subs(100))

	dp.mu.Lock()
	dp.listErr = status.Error(codes.Unavailable, "connection refused")
	dp.mu.Unlock()
	tick(t, b, subs(100))
	dp.restart()
	dp.mu.Lock()
	dp.listErr = nil
	dp.mu.Unlock()
	tick(t, b, subs(100))
	if _, ok := dp.get(100, "10.0.0.7/32"); !ok {
		t.Fatal("a dataplane that answers again after an outage must be re-sent the learned routes")
	}

	dp.restart() // unnoticed: no outage, no instance id
	tick(t, b, subs(100))
	if _, ok := dp.get(100, "10.0.0.7/32"); ok {
		t.Fatal("setup: an unnoticed restart is not re-sent before the sweep is due")
	}
	b.lastFullResync = time.Now().Add(-fullResyncEvery)
	tick(t, b, subs(100))
	if _, ok := dp.get(100, "10.0.0.7/32"); !ok {
		t.Fatal("the slow full sweep must re-send the learned routes")
	}
}

// (4) Neither a withdrawn nor a pruned key is ever re-asserted, restart or sweep.
func TestWithdrawnAndPrunedKeysAreNeverReasserted(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	dp.instanceID = "boot-1"
	b := NewBus("nodeA", selfNH, dp, false)
	tick(t, b, subs(100))
	b.apply(ctx, routeAdd(100, "10.0.0.7/32", remoteNH))
	b.apply(ctx, routeAdd(100, "10.0.0.8/32", remoteNH))
	b.apply(ctx, routeWithdraw(100, "10.0.0.7/32"))
	// Reconnect: the replay no longer carries 10.0.0.8.
	b.seen = map[uint32]map[string]bool{}
	b.rxRoutes = map[uint32]uint32{}
	b.handleServerMsg(ctx, &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfRib{EndOfRib: &rbv1.EndOfRIB{Vni: 100}}})
	n7, n8 := len(addsFor(dp, 100, "10.0.0.7/32")), len(addsFor(dp, 100, "10.0.0.8/32"))

	dp.restart()
	tick(t, b, subs(100))
	b.lastFullResync = time.Now().Add(-fullResyncEvery)
	tick(t, b, subs(100))
	if got := addsFor(dp, 100, "10.0.0.7/32"); len(got) != n7 {
		t.Fatalf("a withdrawn key must not be re-asserted, got %+v", got[n7:])
	}
	if got := addsFor(dp, 100, "10.0.0.8/32"); len(got) != n8 {
		t.Fatalf("a pruned key must not be re-asserted, got %+v", got[n8:])
	}
}

// (5) The re-assert keeps the local-host-key rules: a held key's bus route is passed through (it
// is exactly what flowplane loses across a restart), never as X->self, and a key only this node
// announces is never sent at all.
func TestReassertKeepsTheLocalHostKeyRules(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	dp.instanceID = "boot-1"
	b := newGuestBus(dp)
	localGuest(dp)
	tick(t, b, subs(100))
	b.apply(ctx, routeAdd(100, guestHost, selfNH, remoteNH)) // held: the guest is here
	const onlySelf = "10.0.0.6/32"
	dp.mu.Lock()
	dp.ifaces = append(dp.ifaces, LocalInterface{InterfaceID: "vm2", Vni: 100, OverlayIPs: []string{"10.0.0.6"}, Underlay: selfNH})
	dp.mu.Unlock()
	tick(t, b, subs(100))
	b.apply(ctx, routeAdd(100, onlySelf, selfNH))
	n := len(addsFor(dp, 100, guestHost))

	dp.restart()
	tick(t, b, subs(100))
	got := addsFor(dp, 100, guestHost)
	if len(got) != n+1 || got[n].nexthop != remoteNH {
		t.Fatalf("a held key's bus route must be re-sent -> %s after a restart, got %+v", remoteNH, got[n:])
	}
	for _, c := range append(addsFor(dp, 100, onlySelf), got...) {
		if c.nexthop == selfNH {
			t.Fatalf("X->self must never reach the dataplane, got %+v", c)
		}
	}
}

// (6) Routes of a VNI this node no longer subscribes to are withdrawn — the reflector stops
// updating them, so they could only go stale — and are never re-asserted.
func TestRoutesOfAnUnsubscribedVNIAreWithdrawnAndNotReasserted(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	dp.instanceID = "boot-1"
	b := NewBus("nodeA", selfNH, dp, false)
	tick(t, b, subs(100, 300))
	b.apply(ctx, routeAdd(300, "10.3.0.7/32", remoteNH))
	b.apply(ctx, routeAdd(100, "10.0.0.7/32", remoteNH))

	for range unsubscribeAfterTicks {
		tick(t, b, subs(100))
	}
	if !withdrewKey(dp, 300, "10.3.0.7/32") {
		t.Fatal("a route of an unsubscribed VNI must be withdrawn")
	}
	if withdrewKey(dp, 100, "10.0.0.7/32") {
		t.Fatal("a route of a still-subscribed VNI must stay")
	}
	n := len(addsFor(dp, 300, "10.3.0.7/32"))
	dp.restart()
	tick(t, b, subs(100))
	if got := addsFor(dp, 300, "10.3.0.7/32"); len(got) != n {
		t.Fatalf("a route of an unsubscribed VNI must not be re-asserted, got %+v", got[n:])
	}
	if _, ok := dp.get(100, "10.0.0.7/32"); !ok {
		t.Fatal("the subscribed VNI's route must be re-asserted")
	}
}

// While the dataplane is unreachable a tick stops at the first failed call instead of failing
// every pending route one by one.
func TestTickStopsAtAnUnreachableDataplane(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", selfNH, dp, false)
	dp.mu.Lock()
	dp.failErr = status.Error(codes.Unavailable, "connection refused")
	dp.mu.Unlock()
	failNextAdd(dp, 100, "10.0.0.7/32", 2)
	failNextAdd(dp, 100, "10.0.0.8/32", 2)
	b.apply(ctx, routeAdd(100, "10.0.0.7/32", remoteNH))
	b.apply(ctx, routeAdd(100, "10.0.0.8/32", remoteNH))

	n := attempts(dp)
	tick(t, b, subs(100))
	if got := attempts(dp) - n; got != 1 {
		t.Fatalf("an unreachable dataplane must cost one call per tick, got %d", got)
	}
}

// Peering configured after the peer's routes were learned (its VNI already subscribed, so there is
// no replay) imports them on the next tick, and removing it withdraws them.
func TestPeeringChangeConvergesWithoutAReplay(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", selfNH, dp, false)
	tick(t, b, subs(100, 200))
	b.apply(ctx, routeAdd(200, "10.1.0.5/32", remoteNH))

	peered := DesiredState{
		Subs:           []uint32{100, 200},
		PeeringImports: map[uint32][]PeerImport{100: {{PeerVNI: 200, ImportPrefixes: []string{"10.1.0.0/24"}}}},
	}
	tick(t, b, peered)
	if got := lastAdd(dp, "10.1.0.5/32"); got == nil || got.vni != 100 || got.deliveryVNI != 200 {
		t.Fatalf("a newly configured peering must import the learned route into vni 100, got %+v", got)
	}
	tick(t, b, subs(100, 200))
	if !withdrewKey(dp, 100, "10.1.0.5/32") {
		t.Fatal("removing the peering must withdraw the import")
	}
}

// A public default the reflector no longer has when it replays the public VNI is pruned from the
// egress VNIs like any other route, so the re-assert cannot keep it alive.
func TestPruneOfThePublicVNIDropsAStaleDefault(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", selfNH, dp, false)
	ds := DesiredState{Subs: []uint32{PublicVNI, 100}, EgressVNIs: []uint32{100}}
	tick(t, b, ds)
	b.apply(ctx, &rbv1.RouteUpdate{Vni: PublicVNI, Prefix: "0.0.0.0/0", Nexthops: []string{"fd00::e"}, Op: rbv1.RouteOp_ROUTE_OP_ADD})

	b.seen = map[uint32]map[string]bool{}
	b.rxRoutes = map[uint32]uint32{}
	b.handleServerMsg(ctx, &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfRib{EndOfRib: &rbv1.EndOfRIB{Vni: PublicVNI}}})
	if !withdrewKey(dp, 100, "0.0.0.0/0") {
		t.Fatal("a public default the replay did not carry must be withdrawn from the egress vni")
	}
	if _, ok := b.LearnedPublic()["0.0.0.0/0"]; ok {
		t.Fatal("and forgotten")
	}
}

// A VNI is forgotten only once it has been missing from the subscriptions for
// unsubscribeAfterTicks ticks in a row: a guest pod that restarts, or one reconcile that reads
// without the peering, must not withdraw and re-learn a VNI's routes.
func TestABrieflyUnsubscribedVNIKeepsItsRoutes(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", selfNH, dp, false)
	tick(t, b, subs(100, 300))
	b.apply(ctx, routeAdd(300, "10.3.0.7/32", remoteNH))

	for range unsubscribeAfterTicks - 1 {
		tick(t, b, subs(100))
	}
	tick(t, b, subs(100, 300)) // back: the count starts over
	for range unsubscribeAfterTicks - 1 {
		tick(t, b, subs(100))
	}
	if withdrewKey(dp, 300, "10.3.0.7/32") {
		t.Fatal("a VNI missing for fewer than unsubscribeAfterTicks ticks in a row must keep its routes")
	}
	tick(t, b, subs(100))
	if !withdrewKey(dp, 300, "10.3.0.7/32") {
		t.Fatalf("a VNI missing for %d ticks in a row must be withdrawn", unsubscribeAfterTicks)
	}
}

// learnRoutes applies n routes on vni 100 (1.9.x.y/32 -> remoteNH; they sort before guestHost).
func learnRoutes(b *Bus, n int) {
	for i := range n {
		b.apply(context.Background(), routeAdd(100, fmt.Sprintf("1.9.%d.%d/32", i/250, i%250+1), remoteNH))
	}
}

// A full re-send is spread over ticks, routeCallsPerTick calls at most each, so the Run goroutine
// never blocks long enough on the dataplane to back up the route-bus stream (whose reflector side
// drops live deltas it cannot deliver). The keys a restart actually loses — held local host keys —
// go first.
func TestAFullResendIsSpreadOverTicks(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	dp.instanceID = "boot-1"
	b := newGuestBus(dp)
	localGuest(dp)
	tick(t, b, subs(100))
	n := 2*routeCallsPerTick + routeCallsPerTick/2
	learnRoutes(b, n)
	b.apply(ctx, routeAdd(100, guestHost, remoteNH))

	dp.restart()
	before := attempts(dp)
	tick(t, b, subs(100))
	if got := attempts(dp) - before; got > routeCallsPerTick {
		t.Fatalf("one tick must make at most %d dataplane calls, made %d", routeCallsPerTick, got)
	}
	if _, ok := dp.get(100, guestHost); !ok {
		t.Fatal("the held key, which a restart actually loses, must be re-sent on the first tick")
	}
	for range 2 {
		before = attempts(dp)
		tick(t, b, subs(100))
		if got := attempts(dp) - before; got > routeCallsPerTick {
			t.Fatalf("one tick must make at most %d dataplane calls, made %d", routeCallsPerTick, got)
		}
	}
	dp.mu.Lock()
	got := len(dp.added)
	dp.mu.Unlock()
	if got != n+1 {
		t.Fatalf("the re-send must converge over ticks: %d of %d routes back", got, n+1)
	}
	before = attempts(dp)
	tick(t, b, subs(100))
	if got := attempts(dp) - before; got != 0 {
		t.Fatalf("a finished re-send must leave the tick quiet, got %d calls", got)
	}
}

// A dataplane that reports an instance id announces its restarts, so it gets no timed sweep: each
// would cost a call per learned route for nothing.
func TestNoTimedSweepWhenTheDataplaneReportsAnInstanceID(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	dp.instanceID = "boot-1"
	b := NewBus("nodeA", selfNH, dp, false)
	b.apply(ctx, routeAdd(100, "10.0.0.7/32", remoteNH))
	tick(t, b, subs(100))

	dp.loseRoutes()
	b.lastFullResync = time.Now().Add(-fullResyncEvery)
	before := attempts(dp)
	tick(t, b, subs(100))
	if got := attempts(dp) - before; got != 0 {
		t.Fatalf("no timed sweep against a dataplane with an instance id, got %d calls", got)
	}
}

// A key whose AddRoute keeps failing is retried with exponential backoff, not every tick, and its
// failure is logged once rather than on every retry. It is programmed once the call succeeds.
func TestAPersistentlyFailingRouteBacksOff(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", selfNH, dp, false)
	failNextAdd(dp, 100, "10.0.0.7/32", 1000)
	b.apply(ctx, routeAdd(100, "10.0.0.7/32", remoteNH))

	const ticks = 20
	before := attempts(dp)
	for range ticks {
		tick(t, b, subs(100))
	}
	got := attempts(dp) - before
	if got < 3 || got > 6 {
		t.Fatalf("over %d ticks a failing key must be retried with backoff (about log2 of them), got %d calls", ticks, got)
	}
	if n := strings.Count(logs.String(), "AddRoute vni=100 10.0.0.7/32"); n != 1 {
		t.Fatalf("a persistently failing key must be logged once, not on every retry; got %d lines:\n%s", n, logs.String())
	}

	failNextAdd(dp, 100, "10.0.0.7/32", 0)
	for range retryMaxTicks + 1 {
		tick(t, b, subs(100))
	}
	if _, ok := dp.get(100, "10.0.0.7/32"); !ok {
		t.Fatal("the key must be programmed once its AddRoute succeeds")
	}
	before = attempts(dp)
	tick(t, b, subs(100))
	if got := attempts(dp) - before; got != 0 {
		t.Fatalf("a recovered key must leave the tick quiet, got %d calls", got)
	}
}

// peered is a desired state where vni 100 imports 10.2.0.0/16 from each of peers, in order.
func peered(peers ...uint32) DesiredState {
	ds := DesiredState{Subs: []uint32{100, 200, 300}, PeeringImports: map[uint32][]PeerImport{}}
	for _, p := range peers {
		ds.PeeringImports[100] = append(ds.PeeringImports[100], PeerImport{PeerVNI: p, ImportPrefixes: []string{"10.2.0.0/16"}})
	}
	return ds
}

// backOffImport leaves vni 100's import of 10.2.0.5/32 refused and well into its backoff: the
// peer route moved to fd00::p2 and every AddRoute for the import fails.
func backOffImport(t *testing.T, b *Bus, dp *recordingDP, ds DesiredState) {
	t.Helper()
	ctx := context.Background()
	tick(t, b, ds)
	b.apply(ctx, routeAdd(200, "10.2.0.5/32", "fd00::p1"))
	if nh, ok := dp.get(100, "10.2.0.5/32"); !ok || nh != "fd00::p1" {
		t.Fatalf("setup: the import must be programmed, got %q ok=%v", nh, ok)
	}
	failNextAdd(dp, 100, "10.2.0.5/32", 1000)
	b.apply(ctx, routeAdd(200, "10.2.0.5/32", "fd00::p2"))
	for range 4 {
		tick(t, b, ds)
	}
	r := b.retries[routeRef{100, "10.2.0.5/32"}]
	if r == nil || b.ticks+1 >= r.nextTick {
		t.Fatalf("setup: the import must be backing off past the next tick, got %+v at tick %d", r, b.ticks)
	}
}

// Revoking a peering is a security boundary: the import must leave the kernel on the very next
// tick, even while the import's AddRoute is backing off. Backoff throttles retrying the route that
// failed, never a withdraw.
func TestARevokedPeeringIsWithdrawnAtOnceEvenWhileBackingOff(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("nodeA", selfNH, dp, false)
	backOffImport(t, b, dp, peered(200))

	tick(t, b, peered())
	if !withdrewKey(dp, 100, "10.2.0.5/32") {
		t.Fatal("the import of a revoked peering must be withdrawn on the next tick, backoff or not")
	}
}

// A key backs off only while it still wants the route that failed: once the wanted route changes,
// the new one goes out on the next tick.
func TestANewWantedRouteIsNotHeldBackByTheOldOnesBackoff(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("nodeA", selfNH, dp, false)
	b.apply(context.Background(), routeAdd(300, "10.2.0.5/32", "fd00::q"))
	backOffImport(t, b, dp, peered(200, 300))

	failNextAdd(dp, 100, "10.2.0.5/32", 0) // so the fake records the attempt's route
	before := attempts(dp)
	tick(t, b, peered(300, 200)) // vni 300's route now wins the key
	if got := attempts(dp) - before; got != 1 {
		t.Fatalf("the newly wanted route must be attempted on the next tick, got %d calls", got)
	}
	if got := lastAdd(dp, "10.2.0.5/32"); got == nil || got.vni != 100 || got.deliveryVNI != 300 {
		t.Fatalf("the attempt must be the new route, got %+v", got)
	}
}

// A key the bus withdrew after a full re-send queued it is neither wanted nor programmed: the
// re-send skips it rather than spend a call on it.
func TestAFullResendSkipsKeysForgottenSinceItWasQueued(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	dp.instanceID = "boot-1"
	b := NewBus("nodeA", selfNH, dp, false)
	tick(t, b, subs(100))
	learnRoutes(b, routeCallsPerTick+10)

	dp.restart()
	tick(t, b, subs(100))
	for i := range routeCallsPerTick + 10 {
		b.apply(ctx, routeWithdraw(100, fmt.Sprintf("1.9.%d.%d/32", i/250, i%250+1)))
	}
	before := attempts(dp)
	tick(t, b, subs(100))
	if got := attempts(dp) - before; got != 0 {
		t.Fatalf("a re-send must skip keys neither wanted nor programmed, got %d calls", got)
	}
}
