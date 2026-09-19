package agent

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"testing"

	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The global (NAT + public) channel is replayed in full when a session registers, exactly like a
// VNI's routes — but it had no EndOfRIB equivalent, so nothing ever pruned it. A record WITHDRAWN
// while this agent was disconnected is simply absent from the replayed snapshot, and its dataplane
// entry lingered forever: Maglev kept hashing a share of flows to a backend that no longer exists,
// and neighbor-NAT kept a return route to a block that had moved. These tests pin the EndOfGlobal
// prune that closes it, and — just as importantly — the guard that stops it from pruning LIVE state
// when the replay was lossy.
//
// The NAT half is no longer a prune at all: only a WAN EDGE holds neighbor-NAT blocks, and it makes
// its set exactly the snapshot's in one declarative ReplaceNeighborNats at the marker — which also
// removes a block the dataplane adopted from its pinned maps that no agent remembers installing.

func natAdd(natIP string, min, max uint32, owner string, vni uint32) *rbv1.ServerMsg {
	return &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_NatUpdate{NatUpdate: &rbv1.NatUpdate{
		Vni: vni, SourceIp: "10.0.0.9", NatIp: natIP, PortMin: min, PortMax: max,
		OwnerUnderlay: owner, Op: rbv1.RouteOp_ROUTE_OP_ADD,
	}}}
}

func endOfGlobal(n uint32) *rbv1.ServerMsg {
	return &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfGlobal{EndOfGlobal: &rbv1.EndOfGlobal{RecordCount: n}}}
}

func natWithdraw(natIP string, min, max uint32, owner string, vni uint32) *rbv1.ServerMsg {
	m := natAdd(natIP, min, max, owner, vni)
	m.GetNatUpdate().Op = rbv1.RouteOp_ROUTE_OP_WITHDRAW
	return m
}

// blocksOf renders a replace call as sorted "ip min max owner" strings, to compare as a set.
func blocksOf(bs []NeighborNatBlock) []string {
	out := make([]string, 0, len(bs))
	for _, b := range bs {
		out = append(out, fmt.Sprintf("%s %d %d %s", b.NatIP, b.PortMin, b.PortMax, b.OwnerUnderlay))
	}
	sort.Strings(out)
	return out
}

func wantReplaces(t *testing.T, dp *recordingDP, want ...[]string) {
	t.Helper()
	if len(dp.nbrNatReplaces) != len(want) {
		t.Fatalf("want %d ReplaceNeighborNats calls, got %d: %v", len(want), len(dp.nbrNatReplaces), dp.nbrNatReplaces)
	}
	for i, w := range want {
		if got := blocksOf(dp.nbrNatReplaces[i]); !slices.Equal(got, w) {
			t.Fatalf("replace %d: got %v, want %v", i, got, w)
		}
	}
}

// A compute node opts out of the global feed; an edge takes it.
func TestOnlyAnEdgeTakesTheGlobalFeed(t *testing.T) {
	if f := NewBus("nodeB", "fd00::b", newRecordingDP(), false).hello().GlobalFeed; f != rbv1.GlobalFeed_GLOBAL_FEED_NONE {
		t.Fatalf("compute node Hello: global_feed = %v, want NONE", f)
	}
	if f := NewBus("edge", "fd00::e", newRecordingDP(), true).hello().GlobalFeed; f != rbv1.GlobalFeed_GLOBAL_FEED_ALL {
		t.Fatalf("edge Hello: global_feed = %v, want ALL", f)
	}
}

// A compute node holds no neighbor-NAT blocks (only an edge relays NAT returns). An older reflector
// may still send it NAT records: it ignores them, and its complete snapshot replaces the set with
// the empty one, clearing whatever an older agent installed.
func TestComputeNodeHoldsNoNeighborNat(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeB", "fd00::b", dp, false)
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, natAdd("192.0.2.7", 1024, 2048, "fd00::a", 100))
	b.handleServerMsg(ctx, endOfGlobal(1))
	b.handleServerMsg(ctx, natAdd("192.0.2.8", 1024, 2048, "fd00::a", 100)) // a live delta
	if dp.nbrNatAdds != 0 {
		t.Fatalf("a compute node must not program neighbor-NAT, got %d adds", dp.nbrNatAdds)
	}
	wantReplaces(t, dp, []string{})
}

// An edge applies a complete snapshot as ONE replace — no per-block add during the replay, so an
// unchanged block is never unprogrammed — and leaves out a block this node owns.
func TestEdgeReplacesNeighborNatsAtACompleteSnapshot(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("edge", "fd00::e", dp, true)
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, natAdd("192.0.2.7", 1024, 2048, "fd00::a", 100))
	b.handleServerMsg(ctx, natAdd("192.0.2.8", 2048, 3072, "fd00::c", 100))
	b.handleServerMsg(ctx, natAdd("192.0.2.9", 1024, 2048, "fd00::e", 100)) // owned by this node
	if dp.nbrNatAdds != 0 {
		t.Fatalf("replayed blocks must wait for the marker, got %d adds", dp.nbrNatAdds)
	}
	b.handleServerMsg(ctx, endOfGlobal(3))
	wantReplaces(t, dp, []string{"192.0.2.7 1024 2048 fd00::a", "192.0.2.8 2048 3072 fd00::c"})
}

// A block that left while the edge was disconnected is absent from the next complete snapshot, and
// its replace removes it.
func TestEdgeReplaceDropsABlockThatLeftWhileDisconnected(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("edge", "fd00::e", dp, true)
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, natAdd("192.0.2.7", 1024, 2048, "fd00::a", 100))
	b.handleServerMsg(ctx, natAdd("192.0.2.8", 2048, 3072, "fd00::c", 100))
	b.handleServerMsg(ctx, endOfGlobal(2))
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, natAdd("192.0.2.8", 2048, 3072, "fd00::c", 100))
	b.handleServerMsg(ctx, endOfGlobal(1))
	wantReplaces(t, dp,
		[]string{"192.0.2.7 1024 2048 fd00::a", "192.0.2.8 2048 3072 fd00::c"},
		[]string{"192.0.2.8 2048 3072 fd00::c"})
	if _, ok := dp.getNbrNat("192.0.2.7", 1024, 2048); ok {
		t.Fatal("the block that left must be gone")
	}
}

// The guard: a lossy snapshot (fewer records than the marker says) must not replace — that would
// withdraw live blocks — but must still program what did arrive.
func TestEdgeLossySnapshotProgramsWhatArrivedAndPrunesNothing(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("edge", "fd00::e", dp, true)
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, natAdd("192.0.2.7", 1024, 2048, "fd00::a", 100))
	b.handleServerMsg(ctx, natAdd("192.0.2.8", 2048, 3072, "fd00::c", 100))
	b.handleServerMsg(ctx, endOfGlobal(2))
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, natAdd("192.0.2.9", 4096, 5120, "fd00::d", 100))
	b.handleServerMsg(ctx, endOfGlobal(3)) // the reflector sent 3, we got 1
	if len(dp.nbrNatReplaces) != 1 {
		t.Fatalf("a lossy snapshot must not replace; got %d replaces", len(dp.nbrNatReplaces))
	}
	if _, ok := dp.getNbrNat("192.0.2.9", 4096, 5120); !ok {
		t.Fatal("the block the lossy snapshot did carry must be programmed")
	}
	if _, ok := dp.getNbrNat("192.0.2.7", 1024, 2048); !ok {
		t.Fatal("a lossy snapshot must not remove a block it merely failed to carry")
	}
}

// After the marker, deltas are incremental: an add programs one block, a withdraw removes it.
func TestEdgeLiveNatDeltasAreIncremental(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("edge", "fd00::e", dp, true)
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, endOfGlobal(0))
	b.handleServerMsg(ctx, natAdd("192.0.2.7", 1024, 2048, "fd00::a", 100))
	if owner, ok := dp.getNbrNat("192.0.2.7", 1024, 2048); !ok || owner != "fd00::a" {
		t.Fatalf("a live add must program the block, got %q ok=%v", owner, ok)
	}
	b.handleServerMsg(ctx, natWithdraw("192.0.2.7", 1024, 2048, "fd00::a", 100))
	if !dp.nbrNatWd[natKeyStr("192.0.2.7", 1024, 2048)] {
		t.Fatal("a live withdraw must remove the block")
	}
}

// An older dataplane has no ReplaceNeighborNats: fall back to per-block programming and the diff
// against what this agent installed — the pre-replace behavior.
func TestEdgeFallsBackWhenTheDataplaneCannotReplace(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	dp.replaceErr = status.Error(codes.Unimplemented, "unknown method ReplaceNeighborNats")
	b := NewBus("edge", "fd00::e", dp, true)
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, natAdd("192.0.2.7", 1024, 2048, "fd00::a", 100))
	b.handleServerMsg(ctx, natAdd("192.0.2.8", 2048, 3072, "fd00::c", 100))
	b.handleServerMsg(ctx, endOfGlobal(2))
	if dp.nbrNatAdds != 2 {
		t.Fatalf("fallback must add each block, got %d adds", dp.nbrNatAdds)
	}
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, natAdd("192.0.2.8", 2048, 3072, "fd00::c", 100))
	b.handleServerMsg(ctx, endOfGlobal(1))
	if !dp.nbrNatWd[natKeyStr("192.0.2.7", 1024, 2048)] {
		t.Fatal("fallback must withdraw the block that left")
	}
	if dp.nbrNatWd[natKeyStr("192.0.2.8", 2048, 3072)] {
		t.Fatal("fallback must not withdraw a replayed block")
	}
}

// A Bus that has not closed a snapshot is replaying one — the state every session starts in and
// the only state a fresh Bus can honestly be in. Programming a record now would be programming
// against a set that is still arriving.
func TestAFreshBusIsReplayingItsSnapshot(t *testing.T) {
	dp := newRecordingDP()
	b := NewBus("edge", "fd00::e", dp, true)
	b.handleServerMsg(context.Background(), natAdd("192.0.2.7", 1024, 2048, "fd00::a", 100))
	if dp.nbrNatAdds != 0 {
		t.Fatalf("a Bus with no closed snapshot must collect, not program; got %d adds", dp.nbrNatAdds)
	}
}

// The fallback's diff basis is what a SUCCESSFUL replace installed, kept current by the live
// deltas since — the new-agent/old-dataplane skew the fallback exists for. It must withdraw exactly
// the blocks that replace still holds and the snapshot dropped: not one the agent already withdrew
// on a live delta (a second withdraw is a call against state nothing holds), and not a replayed one.
func TestFallbackDiffWithdrawsExactlyWhatTheReplaceStillHolds(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("edge", "fd00::e", dp, true)

	// Session 1 against a dataplane that CAN replace: three blocks land in one call.
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, natAdd("192.0.2.7", 1024, 2048, "fd00::a", 100))
	b.handleServerMsg(ctx, natAdd("192.0.2.8", 2048, 3072, "fd00::c", 100))
	b.handleServerMsg(ctx, natAdd("192.0.2.9", 3072, 4096, "fd00::d", 100))
	b.handleServerMsg(ctx, endOfGlobal(3))

	// .9's owner releases it while the session is up: a live withdraw, already applied.
	b.handleServerMsg(ctx, natWithdraw("192.0.2.9", 3072, 4096, "fd00::d", 100))

	// Reconnect onto a dataplane without the call, with a snapshot carrying only .7.
	dp.replaceErr = status.Error(codes.Unimplemented, "unknown method ReplaceNeighborNats")
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, natAdd("192.0.2.7", 1024, 2048, "fd00::a", 100))
	b.handleServerMsg(ctx, endOfGlobal(1))

	if got := dp.nbrNatWdN[natKeyStr("192.0.2.8", 2048, 3072)]; got != 1 {
		t.Fatalf("the block the snapshot dropped must be withdrawn exactly once, got %d calls", got)
	}
	if got := dp.nbrNatWdN[natKeyStr("192.0.2.9", 3072, 4096)]; got != 1 {
		t.Fatalf("the live-withdrawn block must not be withdrawn again by the diff, got %d calls", got)
	}
	if got := dp.nbrNatWdN[natKeyStr("192.0.2.7", 1024, 2048)]; got != 0 {
		t.Fatalf("the replayed block must not be withdrawn, got %d calls", got)
	}
}

// A replace that never reached the dataplane changed nothing, so there is nothing to repair: one
// AddNeighborNat per block would only meet the same dead socket. Any other error may have applied
// part of the set, and those blocks ARE reprogrammed. Neither prunes.
func TestEdgeReplaceFailureRepairsOnlyWhatMayHaveLanded(t *testing.T) {
	cases := []struct {
		code     codes.Code
		wantAdds int
	}{
		{codes.Unavailable, 0},
		{codes.DeadlineExceeded, 0},
		{codes.Canceled, 0}, // shutting down: N doomed per-block RPCs would be pure waste
		{codes.Internal, 2}, // the dataplane answered: the set may be part-way applied
	}
	for _, tc := range cases {
		t.Run(tc.code.String(), func(t *testing.T) {
			ctx := context.Background()
			dp := newRecordingDP()
			dp.replaceErr = status.Error(tc.code, "replace failed")
			b := NewBus("edge", "fd00::e", dp, true)
			b.resetGlobalSnapshot()
			b.handleServerMsg(ctx, natAdd("192.0.2.7", 1024, 2048, "fd00::a", 100))
			b.handleServerMsg(ctx, natAdd("192.0.2.8", 2048, 3072, "fd00::c", 100))
			b.handleServerMsg(ctx, endOfGlobal(2))
			if dp.nbrNatAdds != tc.wantAdds {
				t.Fatalf("want %d per-block adds after a %v replace, got %d", tc.wantAdds, tc.code, dp.nbrNatAdds)
			}
			if len(dp.nbrNatWd) != 0 {
				t.Fatalf("a failed replace must prune nothing, got %v", dp.nbrNatWd)
			}
		})
	}
}

// The traffic-affecting half at the edge: a backend that stopped announcing while the edge agent
// was disconnected keeps receiving its Maglev share until something removes it.
func TestEndOfGlobalPrunesUnreplayedLbBackend(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("edge", "fd00::e", dp, true)

	lbIP := "203.0.113.50/32"
	ports := []*rbv1.PortProto{{Port: 443, Proto: 6}}
	beA := &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_PublicUpdate{PublicUpdate: &rbv1.PublicUpdate{
		Op: rbv1.RouteOp_ROUTE_OP_ADD,
		Prefix: &rbv1.PublicPrefix{
			Kind: rbv1.PublicKind_PUBLIC_KIND_LB_IP, Prefix: lbIP,
			OwnerUnderlay: "fd00::a", OverlayIp: "10.0.0.1", Vni: 100, Ports: ports,
		},
	}}}
	beB := &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_PublicUpdate{PublicUpdate: &rbv1.PublicUpdate{
		Op: rbv1.RouteOp_ROUTE_OP_ADD,
		Prefix: &rbv1.PublicPrefix{
			Kind: rbv1.PublicKind_PUBLIC_KIND_LB_IP, Prefix: lbIP,
			OwnerUnderlay: "fd00::c", OverlayIp: "10.0.0.2", Vni: 100, Ports: ports,
		},
	}}}

	// Session 1: both backends attached.
	b.handleServerMsg(ctx, beA)
	b.handleServerMsg(ctx, beB)
	if got := len(dp.lbBackendOverlaysFor("203.0.113.50")); got != 2 {
		t.Fatalf("setup: want 2 backends attached, got %d", got)
	}

	// Reconnect: only backend A is replayed — B went away while we were down.
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, beA)
	b.handleServerMsg(ctx, endOfGlobal(1))

	got := dp.lbBackendOverlaysFor("203.0.113.50")
	if len(got) != 1 || got[0] != "10.0.0.1" {
		t.Fatalf("stale backend must be pruned, leaving only the replayed one; got %v", got)
	}
}

// Pruning the LAST backend must take the load balancer with it rather than leaving a registered
// LB address with an empty Maglev table, which would blackhole instead of failing closed.
func TestEndOfGlobalPruningLastBackendRemovesTheLoadBalancer(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("edge", "fd00::e", dp, true)

	only := &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_PublicUpdate{PublicUpdate: &rbv1.PublicUpdate{
		Op: rbv1.RouteOp_ROUTE_OP_ADD,
		Prefix: &rbv1.PublicPrefix{
			Kind: rbv1.PublicKind_PUBLIC_KIND_LB_IP, Prefix: "203.0.113.50/32",
			OwnerUnderlay: "fd00::a", OverlayIp: "10.0.0.1", Vni: 100,
			Ports: []*rbv1.PortProto{{Port: 443, Proto: 6}},
		},
	}}}
	b.handleServerMsg(ctx, only)

	// Reconnect with an EMPTY snapshot: the whole LB is gone.
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, endOfGlobal(0))

	found := false
	for _, id := range dp.lbDels {
		if id == "203.0.113.50" {
			found = true
		}
	}
	if !found {
		t.Fatalf("pruning the last backend must delete the LB too; dels=%v", dp.lbDels)
	}
}

// The route channel's sibling guard. prune-on-EndOfRIB had the same lossy-snapshot exposure the
// global channel just got fixed for: a replayed ADD dropped by the sink's outbound queue, followed
// by a delivered marker, withdrew a LIVE route. The count makes that a safe no-op instead.
func TestPruneOnEndOfRIBSkipsWhenSnapshotWasLossy(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeB", "fd00::b", dp, false)

	add := func(prefix string) *rbv1.ServerMsg {
		return &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_RouteUpdate{RouteUpdate: &rbv1.RouteUpdate{
			Vni: 100, Prefix: prefix, Nexthops: []string{"fd00::a"}, Op: rbv1.RouteOp_ROUTE_OP_ADD,
		}}}
	}
	b.handleServerMsg(ctx, add("10.0.0.1/32"))
	b.handleServerMsg(ctx, add("10.0.0.2/32"))

	// Reconnect where the replay of 10.0.0.1 was DROPPED: the reflector says it sent 2, we got 1.
	b.seen = map[uint32]map[string]bool{}
	b.resetRouteSnapshot(100)
	b.handleServerMsg(ctx, add("10.0.0.2/32"))
	b.handleServerMsg(ctx, &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfRib{
		EndOfRib: &rbv1.EndOfRIB{Vni: 100, RecordCount: 2},
	}})

	if dp.withdrew[key(100, "10.0.0.1/32")] {
		t.Fatalf("a lossy route snapshot must NOT prune: the route may still be live")
	}
}

// And the complete case still prunes, so the guard has not simply disabled the feature.
func TestPruneOnEndOfRIBStillPrunesOnACompleteSnapshot(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeB", "fd00::b", dp, false)

	add := func(prefix string) *rbv1.ServerMsg {
		return &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_RouteUpdate{RouteUpdate: &rbv1.RouteUpdate{
			Vni: 100, Prefix: prefix, Nexthops: []string{"fd00::a"}, Op: rbv1.RouteOp_ROUTE_OP_ADD,
		}}}
	}
	b.handleServerMsg(ctx, add("10.0.0.1/32"))
	b.handleServerMsg(ctx, add("10.0.0.2/32"))

	// Reconnect: 10.0.0.1 genuinely left the RIB, and the snapshot is complete (1 record, 1 claimed).
	b.seen = map[uint32]map[string]bool{}
	b.resetRouteSnapshot(100)
	b.handleServerMsg(ctx, add("10.0.0.2/32"))
	b.handleServerMsg(ctx, &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfRib{
		EndOfRib: &rbv1.EndOfRIB{Vni: 100, RecordCount: 1},
	}})

	if !dp.withdrew[key(100, "10.0.0.1/32")] {
		t.Fatalf("a complete snapshot must still prune the route that left the RIB")
	}
	if dp.withdrew[key(100, "10.0.0.2/32")] {
		t.Fatalf("replayed route must survive")
	}
}
