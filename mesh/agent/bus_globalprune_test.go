package agent

import (
	"context"
	"testing"

	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// The global (NAT + public) channel is replayed in full when a session registers, exactly like a
// VNI's routes — but it had no EndOfRIB equivalent, so nothing ever pruned it. A record WITHDRAWN
// while this agent was disconnected is simply absent from the replayed snapshot, and its dataplane
// entry lingered forever: Maglev kept hashing a share of flows to a backend that no longer exists,
// and neighbor-NAT kept a return route to a block that had moved. These tests pin the EndOfGlobal
// prune that closes it, and — just as importantly — the guard that stops it from pruning LIVE state
// when the replay was lossy.

func natAdd(natIP string, min, max uint32, owner string, vni uint32) *rbv1.ServerMsg {
	return &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_NatUpdate{NatUpdate: &rbv1.NatUpdate{
		Vni: vni, SourceIp: "10.0.0.9", NatIp: natIP, PortMin: min, PortMax: max,
		OwnerUnderlay: owner, Op: rbv1.RouteOp_ROUTE_OP_ADD,
	}}}
}

func endOfGlobal(n uint32) *rbv1.ServerMsg {
	return &rbv1.ServerMsg{Msg: &rbv1.ServerMsg_EndOfGlobal{EndOfGlobal: &rbv1.EndOfGlobal{RecordCount: n}}}
}

// A neighbor-NAT block learned in a previous session and NOT replayed in the new one is a block
// that moved to another node (or was released) while we were disconnected. Keeping it sends that
// public IP's return traffic to a node that no longer owns it.
func TestEndOfGlobalPrunesUnreplayedNatBlock(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeB", "fd00::b", dp, false)

	// Session 1: two blocks owned by other nodes.
	b.handleServerMsg(ctx, natAdd("192.0.2.7", 1024, 2048, "fd00::a", 100))
	b.handleServerMsg(ctx, natAdd("192.0.2.8", 2048, 3072, "fd00::c", 100))

	// Reconnect: only the second block is replayed.
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, natAdd("192.0.2.8", 2048, 3072, "fd00::c", 100))
	b.handleServerMsg(ctx, endOfGlobal(1))

	if !dp.nbrNatWd[natKeyStr("192.0.2.7", 1024, 2048)] {
		t.Fatalf("a NAT block absent from the replayed snapshot must be pruned")
	}
	if dp.nbrNatWd[natKeyStr("192.0.2.8", 2048, 3072)] {
		t.Fatalf("a replayed NAT block must NOT be pruned")
	}
}

// The guard. A sink's outbound queue drops on overflow, so "fewer records than the reflector says
// it sent" means the snapshot was incomplete — and pruning against it would withdraw live state,
// which is strictly worse than the staleness. The prune must be skipped entirely.
func TestEndOfGlobalSkipsPruneWhenSnapshotWasLossy(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeB", "fd00::b", dp, false)

	b.handleServerMsg(ctx, natAdd("192.0.2.7", 1024, 2048, "fd00::a", 100))
	b.handleServerMsg(ctx, natAdd("192.0.2.8", 2048, 3072, "fd00::c", 100))

	// Reconnect where the replay of 192.0.2.7 was DROPPED: the reflector says it sent 2 records,
	// the agent only got 1.
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, natAdd("192.0.2.8", 2048, 3072, "fd00::c", 100))
	b.handleServerMsg(ctx, endOfGlobal(2))

	if dp.nbrNatWd[natKeyStr("192.0.2.7", 1024, 2048)] {
		t.Fatalf("a lossy snapshot must NOT prune: the record may still be live")
	}
	if dp.nbrNatWd[natKeyStr("192.0.2.8", 2048, 3072)] {
		t.Fatalf("replayed block pruned on a lossy snapshot")
	}
}

// A block this node OWNS is never installed as a neighbor-NAT entry in the first place
// (applyNat skips it), so it must not be pruned either — there is nothing to withdraw, and a
// spurious withdraw would be a call against state we never programmed.
func TestEndOfGlobalIgnoresLocallyOwnedNatBlocks(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeB", "fd00::b", dp, false)

	// Owned by THIS node.
	b.handleServerMsg(ctx, natAdd("192.0.2.7", 1024, 2048, "fd00::b", 100))
	b.resetGlobalSnapshot()
	b.handleServerMsg(ctx, endOfGlobal(0))

	if dp.nbrNatWd[natKeyStr("192.0.2.7", 1024, 2048)] {
		t.Fatalf("a locally-owned block was never installed; it must not be withdrawn")
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
