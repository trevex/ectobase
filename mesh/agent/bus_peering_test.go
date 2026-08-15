package agent

import (
	"context"
	"testing"

	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// peerImportTestHelpers — small helpers to drive the Bus apply path for peering
// precedence tests. Own vs peer routes both land on the LOCAL vni; the recording
// fake keys by prefix, so the installed value for a prefix is what we assert.

func setPeerImports(b *Bus, m map[uint32][]PeerImport) {
	b.mu.Lock()
	b.peerImports = m
	b.mu.Unlock()
}

// deliverOwn delivers an OWN route learned on the local vni (the existing direct-route path).
func deliverOwn(ctx context.Context, b *Bus, vni uint32, prefix, nh string) {
	b.apply(ctx, &rbv1.RouteUpdate{Vni: vni, Prefix: prefix, Nexthops: []string{nh}, Op: rbv1.RouteOp_ROUTE_OP_ADD})
}

func withdrawOwn(ctx context.Context, b *Bus, vni uint32, prefix string) {
	b.apply(ctx, &rbv1.RouteUpdate{Vni: vni, Prefix: prefix, Op: rbv1.RouteOp_ROUTE_OP_WITHDRAW})
}

// deliverPeer delivers a route learned on a PEER vni (imported into any importing local vni).
func deliverPeer(ctx context.Context, b *Bus, peerVNI uint32, prefix, nh string) {
	b.apply(ctx, &rbv1.RouteUpdate{Vni: peerVNI, Prefix: prefix, Nexthops: []string{nh}, Op: rbv1.RouteOp_ROUTE_OP_ADD})
}

// (a) Import within prefixes installs into the LOCAL VNI; outside is dropped.
func TestPeeringImport_FilterByPrefix(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	setPeerImports(b, map[uint32][]PeerImport{
		100: {{PeerVNI: 200, ImportPrefixes: []string{"10.1.0.0/24"}}},
	})

	// Within the imported prefix -> installed into LOCAL vni 100, external=false.
	deliverPeer(ctx, b, 200, "10.1.0.5/32", "fd00::peer")
	if nh, ok := dp.get(100, "10.1.0.5/32"); !ok || nh != "fd00::peer" {
		t.Fatalf("in-range peer route must import into vni=100 -> fd00::peer; got %q ok=%v", nh, ok)
	}
	got := lastAdd(dp, "10.1.0.5/32")
	if got == nil || got.vni != 100 || got.external {
		t.Fatalf("imported route must be vni=100 external=false; got %+v", got)
	}

	// Outside the imported prefix -> dropped (no install under vni 100).
	deliverPeer(ctx, b, 200, "10.9.9.9/32", "fd00::peer")
	if _, ok := dp.get(100, "10.9.9.9/32"); ok {
		t.Fatalf("out-of-range peer route must NOT be imported")
	}
}

// (b) Local precedence: an OWN route for a prefix is never overwritten by a peer import.
func TestPeeringImport_LocalPrecedence(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	setPeerImports(b, map[uint32][]PeerImport{
		100: {{PeerVNI: 200, ImportPrefixes: []string{"10.1.0.0/24"}}},
	})

	// OWN route installed first (direct path on local vni 100).
	deliverOwn(ctx, b, 100, "10.1.0.5/32", "fd00::own")
	// Peer import for the SAME prefix must NOT overwrite it.
	deliverPeer(ctx, b, 200, "10.1.0.5/32", "fd00::peer")

	if nh, ok := dp.get(100, "10.1.0.5/32"); !ok || nh != "fd00::own" {
		t.Fatalf("own route must win; got %q ok=%v", nh, ok)
	}
	if b.origin[100]["10.1.0.5/32"] != "own" {
		t.Fatalf("origin must stay own; got %q", b.origin[100]["10.1.0.5/32"])
	}
}

// (c) Own route arriving AFTER an import evicts it; own withdraw restores the import.
func TestPeeringImport_EvictAndRestore(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	setPeerImports(b, map[uint32][]PeerImport{
		100: {{PeerVNI: 200, ImportPrefixes: []string{"10.1.0.0/24"}}},
	})

	// Peer import installed first.
	deliverPeer(ctx, b, 200, "10.1.0.5/32", "fd00::peer")
	if nh, ok := dp.get(100, "10.1.0.5/32"); !ok || nh != "fd00::peer" {
		t.Fatalf("peer import must install first; got %q ok=%v", nh, ok)
	}
	if b.origin[100]["10.1.0.5/32"] != "peer" {
		t.Fatalf("origin must be peer after import; got %q", b.origin[100]["10.1.0.5/32"])
	}

	// OWN route arrives -> evicts the import (overwrites with own nexthop).
	deliverOwn(ctx, b, 100, "10.1.0.5/32", "fd00::own")
	if nh, ok := dp.get(100, "10.1.0.5/32"); !ok || nh != "fd00::own" {
		t.Fatalf("own route must evict peer import; got %q ok=%v", nh, ok)
	}
	if b.origin[100]["10.1.0.5/32"] != "own" {
		t.Fatalf("origin must flip to own after eviction; got %q", b.origin[100]["10.1.0.5/32"])
	}

	// OWN route withdraws -> the peer import is restored.
	withdrawOwn(ctx, b, 100, "10.1.0.5/32")
	if nh, ok := dp.get(100, "10.1.0.5/32"); !ok || nh != "fd00::peer" {
		t.Fatalf("peer import must be restored on own withdraw; got %q ok=%v", nh, ok)
	}
	if b.origin[100]["10.1.0.5/32"] != "peer" {
		t.Fatalf("origin must be peer after restore; got %q", b.origin[100]["10.1.0.5/32"])
	}
}

// (d) Dual-role VNI: when this node hosts guests in BOTH peered VPCs, a RouteUpdate on VNI-A (its own
// table) must install into A's OWN table AND import into B's table (B imports A). Both, not either.
func TestPeeringImport_DualRoleVNIInstallsBoth(t *testing.T) {
	ctx := context.Background()
	dp := newRecordingDP()
	b := NewBus("nodeA", "fd00::a", dp, false)
	// Node hosts VPC-A (local VNI 100) and VPC-B (local VNI 200); B imports A.
	setPeerImports(b, map[uint32][]PeerImport{
		200: {{PeerVNI: 100, ImportPrefixes: []string{"10.0.0.0/24"}}},
	})

	// An A-guest host route arrives on VNI 100.
	deliverOwn(ctx, b, 100, "10.0.0.5/32", "fd00::nh")

	// Own install into A's OWN table (vni=100).
	if nh, ok := dp.get(100, "10.0.0.5/32"); !ok || nh != "fd00::nh" {
		t.Fatalf("own install into A's table (vni=100) must happen; got %q ok=%v", nh, ok)
	}
	if b.origin[100]["10.0.0.5/32"] != "own" {
		t.Fatalf("origin in A's table must be own; got %q", b.origin[100]["10.0.0.5/32"])
	}
	// Peer import into B's table (vni=200).
	if nh, ok := dp.get(200, "10.0.0.5/32"); !ok || nh != "fd00::nh" {
		t.Fatalf("peer import into B's table (vni=200) must ALSO happen; got %q ok=%v", nh, ok)
	}
	if b.origin[200]["10.0.0.5/32"] != "peer" {
		t.Fatalf("origin in B's table must be peer; got %q", b.origin[200]["10.0.0.5/32"])
	}

	// The withdraw must clear BOTH tables (assert via withdrew: the fake never deletes from `added`).
	withdrawOwn(ctx, b, 100, "10.0.0.5/32")
	if !dp.withdrew[key(100, "10.0.0.5/32")] {
		t.Fatalf("withdraw must clear A's own route (vni=100)")
	}
	if !dp.withdrew[key(200, "10.0.0.5/32")] {
		t.Fatalf("withdraw must clear B's imported route (vni=200)")
	}
}

// lastAdd returns the last recorded AddRoute for a prefix (nil if none).
func lastAdd(dp *recordingDP, prefix string) *routeCall {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	var out *routeCall
	for i := range dp.routeAdds {
		if dp.routeAdds[i].prefix == prefix {
			c := dp.routeAdds[i]
			out = &c
		}
	}
	return out
}
