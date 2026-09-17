package agent

import (
	"context"
	"testing"

	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

// edgeReconciler is a WAN edge as it actually runs: a router with a local dataplane, a loopback,
// and NO Kubernetes client at all.
func edgeReconciler(dp Dataplane) *Reconciler {
	return &Reconciler{nodeID: "edge1", underlay: "fd00:ffff::e1", edgeLoopback: "fd00:ffff::e1", dp: dp}
}

// The regression this whole design exists to prevent. Desired's CompiledNIC read used to abort the
// entire tick on error, so an agent without an API server announced NOTHING — not even the egress
// defaults and its own identity, which need no API data at all. An edge has no API server by
// construction, so that failure would have been its steady state.
func TestEdgeModeDesiredAnnouncesEgressDefaultsWithoutAPIServer(t *testing.T) {
	r := edgeReconciler(newRecordingDP())

	subs, announce, nats, egressVNIs, peerImports, err := r.Desired(context.Background())
	if err != nil {
		t.Fatalf("edge Desired must not fail without an API server: %v", err)
	}

	want := map[string]bool{"0.0.0.0/0": false, "::/0": false, "64:ff9b::/96": false}
	for _, rt := range announce {
		if _, ok := want[rt.Prefix]; !ok {
			t.Errorf("unexpected route announced by an edge: %+v", rt)
			continue
		}
		if rt.Vni != PublicVNI || !rt.External || rt.Nexthop != "fd00:ffff::e1" {
			t.Errorf("external default %s = %+v, want vni=0 external=true nexthop=fd00:ffff::e1", rt.Prefix, rt)
		}
		want[rt.Prefix] = true
	}
	for prefix, seen := range want {
		if !seen {
			t.Errorf("edge did not originate the external default %s", prefix)
		}
	}

	// It must subscribe to the public VNI it originates into, and to nothing else: it hosts no guests.
	if len(subs) != 1 || subs[0] != PublicVNI {
		t.Errorf("subs = %+v, want [%d]", subs, PublicVNI)
	}
	if len(nats) != 0 || len(egressVNIs) != 0 || len(peerImports) != 0 {
		t.Errorf("edge derived tenant state from nothing: nats=%+v egress=%+v peers=%+v", nats, egressVNIs, peerImports)
	}
}

// The edge's own identity on the bus is likewise API-free: it is derived from its flags.
func TestEdgeModeDesiredPublicAnnouncesEdgeUnderlayWithoutAPIServer(t *testing.T) {
	r := edgeReconciler(newRecordingDP())

	pubs, err := r.DesiredPublic(context.Background())
	if err != nil {
		t.Fatalf("edge DesiredPublic must not fail without an API server: %v", err)
	}
	if len(pubs) != 1 {
		t.Fatalf("want exactly the EDGE_UNDERLAY record, got %+v", pubs)
	}
	if pubs[0].Kind != rbv1.PublicKind_PUBLIC_KIND_EDGE_UNDERLAY ||
		pubs[0].Prefix != "fd00:ffff::e1/128" || pubs[0].OwnerUnderlay != "fd00:ffff::e1" {
		t.Errorf("EDGE_UNDERLAY record = %+v", pubs[0])
	}
}

// The per-NIC reconcilers have nothing to do on an edge (it hosts no guests) and must say so
// quietly rather than erroring every tick against an API server that is not there.
func TestEdgeModeNICReconcilersAreQuietNoOps(t *testing.T) {
	r := edgeReconciler(newRecordingDP())
	ctx := context.Background()

	if err := r.ReconcileFirewall(ctx); err != nil {
		t.Errorf("ReconcileFirewall: %v", err)
	}
	if err := r.ReconcileQoS(ctx); err != nil {
		t.Errorf("ReconcileQoS: %v", err)
	}
	// An edge is not a Kubernetes Node, so there is no Node object to carry the fence coordinate.
	if err := r.StampNodePrefix(ctx); err != nil {
		t.Errorf("StampNodePrefix: %v", err)
	}
}

// A clientless Reconciler is what --edge-loopback without a kubeconfig builds; it must come back
// usable rather than failing on an in-cluster config that does not exist outside a Pod.
func TestNewReconcilerWithoutAPIServer(t *testing.T) {
	dp := newRecordingDP()
	r, err := NewReconciler("", "edge1", Deps{
		Underlay: "fd00:ffff::e1", Dataplane: dp, EdgeLoopback: "fd00:ffff::e1", NoAPIServer: true,
	})
	if err != nil {
		t.Fatalf("NewReconciler(NoAPIServer): %v", err)
	}
	if _, err := r.DesiredPublic(context.Background()); err != nil {
		t.Fatalf("clientless reconciler is not usable: %v", err)
	}
}
