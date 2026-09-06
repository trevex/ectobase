package agent

import (
	"sort"
	"testing"

	rbv1 "github.com/trevex/ectobase/mesh/gen/routebusv1"
)

func TestDiffDesired_InitialAnnouncesEverything(t *testing.T) {
	next := DesiredState{
		Subs:   []uint32{100, 200},
		Routes: []Route{{Vni: 100, Prefix: "10.0.0.5/32", Nexthop: "fd00::a"}},
		Nats:   []NatBlock{{Vni: 100, NatIP: "1.2.3.4", PortMin: 1024, PortMax: 2047, OwnerUnderlay: "fd00::a"}},
		Pubs:   []PublicPrefix{{Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "fd00::a"}},
	}
	d := diffDesired(DesiredState{}, next)
	if len(d.announceR) != 1 || len(d.announceN) != 1 || len(d.announceP) != 1 {
		t.Fatalf("initial diff must announce all records: %+v", d)
	}
	sort.Slice(d.subscribe, func(i, j int) bool { return d.subscribe[i] < d.subscribe[j] })
	if len(d.subscribe) != 2 || d.subscribe[0] != 100 || d.subscribe[1] != 200 {
		t.Fatalf("initial diff must subscribe all vnis: %+v", d.subscribe)
	}
	if len(d.withdrawR)+len(d.withdrawN)+len(d.withdrawP)+len(d.unsubscribe) != 0 {
		t.Fatalf("initial diff must not withdraw anything: %+v", d)
	}
}

func TestDiffDesired_NoChangeIsEmpty(t *testing.T) {
	s := DesiredState{
		Subs:   []uint32{100},
		Routes: []Route{{Vni: 100, Prefix: "10.0.0.5/32", Nexthop: "fd00::a"}},
		Nats:   []NatBlock{{Vni: 100, NatIP: "1.2.3.4", PortMin: 1024, PortMax: 2047, OwnerUnderlay: "fd00::a"}},
		Pubs:   []PublicPrefix{{Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "fd00::a"}},
	}
	if d := diffDesired(s, s); !d.empty() {
		t.Fatalf("identical desired must produce no delta: %+v", d)
	}
}

func TestDiffDesired_RemovedRecordsAreWithdrawn(t *testing.T) {
	applied := DesiredState{
		Subs:   []uint32{100, 200},
		Routes: []Route{{Vni: 100, Prefix: "10.0.0.5/32", Nexthop: "fd00::a"}},
		Nats:   []NatBlock{{Vni: 100, NatIP: "1.2.3.4", PortMin: 1024, PortMax: 2047, OwnerUnderlay: "fd00::a"}},
		Pubs:   []PublicPrefix{{Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "fd00::a"}},
	}
	// NIC descheduled: everything drops away.
	d := diffDesired(applied, DesiredState{Subs: []uint32{100}})
	if len(d.withdrawR) != 1 || d.withdrawR[0] != (routeRef{Vni: 100, Prefix: "10.0.0.5/32"}) {
		t.Fatalf("removed route must be withdrawn: %+v", d.withdrawR)
	}
	if len(d.withdrawN) != 1 || d.withdrawN[0] != (natRef{NatIP: "1.2.3.4", PortMin: 1024, PortMax: 2047}) {
		t.Fatalf("removed nat must be withdrawn: %+v", d.withdrawN)
	}
	if len(d.withdrawP) != 1 || d.withdrawP[0].Prefix != "203.0.113.50/32" {
		t.Fatalf("removed public must be withdrawn: %+v", d.withdrawP)
	}
	if len(d.unsubscribe) != 1 || d.unsubscribe[0] != 200 {
		t.Fatalf("removed sub 200 must be unsubscribed: %+v", d.unsubscribe)
	}
	if len(d.announceR)+len(d.announceN)+len(d.announceP)+len(d.subscribe) != 0 {
		t.Fatalf("nothing new to announce: %+v", d)
	}
}

// TestDiffDesired_SameNodeLBBackendsDistinctOverlayBothSurvive proves the control-plane half of the
// same-node-multi-backend fix: two LB_VIP records for the SAME (vip, owner-node) but with DIFFERENT
// backend overlay IPs (e.g. two pods of one Service scheduled on the same node) must NOT collapse
// into one announce — pubKey must disambiguate by overlay IP so both reach AddLbBackend.
func TestDiffDesired_SameNodeLBBackendsDistinctOverlayBothSurvive(t *testing.T) {
	next := DesiredState{
		Pubs: []PublicPrefix{
			{Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "fd00::a", Vni: 100, OverlayIP: "10.0.0.5"},
			{Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "fd00::a", Vni: 100, OverlayIP: "10.0.0.7"},
		},
	}
	d := diffDesired(DesiredState{}, next)
	if len(d.announceP) != 2 {
		t.Fatalf("two same-node backends with distinct overlay IPs must both be announced, got %d: %+v", len(d.announceP), d.announceP)
	}
	seen := map[string]bool{}
	for _, p := range d.announceP {
		seen[p.OverlayIP] = true
	}
	if !seen["10.0.0.5"] || !seen["10.0.0.7"] {
		t.Fatalf("both overlay IPs must be present in the announce set, got %+v", d.announceP)
	}

	// Now withdraw the first (10.0.0.5) only: the second (10.0.0.7) must remain applied, not withdrawn.
	applied := next
	next2 := DesiredState{
		Pubs: []PublicPrefix{
			{Kind: rbv1.PublicKind_PUBLIC_KIND_LB_VIP, Prefix: "203.0.113.50/32", OwnerUnderlay: "fd00::a", Vni: 100, OverlayIP: "10.0.0.7"},
		},
	}
	d2 := diffDesired(applied, next2)
	if len(d2.withdrawP) != 1 || d2.withdrawP[0].OverlayIP != "10.0.0.5" {
		t.Fatalf("only the removed overlay IP's backend must be withdrawn, got %+v", d2.withdrawP)
	}
	if len(d2.announceP) != 0 {
		t.Fatalf("the surviving backend must not be re-announced (unchanged), got %+v", d2.announceP)
	}
}

func TestDiffDesired_ChangedValueReAnnouncesWithoutWithdraw(t *testing.T) {
	applied := DesiredState{
		Routes: []Route{{Vni: 100, Prefix: "0.0.0.0/0", Nexthop: "fd00::e1"}},
	}
	next := DesiredState{
		Routes: []Route{{Vni: 100, Prefix: "0.0.0.0/0", Nexthop: "fd00::e2"}}, // nexthop changed
	}
	d := diffDesired(applied, next)
	if len(d.announceR) != 1 || d.announceR[0].Nexthop != "fd00::e2" {
		t.Fatalf("changed nexthop must re-announce with new value: %+v", d.announceR)
	}
	if len(d.withdrawR) != 0 {
		t.Fatalf("re-announce (upsert by key) must not withdraw: %+v", d.withdrawR)
	}
}
