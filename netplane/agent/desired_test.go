package agent

import (
	"sort"
	"testing"

	rbv1 "github.com/trevex/xdp-dp/netplane/gen/routebusv1"
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
